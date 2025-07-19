/* 
 * This file is part of the 'Stitch' binary patching library.
 * Copyright (c) 2025 pygrum
 * 
 * This program is free software: you can redistribute it and/or modify  
 * it under the terms of the GNU General Public License as published by  
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but 
 * WITHOUT ANY WARRANTY; without even the implied warranty of 
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU 
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License 
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#include "stitch/target/x86.h"

#include <algorithm>
#include <set>

namespace stitch {
Function* X86Code::EditFunction(const VA address, const Section& scn) {
  return EditFunction(address, scn.GetName());
}

X86Function* X86Code::editFunction(const VA address, const std::string& in) {
  int reopen_idx = -1;
  for (int i = 0; i < functions_.size(); i++) {
    X86Function* fn = functions_[i].get();
    if (fn->GetAddress() == address) {
      if (!fn->finished_)
        return fn;
      reopen_idx = i;
      break;
    }
  }
  std::string new_scn_name = in;
  if (in.empty())
    new_scn_name = ".stitch";
  Section* scn = GetParent();
  const RVA scn_address = scn->GetAddress();
  const uint64_t scn_size = scn->GetSize();
  const std::vector<uint8_t>& scn_data = scn->GetData();

  const RVA rva = address - scn->GetParent()->GetImageBase(); // to RVA
  // has to be within scn
  if (rva < scn_address || rva > scn_address + scn_size)
    throw code_error("address out of range");

  const VA scn_rel_address = rva - scn_address;
  const uint8_t* data = scn_data.data() + scn_rel_address;
  const size_t data_size = scn_data.size() - scn_rel_address;

  Binary* bin = GetParent()->GetParent();
  Section* new_scn = nullptr;
  try {
    new_scn = bin->OpenSection(new_scn_name);
  } catch (const std::exception& _) {
    new_scn = bin->AddSection(new_scn_name, SectionType::Code);
  }
  X86Function* fn = buildFunction(address, data, data_size, reopen_idx);
  fn->setNewSection(new_scn);
  return fn;
}

Function* X86Code::EditFunction(const VA address, const std::string& in) {
  X86Function* fn = editFunction(address, in);
  fn->finalize();
  return fn;
}

Function* X86Code::RebuildFunction(const VA address, const std::string& in) {
  X86Function* fn = editFunction(address, in);
  return fn;
}

Function* X86Code::RebuildFunction(const VA address, const Section& scn) {
  X86Function* fn = editFunction(address, scn.GetName());
  return fn;
}

// assumes moveDelta was NOT called before this
void
X86Code::patchOriginalLocation(const X86Function& fn, const VA new_loc) const {
  Section* scn = GetParent();
  const VA image_base = scn->GetParent()->GetImageBase();
  for (const auto& bb : fn.basic_blocks_) {
    const VA bb_addr = bb->GetAddress();
    const int64_t bb_size = bb->GetSize();
    // basic block address relative to the section's start address
    const RVA bb_rel_addr = bb_addr
                            - scn->GetAddress()
                            - image_base;
    // double check that basic block fits inside section
    if (bb_addr - image_base + bb_size > scn->GetAddress() + scn->GetSize())
      throw code_error("basic block outside of section range");
    scn->Memset(bb_rel_addr, 0xcc, bb_size); // patch with int3
  }
  zasm::Program program(fn.getMachineMode());
  zasm::x86::Assembler as(program);
  patch_policy_(as, fn.GetAddress(), new_loc);
  zasm::Serializer serializer;
  const zasm::Error err = serializer.serialize(program, fn.GetAddress());
  if (err.getCode() != zasm::ErrorCode::None)
    throw code_error(std::string("failed to move function: ")
                     + err.getErrorMessage());
  // make sure that the patch code fits within the first basic block so that we aren't
  // overwriting code of another function
  const X86BasicBlock* first_bb = fn.basic_blocks_.front().get();
  if (serializer.getCodeSize() > first_bb->GetSize())
    throw code_error("patch stub too large");
  // now replace first basic block's address with the patch
  const RVA bb_rel_addr = first_bb->GetAddress()
                          - scn->GetAddress()
                          - image_base;
  scn->WriteAt(bb_rel_addr, serializer.getCode(), serializer.getCodeSize());
}

void
X86Function::findAndSplitBasicBlock(const VA address,
                                    X86BasicBlock* new_parent) {
  for (const auto& bb : basic_blocks_) {
    // if we fall at the start of the basic block then no need to split,
    // just add our own block as a parent
    const VA bb_addr = bb->GetAddress();
    if (address == bb_addr) {
      bb->AddParent(new_parent);
      return;
    }
    // if address is within basic block, then split it
    if (address > bb_addr && address < bb_addr + bb->GetSize()) {
      X86BasicBlock* new_block = splitAfter(bb.get(), address);
      new_block->AddParent(new_parent);
      return;
    }
  }
}

X86BasicBlock* X86Function::splitAfter(X86BasicBlock* block, const VA address) {
  std::vector<X86Inst*> insts;
  // new block is child of old block
  X86BasicBlock* new_block = addBasicBlock(address, 0, block);
  for (auto& inst : instructions_) {
    // move insts that are within the old block to the new block
    if (inst.getAddress() >= address &&
        inst.getAddress() < block->GetAddress() + block->GetSize()) {
      inst.setBasicBlock(new_block);
      new_block->SetSize(new_block->GetSize() + inst.RawInst().getLength());
    }
  }
  return new_block;
}

X86BasicBlock* X86Function::addBasicBlock(VA loc,
                                          uint64_t size,
                                          X86BasicBlock* parent) {
  return basic_blocks_.emplace_back(std::make_unique<X86BasicBlock>(
      loc, size, parent)).get();
}

// Used only for tail calls. Before we improve the detection for tail calls, we will add
// the basic block's parents as exit blocks.
void X86Function::removeBasicBlockTree(const VA loc) {
  std::set<VA> parents;
  parents.insert(loc);
  for (auto it = basic_blocks_.begin(); it != basic_blocks_.end();) {
    const auto& bb = *it;
    VA bb_addr = bb->GetAddress();
    bool removed = false;
    if (bb_addr == loc) {
      // add parent(s) as exit block(s)
      for (const auto& parent : (*it)->GetParents())
        exit_blocks_.push_back(parent);
      it = basic_blocks_.erase(it);
      continue;
    }
    // remove any children of this BB add their address to parents<>
    // to remove their children too on later iterations
    for (const X86BasicBlock* parent : bb->GetParents()) {
      if (parent && parents.contains(parent->GetAddress())) {
        it = basic_blocks_.erase(it);
        parents.insert(bb_addr);
        removed = true;
        break;
      }
    }
    if (!removed) {
      ++it;
    }
  }
}

X86Function* X86Code::buildFunction(const VA fn_address,
                                    const uint8_t* code,
                                    const size_t code_size,
                                    const int reopen_idx
    ) {
  std::set<VA> visited_insts;
  std::map<VA, int64_t> jump_gaps;

  const zasm::MachineMode mm =
      GetArchitecture() == TargetArchitecture::I386
        ? zasm::MachineMode::I386
        : zasm::MachineMode::AMD64;

  X86Function* fn = nullptr;
  auto uf = std::make_unique<X86Function>(fn_address, zasm::Program(mm), this);
  if (reopen_idx != -1) {
    functions_[reopen_idx] = std::move(uf);
    fn = functions_[reopen_idx].get();
  } else {
    functions_.emplace_back(std::move(uf));
    fn = functions_.back().get();
  }
  zasm::Decoder decoder(mm);

  fn->buildBasicBlocks(decoder,
                       code,
                       code_size,
                       fn_address,
                       0,
                       visited_insts,
                       jump_gaps,
                       false,
                       nullptr);
  std::sort(fn->instructions_.begin(), fn->instructions_.end());
  fn->assembler_.align(zasm::Align::Type::Code, kFunctionAlignment);
  return fn;
}

zasm::MachineMode X86Function::getMachineMode() const {
  return GetParent()->GetArchitecture() == TargetArchitecture::I386
           ? zasm::MachineMode::I386
           : zasm::MachineMode::AMD64;
}

void X86Function::buildBasicBlocks(zasm::Decoder& decoder,
                                   const uint8_t* code,
                                   const size_t code_size,
                                   VA runtime_address,
                                   VA offset,
                                   std::set<VA>& visited_insts,
                                   std::map<VA, int64_t>& jump_gaps,
                                   const bool recursed,
                                   X86BasicBlock* parent_block) {
  X86BasicBlock* basic_block = nullptr;
  if (recursed) {
    checkTailCall(runtime_address, jump_gaps);
  }
  while (offset < code_size) {
    if (visited_insts.contains(runtime_address)) {
      /*
       * This will either:
       * 1. Add a new parent for the basic block that we've reached, or
       * 2. If we jumped to the middle of an already-created basic block, then we
       *    split it at that point, and set the new block's parents to where we
       *    jumped from (parent_block) and the block that used to own the instruction
       *    at that address
       */
      findAndSplitBasicBlock(runtime_address, parent_block);
      return;
    }
    if (basic_block == nullptr)
      basic_block = addBasicBlock(runtime_address, 0, parent_block);
    auto result = decoder.decode(code + offset,
                                 code_size - offset,
                                 runtime_address);
    if (!result) {
      throw code_error(result.error().getErrorMessage());
    }
    const auto& inst = result.value();
    const uint8_t inst_length = inst.getLength();
    visited_insts.emplace(runtime_address);
    instructions_.emplace_back(inst, this, basic_block)
                 .setAddress(runtime_address);
    // move 'cursor' forward
    basic_block->SetSize(basic_block->GetSize() + inst_length);
    offset += inst_length;
    runtime_address += inst_length;
    // any branching instruction other than call terminates a basic block
    if (zasm::x86::isBranching(inst) && inst.getCategory() !=
        zasm::x86::Category::Call) {
      if (inst.getCategory() == zasm::x86::Category::Ret) {
        exit_blocks_.push_back(basic_block);
        return;
      }
      int64_t cf_dst = 0;
      // if not immediate, e.g. reg or mem/var jmp, then don't turn into BB
      try {
        cf_dst = inst.getOperand<zasm::Imm>(0).value<int64_t>();
      } catch (const std::exception& _) {
        // terminate basic block even if we can't determine the jmp destination
        if (inst.getCategory() == zasm::x86::Category::UncondBR) {
          exit_blocks_.push_back(basic_block);
        }
        return;
      }
      /*
       * With an unconditional jump, we will be jumping over code and going to a new location.
       * we need to make sure that this skipped block is referred to again. if it isn't then we
       * class this jump as a tail call.
       *
       * Once we've gotten back to the top level, we check if jump gaps exist. If they do,
       * we eliminate every basic block that is a child of that jump, as it isn't part of the
       * function.
       */
      int64_t jump_distance = cf_dst - runtime_address;
      if (inst.getCategory() == zasm::x86::Category::UncondBR) {
        jump_gaps.emplace(runtime_address, jump_distance);
      }
      buildBasicBlocks(decoder,
                       code,
                       code_size,
                       cf_dst,
                       offset + jump_distance,
                       visited_insts,
                       jump_gaps,
                       true,
                       basic_block);
      // We check if we jumped over code that was never referenced and eliminate
      // the block that we jumped to as well as all its children
      if (inst.getCategory() == zasm::x86::Category::UncondBR) {
        if (!recursed && !jump_gaps.empty()) {
          for (auto [skip_addr, gap_size] : jump_gaps) {
            removeBasicBlockTree(skip_addr + gap_size);
          }
        }
        // unconditional jump terminates a BB
        return;
      }
      basic_block = addBasicBlock(runtime_address, 0, basic_block);
    }
  }
}

/*
 * We check if the address we have reached is anywhere within a gap
 * that we previously (unconditionally) jumped over, and if it is then it
 * is safe to say that it was not a tail call.
 */
void X86Function::checkTailCall(const VA current_inst_addr,
                                std::map<VA, int64_t>& jump_gaps) const {
  for (auto [jmp_inst_addr, jmp_rel_dst] : jump_gaps) {
    const VA jmp_abs_dst = jmp_inst_addr + jmp_rel_dst;
    // if jump goes outside of function (above), then it's def a tail call.
    // don't erase it, the basic block will be removed at the top level
    if (jmp_abs_dst < GetAddress()) {
      continue;
    }
    // if the jmp dest is between the start of the function and the jmp instruction
    // address, then it can't be a tail call since it's intra-function
    if (jmp_abs_dst >= GetAddress() && jmp_abs_dst < jmp_inst_addr) {
      jump_gaps.erase(jmp_inst_addr);
      break;
    }
    // if the jmp dest is after the jmp instruction AND it is being visited by us,
    // we remove it from the potential tail call list
    for (VA skip_addr = jmp_inst_addr; skip_addr < jmp_abs_dst; skip_addr
         ++) {
      if (skip_addr == current_inst_addr) {
        // we beat the tail call allegations
        jump_gaps.erase(jmp_inst_addr);
        break;
      }
    }
  }
}

bool X86Function::isWithinFunction(const uint64_t address) const {
  bool within = false;
  for (const auto& bb : basic_blocks_) {
    if (address >= bb->GetAddress() &&
        address < bb->GetAddress() + bb->GetSize()) {
      within = true;
      break;
    }
  }
  return within;
}

void X86Function::moveDelta(const int64_t delta) {
  // fix any references to the instruction in .reloc
  for (X86Inst& inst : instructions_) {
    inst.Relocate(inst.getAddress() + delta);
  }
}

void X86Function::finalize() {
  std::map<VA, zasm::Label> labels;
  std::map<VA, zasm::Node*> jump_dsts;
  assembler_.align(zasm::Align::Type::Code, X86Code::GetFunctionAlignment());
  // first iteration - get all relN instructions and create labels for them
  for (X86Inst& inst : instructions_) {
    const zasm::InstructionDetail& raw_inst = inst.RawInst();
    if ((zasm::x86::isBranching(raw_inst) &&
         raw_inst.getMnemonic() != zasm::x86::Mnemonic::Ret) ||
        raw_inst.getMnemonic() == zasm::x86::Mnemonic::Loop ||
        raw_inst.getMnemonic() == zasm::x86::Mnemonic::Loope ||
        raw_inst.getMnemonic() == zasm::x86::Mnemonic::Loopne
    ) {
      VA jmp_addr = raw_inst.getOperand<zasm::Imm>(0).value<int64_t>();
      if (!isWithinFunction(jmp_addr)) {
        assembler_.emit(raw_inst);
        inst.setPos(assembler_.getCursor());
        continue;
      }
      zasm::Label jmp_label = assembler_.createLabel();
      labels.emplace(jmp_addr, jmp_label);
      assembler_.emit(raw_inst.getMnemonic(), jmp_label);
    } else {
      assembler_.emit(raw_inst);
    }
    inst.setPos(assembler_.getCursor());
  }
  zasm::Node* end = assembler_.getCursor();
  // second iteration - bind labels to
  for (X86Inst& inst : instructions_) {
    // if we reach instruction that is destination of a jmp label, then
    // bind assembler cursor to the label (since we are going to emit this
    // instruction next)
    if (labels.contains(inst.getAddress())) {
      const zasm::Label& label = labels[inst.getAddress()];
      assembler_.setCursor(inst.GetPos()->getPrev());
      assembler_.bind(label);
    }
  }
  assembler_.setCursor(end);
}

void X86Function::Finish() {
  if (finished_)
    throw std::runtime_error("function already marked as finished");
  // pointer to end of section
  VA new_write_address = new_section_->GetParent()->GetImageBase()
                         + new_section_->GetAddress()
                         + new_section_->GetSize();
  // align to boundary since assembler pushes align bytes at start of program
  new_write_address = utils::RoundToBoundary(new_write_address,
                                             X86Code::GetFunctionAlignment());
  const int64_t move_dist = new_write_address - GetAddress();
  GetParent<X86Code>()->patchOriginalLocation(*this, new_write_address);
  moveDelta(move_dist);
  zasm::Serializer serializer;
  const zasm::Error code = serializer.serialize(program_, new_write_address);
  if (code.getCode() != zasm::ErrorCode::None)
    throw code_error(code.getErrorMessage());
  new_section_->Write(serializer.getCode(), serializer.getCodeSize());
  finished_ = true;
}

void X86FunctionBuilder::Finish() {
  if (finished_)
    throw std::runtime_error("function already marked as finished");
  code_->Assemble(program_);
  finished_ = true;
}
}