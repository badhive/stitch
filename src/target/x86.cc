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

#include <iostream>

namespace stitch {
Function& X86Code::EditFunction(const VA address, const Section& scn) {
  return EditFunction(address, scn.GetName());
}

Function& X86Code::EditFunction(const VA address, std::string in) {
  int reopen_idx = -1;
  for (int i = 0; i < functions_.size(); i++) {
    X86Function& fn = functions_[i].value();
    if (fn.GetAddress() == address) {
      if (!fn.finished_)
        return fn;
      reopen_idx = i;
      break;
    }
  }
  if (in.empty())
    in = ".stitch";
  Section* scn = GetParent();
  const RVA scn_address = scn->GetAddress();
  const uint64_t scn_size = scn->GetSize();
  const std::vector<uint8_t>& scn_data = scn->GetData();

  const RVA rva = address - scn->GetParent()->GetImageBase(); // to RVA
  // has to be within scn
  if (rva < scn_address || rva > (scn_address + scn_size))
    throw code_error("address out of range");

  const RVA scn_rel_address = rva - scn_address;
  const uint8_t* data = scn_data.data() + scn_rel_address;
  const size_t data_size = scn_data.size() - scn_rel_address;

  Binary* bin = GetParent()->GetParent();
  Section* new_scn = nullptr;
  try {
    new_scn = &bin->OpenSection(in);
  } catch (const std::exception& _) {
    new_scn = &bin->AddSection(in, Section::Type::Code);
  }
  X86Function& fn = buildFunction(address, data, data_size, reopen_idx);
  fn.setNewSection(new_scn);
  fn.finalize();
  return fn;
}

// assumes moveDelta was NOT called before this
void X86Code::patchOriginalLocation(X86Function& fn, const VA new_loc) const {
  Section* scn = GetParent();
  const VA image_base = scn->GetParent()->GetImageBase();
  for (const auto [bb_addr, bb_size, _] : fn.basic_blocks_) {
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
  auto [bb_addr, bb_size, _] = fn.basic_blocks_.front();
  if (serializer.getCodeSize() > bb_size)
    throw code_error("patch stub too large");
  // now replace first basic block's address with the patch
  const RVA bb_rel_addr = bb_addr
                          - scn->GetAddress()
                          - image_base;
  scn->WriteAt(bb_rel_addr, serializer.getCode(), serializer.getCodeSize());
}

X86Function& X86Code::buildFunction(const RVA fn_address,
                                    const uint8_t* code,
                                    const size_t code_size,
                                    const int reopen_idx
    ) {
  std::map<RVA, const zasm::InstructionDetail&> visited_insts;
  std::map<RVA, int64_t> jump_gaps;

  const zasm::MachineMode mm =
      GetArchitecture() == TargetArchitecture::I386
        ? zasm::MachineMode::I386
        : zasm::MachineMode::AMD64;

  X86Function& fn = reopen_idx != -1
                      ? functions_[reopen_idx].emplace(
                          fn_address, zasm::Program(mm), this)
                      : *functions_.emplace_back(std::in_place, fn_address,
                                                 zasm::Program(mm),
                                                 this);
  zasm::Decoder decoder(mm);

  fn.buildBasicBlocks(decoder,
                      code,
                      code_size,
                      fn_address,
                      0,
                      visited_insts,
                      jump_gaps,
                      false,
                      -1);
  return fn;
}

zasm::MachineMode X86Function::getMachineMode() const {
  return GetParent()->GetArchitecture() == TargetArchitecture::I386
           ? zasm::MachineMode::I386
           : zasm::MachineMode::AMD64;
}

void X86Function::addBasicBlock(RVA loc, uint64_t size, RVA parent) {
  basic_blocks_.emplace_back(loc, size, parent);
}

// relies on the fact that basic block children come after their parents in the list
void X86Function::removeBasicBlockTree(const RVA loc) {
  std::map<RVA, bool> parents;
  parents[loc] = true;
  for (auto it = basic_blocks_.begin(); it != basic_blocks_.end();) {
    auto& [bb_addr, bb_size, bb_parent] = *it;
    bool removed = false;
    // remove parent block
    if (bb_addr == loc) {
      it = basic_blocks_.erase(it);
      removed = true;
    }
    // remove any children and add their address to parents<> to remove their children too
    if (parents.contains(bb_parent)) {
      it = basic_blocks_.erase(it);
      parents[bb_addr] = true;
      removed = true;
    }
    if (!removed) {
      ++it;
    }
  }
}

void X86Function::buildBasicBlocks(zasm::Decoder& decoder,
                                   const uint8_t* code,
                                   const size_t code_size,
                                   RVA runtime_address,
                                   RVA offset,
                                   std::map<
                                     RVA, const zasm::InstructionDetail&>&
                                   visited_insts,
                                   std::map<RVA, int64_t>& jump_gaps,
                                   const bool recursed,
                                   RVA parent_block) {
  struct {
    RVA address;
    uint64_t size;
  } basic_block = {};

  if (recursed) {
    checkTailCall(runtime_address, jump_gaps);
  }
  while (offset < code_size) {
    auto result = decoder.decode(code + offset,
                                 code_size - offset,
                                 runtime_address);
    if (!result) {
      throw code_error(result.error().getErrorMessage());
    }
    const auto& inst = result.value();
    const uint8_t inst_length = inst.getLength();
    if (basic_block.address == 0)
      basic_block.address = runtime_address;
    if (visited_insts.contains(runtime_address)) {
      addBasicBlock(basic_block.address, basic_block.size, parent_block);
      return;
    }
    visited_insts.emplace(runtime_address, inst);
    instructions_.emplace_back(inst, this).setAddress(runtime_address);
    // move 'cursor' forward
    basic_block.size += inst_length;
    offset += inst_length;
    runtime_address += inst_length;
    // any branching instruction other than call terminates a basic block
    if (zasm::x86::isBranching(inst) && inst.getMnemonic() !=
        zasm::x86::Mnemonic::Call) {
      const RVA new_parent_block = basic_block.address;
      // used for recursive call
      addBasicBlock(basic_block.address, basic_block.size, parent_block);
      memset(&basic_block, 0, sizeof(basic_block));
      // if not ret, calc new runtime address for traversal of branch (dfs)
      if (inst.getMnemonic() != zasm::x86::Mnemonic::Ret) {
        // any instructions decoded after this will have a new parent block
        parent_block = new_parent_block;
        try {
          const auto jmp_dst = inst.getOperand<zasm::Imm>(0).value<int64_t>();
          /*
           * With an unconditional jump, we will be jumping over code and going to a new location.
           * we need to make sure that this skipped block is referred to again. if it isn't then we
           * class this jump as a tail call.
           *
           * Once we've gotten back to the top level, we check if jump gaps exist. If they do,
           * we eliminate every basic block that is a child of that jump, as it isn't part of the
           * function.
           */
          int64_t jump_distance = jmp_dst - runtime_address;
          if (inst.getMnemonic() == zasm::x86::Mnemonic::Jmp) {
            jump_gaps.emplace(runtime_address, jump_distance);
          }
          buildBasicBlocks(decoder,
                           code,
                           code_size,
                           jmp_dst,
                           offset + jump_distance,
                           visited_insts,
                           jump_gaps,
                           true,
                           new_parent_block
              );
          // We check if we jumped over code
          // that was never referenced and eliminate the block that we jumped to as
          // well as all its children
          if (inst.getMnemonic() == zasm::x86::Mnemonic::Jmp) {
            if (!recursed && !jump_gaps.empty()) {
              for (auto [skip_addr, gap_size] : jump_gaps) {
                removeBasicBlockTree(skip_addr + gap_size);
              }
            }
            // unconditional jump terminates a BB
            return;
          }
        } catch (const std::exception& _) {
          // if not immediate, e.g. register access, then don't turn into BB
        }
      } else {
        // ret terminates a BB
        return;
      }
    }
  }
}

/*
 * We check if the address we have reached is anywhere within a gap
 * that we previously (unconditionally) jumped over, and if it is then it
 * is safe to say that it was not a tail call.
 */
void X86Function::checkTailCall(const VA current_inst_addr,
                                std::map<RVA, int64_t>& jump_gaps) const {
  for (auto [jmp_inst_addr, jmp_rel_dst] : jump_gaps) {
    const RVA jmp_abs_dst = jmp_inst_addr + jmp_rel_dst;
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
    for (RVA skip_addr = jmp_inst_addr; skip_addr < jmp_abs_dst; skip_addr
         ++) {
      if (skip_addr == current_inst_addr) {
        // we beat the tail call allegations
        jump_gaps.erase(jmp_inst_addr);
        break;
      }
    }
  }
}

bool X86Function::isWithinFunction(const uint64_t address) {
  bool within = false;
  for (auto [bb_addr, size, _] : basic_blocks_) {
    if (address >= bb_addr && address < bb_addr + size) {
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
  std::map<RVA, zasm::Label> labels;
  std::map<RVA, zasm::Node*> jump_dsts;
  assembler_.align(zasm::Align::Type::Code, X86Code::GetFunctionAlignment());
  // sort instructions by address
  std::sort(instructions_.begin(), instructions_.end());
  // first iteration - get all relN instructions and create labels for them
  for (X86Inst& inst : instructions_) {
    inst.setPos(assembler_.getCursor());
    const zasm::InstructionDetail& raw_inst = inst.RawInst();
    if ((zasm::x86::isBranching(raw_inst) &&
         raw_inst.getMnemonic() != zasm::x86::Mnemonic::Ret) ||
        raw_inst.getMnemonic() == zasm::x86::Mnemonic::Loop ||
        raw_inst.getMnemonic() == zasm::x86::Mnemonic::Loope ||
        raw_inst.getMnemonic() == zasm::x86::Mnemonic::Loopne
    ) {
      RVA jmp_addr = raw_inst.getOperand<zasm::Imm>(0).value<int64_t>();
      if (!isWithinFunction(jmp_addr)) {
        assembler_.emit(raw_inst);
        continue;
      }
      zasm::Label jmp_label = assembler_.createLabel();
      labels.emplace(jmp_addr, jmp_label);
      assembler_.emit(raw_inst.getMnemonic(), jmp_label);
    } else {
      assembler_.emit(raw_inst);
    }
  }
  zasm::Node* end = assembler_.getCursor();
  // second iteration - bind labels to
  for (X86Inst& inst : instructions_) {
    // if we reach instruction that is destination of a jmp label, then
    // bind assembler cursor to the label (since we are going to emit this
    // instruction next)
    if (labels.contains(inst.getAddress())) {
      const zasm::Label& label = labels[inst.getAddress()];
      assembler_.setCursor(inst.GetPos());
      assembler_.bind(label);
    }
  }
  assembler_.setCursor(end);
}

void X86Function::Finish() {
  if (finished_)
    throw std::runtime_error("function already marked as finished");
  const auto* x86code = dynamic_cast<X86Code*>(GetParent());
  // pointer to end of section
  const VA new_write_address = new_section_->GetParent()->GetImageBase()
                               + new_section_->GetAddress()
                               + new_section_->GetSize();
  const int64_t move_dist = new_write_address - GetAddress();
  x86code->patchOriginalLocation(*this, new_write_address);
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