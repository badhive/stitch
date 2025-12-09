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
#include <map>
#include <queue>
#include <set>

namespace stitch {
constexpr VA INVALID_ADDRESS = -1;

/*
 * Called only once. Performs the following analyses:
 * - Disassembly
 * - Control flow analysis
 * - Liveness analysis
 * - Tail call analysis
 */
void X86Code::AnalyzeFrom(const VA address) {
  if (analyzed_) return;
  analyzeFunction(address);
  analyzeTailCalls();
  analyzed_ = true;
}

X86Function* X86Code::analyzeFunction(const VA address) {
  int reopen_idx = -1;
  for (int i = 0; i < functions_.size(); i++) {
    X86Function* fn = functions_[i].get();
    if (fn->GetAddress() == address) {
      if (!fn->finished_) return fn;
      reopen_idx = i;
      break;
    }
  }
  Section* scn = GetParent()->OpenSectionAt(address);
  if (!scn) throw code_error("address out of range");
  X86Function* fn = buildFunction(address, scn, reopen_idx);
  fn->setOldSection(scn);
  return fn;
}

void X86Code::analyzeTailCalls() {
  // returns true if the jump was to the start of a known function
  auto check_jmp_to_fn = [&](const VA address) -> bool {
    for (const auto& fn : functions_) {
      if (fn->GetAddress() == address) return true;
    }
    return false;
  };
  // returns basic block that was the jump destination
  auto get_local_jmp_dst = [&](const X86Function* fn,
                               const VA address) -> X86BasicBlock* {
    for (const auto& bb : fn->getBasicBlocks()) {
      if (bb->GetAddress() == address && fn->GetAddress() != address)
        return bb.get();
    }
    return nullptr;
  };

  std::queue<X86Function*> worklist;
  for (const auto& fn : functions_) worklist.push(fn.get());
  while (!worklist.empty()) {
    X86Function* fn = worklist.front();
    worklist.pop();
    std::set<VA> tail_callers;
    for (auto& bb : fn->getBasicBlocks()) {
      // analyse BB if terminated due to unconditional jump
      if (bb->GetTermReason() == X86BlockTermReason::Jmp) {
        const auto inst = fn->getBlockInstructions(bb.get()).back();
        const auto dst = inst->RawInst().getOperandIf<zasm::Imm>(0);
        if (!dst) continue;
        const VA jmp_dst = dst->value<VA>();
        // in case it's a tail call to the current function (odd) ignore
        if (jmp_dst == fn->GetAddress()) continue;
        // check if jump goes to start of another function
        if (check_jmp_to_fn(jmp_dst) && inst->GetStackOffset() == 0) {
          tail_callers.insert(bb->GetAddress());
          bb->SetTermReason(X86BlockTermReason::TailCall);
        }
        /* if jump is (seemingly) internal, check stack offsets. multiple
         * functions tail calling to the same function will have their own
         * copies of the destination CFG. Get rid of those and create a single
         * function object instead
         *
         * this should also handle tail calls to functions with only 1 call site
         */
        else if (const auto dst_block = get_local_jmp_dst(fn, jmp_dst)) {
          const auto dst_inst = fn->getBlockInstructions(dst_block).front();
          if (inst->GetStackOffset() == 0 && dst_inst->GetStackOffset() == 0) {
            tail_callers.insert(bb->GetAddress());
            bb->SetTermReason(X86BlockTermReason::TailCall);
            worklist.push(analyzeFunction(jmp_dst));
          }
        }
      }
    }
    for (const auto tail_caller : tail_callers)
      fn->removeBasicBlocksAfter(fn->GetBasicBlockAt(tail_caller));
  }
}

X86Function* X86Code::editFunction(const VA address, const std::string& in) {
  X86Function* fn = analyzeFunction(address);
  std::string new_scn_name = in;
  if (in.empty()) new_scn_name = ".stitch";
  Binary* bin = GetParent();
  Section* new_scn = nullptr;
  try {
    new_scn = bin->OpenSection(new_scn_name);
  } catch (const std::exception& _) {
    new_scn = bin->AddSection(new_scn_name, SectionType::Code);
  }
  fn->setNewSection(new_scn);
  return fn;
}

Function* X86Code::CreateFunction(const std::string& in) {
  Section* new_scn = nullptr;
  std::string new_scn_name = in;
  if (in.empty()) new_scn_name = ".stitch";
  auto* bin = GetParent();

  try {
    new_scn = bin->OpenSection(new_scn_name);
  } catch (const std::exception& _) {
    new_scn = bin->AddSection(new_scn_name, SectionType::Code);
  }

  auto fn =
      std::make_unique<X86Function>(INVALID_ADDRESS, zasm::Program(mm_), this);
  fn->setNewSection(new_scn);
  fn->finalize();
  functions_.push_back(std::move(fn));
  return functions_.back().get();
}

Function* X86Code::CreateFunction(const Section& new_scn) {
  return CreateFunction(new_scn.GetName());
}

Function* X86Code::EditFunction(const VA address, const std::string& in) {
  X86Function* fn = editFunction(address, in);
  fn->finalize();
  return fn;
}

Function* X86Code::EditFunction(const VA address, const Section& scn) {
  return EditFunction(address, scn.GetName());
}

Function* X86Code::RebuildFunction(const VA address, const std::string& in) {
  X86Function* fn = editFunction(address, in);
  return fn;
}

Function* X86Code::RebuildFunction(const VA address, const Section& scn) {
  X86Function* fn = editFunction(address, scn.GetName());
  return fn;
}

void X86Code::patchOriginalLocation(const X86Function& fn,
                                    const VA new_loc) const {
  if (fn.GetAddress() == INVALID_ADDRESS) return;
  const Binary* binary = GetParent();
  const VA image_base = binary->GetImageBase();
  Section* scn = fn.getOldSection();
  if (!scn) return;

  for (const auto& block : fn.getBasicBlocks()) {
    const VA block_addr = block->GetAddress();
    const int64_t block_size = block->GetSize();
    // basic block address relative to the section's start address
    const RVA block_rel_addr = block_addr - scn->GetAddress() - image_base;
    // double check that basic block fits inside section
    if (block_addr - image_base + block_size >
        scn->GetAddress() + scn->GetSize())
      throw code_error("basic block outside of section range");
    scn->Memset(block_rel_addr, 0xcc, block_size);  // patch with int3
  }

  zasm::Program program(fn.getMachineMode());
  zasm::x86::Assembler as(program);
  patch_policy_(as, fn.GetAddress(), new_loc);
  zasm::Serializer serializer;
  const zasm::Error err = serializer.serialize(program, fn.GetAddress());

  if (err.getCode() != zasm::ErrorCode::None)
    throw code_error(std::string("failed to move function: ") +
                     err.getErrorMessage());

  // make sure that the patch code fits within the first basic block so that we
  // aren't overwriting code of another function
  const X86BasicBlock* first_block = fn.GetBasicBlockAt(fn.GetAddress());
  if (serializer.getCodeSize() > first_block->GetSize())
    throw code_error("patch stub too large");
  // now replace first basic block's address with the patch
  const RVA block_rel_addr =
      first_block->GetAddress() - scn->GetAddress() - image_base;
  scn->WriteAt(block_rel_addr, serializer.getCode(), serializer.getCodeSize());
}

X86Function* X86Code::buildFunction(const VA fn_address, const Section* scn,
                                    const int reopen_idx) {
  std::set<VA> visited_insts;
  X86Function* fn = nullptr;
  auto uf = std::make_unique<X86Function>(fn_address, zasm::Program(mm_), this);
  if (reopen_idx != -1) {
    functions_[reopen_idx] = std::move(uf);
    fn = functions_[reopen_idx].get();
  } else {
    functions_.emplace_back(std::move(uf));
    fn = functions_.back().get();
  }
  zasm::Decoder decoder(mm_);
  const RVA build_offset =
      fn_address - GetParent()->GetImageBase() - scn->GetAddress();
  fn->disassemble(decoder, scn->GetData().data(), scn->GetSize(), fn_address,
                  build_offset, fn->visited_insts_);
  fn->runAnalyses();
  const X86Inst& last_inst = fn->instructions_.back();
  fn->setSize(last_inst.GetAddress() + last_inst.RawInst().getLength() -
              fn->GetAddress());
  return fn;
}

zasm::MachineMode X86Function::getMachineMode() const {
  return GetParent()->GetArchitecture() == TargetArchitecture::I386
             ? zasm::MachineMode::I386
             : zasm::MachineMode::AMD64;
}

void X86Function::disassemble(zasm::Decoder& decoder, const uint8_t* code,
                              const size_t code_size, VA runtime_address,
                              VA offset, std::set<VA>& visited_insts) {
  while (offset < code_size) {
    // don't disassemble twice
    if (visited_insts.contains(runtime_address)) break;
    auto result =
        decoder.decode(code + offset, code_size - offset, runtime_address);
    if (!result) {
      setError(result.error().getErrorMessage());
      return;
    }
    const auto& inst = result.value();
    const uint8_t inst_length = inst.getLength();
    visited_insts.insert(runtime_address);

    X86Inst& x86inst =
        instructions_.emplace_back(decoder.getMode(), inst, this);
    x86inst.setAddress(runtime_address);

    // move 'cursor' forward
    offset += inst_length;
    runtime_address += inst_length;
    // any branching instruction other than call terminates a basic block
    if (zasm::x86::isBranching(inst)) {
      if (inst.getCategory() == zasm::x86::Category::Ret) break;
      if (inst.getCategory() == zasm::x86::Category::Call) {
        const auto* address = inst.getOperandIf<zasm::Imm>(0);
        // recursive disassembly, won't reanalyze if already in database
        if (address != nullptr)
          GetParent<X86Code>()->analyzeFunction(address->value<VA>());
        continue;
      }
      int64_t cf_dst = 0;
      try {
        cf_dst = inst.getOperand<zasm::Imm>(0).value<int64_t>();
      } catch (const std::exception& _) {
        // continue on conditional branch but exit on unconditional.
        // still need to follow basic control flow rules to disassemble
        // everything.
        if (inst.getCategory() == zasm::x86::Category::CondBr) continue;
        break;
      }
      const int64_t jump_distance = cf_dst - runtime_address;
      disassemble(decoder, code, code_size, cf_dst, offset + jump_distance,
                  visited_insts);
      if (inst.getMnemonic() == zasm::x86::Mnemonic::Jmp) {
        break;
      }
    }
  }
}

X86BasicBlock* X86Function::analyzeControlFlow(
    std::vector<X86Inst>::iterator curr, std::set<VA>& analyzed_insts,
    X86BasicBlock* parent_block) {
  X86BasicBlock* basic_block = nullptr;
  for (; curr != instructions_.end(); ++curr) {
    const auto& inst = curr->RawInst();
    const VA runtime_address = curr->GetAddress();

    if (analyzed_insts.contains(runtime_address)) {
      /*
       * This will either:
       * 1. Add a new parent for the basic block that we've reached, or
       * 2. If we jumped to the middle of an already-created basic block, then
       * we split it at that point, and set the new block's parents to where we
       *    jumped from (parent_block) and the block that used to own the
       * instruction at that address
       */
      findAndSplitBasicBlock(runtime_address, parent_block);
      break;
    }
    if (basic_block == nullptr) {
      basic_block = addBasicBlock(runtime_address, 0, parent_block);
    }

    curr->setBasicBlock(basic_block);
    const uint8_t inst_length = inst.getLength();
    analyzed_insts.insert(runtime_address);

    basic_block->SetSize(basic_block->GetSize() + inst_length);
    // any branching instruction other than call terminates a basic block
    if (zasm::x86::isBranching(inst)) {
      if (inst.getCategory() == zasm::x86::Category::Call) continue;
      if (inst.getCategory() == zasm::x86::Category::Ret) {
        basic_block->SetTermReason(X86BlockTermReason::Ret);
        exit_blocks_.insert(basic_block);
        break;
      }
      int64_t cf_dst = 0;
      try {
        cf_dst = inst.getOperand<zasm::Imm>(0).value<int64_t>();
      } catch (const std::exception& _) {
        // continue on conditional branch but exit on unconditional.
        // we don't need to create a child block as we don't know the other
        // branch location.
        // add as exit block; we can't recover CF following this block
        if (inst.getCategory() == zasm::x86::Category::CondBr) continue;
        basic_block->SetTermReason(X86BlockTermReason::Jmp);
        exit_blocks_.insert(basic_block);
        break;
      }
      const auto next_idx = getInstructionAtAddress(cf_dst);
      // shouldn't happen since we haven't done any function-level analysis at
      // this point
      if (next_idx < 0)
        throw code_error("got jump to non-existent instruction");
      const auto next = instructions_.begin() + next_idx;

      analyzeControlFlow(next, analyzed_insts, basic_block);

      // unconditional jump terminates a BB
      if (inst.getMnemonic() == zasm::x86::Mnemonic::Jmp) {
        basic_block->SetTermReason(X86BlockTermReason::Jmp);
        break;
      }
      basic_block->SetTermReason(X86BlockTermReason::CondBr);
      const auto inst_len = curr->RawInst().getLength();
      X86BasicBlock* old_block = basic_block;
      basic_block =
          addBasicBlock(runtime_address + inst_len, 0, old_block, old_block);
    }
  }
  if (!error_.empty() && basic_block != nullptr)
    basic_block->SetTermReason(X86BlockTermReason::Error);
  return basic_block;
}

void X86Function::findAndSplitBasicBlock(const VA address,
                                         X86BasicBlock* new_parent) {
  for (const auto& block : basic_blocks_) {
    // if we fall at the start of the basic block then no need to split,
    // just add our own block as a parent
    const VA block_addr = block->GetAddress();
    if (address == block_addr && new_parent) {
      block->AddParent(new_parent);
      new_parent->AddChild(block.get());
      return;
    }
    // if address is within basic block, then split it
    if (address > block_addr && address < block_addr + block->GetSize()) {
      X86BasicBlock* new_block = splitAfter(block.get(), address);
      if (new_parent) {
        new_block->AddParent(new_parent);
        new_parent->AddChild(new_block);
      }
      // if old block was an exit block, new block will become an exit block
      for (auto it = exit_blocks_.begin(); it != exit_blocks_.end(); ++it) {
        if (block_addr == (*it)->GetAddress()) {
          exit_blocks_.erase(it);
          exit_blocks_.insert(new_block);
          return;
        }
      }
      return;
    }
  }
}

X86BasicBlock* X86Function::splitAfter(X86BasicBlock* block, const VA address) {
  std::vector<X86Inst*> insts;
  // new block is child of old block
  X86BasicBlock* new_block = addBasicBlock(address, 0, block, block);
  // new block is effectively transferred ownership of old block's children
  auto& block_children = block->getChildren();
  for (auto it = block_children.begin(); it != block_children.end();) {
    const auto child = *it;
    if (child == new_block) {
      ++it;
      continue;
    }
    child->getParents().erase(block);
    child->AddParent(new_block);
    it = block_children.erase(it);
  }
  new_block->SetTermReason(block->GetTermReason());
  block->SetTermReason(X86BlockTermReason::Fallthrough);
  // move insts that are within the old block lower range to the new block
  for (const auto inst : getBlockInstructions(block)) {
    if (inst->GetAddress() >= address) {
      inst->setBasicBlock(new_block);
      const auto inst_size = inst->RawInst().getLength();
      new_block->SetSize(new_block->GetSize() + inst_size);
      block->SetSize(block->GetSize() - inst_size);
    }
  }
  return new_block;
}

// remove basic blocks after specified block if it is a tail call
void X86Function::removeBasicBlocksAfter(const X86BasicBlock* final_block) {
  if (!final_block) return;

  std::queue<X86BasicBlock*> to_delete;
  std::set<VA> seen;

  for (auto child : final_block->GetChildren()) to_delete.push(child);

  while (!to_delete.empty()) {
    auto block = to_delete.front();
    to_delete.pop();

    if (!seen.insert(block->GetAddress()).second) continue;

    // queue children for deletion
    for (auto child : block->GetChildren()) {
      to_delete.push(child);
    }
    // erase reference to block from parents
    for (const auto parent : block->getParents())
      parent->getChildren().erase(block);

    // erase instructions associated with block
    auto insts = GetBlockInstructions(block);
    for (auto inst : insts) {
      std::erase_if(instructions_, [inst](auto& i) {
        return i.GetAddress() == inst->GetAddress();
      });
    }
  }
  // erase blocks that we have visited
  for (auto block_address : seen) {
    std::erase_if(basic_blocks_, [block_address](auto& b) {
      return b->GetAddress() == block_address;
    });
  }
}

X86BasicBlock* X86Function::addBasicBlock(VA loc, uint64_t size,
                                          X86BasicBlock* parent,
                                          X86BasicBlock* fallthrough) {
  const auto bb = basic_blocks_
                      .emplace_back(std::make_unique<X86BasicBlock>(
                          loc, size, parent, fallthrough))
                      .get();
  if (parent) parent->AddChild(bb);
  return bb;
}

std::vector<X86Inst*> X86Function::getBlockInstructions(
    const X86BasicBlock* block) {
  std::vector<X86Inst*> insts;
  for (X86Inst& inst : instructions_) {
    // skip over instructions that haven't gone through control flow analysis
    // yet
    if (const auto* bb = inst.GetBasicBlock();
        bb && bb->GetAddress() == block->GetAddress()) {
      insts.push_back(&inst);
    }
  }
  return insts;
}

std::vector<const X86Inst*> X86Function::getBlockInstructions(
    const X86BasicBlock* block) const {
  std::vector<const X86Inst*> insts;
  for (const X86Inst& inst : instructions_) {
    if (const auto* bb = inst.GetBasicBlock();
        bb && bb->GetAddress() == block->GetAddress()) {
      insts.push_back(&inst);
    }
  }
  std::sort(insts.begin(), insts.end());
  return insts;
}

// Refs:
// https://en.wikipedia.org/wiki/Live-variable_analysis
// https://github.com/thesecretclub/riscy-business/blob/zasm-obfuscator/obfuscator/src/obfuscator/analyze.cpp#L186
void X86Function::genBlockLivenessInfo() {
  // 1: create GEN and KILL sets for each BB
  for (const auto& block : basic_blocks_) {
    for (const X86Inst* inst : getBlockInstructions(block.get())) {
      // kills regs that are written to before being read
      block->regs_gen_ |= inst->regs_read_ & ~block->regs_kill_;
      block->regs_kill_ |= inst->regs_written_;
      // kills flags that are modified before being tested
      block->flags_gen_ =
          block->flags_gen_ | (inst->flags_tested_ & ~block->flags_kill_);
      block->flags_kill_ = block->flags_kill_ | inst->flags_modified_;
    }
  }
  // 2: create block LIVEin and LIVEout sets through backwards iteration
  std::queue<X86BasicBlock*> blocks;
  std::set<RVA> visited_blocks;
  for (X86BasicBlock* block : exit_blocks_) {
    blocks.push(block);
    visited_blocks.insert(block->GetAddress());
  }
  while (!blocks.empty()) {
    auto* block = blocks.front();
    blocks.pop();
    visited_blocks.insert(block->GetAddress());
    // solve LIVEin and LIVEout equations
    block->regs_live_in_ =
        block->regs_gen_ | (block->regs_live_out_ & ~block->regs_kill_);
    block->flags_live_in_ =
        block->flags_gen_ | (block->flags_live_out_ & ~block->flags_kill_);

    for (X86BasicBlock* parent : block->GetParents()) {
      const auto old_regs_live_out = parent->regs_live_out_;
      const auto old_flags_live_out = parent->flags_live_out_;

      parent->regs_live_out_ |= block->regs_live_in_;
      parent->flags_live_out_ = parent->flags_live_out_ | block->flags_live_in_;

      // recompute parent LIVEin if its LIVEout as changed
      if (old_regs_live_out != parent->regs_live_out_ ||
          old_flags_live_out != parent->flags_live_out_)
        blocks.push(parent);
    }
  }
}

// Compute liveness for each individual instruction
void X86Function::genInstructionLivenessInfo() {
  for (const auto& block : basic_blocks_) {
    std::vector<X86Inst*> insts = getBlockInstructions(block.get());
    uint32_t regs_live = block->regs_live_out_;
    uint32_t flags_live = block->flags_live_out_;
    for (auto it = insts.rbegin(); it != insts.rend(); ++it) {
      X86Inst* inst = *it;
      /*
       * if var has been read from, it's considered live.
       * if var has been written to without being read from, it's now considered
       * dead.
       */
      regs_live |= inst->regs_read_;
      inst->regs_live_ = regs_live;

      const uint32_t regs_overwritten = inst->regs_written_ & ~inst->regs_read_;
      regs_live &= ~regs_overwritten;

      flags_live |= inst->flags_tested_;
      inst->flags_live_ = flags_live;

      const uint32_t flags_overwritten =
          inst->flags_modified_ & ~inst->flags_tested_;
      flags_live &= ~flags_overwritten;
    }
  }
}

bool X86Function::isWithinFunction(const VA address) const {
  bool within = false;
  for (const auto& block : basic_blocks_) {
    if (address >= block->GetAddress() &&
        address < block->GetAddress() + block->GetSize()) {
      within = true;
      break;
    }
  }
  return within;
}

X86BasicBlock* X86Function::GetBasicBlockAt(const VA address) const {
  for (const auto& block : basic_blocks_) {
    if (block->GetAddress() == address) {
      return block.get();
    }
  }
  return nullptr;
}

int X86Function::getInstructionAtAddress(const VA address) const {
  for (int i = 0; i < instructions_.size(); i++) {
    if (instructions_[i].GetAddress() == address) {
      return i;
    }
  }
  return -1;
}

void X86Function::genStackInfo(const uint64_t initial_sp) {
  using namespace utils;

  std::map<int8_t, sym::Reg> reg_map = {
      {zasm::x86::rsp.getIndex(), sym::Reg("sp", initial_sp)},  // initialised
      {zasm::x86::rbp.getIndex(), sym::Reg("bp")},
      {zasm::x86::rdi.getIndex(), sym::Reg("di")},
      {zasm::x86::rsi.getIndex(), sym::Reg("si")},
      {zasm::x86::rax.getIndex(), sym::Reg("ax")},
      {zasm::x86::rbx.getIndex(), sym::Reg("bx")},
      {zasm::x86::rcx.getIndex(), sym::Reg("cx")},
      {zasm::x86::rdx.getIndex(), sym::Reg("dx")},
      {zasm::x86::r8.getIndex(), sym::Reg("8")},
      {zasm::x86::r9.getIndex(), sym::Reg("9")},
      {zasm::x86::r10.getIndex(), sym::Reg("10")},
      {zasm::x86::r11.getIndex(), sym::Reg("11")},
      {zasm::x86::r12.getIndex(), sym::Reg("12")},
      {zasm::x86::r13.getIndex(), sym::Reg("13")},
      {zasm::x86::r14.getIndex(), sym::Reg("14")},
      {zasm::x86::r15.getIndex(), sym::Reg("15")}};

  // initialise volatile regs to zero
  if (GetParent()->GetParent()->GetPlatform() == Platform::Windows) {
    for (auto reg : x86::gpVolWin64) reg_map.at(reg.getIndex()) = 0;
  }

  std::set<VA> visited_insts;
  // start analysis from the entry; we haven't detected tail calls yet and
  // genStackOffsets follows the control flow so it works out
  const auto entry_inst =
      instructions_.begin() + getInstructionAtAddress(GetAddress());
  genStackOffsets(entry_inst, reg_map, visited_insts);
}

/// Sets a stack offset property for each instruction in the function.
/// This only handles common instructions that may modify the stack pointer.
void X86Function::genStackOffsets(std::vector<X86Inst>::iterator it,
                                  std::map<int8_t, utils::sym::Reg>& reg_map,
                                  std::set<VA>& visited_insts) {
  using namespace utils;

  for (; it != instructions_.end(); ++it) {
    X86Inst& inst = *it;
    if (visited_insts.contains(inst.GetAddress())) return;
    visited_insts.insert(inst.GetAddress());
    const zasm::InstructionDetail& ri = inst.RawInst();
    sym::Reg& rsp = reg_map.at(zasm::x86::rsp.getIndex());

    if (it == instructions_.begin()) inst.setStackOffset(0);

    // ret
    if (ri.getCategory() == zasm::x86::Category::Ret) return;

    if (ri.getOperandCount() == 0) {
      if (it + 1 != instructions_.end() && rsp.Defined())
        (it + 1)->setStackOffset(rsp);
      continue;
    }
    const zasm::Operand& op0 = ri.getOperand(0);

    // jmp
    if (ri.getCategory() == zasm::x86::Category::UncondBR) {
      const auto jmp_dst = op0.getIf<zasm::Imm>();
      if (jmp_dst) {
        const int inst_pos = getInstructionAtAddress(jmp_dst->value<VA>());
        if (inst_pos != -1) {
          const auto inst_it = instructions_.begin() + inst_pos;
          if (rsp.Defined()) inst_it->setStackOffset(rsp);
          auto reg_map_br = reg_map;
          genStackOffsets(inst_it, reg_map_br, visited_insts);
        }
      }
      return;
    }
    // jcc
    if (ri.getCategory() == zasm::x86::Category::CondBr) {
      const auto jmp_dst = op0.getIf<zasm::Imm>();
      if (jmp_dst) {
        const int inst_pos = getInstructionAtAddress(jmp_dst->value<VA>());
        if (inst_pos != -1) {
          const auto inst_it = instructions_.begin() + inst_pos;
          if (rsp.Defined()) inst_it->setStackOffset(rsp);
          auto reg_map_br = reg_map;
          genStackOffsets(inst_it, reg_map_br, visited_insts);
        }
      }
      // don't return, still need to set next instr's stack offset
    }

    try {
      switch (ri.getMnemonic()) {
        case zasm::x86::Mnemonic::Sub: {
          if (const auto reg_op0 = op0.getIf<zasm::x86::Reg>()) {
            sym::Reg& sym = reg_map.at(reg_op0->getIndex());
            if (const auto reg = ri.getOperandIf<zasm::x86::Reg>(1)) {
              sym = sym - reg_map.at(reg->getIndex());
            } else if (const auto imm = ri.getOperandIf<zasm::Imm>(1)) {
              sym = sym - imm->value<uint64_t>();
            } else
              sym.Undefine();
          }
        } break;
        case zasm::x86::Mnemonic::Add: {
          if (const auto reg_op0 = op0.getIf<zasm::x86::Reg>()) {
            sym::Reg& sym = reg_map.at(reg_op0->getIndex());
            if (const auto reg = ri.getOperandIf<zasm::x86::Reg>(1))
              sym = sym + reg_map.at(reg->getIndex());
            else if (const auto imm = ri.getOperandIf<zasm::Imm>(1))
              sym = sym + imm->value<uint64_t>();
            else
              sym.Undefine();
          }
        } break;
        case zasm::x86::Mnemonic::And: {
          const auto r_op0 = op0.getIf<zasm::x86::Reg>();
          if (!r_op0) break;
          sym::Reg& sym = reg_map.at(r_op0->getIndex());
          uint64_t mask = ~0;
          if (r_op0->isGp8())
            mask = 0xff;
          else if (r_op0->isGp16())
            mask = 0xffff;
          // set upper FULLSIZE - N bits if N != FULLSIZE to retain them
          if (const auto reg = ri.getOperandIf<zasm::x86::Reg>(1))
            sym = sym & (reg_map.at(reg->getIndex()) | ~mask);
          else if (const auto imm = ri.getOperandIf<zasm::Imm>(1))
            sym = sym & (imm->value<uint64_t>() | ~mask);
          else
            sym.Undefine();
        } break;
        case zasm::x86::Mnemonic::Or: {
          const auto r_op0 = op0.getIf<zasm::x86::Reg>();
          if (!r_op0) break;
          sym::Reg& sym = reg_map.at(r_op0->getIndex());
          uint64_t mask = ~0;
          if (r_op0->isGp8())
            mask = 0xff;
          else if (r_op0->isGp16())
            mask = 0xffff;
          // only OR with lower N bits of operand if not full size
          if (const auto reg = ri.getOperandIf<zasm::x86::Reg>(1))
            sym = sym | (reg_map.at(reg->getIndex()) & mask);
          else if (const auto imm = ri.getOperandIf<zasm::Imm>(1))
            sym = sym | (imm->value<uint64_t>() & mask);
          else
            sym.Undefine();
        } break;
        case zasm::x86::Mnemonic::Xor: {
          const auto r_op0 = op0.getIf<zasm::x86::Reg>();
          if (!r_op0) break;
          sym::Reg& sym = reg_map.at(r_op0->getIndex());
          uint64_t mask = ~0;
          if (r_op0->isGp8())
            mask = 0xff;
          else if (r_op0->isGp16())
            mask = 0xffff;
          // only XOR with lower N bits of operand if not full size
          if (const auto reg = ri.getOperandIf<zasm::x86::Reg>(1))
            sym = sym ^ (reg_map.at(reg->getIndex()) & mask);
          else if (const auto imm = ri.getOperandIf<zasm::Imm>(1))
            sym = sym ^ (imm->value<uint64_t>() & mask);
          else
            sym.Undefine();
        } break;
        case zasm::x86::Mnemonic::Lea: {
          if (const auto reg_op0 = op0.getIf<zasm::x86::Reg>()) {
            sym::Reg& sym = reg_map.at(reg_op0->getIndex());
            if (const auto mem = ri.getOperandIf<zasm::x86::Mem>(1)) {
              const int8_t reg_idx = mem->getBase().getIndex();
              // if base register cannot be fetched (i.e. is the ip) we break
              if (reg_idx < 0) break;
              const sym::Reg& base = reg_map.at(reg_idx);
              const int8_t index = mem->getIndex().getIndex();
              const uint8_t scale = mem->getScale();
              const int64_t disp = mem->getDisplacement();
              sym = base;
              if (index != -1)
                sym = sym + (reg_map.at(index) * static_cast<uint64_t>(scale));
              sym = sym + static_cast<uint64_t>(disp);
            } else
              sym.Undefine();
          }
        } break;
        case zasm::x86::Mnemonic::Xchg: {
          if (const auto reg_op0 = op0.getIf<zasm::x86::Reg>()) {
            sym::Reg& sym = reg_map.at(reg_op0->getIndex());
            if (const auto reg = ri.getOperandIf<zasm::x86::Reg>(1)) {
              const sym::Reg saved_sym = sym;
              sym = reg_map.at(reg->getIndex());
              reg_map.at(reg->getIndex()) = saved_sym;
            }
          }
        } break;
        case zasm::x86::Mnemonic::Mov: {
          if (const auto reg_op0 = op0.getIf<zasm::x86::Reg>()) {
            sym::Reg& sym = reg_map.at(reg_op0->getIndex());
            if (const auto reg = ri.getOperandIf<zasm::x86::Reg>(1))
              sym = reg_map.at(reg->getIndex());
            else if (const auto imm = ri.getOperandIf<zasm::Imm>(1))
              sym = imm->value<uint64_t>();
            else
              sym.Undefine();
          }
        } break;
          // subtract
        case zasm::x86::Mnemonic::Push: {
          sym::Reg& sym = reg_map.at(zasm::x86::rsp.getIndex());
          const uint64_t val =
              getMachineMode() == zasm::MachineMode::I386 ? 4 : 8;
          sym = sym - val;
        } break;
          // add
        case zasm::x86::Mnemonic::Pop: {
          sym::Reg& sym = reg_map.at(zasm::x86::rsp.getIndex());
          const uint64_t val =
              getMachineMode() == zasm::MachineMode::I386 ? 4 : 8;
          sym = sym + val;
        } break;
        default:;
      }
    } catch (const std::out_of_range& _) {
      continue;
    }
    // each instruction stores stack offset before it is run
    // technically sp should always be defined unless silliness is involved
    if (it + 1 != instructions_.end() && rsp.Defined())
      (it + 1)->setStackOffset(rsp);
  }
}

void X86Function::refreshCode() {
  new_instructions_.clear();
  for (zasm::Node* node = program_.getHead(); node != nullptr;
       node = node->getNext()) {
    if (const auto* inst = node->getIf<zasm::Instruction>()) {
      new_instructions_.emplace_back(*inst, node, this);
    }
  }
}

uint64_t X86Function::ImportJumpTable(const VA address,
                                      const uint32_t num_entries,
                                      X86BasicBlock* dispatcher_block,
                                      const bool le) {
  constexpr bool is_le = std::endian::native == std::endian::little;

  auto flip_int = [le](auto v) -> int64_t {
    constexpr size_t size = sizeof(v);
    if (is_le != le) {
      int64_t out = 0;
      const auto* src = reinterpret_cast<uint8_t*>(&v);
      auto* dst = reinterpret_cast<uint8_t*>(&out);
      for (size_t i = 0; i < size; ++i) dst[i] = src[size - 1 - i];
      return out;
    } else {
      return static_cast<int64_t>(v);
    }
  };

  const uint8_t* jt = GetParent<X86Code>()->GetParent()->ReadDataAt(address);
  std::vector<int64_t> addresses;
  zasm::Decoder decoder(getMachineMode());

  // Disassemble and run analyses on registered handlers. This can be done
  // even after the initial function analysis has been performed since we
  // end up calling finalize() again
  auto analyze_handler = [&](const int64_t hnd_address) {
    const Binary* bin = GetParent()->GetParent();
    const Section* scn = bin->OpenSectionAt(hnd_address);
    if (!scn) {
      throw code_error("invalid handler address");
    }
    const VA offset = hnd_address - bin->GetImageBase() - scn->GetAddress();
    disassemble(decoder, scn->GetData().data(), scn->GetSize(), hnd_address,
                offset, visited_insts_);

    // run analyses manually
    const int inst_pos = getInstructionAtAddress(hnd_address);
    runAnalyses(inst_pos, dispatcher_block);
  };

  if (getMachineMode() == zasm::MachineMode::I386) {
    const auto* ptr = reinterpret_cast<const int32_t*>(jt);
    for (uint32_t i = 0; i < num_entries; ++i) {
      addresses.push_back(flip_int(ptr[i]));
    }
  } else {  // amd64
    const auto* ptr = reinterpret_cast<const int64_t*>(jt);
    for (uint32_t i = 0; i < num_entries; ++i) {
      addresses.push_back(flip_int(ptr[i]));
    }
  }

  for (uint32_t i = 0; i < num_entries; ++i) {
    analyze_handler(addresses[i]);
  }
  finalize();

  const auto id = CreateJumpTable();
  // Mark handlers if found
  for (const auto addr : addresses) {
    X86BasicBlock* bb = GetBasicBlockAt(addr);
    if (!bb) {
      throw code_error("no jump table handler found at " +
                       std::to_string(addr));
    }
    const auto cur = assembler_->getCursor();
    if (auto first = GetBlockInstructions(bb).front(); first) {
      assembler_->setCursor(first->GetPos()->getPrev());
      auto label = assembler_->createLabel();
      assembler_->bind(label);
      bb->block_label_ = assembler_->getCursor();
    }
    assembler_->setCursor(cur);
    MarkJumpTableHandler(id, bb);
  }
  return id;
}

uint64_t X86Function::CreateJumpTable() {
  jump_tables_handlers_[jump_tables_handlers_.size()] = {};
  return jump_tables_handlers_.size() - 1;
}

void X86Function::MarkJumpTableHandler(const uint64_t jt_id,
                                       const X86BasicBlock* bb) {
  if (!jump_tables_handlers_.contains(jt_id))
    throw code_error("jump table not found");
  jump_tables_handlers_[jt_id].push_back(bb);
}

void X86Function::finalize() {
  // can't use program object again after calling clear()
  program_.clear();
  program_ = zasm::Program(getMachineMode());
  assembler_.reset();
  assembler_.emplace(program_);

  std::map<VA, zasm::Label> labels;
  start_pos_ = assembler_->getCursor();
  // first iteration - get all relN instructions and create labels for them
  for (X86Inst& inst : instructions_) {
    // auto v = inst.RawInst().getInstruction();
    // std::cout << "" << std::hex << inst.GetAddress() << std::dec << ": "
    //           << zasm::formatter::toString(
    //                  program_, &v,
    //                  zasm::formatter::detail::FormatOptions::HexImmediates)
    //           << " ; stack offset = "
    //           << static_cast<int64_t>(inst.GetStackOffset()) << std::endl;
    const zasm::InstructionDetail& raw_inst = inst.RawInst();
    if (zasm::x86::isBranching(raw_inst) &&
        raw_inst.getCategory() != zasm::x86::Category::Ret) {
      if (const auto jmp_imm = raw_inst.getOperandIf<zasm::Imm>(0)) {
        VA jmp_addr = jmp_imm->value<VA>();
        if (!isWithinFunction(jmp_addr)) {
          assembler_->emit(raw_inst);
          inst.setPos(assembler_->getCursor());
          continue;
        }
        inst.setIsLocalBranch(true);
        // don't create more labels if one exists for that address
        zasm::Label jmp_label;
        if (labels.contains(jmp_addr))
          jmp_label = labels.at(jmp_addr);
        else
          jmp_label = assembler_->createLabel();
        labels.emplace(jmp_addr, jmp_label);
        assembler_->emit(raw_inst.getMnemonic(), jmp_label);
      } else
        assembler_->emit(raw_inst);
    } else
      assembler_->emit(raw_inst);
    inst.setPos(assembler_->getCursor());
  }
  zasm::Node* end = assembler_->getCursor();
  // second iteration - bind labels to
  for (X86Inst& inst : instructions_) {
    // if we reach instruction that is destination of a jmp label, then
    // bind assembler cursor to the label (since we are going to emit this
    // instruction next)
    if (labels.contains(inst.GetAddress())) {
      const zasm::Label label = labels[inst.GetAddress()];
      labels.erase(inst.GetAddress());
      assembler_->setCursor(inst.GetPos()->getPrev());
      assembler_->bind(label);
    }
  }
  assembler_->setCursor(end);
  const auto& first = instructions_.at(getInstructionAtAddress(GetAddress()));
  entry_point_ = first.GetPos();
  refreshCode();
}

template <typename T>
void move_element(std::vector<T>& v, const T& elem, size_t new_index) {
  // infer old index from the reference
  size_t old_index = &elem - &v[0];

  if (old_index == new_index) {
    return;
  }

  if (old_index < new_index) {
    // move forward
    std::rotate(v.begin() + old_index, v.begin() + old_index + 1,
                v.begin() + new_index + 1);
  } else {
    // move backward
    std::rotate(v.begin() + new_index, v.begin() + old_index,
                v.begin() + old_index + 1);
  }
}

// sort instructions by basic block appearances
void X86Function::smartSortInstructions() {
  std::queue<X86BasicBlock*> worklist;
  std::set<VA> visited;
  worklist.push(GetBasicBlockAt(GetAddress()));

  int bb_start = 0;
  while (!worklist.empty()) {
    const auto block = worklist.front();
    worklist.pop();

    if (visited.contains(block->GetAddress())) continue;
    visited.insert(block->GetAddress());

    int idx = 0;
    auto instructions = GetBlockInstructions(block);
    for (int i = 0; i < instructions.size(); ++i) {
      // move to the front
      move_element(instructions_, *instructions[i], bb_start + i);
      idx++;
    }
    const X86BasicBlock* found_fallthrough = nullptr;
    bb_start += idx;
    // prioritize the block that is directly after this one in code
    for (auto child : block->GetChildren()) {
      if (child->GetFallthroughParent() == block) {
        worklist.push(child);
        found_fallthrough = child;
        break;
      }
    }
    // push all other blocks after
    for (auto child : block->GetChildren()) {
      if (child != found_fallthrough) worklist.push(child);
    }
  }
}

const GlobalRef* X86Function::Finish() {
  if (finished_)
    throw std::runtime_error("function already marked as finished");
  // pointer to end of section
  VA new_write_address = new_section_->GetParent()->GetImageBase() +
                         new_section_->GetAddress() + new_section_->GetSize();

  const zasm::Label entry_label = assembler_->createLabel();
  const auto* entry = GetEntryPoint();

  zasm::Node* cur = assembler_->getCursor();

  assembler_->setCursor(nullptr);
  assembler_->align(zasm::Align::Type::Code, X86Code::kFunctionAlignment);

  if (entry == nullptr) {
    // set entry to the next node after alignment
    assembler_->setCursor(program_.getHead()->getNext());
  } else {
    assembler_->setCursor(entry->getPrev());
  }
  assembler_->bind(entry_label);

  std::map<uint64_t, std::vector<zasm::Label>> labels_map;

  // create label for each handler
  for (const auto& [id, handlers] : jump_tables_handlers_) {
    auto& labels = labels_map[id];
    for (const auto handler : handlers) {
      zasm::Node* bb_head = handler->block_label_;
      auto label = program_.createLabel();
      labels.push_back(label);
      assembler_->setCursor(bb_head->getPrev());
      assembler_->bind(label);
    }
  }

  assembler_->setCursor(cur);

  zasm::Serializer serializer;
  const zasm::Error code = serializer.serialize(program_, new_write_address);
  if (code.getCode() != zasm::ErrorCode::None)
    throw code_error(code.getErrorMessage());

  // now patch with entrypoint instruction address
  const VA entry_point_offset = serializer.getLabelOffset(entry_label.getId());
  const VA write_address_final = new_write_address + entry_point_offset;

  GetParent<X86Code>()->patchOriginalLocation(*this, write_address_final);

  // serialize jump tables
  for (auto& [jt_id, labels] : labels_map) {
    if (getMachineMode() == zasm::MachineMode::I386) {
      jump_tables_.emplace(jt_id, JumpTable32());
      auto& jt32 = std::get<JumpTable32>(jump_tables_.at(jt_id));
      for (auto l : labels)
        jt32.RegisterHandler(serializer.getLabelAddress(l.getId()));
    } else {
      jump_tables_.emplace(jt_id, JumpTable64());
      auto& jt64 = std::get<JumpTable64>(jump_tables_.at(jt_id));
      for (auto l : labels)
        jt64.RegisterHandler(serializer.getLabelAddress(l.getId()));
    }
  }

  finished_ = true;
  return new_section_->WriteWithRef(serializer.getCode(),
                                    serializer.getCodeSize());
}

// add liveness info on construction of X86Inst. Refs:
// https://github.com/thesecretclub/riscy-business/blob/zasm-obfuscator/obfuscator/src/obfuscator/program.cpp#L139
void X86Inst::addInstructionContext() {
  for (size_t i = 0; i < instruction_.getOperandCount(); i++) {
    const auto& operand = instruction_.getOperand(i);
    const auto access = instruction_.getOperandAccess(i);
    if (const auto reg = operand.getIf<zasm::Reg>()) {
      if (static_cast<uint32_t>(access & zasm::Operand::Access::MaskRead)) {
        regs_read_ |= regMask(reg->getRoot(mm_));
      } else if (static_cast<uint32_t>(access &
                                       zasm::Operand::Access::MaskWrite)) {
        regs_written_ |= regMask(reg->getRoot(mm_));
      }
    } else if (const auto mem = operand.getIf<zasm::Mem>()) {
      // index and base regs get read for mem ops
      regs_read_ |= regMask(mem->getIndex().getRoot(mm_));
      regs_read_ |= regMask(mem->getBase().getRoot(mm_));
    }
  }
  const auto& flags = instruction_.getCPUFlags();
  flags_modified_ = flags.set0 | flags.set1 | flags.modified | flags.undefined;
  flags_tested_ = flags.tested;
}

void X86Inst::addInstructionSpecificContext(const TargetArchitecture arch,
                                            const Platform platform) {
  // add instruction-specific context based on calling conventions across
  // platforms and architectures
  if (instruction_.getCategory() == zasm::x86::Category::Call) {
    //
    if (arch == TargetArchitecture::I386) {
      if (platform == Platform::Windows) {
        // __fastcall, esp read by push eip
        regs_read_ |= regMask(zasm::x86::ecx) | regMask(zasm::x86::edx) |
                      regMask(zasm::x86::esp);
        // volatile and return regs are stomped
        for (const auto reg : x86::gpVolWin32) regs_written_ |= regMask(reg);
      }
      regs_written_ |= regMask(zasm::x86::eax);
    } else if (arch == TargetArchitecture::AMD64) {
      if (platform == Platform::Windows) {
        // __fastcall, rsp read by push rip
        regs_read_ |= regMask(zasm::x86::rcx) | regMask(zasm::x86::rdx) |
                      regMask(zasm::x86::r8) | regMask(zasm::x86::r9) |
                      regMask(zasm::x86::rsp);
        // volatile and return regs are stomped
        for (const auto reg : x86::gpVolWin64) regs_written_ |= regMask(reg);
      }
      regs_written_ |= regMask(zasm::x86::rax);
    }
  } else if (instruction_.getCategory() == zasm::x86::Category::Ret) {
    if (arch == TargetArchitecture::I386) {
      if (platform == Platform::Windows) {
        regs_read_ |= regMask(zasm::x86::eax) | regMask(zasm::x86::ebx) |
                      regMask(zasm::x86::esi) | regMask(zasm::x86::edi) |
                      regMask(zasm::x86::ebp) | regMask(zasm::x86::esp);
      }
    } else if (arch == TargetArchitecture::AMD64) {
      if (platform == Platform::Windows) {
        regs_read_ |= regMask(zasm::x86::rax) | regMask(zasm::x86::rbx) |
                      regMask(zasm::x86::rbp) | regMask(zasm::x86::rsp) |
                      regMask(zasm::x86::rdi) | regMask(zasm::x86::rsi) |
                      regMask(zasm::x86::r12) | regMask(zasm::x86::r13) |
                      regMask(zasm::x86::r14) | regMask(zasm::x86::r15);
      }
    }
  }
}
}  // namespace stitch
