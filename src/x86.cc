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
#include <iostream>
#include <map>
#include <queue>
#include <set>
#include <zasm/formatter/formatter.hpp>

namespace stitch {
/*
 * Called only once. Performs the following analyses:
 * - Disassembly
 * - Control flow analysis
 * - TODO Tail call analysis
 */
void X86Code::AnalyzeFrom(const VA address) {
  if (analyzed_) return;
  analyzeFunction(address);
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

  const RVA scn_address = scn->GetAddress();
  const std::vector<uint8_t>& scn_data = scn->GetData();
  const RVA rva = address - scn->GetParent()->GetImageBase();

  const VA scn_rel_address = rva - scn_address;
  const uint8_t* data = scn_data.data() + scn_rel_address;
  const size_t data_size = scn_data.size() - scn_rel_address;
  X86Function* fn = buildFunction(address, data, data_size, reopen_idx);
  fn->setOldSection(scn);
  return fn;
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
  const Binary* binary = GetParent();
  const VA image_base = binary->GetImageBase();
  Section* scn = fn.getOldSection();

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
  const X86BasicBlock* first_block = fn.getBasicBlocks().front().get();
  if (serializer.getCodeSize() > first_block->GetSize())
    throw code_error("patch stub too large");
  // now replace first basic block's address with the patch
  const RVA block_rel_addr =
      first_block->GetAddress() - scn->GetAddress() - image_base;
  scn->WriteAt(block_rel_addr, serializer.getCode(), serializer.getCodeSize());
}

X86Function* X86Code::buildFunction(const VA fn_address, const uint8_t* code,
                                    const size_t code_size,
                                    const int reopen_idx) {
  std::set<VA> visited_insts;
  const zasm::MachineMode mm = GetArchitecture() == TargetArchitecture::I386
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

  fn->buildBasicBlocks(decoder, code, code_size, fn_address, 0, visited_insts,
                       nullptr);
  std::sort(fn->instructions_.begin(), fn->instructions_.end());
  fn->runAnalyses();
  fn->assembler_.align(zasm::Align::Type::Code, kFunctionAlignment);
  return fn;
}

zasm::MachineMode X86Function::getMachineMode() const {
  return GetParent()->GetArchitecture() == TargetArchitecture::I386
             ? zasm::MachineMode::I386
             : zasm::MachineMode::AMD64;
}

void X86Function::buildBasicBlocks(zasm::Decoder& decoder, const uint8_t* code,
                                   const size_t code_size, VA runtime_address,
                                   VA offset, std::set<VA>& visited_insts,
                                   X86BasicBlock* parent_block) {
  X86BasicBlock* basic_block = nullptr;
  while (offset < code_size) {
    if (visited_insts.contains(runtime_address)) {
      /*
       * This will either:
       * 1. Add a new parent for the basic block that we've reached, or
       * 2. If we jumped to the middle of an already-created basic block, then
       * we split it at that point, and set the new block's parents to where we
       *    jumped from (parent_block) and the block that used to own the
       * instruction at that address
       */
      findAndSplitBasicBlock(runtime_address, parent_block);
      return;
    }
    if (basic_block == nullptr)
      basic_block = addBasicBlock(runtime_address, 0, parent_block);
    auto result =
        decoder.decode(code + offset, code_size - offset, runtime_address);
    if (!result) {
      throw code_error(result.error().getErrorMessage());
    }
    const auto& inst = result.value();
    const uint8_t inst_length = inst.getLength();
    visited_insts.emplace(runtime_address);

    X86Inst& x86inst =
        instructions_.emplace_back(decoder.getMode(), inst, this, basic_block);
    x86inst.setAddress(runtime_address);

    // move 'cursor' forward
    basic_block->SetSize(basic_block->GetSize() + inst_length);
    offset += inst_length;
    runtime_address += inst_length;
    // any branching instruction other than call terminates a basic block
    if (zasm::x86::isBranching(inst)) {
      if (inst.getCategory() == zasm::x86::Category::Ret) {
        exit_blocks_.insert(basic_block);
        return;
      }
      if (inst.getCategory() == zasm::x86::Category::Call) {
        const auto* address = inst.getOperandIf<zasm::Imm>(0);
        // recursive function analysis, won't reanalyze if already in database
        if (address != nullptr)
          GetParent<X86Code>()->analyzeFunction(address->value<VA>());
        continue;
      }
      int64_t cf_dst = 0;
      try {
        cf_dst = inst.getOperand<zasm::Imm>(0).value<int64_t>();
      } catch (const std::exception& _) {
        return;
      }
      const int64_t jump_distance = cf_dst - runtime_address;
      buildBasicBlocks(decoder, code, code_size, cf_dst, offset + jump_distance,
                       visited_insts, basic_block);
      // unconditional jump terminates a BB
      if (inst.getCategory() == zasm::x86::Category::UncondBR) {
        return;
      }
      basic_block = addBasicBlock(runtime_address, 0, basic_block);
    }
  }
}

void X86Function::findAndSplitBasicBlock(const VA address,
                                         X86BasicBlock* new_parent) {
  for (const auto& block : basic_blocks_) {
    // if we fall at the start of the basic block then no need to split,
    // just add our own block as a parent
    const VA block_addr = block->GetAddress();
    if (address == block_addr) {
      block->AddParent(new_parent);
      return;
    }
    // if address is within basic block, then split it
    if (address > block_addr && address < block_addr + block->GetSize()) {
      X86BasicBlock* new_block = splitAfter(block.get(), address);
      new_block->AddParent(new_parent);
      // if old block was an exit block, new block will become an exit block
      for (auto it = exit_blocks_.begin(); it != exit_blocks_.end(); ++it) {
        if (block.get() == *it) {
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
  X86BasicBlock* new_block = addBasicBlock(address, 0, block);
  for (auto& inst : instructions_) {
    // move insts that are within the old block to the new block
    if (inst.GetAddress() >= address &&
        inst.GetAddress() < block->GetAddress() + block->GetSize()) {
      inst.setBasicBlock(new_block);
      new_block->SetSize(new_block->GetSize() + inst.RawInst().getLength());
    }
  }
  return new_block;
}

X86BasicBlock* X86Function::addBasicBlock(VA loc, uint64_t size,
                                          X86BasicBlock* parent) {
  return basic_blocks_
      .emplace_back(std::make_unique<X86BasicBlock>(loc, size, parent))
      .get();
}

std::vector<X86Inst*> X86Function::getBlockInstructions(
    const X86BasicBlock* block) {
  std::vector<X86Inst*> insts;
  for (X86Inst& inst : instructions_) {
    if (inst.getBasicBlock()->GetAddress() == block->GetAddress()) {
      insts.push_back(&inst);
    }
  }
  return insts;
}

void X86Function::genLivenessInfo() {
  genBlockLivenessInfo();
  genInstructionLivenessInfo();
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
    // solve LIVEin and LIVEOut equations
    block->regs_live_in_ =
        block->regs_gen_ | (block->regs_live_out_ & ~block->regs_kill_);
    block->flags_live_in_ =
        block->flags_gen_ | (block->flags_live_out_ & ~block->flags_kill_);

    for (X86BasicBlock* parent : block->GetParents()) {
      parent->regs_live_out_ |= block->regs_live_in_;
      parent->flags_live_out_ = parent->flags_live_out_ | block->flags_live_in_;
      // prevent infinite recursion
      if (!visited_blocks.contains(parent->GetAddress())) blocks.push(parent);
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

bool X86Function::isWithinFunction(const uint64_t address) const {
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

/// Sets a stack offset property for each instruction in the function.
/// This only handles common instructions that may modify the stack pointer.
void X86Function::genStackOffsets() {
  using namespace utils;

  std::map<int8_t, sym::Reg> reg_map = {
      {zasm::x86::rsp.getIndex(), sym::Reg("sp", 0)},  // initialised
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

  for (auto it = instructions_.begin(); it != instructions_.end(); ++it) {
    X86Inst& inst = *it;
    const zasm::InstructionDetail& ri = inst.RawInst();

    if (ri.getOperandCount() == 0) continue;
    const zasm::Operand& op0 = ri.getOperand(0);

    try {
      switch (ri.getMnemonic()) {
        case zasm::x86::Mnemonic::Sub: {
          if (const auto reg_op0 = op0.getIf<zasm::x86::Reg>()) {
            sym::Reg& sym = reg_map.at(reg_op0->getIndex());
            if (const auto reg = ri.getOperandIf<zasm::x86::Reg>(1)) {
              sym = sym - reg_map.at(reg->getIndex());
            } else if (const auto imm = ri.getOperandIf<zasm::Imm>(1)) {
              sym = sym - imm->value<uint64_t>();
            }
          }
        } break;
        case zasm::x86::Mnemonic::Add: {
          if (const auto reg_op0 = op0.getIf<zasm::x86::Reg>()) {
            sym::Reg& sym = reg_map.at(reg_op0->getIndex());
            if (const auto reg = ri.getOperandIf<zasm::x86::Reg>(1)) {
              sym = sym + reg_map.at(reg->getIndex());
            } else if (const auto imm = ri.getOperandIf<zasm::Imm>(1)) {
              sym = sym + imm->value<uint64_t>();
            }
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
          if (const auto reg = ri.getOperandIf<zasm::x86::Reg>(1)) {
            sym = sym & (reg_map.at(reg->getIndex()) | ~mask);
          } else if (const auto imm = ri.getOperandIf<zasm::Imm>(1)) {
            sym = sym & (imm->value<uint64_t>() | ~mask);
          }
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
          if (const auto reg = ri.getOperandIf<zasm::x86::Reg>(1)) {
            sym = sym | (reg_map.at(reg->getIndex()) & mask);
          } else if (const auto imm = ri.getOperandIf<zasm::Imm>(1)) {
            sym = sym | (imm->value<uint64_t>() & mask);
          }
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
          if (const auto reg = ri.getOperandIf<zasm::x86::Reg>(1)) {
            sym = sym ^ (reg_map.at(reg->getIndex()) & mask);
          } else if (const auto imm = ri.getOperandIf<zasm::Imm>(1)) {
            sym = sym ^ (imm->value<uint64_t>() & mask);
          }
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
              if (index != -1) {
                sym = sym + (reg_map.at(index) * scale);
              }
              sym = sym + disp;
            }
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
            if (const auto reg = ri.getOperandIf<zasm::x86::Reg>(1)) {
              sym = reg_map.at(reg->getIndex());
            } else if (const auto imm = ri.getOperandIf<zasm::Imm>(1)) {
              sym = imm->value<uint64_t>();
            }
          }
        } break;
          // subtract
        case zasm::x86::Mnemonic::Push: {
          sym::Reg& sym = reg_map.at(zasm::x86::rsp.getIndex());
          sym = sym - (getMachineMode() == zasm::MachineMode::I386 ? 4 : 8);
        } break;
          // add
        case zasm::x86::Mnemonic::Pop: {
          sym::Reg& sym = reg_map.at(zasm::x86::rsp.getIndex());
          sym = sym + (getMachineMode() == zasm::MachineMode::I386 ? 4 : 8);
        } break;
        default:;
      }
    } catch (const std::out_of_range& _) {
      continue;
    }
    // each instruction stores stack offset before it is run
    // technically sp should always be defined unless silliness is involved
    sym::Reg& rsp = reg_map.at(zasm::x86::rsp.getIndex());
    if (it + 1 != instructions_.end() && rsp.Defined())
      (it + 1)->setStackOffset(reg_map.at(zasm::x86::rsp.getIndex()));
  }
}

void X86Function::finalize() {
  std::map<VA, zasm::Label> labels;
  assembler_.align(zasm::Align::Type::Code, X86Code::kFunctionAlignment);
  // first iteration - get all relN instructions and create labels for them
  for (X86Inst& inst : instructions_) {
    // auto v = inst.RawInst().getInstruction();
    // std::cout << "" << std::hex << inst.GetAddress() << std::dec << ": "
    //           << zasm::formatter::toString(program_, &v) << " ; stack offset = "
    //           << static_cast<int64_t>(inst.getStackOffset()) << std::endl;
    const zasm::InstructionDetail& raw_inst = inst.RawInst();
    if ((zasm::x86::isBranching(raw_inst) &&
         raw_inst.getMnemonic() != zasm::x86::Mnemonic::Ret) ||
        raw_inst.getMnemonic() == zasm::x86::Mnemonic::Loop ||
        raw_inst.getMnemonic() == zasm::x86::Mnemonic::Loope ||
        raw_inst.getMnemonic() == zasm::x86::Mnemonic::Loopne) {
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
    if (labels.contains(inst.GetAddress())) {
      const zasm::Label& label = labels[inst.GetAddress()];
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
  VA new_write_address = new_section_->GetParent()->GetImageBase() +
                         new_section_->GetAddress() + new_section_->GetSize();
  // align to boundary since assembler pushes align bytes at start of program
  new_write_address =
      utils::RoundToBoundary(new_write_address, X86Code::kFunctionAlignment);
  GetParent<X86Code>()->patchOriginalLocation(*this, new_write_address);
  zasm::Serializer serializer;
  const zasm::Error code = serializer.serialize(program_, new_write_address);
  if (code.getCode() != zasm::ErrorCode::None)
    throw code_error(code.getErrorMessage());
  new_section_->Write(serializer.getCode(), serializer.getCodeSize());
  finished_ = true;
}
}  // namespace stitch