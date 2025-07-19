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

#ifndef STITCH_TARGET_X86_H_
#define STITCH_TARGET_X86_H_

#include <functional>
#include <map>
#include <memory>
#include <set>

#include <zasm/zasm.hpp>

#include "stitch/binary/binary.h"
#include "stitch/target/target.h"

namespace stitch {
class X86Function;
class X86BasicBlock;
class X86Inst;
class X86Operand;

using PatchPolicy = std::function<void(zasm::x86::Assembler& as,
                                       VA old_loc,
                                       VA new_loc)>;
using Instrumentor = std::function<void(zasm::x86::Assembler& as)>;
using ProgramInstrumentor = std::function<void(zasm::Program& pr,
                                               zasm::x86::Assembler& as)>;

inline void
DefaultPatchPolicy(zasm::x86::Assembler& as, const VA _, const VA new_loc) {
  as.jmp(zasm::Imm(new_loc));
}

class X86Code final : public Code {
  friend class X86Function;

  std::vector<std::unique_ptr<X86Function>> functions_;
  std::vector<std::unique_ptr<X86BasicBlock>> basic_blocks_;
  PatchPolicy patch_policy_;

  static constexpr uint8_t kFunctionAlignment = 16;

  X86Function* editFunction(VA address, const std::string& in);
  X86Function* buildFunction(VA fn_address,
                             const uint8_t* code,
                             size_t code_size,
                             int reopen_idx);
  void patchOriginalLocation(const X86Function& fn, VA new_loc) const;

public:
  explicit X86Code(Section* scn, const TargetArchitecture arch) : Code(
        scn, arch), patch_policy_(DefaultPatchPolicy) {
    if (arch != TargetArchitecture::I386 &&
        arch != TargetArchitecture::AMD64) {
      throw std::runtime_error("unexpected architecture");
    }
    if (scn->GetType() != SectionType::Code)
      throw unsupported_section_type_error(scn->GetName());
  }


  /// Changes the default method used to patch moved functions, which is
  /// to emit a jump call to the function's new VA.
  /// @param policy function that ultimately emits a jump call to the new
  /// function address
  void SetPatchPolicy(const PatchPolicy& policy) {
    patch_policy_ = policy;
  }

  /// Creates a new function object from the code at the provided address, to
  /// be edited in the specified section. If an empty name is specified,
  /// ".stitch" is used.
  /// @param address VA of function
  /// @param in name of section that code is moved to
  /// @return reference to new Function object.
  Function* EditFunction(VA address, const std::string& in) override;

  Function* EditFunction(VA address, const Section& scn) override;

  /// Creates a new function to replace the function at the provided address.
  /// The resulting object will have an empty assembler instance.
  /// @param address VA of function
  /// @param in name of section that code is moved to
  /// @return reference to new Function object
  Function* RebuildFunction(VA address, const std::string& in) override;

  Function* RebuildFunction(VA address, const Section& scn) override;

  void Assemble(const zasm::Program& pr) const {
    Section* scn = GetParent();
    if (scn->OnDisk()) {
      throw std::runtime_error("cannot write to existing code section");
    }
    // pointer to end of section
    const VA fn_addr = scn->GetParent()->GetImageBase()
                       + scn->GetAddress()
                       + scn->GetSize();
    zasm::Serializer serializer;
    const zasm::Error err = serializer.serialize(pr, fn_addr).getCode();
    if (err != zasm::ErrorCode::None)
      throw code_error(
          std::string("failed to assemble: ") + err.getErrorMessage());
    scn->Write(serializer.getCode(), serializer.getCodeSize());
  }

  static uint8_t GetFunctionAlignment() {
    return kFunctionAlignment;
  }
};

class X86Function final : public Function {
  friend class X86Code;

  bool finished_;
  zasm::Program program_;
  zasm::x86::Assembler assembler_;
  std::vector<X86Inst> instructions_;
  // only used for initial copy of function to new section
  std::vector<std::unique_ptr<X86BasicBlock>> basic_blocks_;
  std::vector<X86BasicBlock*> exit_blocks_;
  Section* new_section_;

  zasm::MachineMode getMachineMode() const;
  void buildBasicBlocks(zasm::Decoder& decoder,
                        const uint8_t* code,
                        size_t code_size,
                        VA runtime_address,
                        VA offset,
                        std::set<VA>& visited_insts,
                        std::map<VA, int64_t>& jump_gaps,
                        bool recursed,
                        X86BasicBlock* parent_block
      );
  void findAndSplitBasicBlock(VA address, X86BasicBlock* new_parent);
  X86BasicBlock* splitAfter(X86BasicBlock* block, VA address);
  X86BasicBlock* addBasicBlock(VA loc, uint64_t size, X86BasicBlock* parent);
  void removeBasicBlockTree(VA loc);
  void checkTailCall(VA current_inst_addr,
                     std::map<VA, int64_t>& jump_gaps) const;
  bool isWithinFunction(uint64_t address) const;
  void moveDelta(int64_t delta);
  void setNewSection(Section* section) { new_section_ = section; }
  void finalize();

public:
  explicit X86Function(const VA address, zasm::Program&& program,
                       X86Code* code)
    : Function(address, code),
      finished_(false),
      program_(std::move(program)),
      assembler_(program_),
      new_section_(nullptr) {
  }

  std::vector<X86Inst>& GetOriginalCode() { return instructions_; }

  /// Use a dedicated function to instrument this X86Function.
  /// Instrument automatically calls Finish() on this X86Function.
  /// @param instrumentor instrumentation function
  void Instrument(const Instrumentor& instrumentor) {
    instrumentor(assembler_);
    Finish();
  }

  void Instrument(const ProgramInstrumentor& instrumentor) {
    instrumentor(program_, assembler_);
    Finish();
  }

  /// Saves new code to file
  void Finish() override;
};

// TODO use this
class X86BasicBlock {
  VA address_;
  int64_t size_;
  std::vector<X86BasicBlock*> parents_;
  bool is_exit_ = false;

public:
  X86BasicBlock(const VA address, const int64_t size, X86BasicBlock* parent)
    : address_(address), size_(size) {
    parents_.push_back(parent);
  }

  VA GetAddress() const { return address_; }

  const std::vector<X86BasicBlock*>& GetParents() const { return parents_; }

  void AddParent(X86BasicBlock* parent) { parents_.push_back(parent); }

  int64_t GetSize() const { return size_; }

  void SetSize(const int64_t size) { size_ = size; }

  void SetExit(const bool is_exit) { is_exit_ = is_exit; }
};

class X86Inst final : public Inst {
  friend class X86Function;

  zasm::Node* pos_;
  zasm::InstructionDetail instruction_;
  X86BasicBlock* basic_block_;

  // fix references from .reloc when instruction is moved
  void fixupRelocReferences();

  void setPos(zasm::Node* pos) {
    pos_ = pos;
  }

  X86BasicBlock* getBasicBlock() const { return basic_block_; }

  void setBasicBlock(X86BasicBlock* basic_block) {
    basic_block_ = basic_block;
  }

public:
  X86Inst(const zasm::InstructionDetail& instruction, X86Function* function,
          X86BasicBlock* bb) :
    Inst(0, function), pos_(nullptr), instruction_(instruction),
    basic_block_(bb) {
  }

  const zasm::InstructionDetail& RawInst() const {
    return instruction_;
  }

  /// Gets the position of the instruction within the assembler. This position
  /// can only be used with the assembler that this instruction comes from
  /// @return position of instruction
  zasm::Node* GetPos() const {
    return pos_;
  }

  bool operator<(const X86Inst& other) const {
    return getAddress() < other.getAddress();
  }

  X86Inst& operator=(const X86Inst& other) {
    if (this != &other) {
      if (other.pos_ != nullptr)
        this->pos_ = other.pos_;
      if (other.getAddress())
        this->setAddress(other.getAddress());
      this->instruction_ = other.instruction_;
    }
    return *this;
  }
};

class X86FunctionBuilder {
  zasm::Program program_;
  zasm::x86::Assembler assembler_;
  X86Code* code_;
  bool finished_;

public:
  X86FunctionBuilder(const TargetArchitecture arch, X86Code* code) :
    program_(
        arch == TargetArchitecture::I386
          ? zasm::MachineMode::I386
          : arch == TargetArchitecture::AMD64
          ? zasm::MachineMode::AMD64
          : zasm::MachineMode::Invalid
        ),
    assembler_(program_),
    code_(code),
    finished_(false) {
    if (!code)
      throw code_error("function builder must be bound to code");
    assembler_.align(zasm::Align::Type::Code, X86Code::GetFunctionAlignment());
  }

  zasm::x86::Assembler& GetAssembler() { return assembler_; }

  void Finish();
};
}

#endif //STITCH_TARGET_X86_H_