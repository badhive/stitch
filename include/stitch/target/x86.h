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
#include <optional>

#include <zasm/zasm.hpp>

#include "stitch/binary/binary.h"
#include "stitch/target/target.h"

namespace stitch {
class X86Function;
class X86Inst;
class X86Operand;

using PatchPolicy = std::function<void(zasm::x86::Assembler& as,
                                       RVA old_loc,
                                       RVA new_loc)>;
using Instrumentor = std::function<void(zasm::x86::Assembler& as)>;

inline void
DefaultPatchPolicy(zasm::x86::Assembler& as, const RVA _, const RVA new_loc) {
  as.jmp(zasm::Imm(new_loc));
}

class X86Code final : public Code {
  friend class X86Function;

  std::vector<std::optional<X86Function>> functions_;
  PatchPolicy patch_policy_;

  static constexpr uint8_t kFunctionAlignment = 16;

  X86Function& editFunction(VA address, const std::string& in);
  X86Function& buildFunction(RVA fn_address,
                             const uint8_t* code,
                             size_t code_size,
                             int reopen_idx);
  void patchOriginalLocation(X86Function& fn, VA new_loc) const;

public:
  explicit X86Code(Section* scn, const TargetArchitecture arch) : Code(
                                                                      scn, arch), patch_policy_(DefaultPatchPolicy) {
    if (arch != TargetArchitecture::I386 &&
        arch != TargetArchitecture::AMD64) {
      throw std::runtime_error("unexpected architecture");
    }
    if (scn->GetType() != Section::Type::Code)
      throw unsupported_section_type_error(scn->GetName());
  }


  /// Changes the default method used to patch moved functions, which is
  /// to emit a jump call to the function's new RVA.
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
  Function& EditFunction(VA address, const std::string& in) override;

  Function& EditFunction(VA address, const Section& scn) override;

  /// Creates a new function to replace the function at the provided address.
  /// The resulting object will have an empty assembler instance.
  /// @param address VA of function
  /// @param in name of section that code is moved to
  /// @return reference to new Function object
  Function& RebuildFunction(VA address, const std::string& in) override;

  Function& RebuildFunction(VA address, const Section& scn) override;

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
  std::vector<std::tuple<RVA, uint64_t, RVA>> basic_blocks_;
  Section* new_section_;

  zasm::MachineMode getMachineMode() const;
  void addBasicBlock(RVA loc, uint64_t size, RVA parent);
  void removeBasicBlockTree(RVA loc);
  void buildBasicBlocks(zasm::Decoder& decoder,
                        const uint8_t* code,
                        size_t code_size,
                        RVA runtime_address,
                        RVA offset,
                        std::map<RVA, const zasm::InstructionDetail&>&
                        visited_insts,
                        std::map<RVA, int64_t>& jump_gaps,
                        bool recursed,
                        RVA parent_block
      );
  void checkTailCall(RVA current_inst_addr,
                     std::map<RVA, int64_t>& jump_gaps) const;
  bool isWithinFunction(uint64_t address);
  void moveDelta(int64_t delta);
  void setNewSection(Section* section) { new_section_ = section; }
  void finalize();

public:
  explicit X86Function(const RVA address, zasm::Program&& program,
                       X86Code* code)
    : Function(address, code),
      finished_(false),
      program_(std::move(program)),
      assembler_(program_),
      new_section_(nullptr) {
  }

  std::vector<X86Inst>& GetOriginalCode() { return instructions_; }

  void Instrument(const Instrumentor& instrumentor) {
    instrumentor(assembler_);
  }

  /// Saves new code to file
  void Finish() override;
};

class X86Inst final : public Inst {
  friend class X86Function;

  zasm::Node* pos_;
  zasm::InstructionDetail instruction_;

  // fix references from .reloc when instruction is moved
  void fixupRelocReferences();

  void setPos(zasm::Node* pos) {
    pos_ = pos;
  }

public:
  X86Inst(const zasm::InstructionDetail& instruction, X86Function* function) :
    Inst(0, function), pos_(nullptr), instruction_(instruction) {
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