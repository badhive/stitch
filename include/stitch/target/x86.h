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
#include <memory>
#include <optional>
#include <set>
#include <zasm/zasm.hpp>

#include "stitch/binary/binary.h"
#include "stitch/target/target.h"

namespace stitch {
class X86Function;
class X86BasicBlock;
class X86Inst;
class X86Operand;

namespace x86 {
static std::vector regs64 = {
    zasm::x86::rax, zasm::x86::rbx, zasm::x86::rcx, zasm::x86::rdx,
    zasm::x86::rbp, zasm::x86::rsp, zasm::x86::rdi, zasm::x86::rsi,
    zasm::x86::r8,  zasm::x86::r9,  zasm::x86::r10, zasm::x86::r11,
    zasm::x86::r12, zasm::x86::r13, zasm::x86::r14, zasm::x86::r15};

static std::vector regs32 = {zasm::x86::eax, zasm::x86::ebx, zasm::x86::ecx,
                             zasm::x86::edx, zasm::x86::ebp, zasm::x86::esp,
                             zasm::x86::edi, zasm::x86::esi};
}  // namespace x86

using PatchPolicy =
    std::function<void(zasm::x86::Assembler& as, VA old_loc, VA new_loc)>;
using Instrumentor = std::function<void(zasm::x86::Assembler& as)>;
using ProgramInstrumentor =
    std::function<void(zasm::Program& pr, zasm::x86::Assembler& as)>;

inline void DefaultPatchPolicy(zasm::x86::Assembler& as, const VA _,
                               const VA new_loc) {
  as.jmp(zasm::Imm(new_loc));
}

class X86Code final : public Code {
  friend class X86Function;

  std::vector<std::unique_ptr<X86Function>> functions_;
  PatchPolicy patch_policy_;

  static constexpr uint8_t kFunctionAlignment = 16;

  X86Function* editFunction(VA address, const std::string& in);
  X86Function* buildFunction(VA fn_address, const uint8_t* code,
                             size_t code_size, int reopen_idx);
  void patchOriginalLocation(const X86Function& fn, VA new_loc) const;

 public:
  explicit X86Code(Section* scn, const TargetArchitecture arch)
      : Code(scn, arch), patch_policy_(DefaultPatchPolicy) {
    if (arch != TargetArchitecture::I386 && arch != TargetArchitecture::AMD64) {
      throw std::runtime_error("unexpected architecture");
    }
    if (scn->GetType() != SectionType::Code)
      throw unsupported_section_type_error(scn->GetName());
  }

  /// Changes the default method used to patch moved functions, which is
  /// to emit a jump call to the function's new VA.
  /// @param policy function that ultimately emits a jump call to the new
  /// function address
  void SetPatchPolicy(const PatchPolicy& policy) { patch_policy_ = policy; }

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
    const VA fn_addr =
        scn->GetParent()->GetImageBase() + scn->GetAddress() + scn->GetSize();
    zasm::Serializer serializer;
    const zasm::Error err = serializer.serialize(pr, fn_addr).getCode();
    if (err != zasm::ErrorCode::None)
      throw code_error(std::string("failed to assemble: ") +
                       err.getErrorMessage());
    scn->Write(serializer.getCode(), serializer.getCodeSize());
  }

  static uint8_t GetFunctionAlignment() { return kFunctionAlignment; }
};

class X86Function final : public Function {
  friend class X86Code;

  bool finished_;
  zasm::Program program_;
  zasm::x86::Assembler assembler_;
  std::vector<X86Inst> instructions_;
  // only used for initial copy of function to new section
  std::vector<std::unique_ptr<X86BasicBlock>> basic_blocks_;
  std::set<X86BasicBlock*> exit_blocks_;
  Section* new_section_;

  zasm::MachineMode getMachineMode() const;
  std::vector<X86Inst*> getBlockInstructions(const X86BasicBlock* block);
  void buildBasicBlocks(zasm::Decoder& decoder, const uint8_t* code,
                        size_t code_size, VA runtime_address, VA offset,
                        std::set<VA>& visited_insts,
                        X86BasicBlock* parent_block);
  void genLivenessInfo();
  void genBlockLivenessInfo();
  void genInstructionLivenessInfo();
  void findAndSplitBasicBlock(VA address, X86BasicBlock* new_parent);
  X86BasicBlock* splitAfter(X86BasicBlock* block, VA address);
  X86BasicBlock* addBasicBlock(VA loc, uint64_t size, X86BasicBlock* parent);
  void removeBasicBlockTree(VA loc);
  bool isWithinFunction(uint64_t address) const;
  void moveDelta(int64_t delta);
  void setNewSection(Section* section) { new_section_ = section; }
  void finalize();

 public:
  explicit X86Function(const VA address, zasm::Program&& program, X86Code* code)
      : Function(address, code),
        finished_(false),
        program_(std::move(program)),
        assembler_(program_),
        new_section_(nullptr) {}

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

class X86BasicBlock {
  friend class X86Function;

  VA address_;
  int64_t size_;
  std::vector<X86BasicBlock*> parents_;
  bool is_exit_ = false;

  uint32_t regs_gen_;
  uint32_t regs_kill_;
  zasm::InstrCPUFlags flags_gen_;
  zasm::InstrCPUFlags flags_kill_;

  uint32_t regs_live_in_;
  uint32_t regs_live_out_;
  zasm::InstrCPUFlags flags_live_in_;
  zasm::InstrCPUFlags flags_live_out_;

 public:
  X86BasicBlock(const VA address, const int64_t size, X86BasicBlock* parent)
      : address_(address),
        size_(size),
        regs_gen_(0),
        regs_kill_(0),
        flags_gen_(0),
        flags_kill_(0),
        regs_live_in_(0),
        regs_live_out_(0),
        flags_live_in_(0),
        flags_live_out_(0) {
    AddParent(parent);
  }

  VA GetAddress() const { return address_; }

  const std::vector<X86BasicBlock*>& GetParents() const { return parents_; }

  void AddParent(X86BasicBlock* parent) {
    if (parent) parents_.push_back(parent);
  }

  int64_t GetSize() const { return size_; }

  void SetSize(const int64_t size) { size_ = size; }

  void SetExit(const bool is_exit) { is_exit_ = is_exit; }
};

#define mask(r) 1u << r.getIndex()

class X86Inst final : public Inst {
  friend class X86Function;

  zasm::Node* pos_;
  zasm::InstructionDetail instruction_;
  zasm::MachineMode mm_;
  X86BasicBlock* basic_block_;

  uint32_t regs_read_;
  uint32_t regs_written_;
  zasm::InstrCPUFlags flags_modified_;
  zasm::InstrCPUFlags flags_tested_;

  uint32_t regs_live_;
  zasm::InstrCPUFlags flags_live_;

  // fix references from .reloc when instruction is moved
  void fixupRelocReferences();

  void setPos(zasm::Node* pos) { pos_ = pos; }

  X86BasicBlock* getBasicBlock() const { return basic_block_; }

  void setBasicBlock(X86BasicBlock* basic_block) { basic_block_ = basic_block; }

 public:
  X86Inst(const zasm::MachineMode mm,
          const zasm::InstructionDetail& instruction, X86Function* function,
          X86BasicBlock* bb)
      : Inst(0, function),
        pos_(nullptr),
        instruction_(instruction),
        mm_(mm),
        basic_block_(bb),
        regs_read_(0),
        regs_written_(0),
        flags_modified_(0),
        flags_tested_(0),
        regs_live_(0),
        flags_live_(0) {
    const TargetArchitecture arch = function->GetParent()->GetArchitecture();
    const Platform platform =
        function->GetParent()->GetParent()->GetParent()->GetPlatform();
    addInstructionContext();
    addInstructionSpecificContext(arch, platform);
  }

  // add liveness info on construction of X86Inst. Refs:
  // https://github.com/thesecretclub/riscy-business/blob/zasm-obfuscator/obfuscator/src/obfuscator/program.cpp#L139
  void addInstructionContext() {
    for (size_t i = 0; i < instruction_.getOperandCount(); i++) {
      const auto& operand = instruction_.getOperand(i);
      const auto access = instruction_.getOperandAccess(i);
      if (const auto reg = operand.getIf<zasm::Reg>()) {
        if (static_cast<uint32_t>(access & zasm::Operand::Access::MaskRead)) {
          regs_read_ |= mask(reg->getRoot(mm_));
        } else if (static_cast<uint32_t>(access &
                                         zasm::Operand::Access::MaskWrite)) {
          regs_written_ |= mask(reg->getRoot(mm_));
        }
      } else if (const auto mem = operand.getIf<zasm::Mem>()) {
        // index and base regs get read for mem ops
        regs_read_ |= mask(mem->getIndex().getRoot(mm_));
        regs_read_ |= mask(mem->getBase().getRoot(mm_));
      }
    }
    const auto& flags = instruction_.getCPUFlags();
    // todo - potentially smarter way to store these
    flags_modified_ =
        flags.set0 | flags.set1 | flags.modified | flags.undefined;
    flags_tested_ = flags.tested;
  }

  void addInstructionSpecificContext(const TargetArchitecture arch,
                                     const Platform platform) {
    // add instruction-specific context based on calling conventions across
    // platforms and architectures
    if (instruction_.getCategory() == zasm::x86::Category::Call) {
      //
      if (arch == TargetArchitecture::I386) {
        if (platform == Platform::Windows) {
          // __fastcall, esp read by push eip
          regs_read_ |= mask(zasm::x86::ecx) | mask(zasm::x86::edx) |
                        mask(zasm::x86::esp);
          // volatile regs and return reg
          regs_written_ |= mask(zasm::x86::eax) | mask(zasm::x86::ecx) |
                           mask(zasm::x86::edx);
        }
      } else if (arch == TargetArchitecture::AMD64) {
        if (platform == Platform::Windows) {
          // __fastcall, rsp read by push rip
          regs_read_ |= mask(zasm::x86::rcx) | mask(zasm::x86::rdx) |
                        mask(zasm::x86::r8) | mask(zasm::x86::r9) |
                        mask(zasm::x86::rsp);
          // volatile regs and return register are overwritten
          regs_written_ |= mask(zasm::x86::rax) | mask(zasm::x86::rcx) |
                           mask(zasm::x86::rdx) | mask(zasm::x86::r8) |
                           mask(zasm::x86::r9) | mask(zasm::x86::r10) |
                           mask(zasm::x86::r11) | mask(zasm::x86::rflags);
        }
      }
    } else if (instruction_.getCategory() == zasm::x86::Category::Ret) {
      if (arch == TargetArchitecture::I386) {
        if (platform == Platform::Windows) {
          regs_read_ |= mask(zasm::x86::eax) | mask(zasm::x86::ebx) |
                        mask(zasm::x86::esi) | mask(zasm::x86::edi) |
                        mask(zasm::x86::ebp) | mask(zasm::x86::esp);
        }
      } else if (arch == TargetArchitecture::AMD64) {
        if (platform == Platform::Windows) {
          regs_read_ |= mask(zasm::x86::rax) | mask(zasm::x86::rbx) |
                        mask(zasm::x86::rbp) | mask(zasm::x86::rsp) |
                        mask(zasm::x86::rdi) | mask(zasm::x86::rsi) |
                        mask(zasm::x86::r12) | mask(zasm::x86::r13) |
                        mask(zasm::x86::r14) | mask(zasm::x86::r15);
        }
      }
    }
  }

  const zasm::InstructionDetail& RawInst() const { return instruction_; }

  /// Gets the position of the instruction within the assembler. This position
  /// can only be used with the assembler that this instruction comes from
  /// @return position of instruction
  zasm::Node* GetPos() const { return pos_; }

  template <typename T = zasm::x86::Gp64>
  std::optional<T> GetAvailableRegister() const {
    auto available = GetAvailableRegisters<T>();
    if (available.size() == 0) return std::nullopt;
    return available.front();
  }

  template <typename T = zasm::x86::Gp64>
  std::vector<T> GetAvailableRegisters() const {
    std::vector<T> available;
    if constexpr (std::is_base_of_v<zasm::x86::Gp32, T>) {
      for (const auto& reg : x86::regs32) {
        if ((regs_live_ & mask(reg)) == 0) {
          available.push_back(reg);  // reg is Gp32, matches T
        }
      }
    } else if constexpr (std::is_base_of_v<zasm::x86::Gp64, T>) {
      for (const auto& reg : x86::regs64) {
        if ((regs_live_ & mask(reg)) == 0) {
          available.push_back(reg);  // reg is Gp64, matches T
        }
      }
    }
    return available;
  }

  uint32_t GetLiveFlags() const { return flags_live_; }

  bool CFLive() const { return flags_live_ & zasm::x86::CPUFlags::CF; }

  bool PFLive() const { return flags_live_ & zasm::x86::CPUFlags::PF; }

  bool AFLive() const { return flags_live_ & zasm::x86::CPUFlags::AF; }

  bool ZFLive() const { return flags_live_ & zasm::x86::CPUFlags::ZF; }

  bool SFLive() const { return flags_live_ & zasm::x86::CPUFlags::SF; }

  bool OFLive() const { return flags_live_ & zasm::x86::CPUFlags::OF; }

  /// Returns true if CF, PF, AF, ZF, SF, and OF flags are available to be
  /// overwritten
  /// @return true if available
  bool CommonFlagsAvailable() const {
    return !(CFLive() || PFLive() || AFLive() || ZFLive() || SFLive() ||
             OFLive());
  }

  bool operator<(const X86Inst& other) const {
    return GetAddress() < other.GetAddress();
  }

  X86Inst& operator=(const X86Inst& other) = default;
};

#undef mask

class X86FunctionBuilder {
  zasm::Program program_;
  zasm::x86::Assembler assembler_;
  X86Code* code_;
  bool finished_;

 public:
  X86FunctionBuilder(const TargetArchitecture arch, X86Code* code)
      : program_(arch == TargetArchitecture::I386 ? zasm::MachineMode::I386
                 : arch == TargetArchitecture::AMD64
                     ? zasm::MachineMode::AMD64
                     : zasm::MachineMode::Invalid),
        assembler_(program_),
        code_(code),
        finished_(false) {
    if (!code) throw code_error("function builder must be bound to code");
    assembler_.align(zasm::Align::Type::Code, X86Code::GetFunctionAlignment());
  }

  zasm::x86::Assembler& GetAssembler() { return assembler_; }

  void Finish();
};
}  // namespace stitch

#endif  // STITCH_TARGET_X86_H_