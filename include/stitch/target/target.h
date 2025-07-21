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

#ifndef STITCH_TARGET_TARGET_H_
#define STITCH_TARGET_TARGET_H_

#include "stitch/binary/binary.h"
#include "stitch/utils.h"

namespace stitch {

class Function;
class Inst;
class Operand;

enum class TargetArchitecture {
  Invalid = 0,
  I386,
  AMD64,
  ARM64,
};

class Code {
  Section* scn_;
  const TargetArchitecture kArch;

 public:
  explicit Code(Section* scn, const TargetArchitecture arch)
      : scn_(scn), kArch(arch) {}

  virtual ~Code() = default;

  TargetArchitecture GetArchitecture() const { return kArch; }

  template <typename T = Section>
  T* GetParent() const {
    return dynamic_cast<T*>(scn_);
  }

  virtual Function* EditFunction(VA address, const std::string& in) = 0;

  virtual Function* EditFunction(VA address, const Section& new_scn) = 0;

  virtual Function* RebuildFunction(VA address, const std::string& in) = 0;

  virtual Function* RebuildFunction(VA address, const Section& new_scn) = 0;
};

class Function {
  RVA address_;
  Code* code_;

 protected:
  RVA startAddress() const { return address_; }

  void setAddress(const RVA address) { address_ = address; }

 public:
  explicit Function(const RVA address, Code* code)
      : address_(address), code_(code) {}

  virtual ~Function() = default;

  RVA GetAddress() const { return address_; }

  template <typename T = Code>
  T* GetParent() const {
    return dynamic_cast<T*>(code_);
  }

  virtual void Finish() = 0;
};

class Inst {
  RVA address_;
  Function* function_;
  Binary* binary_;

 protected:
  void setAddress(const RVA address) { address_ = address; }

 public:
  explicit Inst(const RVA address, Function* function)
      : address_(address),
        function_(function),
        binary_(function->GetParent()->GetParent()->GetParent()) {}

  virtual ~Inst() = default;

  void Relocate(const RVA new_loc) const {
    binary_->fixRelocation(address_, new_loc);
  }

  template <typename T = Function>
  T* GetParent() const {
    return dynamic_cast<T*>(function_);
  }

  RVA GetAddress() const { return address_; }
};
}  // namespace stitch

#endif  // STITCH_TARGET_TARGET_H_