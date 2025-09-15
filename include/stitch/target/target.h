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

#include "stitch/misc/utils.h"
#include "stitch/binary/binary.h"

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
  Binary* binary_;
  const TargetArchitecture kArch;

 public:
  explicit Code(Binary* binary, const TargetArchitecture arch)
      : binary_(binary), kArch(arch) {}

  virtual ~Code() = default;

  TargetArchitecture GetArchitecture() const { return kArch; }

  template <typename T = Binary>
  T* GetParent() const {
    return dynamic_cast<T*>(binary_);
  }

  virtual void AnalyzeFrom(VA address) = 0;

  virtual Function* CreateFunction(const std::string& in) = 0;

  virtual Function* CreateFunction(const Section& new_scn) = 0;

  virtual Function* EditFunction(VA address, const std::string& in) = 0;

  virtual Function* EditFunction(VA address, const Section& new_scn) = 0;

  virtual Function* RebuildFunction(VA address, const std::string& in) = 0;

  virtual Function* RebuildFunction(VA address, const Section& new_scn) = 0;
};

class Function {
  VA address_;
  int64_t size_;
  Code* code_;

 protected:
  VA startAddress() const { return address_; }

  void setAddress(const VA address) { address_ = address; }

  void setSize(const VA size) { size_ = size; }

 public:
  explicit Function(const VA address, Code* code)
      : address_(address), size_(0), code_(code) {}

  virtual ~Function() = default;

  VA GetAddress() const { return address_; }

  VA GetSize() const { return size_; }

  template <typename T = Code>
  T* GetParent() const {
    return dynamic_cast<T*>(code_);
  }

  virtual const GlobalRef* Finish() = 0;
};

class Inst {
  VA address_;
  Function* function_;
  Binary* binary_;

 protected:
  void setAddress(const VA address) { address_ = address; }

 public:
  explicit Inst(const VA address, Function* function)
      : address_(address),
        function_(function),
        binary_(function->GetParent()->GetParent()) {}

  virtual ~Inst() = default;

  template <typename T = Function>
  T* GetParent() const {
    return dynamic_cast<T*>(function_);
  }

  VA GetAddress() const { return address_; }
};
}  // namespace stitch

#endif  // STITCH_TARGET_TARGET_H_