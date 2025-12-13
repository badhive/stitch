/*
 * Licensed to BadHive under one or more contributor license
 * agreements.  See the NOTICE file distributed with this work
 * for additional information regarding copyright ownership.
 * BadHive licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file
 * except in compliance with the License.  You may obtain a
 * copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

#ifndef STITCH_TARGET_TARGET_H_
#define STITCH_TARGET_TARGET_H_

#include "stitch/binary/binary.h"
#include "stitch/misc/utils.h"

namespace stitch {

class Function;
class Inst;
class Operand;

constexpr bool is_little_endian = std::endian::native == std::endian::little;

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
  Inst* entry_point_;

 protected:
  VA startAddress() const { return address_; }

  void setAddress(const VA address) { address_ = address; }

  void setSize(const VA size) { size_ = size; }

 public:
  explicit Function(const VA address, Code* code)
      : address_(address), size_(0), code_(code), entry_point_(nullptr) {}

  virtual ~Function() = default;

  VA GetAddress() const { return address_; }

  VA GetSize() const { return size_; }

  template <typename T = Code>
  T* GetParent() const {
    return dynamic_cast<T*>(code_);
  }

  virtual const GlobalRef* Finish() = 0;

  void StartEdit(const std::string& in) const {
    code_->EditFunction(address_, in);
  }

  void StartEdit(const Section& in) const { code_->EditFunction(address_, in); }
};

class BasicBlock {
  VA address_;
  int64_t size_;
  const BasicBlock* fallthrough_;

 protected:
  void setFallthrough(const BasicBlock* bb) { fallthrough_ = bb; }

 public:
  BasicBlock(const VA address, const int64_t size,
             const BasicBlock* fallthrough = nullptr)
      : address_(address), size_(size), fallthrough_(fallthrough) {}

  VA GetAddress() const { return address_; }

  int64_t GetSize() const { return size_; }

  void SetSize(const int64_t size) { size_ = size; }

  template <typename T = BasicBlock>
  const T* GetFallthroughParent() const {
    return dynamic_cast<const T*>(fallthrough_);
  }
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

class JumpTable32 {
  const bool le_;
  std::vector<uint32_t> handlers_;

  static uint32_t byteSwap(const uint32_t v) {
    uint32_t out{};
    auto* dst = reinterpret_cast<unsigned char*>(&out);
    auto* src = reinterpret_cast<const unsigned char*>(&v);
    for (size_t i = 0; i < sizeof(uint32_t); ++i)
      dst[i] = src[sizeof(uint32_t) - 1 - i];
    return out;
  }

  void normalize() {
    if (le_ == is_little_endian) return;
    for (auto& h : handlers_) h = byteSwap(h);
  }

 public:
  explicit JumpTable32(const bool le = true) : le_(le) {}

  uint64_t RegisterHandler(const uint32_t address) {
    handlers_.push_back(address);
    return handlers_.size() - 1;
  }

  uint64_t GetSize() const { return handlers_.size() * sizeof(uint32_t); }

  template <typename T = uint32_t*>
  T Get() {
    normalize();
    return reinterpret_cast<T>(handlers_.data());
  }
};

class JumpTable64 {
  const bool le_;
  std::vector<uint64_t> handlers_;

  static uint64_t byteSwap(const uint64_t v) {
    uint64_t out{};
    auto* dst = reinterpret_cast<unsigned char*>(&out);
    auto* src = reinterpret_cast<const unsigned char*>(&v);
    for (size_t i = 0; i < sizeof(uint64_t); ++i)
      dst[i] = src[sizeof(uint64_t) - 1 - i];
    return out;
  }

  void normalize() {
    std::sort(handlers_.begin(), handlers_.end());
    if (le_ == is_little_endian) return;
    for (auto& h : handlers_) h = byteSwap(h);
  }

 public:
  explicit JumpTable64(const bool le = true) : le_(le) {}

  uint64_t RegisterHandler(const uint64_t address) {
    handlers_.push_back(address);
    return handlers_.size() - 1;
  }

  void UpdateHandler(const uint64_t id, const uint64_t new_value) {
    if (handlers_.size() <= id) throw code_error("invalid handler id");
    handlers_[id] = new_value;
  }

  uint64_t GetSize() const { return handlers_.size() * sizeof(uint64_t); }

  template <typename T = uint64_t>
  T* Get() {
    normalize();
    return reinterpret_cast<T*>(handlers_.data());
  }
};
}  // namespace stitch

#endif  // STITCH_TARGET_TARGET_H_