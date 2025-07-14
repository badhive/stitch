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

#ifndef STITCH_BINARY_BINARY_H_
#define STITCH_BINARY_BINARY_H_

#include <fstream>
#include <vector>

#include "stitch/errors.h"
#include "stitch/utils.h"

namespace stitch {
class Binary;
class Code;
class Section;

enum class SectionType {
  Code,
  Data,
  ROData,
  BSS,
};

class GlobalRef {
  VA value_;

public:
  GlobalRef() : value_(0) {
  }

  explicit GlobalRef(const VA value) : value_(value) {
  }

  void SetValue(const VA value) { value_ = value; }

  void AdjustValue(const VA delta) { value_ += delta; }

  VA GetValue() const { return value_; }
};

class Binary {
public:
  explicit Binary() : open_(false), opened_(false) {
  }

  explicit Binary(const std::string& file_name) : open_(false), opened_(false) {
    Binary::Open(file_name);
  }

  virtual ~Binary() = default;

  virtual VA GetImageBase() const = 0;

  virtual RVA GetEntrypoint() const = 0;

  virtual void Open(const std::string& file_name) {
    if (opened_)
      throw std::runtime_error("object cannot be re-opened");
    file_stream_ = std::fstream(file_name,
                                std::ios::in
                                | std::ios::out
                                | std::ios::binary);
    file_name_ = file_name;
    open_ = opened_ = true;
  }

  virtual Section* OpenSection(const std::string& name) = 0;

  virtual Section* AddSection(const std::string& name, SectionType type) = 0;

  virtual Code* OpenCodeSection(const std::string& name) = 0;

  virtual void Save() = 0;

  virtual void SaveAs(const std::string& file_name) = 0;

  void Close() {
    if (!open_)
      throw std::runtime_error("object cannot be closed");
    file_stream_.close();
    open_ = false;
  }

  void SaveAndClose() {
    Save();
    Close();
  }

  virtual void fixRelocation(RVA old_loc, RVA new_loc) = 0;

protected:
  std::string file_name_;
  std::fstream file_stream_;
  bool open_;

private:
  bool opened_;
};

class Section {
  std::string name_;
  Binary* parent_;
  std::unique_ptr<Code> code_;
  std::vector<uint8_t> data_;
  const bool existed_;
  SectionType type_;
  std::vector<std::unique_ptr<GlobalRef>> refs_;

public:
  Section(
      const std::string& name,
      const SectionType type,
      const std::vector<uint8_t>& data,
      Binary* parent,
      const bool existed
      ) :
    name_(name), parent_(parent), code_(nullptr), data_(data),
    existed_(existed), type_(type) {
  }

  virtual ~Section() = default;

  Section(Section&&) = default;

  const std::string& GetName() const {
    return name_;
  }

  SectionType GetType() const {
    return type_;
  }

  Binary* GetParent() const {
    return parent_;
  }

  std::vector<uint8_t>& GetData() {
    return data_;
  }

  virtual RVA GetAddress() = 0;

  virtual void Relocate(const int64_t delta) {
    for (const auto& ref : refs_) {
      ref->AdjustValue(delta);
    }
  }

  uint64_t GetSize() const {
    return data_.size();
  }

  bool OnDisk() const {
    return existed_;
  }

  void Write(const std::vector<char>& data) {
    const std::vector<uint8_t> v(data.begin(), data.end());
    Write(v);
  }

  void Write(const std::vector<int8_t>& data) {
    const std::vector<uint8_t> v(data.begin(), data.end());
    Write(v);
  }

  void Write(const std::string& str) {
    const std::vector v(
        reinterpret_cast<const uint8_t*>(str.c_str()),
        reinterpret_cast<const uint8_t*>(str.c_str()) + str.length() + 1);
    Write(v);
  }

  void Write(const std::wstring& str) {
    const std::vector v(
        reinterpret_cast<const uint8_t*>(str.c_str()),
        reinterpret_cast<const uint8_t*>(str.c_str()) + (str.length() + 1) *
        sizeof(wchar_t));
    Write(v);
  }

  void Write(const uint8_t* data, const uint64_t size) {
    const std::vector v(data, data + size);
    Write(v);
  }

  void Write(const char* str, const uint64_t size) {
    const std::vector<uint8_t> v(str, str + size);
    Write(v);
  }

  /// Writes data to section and returns a dynamic reference to that
  /// data. Classes implementing Section are responsible for
  /// calling Section::Relocate in their own Relocate function to update these refs
  /// if the section is moved
  /// @param args Write() args
  /// @return pointer to GlobalRef
  template <typename... Args>
  const GlobalRef* WriteWithRef(Args&&... args) {
    auto ref = std::make_unique<GlobalRef>(
        GetParent()->GetImageBase() + GetAddress() + GetSize()
        );
    Write(std::forward<Args>(args)...);
    refs_.push_back(std::move(ref));
    return refs_.back().get();
  }

  virtual void Write(const std::vector<uint8_t>& data) = 0;

  void Memset(const RVA address, const uint8_t val, const size_t count) {
    if (address > GetSize())
      throw section_error("address out of range");
    if (address + count > GetSize())
      throw section_error("writing out of range");
    for (RVA i = address; i < address + count; i++) {
      data_[i] = val;
    }
  }

  void WriteAt(const RVA address, const uint8_t* data, const size_t size) {
    const std::vector buf(data, data + size);
    WriteAt(address, buf);
  }

  void WriteAt(const RVA address, const std::vector<uint8_t>& data) {
    if (address > GetSize())
      throw section_error("address out of range");
    if (address + data.size() > GetSize())
      throw section_error("writing out of range");
    for (RVA i = address; i < address + data.size(); i++) {
      data_[i] = data[i - address];
    }
  }

protected:
  void setCode(std::unique_ptr<Code> code) {
    if (type_ != SectionType::Code) {
      throw unsupported_section_type_error(name_);
    }
    code_ = std::move(code);
  }

  virtual void setData(const std::vector<uint8_t>& data) {
    if (data.size() != data_.size())
      throw std::runtime_error("new data must be the same size as old data");
    data_ = data;
  }

  Code* getCode() const {
    if (type_ != SectionType::Code)
      throw unsupported_section_type_error(name_);
    return code_.get();
  }
};
}
#endif //STITCH_BINARY_BINARY_H_