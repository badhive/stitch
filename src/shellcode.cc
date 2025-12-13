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

#include "stitch/binary/shellcode.h"

#include <memory>

#include "stitch/target/x86.h"

namespace stitch {
void Shellcode::parse() {
  if (parsed_) return;
  switch (architecture_) {
    case TargetArchitecture::I386:
    case TargetArchitecture::AMD64:
      setCode(std::make_unique<X86Code>(this, architecture_));
      break;
    default:
      throw code_error("invalid architecture");
  }

  file_stream_.seekg(0, std::ios::end);
  const std::streamsize size = file_stream_.tellg();
  file_stream_.seekg(0, std::ios::beg);

  std::vector<uint8_t> data(size);
  if (!file_stream_.read(reinterpret_cast<char*>(data.data()), size)) {
    throw binary_error("could not read shellcode file");
  }
  old_section_ = std::make_unique<SCSection>(0, data, this, true);
  new_section_ = std::make_unique<SCSection>(
      data.size(), std::vector<uint8_t>{}, this, false);
  parsed_ = true;
}

const uint8_t* Shellcode::ReadDataAt(const VA address) const {
  const Section* scn = OpenSectionAt(address);
  if (!scn) return nullptr;
  return scn->GetData().data() + (address - GetImageBase());
}

Section* Shellcode::AddSection(const std::string& name, SectionType type) {
  return new_section_.get();
}

Section* Shellcode::OpenSection(const std::string& name) const {
  return new_section_.get();
}

Section* Shellcode::OpenSectionAt(const VA address) const {
  if (address >= 0 && address < old_section_->GetSize())
    return old_section_.get();
  if (address >= new_section_->GetAddress() &&
      address < new_section_->GetAddress() + new_section_->GetSize())
    return new_section_.get();
  return nullptr;
}

void Shellcode::Save() {
  if (!open_ || !parsed_) return;
  file_stream_.close();
  file_stream_ =
      std::fstream(file_name_, std::ios::in | std::ios::out | std::ios::trunc |
                                   std::ios::binary);
  file_stream_.write(
      reinterpret_cast<const char*>(old_section_->GetData().data()),
      static_cast<uint32_t>(old_section_->GetSize()));
  file_stream_.write(
      reinterpret_cast<const char*>(new_section_->GetData().data()),
      static_cast<uint32_t>(new_section_->GetSize()));
}

void Shellcode::SaveAs(const std::string& file_name) {
  std::ofstream ofs(file_name, std::ios::binary);
  ofs.write(reinterpret_cast<const char*>(old_section_->GetData().data()),
            static_cast<uint32_t>(old_section_->GetSize()));
  ofs.write(reinterpret_cast<const char*>(new_section_->GetData().data()),
            static_cast<uint32_t>(new_section_->GetSize()));
  ofs.close();
}
}  // namespace stitch