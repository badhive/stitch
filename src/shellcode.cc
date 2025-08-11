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
  file_stream_.write(reinterpret_cast<char*>(old_section_->GetData().data()),
                     static_cast<uint32_t>(old_section_->GetSize()));
  file_stream_.write(reinterpret_cast<char*>(new_section_->GetData().data()),
                     static_cast<uint32_t>(new_section_->GetSize()));
}

void Shellcode::SaveAs(const std::string& file_name) {
  std::ofstream ofs(file_name, std::ios::binary);
  ofs.write(reinterpret_cast<char*>(old_section_->GetData().data()),
            static_cast<uint32_t>(old_section_->GetSize()));
  ofs.write(reinterpret_cast<char*>(new_section_->GetData().data()),
          static_cast<uint32_t>(new_section_->GetSize()));
  ofs.close();
}
}  // namespace stitch