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

#ifndef STITCH_BINARY_SHELLCODE_H_
#define STITCH_BINARY_SHELLCODE_H_

#include <memory>

#include "stitch/binary/binary.h"
#include "stitch/target/target.h"

namespace stitch {
class SCSection final : public Section {
  RVA address_;

 public:
  explicit SCSection(const RVA address, const std::vector<uint8_t>& data,
                     Binary* parent, const bool existed)
      : Section("", SectionType::Code, data, parent, existed),
        address_(address) {}

  RVA GetAddress() const override { return address_; }

  void Write(const std::vector<uint8_t>& data) override {
    GetData().insert(GetData().end(), data.begin(), data.end());
  }
};

class Shellcode final : public Binary {
  const TargetArchitecture architecture_;
  std::unique_ptr<SCSection> old_section_;
  std::unique_ptr<SCSection> new_section_;
  bool parsed_;

  void parse();

 public:
  Shellcode(const TargetArchitecture arch, const Platform platform)
      : Binary(platform), architecture_(arch), parsed_(false) {}

  Shellcode(const std::string& file_name, const TargetArchitecture arch,
            const Platform platform, const bool no_analyze = false)
      : Binary(file_name, platform), architecture_(arch), parsed_(false) {
    Shellcode::Open(file_name);
    if (!no_analyze) OpenCode()->AnalyzeFrom(0);
  }

  void Open(const std::string& file_name) override {
    Binary::Open(file_name);
    parse();
  }

  Section* AddSection(const std::string& name, SectionType type) override;

  Section* OpenSection(const std::string& name) const override;

  Section* OpenSectionAt(VA address) const override;

  VA GetImageBase() const override { return 0; }

  VA GetEntrypoint() const override { return 0; }

  void Save() override;

  void SaveAs(const std::string& file_name) override;
};
}  // namespace stitch
#endif  // STITCH_BINARY_SHELLCODE_H_