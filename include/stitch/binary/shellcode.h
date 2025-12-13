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
    getData().insert(GetData().end(), data.begin(), data.end());
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

  const uint8_t* ReadDataAt(VA address) const override;

  Section* AddSection(const std::string& name, SectionType type) override;

  Section* OpenSection(const std::string& name) const override;

  Section* OpenSectionAt(VA address) const override;

  VA GetImageBase() const override { return 0; }

  VA GetEntrypoint() const override { return 0; }

  void Save() override;

  void SaveAs(const std::string& file_name) override;

  char GetBitSize() const override {
    return architecture_ == TargetArchitecture::I386 ? 32 : 64;
  }

  std::string GetImportForAddress(VA address) const override { return ""; }

  VA GetAddressForImport(const std::string& import) const override { return 0; }
};
}  // namespace stitch
#endif  // STITCH_BINARY_SHELLCODE_H_