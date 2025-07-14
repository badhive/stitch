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

#include "stitch/binary/pe.h"

#include <iostream>

#include "stitch/errors.h"
#include "stitch/target/x86.h"

namespace stitch {
void PEFormat::Parse(std::fstream& stream, PEFormat& format) {
  using namespace pe;
  stream.exceptions(std::ifstream::failbit | std::ifstream::badbit);

  stream.read(reinterpret_cast<char*>(&format.dos_header),
              sizeof(format.dos_header));
  if (format.dos_header.e_magic != IMAGE_DOS_SIGNATURE) {
    throw invalid_binary_format_error();
  }

  const auto curr = stream.tellg();
  const auto stub_size = format.dos_header.e_lfanew - curr;
  format.dos_stub.resize(stub_size);
  stream.read(format.dos_stub.data(), stub_size);

  // check signature
  stream.seekg(format.dos_header.e_lfanew);
  stream.read(reinterpret_cast<char*>(&format.nt_headers32.Signature),
              sizeof(format.nt_headers32.Signature));
  if (format.nt_headers32.Signature != IMAGE_NT_SIGNATURE) {
    throw invalid_binary_format_error();
  }

  // read file header and optional header magic
  stream.read(reinterpret_cast<char*>(&format.nt_headers32.FileHeader),
              sizeof(format.nt_headers32.FileHeader));

  switch (format.nt_headers32.FileHeader.Machine) {
    case IMAGE_FILE_MACHINE_AMD64:
      format.architecture = TargetArchitecture::AMD64;
      break;
    case IMAGE_FILE_MACHINE_I386:
      format.architecture = TargetArchitecture::I386;
      break;
    case IMAGE_FILE_MACHINE_ARM64:
      format.architecture = TargetArchitecture::ARM64;
      break;
    default:
      break;
  }

  stream.read(
      reinterpret_cast<char*>(&format.nt_headers32.OptionalHeader.Magic),
      sizeof(format.nt_headers32.OptionalHeader.Magic));

  // read the rest of the optional header depending on architecture
  if (format.Is64Bit()) {
    stream.read(
        reinterpret_cast<char*>(&format.nt_headers64.OptionalHeader.
                                        MajorLinkerVersion),
        sizeof(format.nt_headers64.OptionalHeader) - sizeof(format.nt_headers64.
          OptionalHeader
          .Magic));
  } else if (format.Is32Bit()) {
    stream.read(
        reinterpret_cast<char*>(&format.nt_headers32.OptionalHeader.
                                        MajorLinkerVersion),
        sizeof(format.nt_headers32.OptionalHeader) - sizeof(format.nt_headers32.
          OptionalHeader
          .Magic));
  } else {
    throw invalid_binary_format_error();
  }

  for (WORD i = 0; i < format.nt_headers32.FileHeader.NumberOfSections; ++
       i) {
    // sections come right after NT header
    SectionHeader section_header = {};
    stream.read(reinterpret_cast<char*>(&section_header),
                sizeof(section_header));
    const auto nextHeader = stream.tellg();

    std::vector<uint8_t> section_data(section_header.SizeOfRawData);

    stream.seekg(section_header.PointerToRawData);
    stream.read(reinterpret_cast<char*>(section_data.data()),
                section_header.SizeOfRawData);

    format.sections.emplace_back(section_header, section_data);
    stream.seekg(nextHeader);
  }

  const NtDataDirectory* cert_table = nullptr;
  if (format.Is32Bit())
    cert_table = &format.nt_headers32.OptionalHeader.DataDirectory[
      IMAGE_DIRECTORY_ENTRY_SECURITY];
  else if (format.Is64Bit())
    cert_table = &format.nt_headers64.OptionalHeader.DataDirectory[
      IMAGE_DIRECTORY_ENTRY_SECURITY];
  if (cert_table && cert_table->VirtualAddress) {
    stream.seekg(cert_table->VirtualAddress);
    stream.read(format.cert_table.data(), cert_table->Size);
  }
}

bool PEFormat::Is64Bit() const {
  return nt_headers32.OptionalHeader.Magic ==
         pe::IMAGE_NT_OPTIONAL_HDR64_MAGIC;
}

bool PEFormat::Is32Bit() const {
  return nt_headers32.OptionalHeader.Magic ==
         pe::IMAGE_NT_OPTIONAL_HDR32_MAGIC;
}

pe::DWORD PEFormat::Entrypoint() const {
  if (Is32Bit())
    return nt_headers32.OptionalHeader.AddressOfEntryPoint;
  if (Is64Bit())
    return nt_headers64.OptionalHeader.AddressOfEntryPoint;
  return 0;
}

pe::ULONGLONG PEFormat::ImageBase() const {
  if (Is32Bit())
    return nt_headers32.OptionalHeader.ImageBase;
  if (Is64Bit())
    return nt_headers64.OptionalHeader.ImageBase;
  return 0;
}

pe::DWORD PEFormat::FileAlignment() const {
  if (Is32Bit())
    return nt_headers32.OptionalHeader.FileAlignment;
  if (Is64Bit())
    return nt_headers64.OptionalHeader.FileAlignment;
  return 0;
}

pe::DWORD PEFormat::SectionAlignment() const {
  if (Is32Bit())
    return nt_headers32.OptionalHeader.SectionAlignment;
  if (Is64Bit())
    return nt_headers64.OptionalHeader.SectionAlignment;
  return 0;
}

pe::DWORD& PEFormat::SizeOfHeaders() {
  if (Is64Bit())
    return nt_headers64.OptionalHeader.SizeOfHeaders;
  return nt_headers32.OptionalHeader.SizeOfHeaders;
}

pe::DWORD& PEFormat::SizeOfImage() {
  if (Is64Bit())
    return nt_headers64.OptionalHeader.SizeOfImage;
  return nt_headers32.OptionalHeader.SizeOfImage;
}

pe::DWORD& PEFormat::SizeOfInitializedData() {
  if (Is64Bit())
    return nt_headers64.OptionalHeader.SizeOfInitializedData;
  return nt_headers32.OptionalHeader.SizeOfInitializedData;
}

pe::DWORD& PEFormat::SizeOfUninitializedData() {
  if (Is64Bit())
    return nt_headers64.OptionalHeader.SizeOfUninitializedData;
  return nt_headers32.OptionalHeader.SizeOfUninitializedData;
}

pe::DWORD& PEFormat::SizeOfCode() {
  if (Is64Bit())
    return nt_headers64.OptionalHeader.SizeOfCode;
  return nt_headers32.OptionalHeader.SizeOfCode;
}

pe::NtDataDirectory& PEFormat::DataDirectory(const char id) {
  if (Is64Bit())
    return nt_headers64.OptionalHeader.DataDirectory[id];
  return nt_headers32.OptionalHeader.DataDirectory[id];
}

const PESectionInfo& PEFormat::GetSectionInfo(const std::string& name) {
  for (auto& scn : sections) {
    if (name == scn.header.Name)
      return scn;
  }
  throw section_not_found_error(name);
}

unsigned PESection::Characteristics() const {
  return si_.header.Characteristics;
}

void PESection::SetCharacteristics(const unsigned ch) {
  si_.header.Characteristics = ch;
}

void PESection::Write(const std::vector<uint8_t>& data) {
  std::vector<uint8_t>& m_data = GetData();

  growRaw(static_cast<int64_t>(m_data.size()),
          static_cast<int64_t>(data.size()));
  growVirtual(static_cast<int64_t>(m_data.size()),
              static_cast<int64_t>(data.size()));

  m_data.insert(m_data.end(), data.begin(), data.end());
}

void PESection::growRaw(const int64_t old, const int64_t amount) const {
  if (auto* pe = dynamic_cast<PE*>(GetParent())) {
    const int64_t free_space = si_.header.SizeOfRawData
                               - static_cast<int64_t>(old);
    if (free_space < old + amount) {
      pe->growSectionRawSize(GetName(), amount - free_space);
    }
  }
}

void PESection::growVirtual(const int64_t old, const int64_t amount) const {
  if (auto* pe = dynamic_cast<PE*>(GetParent())) {
    pe->growSectionVirtualSize(GetName(), old, amount);
  }
}

void PE::Open(const std::string& file_name) {
  Binary::Open(file_name);
  parse();
}

void PE::parse() {
  using namespace pe;
  if (!open_ || parsed_)
    return;
  sections_.reserve(max_sections_);
  PEFormat::Parse(file_stream_, file_mapping_);
  for (const auto& si : file_mapping_.sections) {
    SectionType type = (si.header.Characteristics & code_flags) == code_flags
                         ? SectionType::Code
                         : (si.header.Characteristics & data_flags) ==
                           data_flags
                         ? SectionType::Data
                         : (si.header.Characteristics & bss_flags) ==
                           bss_flags
                         ? SectionType::BSS
                         : SectionType::ROData;

    if (sections_.size() >= max_sections_)
      throw section_error("max number of sections has been reached");
    auto scn = std::make_unique<PESection>(si, type, si.data, this, true);
    if (type == SectionType::Code) {
      if (const TargetArchitecture arch = file_mapping_.architecture;
        arch == TargetArchitecture::I386 ||
        arch == TargetArchitecture::AMD64) {
        auto code_container = std::make_unique<X86Code>(scn.get(), arch);
        scn->setCodeContainer(std::move(code_container));
      }
    }
    sections_.push_back(std::move(scn));
  }
  parseRelocations();
  // the sections as read from disk will no longer be used
  file_mapping_.sections.clear();
  parsed_ = true;
}

PESection* PE::findRelocations() {
  using namespace pe;
  const NtDataDirectory& reloc_dir = file_mapping_.DataDirectory(
      IMAGE_DIRECTORY_ENTRY_BASERELOC);
  if (reloc_dir.VirtualAddress == 0 || reloc_dir.Size == 0)
    return nullptr;
  for (const auto& section : sections_) {
    const uint64_t scn_size = section->GetSize();
    if (section->GetAddress() >= reloc_dir.VirtualAddress &&
        reloc_dir.VirtualAddress < section->GetAddress() + scn_size) {
      return section.get();
    }
  }
  return nullptr;
}

void PE::parseRelocations() {
  using namespace pe;
  const NtDataDirectory& reloc_dir = file_mapping_.DataDirectory(
      IMAGE_DIRECTORY_ENTRY_BASERELOC);
  if (reloc_dir.VirtualAddress == 0 || reloc_dir.Size == 0)
    return;
  PESection* section = findRelocations();
  if (section == nullptr)
    return;
  // not entirely sure if reloc entries start at the very beginning of the section
  const uint64_t disp = reloc_dir.VirtualAddress - section->GetAddress();
  uint8_t* p_reloc = section->GetData().data();
  void* data = p_reloc + disp;
  FullBaseRelocation full_reloc;
  auto* base_reloc = static_cast<BaseRelocation*>(data);
  // make sure we're still parsing within .reloc
  while (base_reloc->VirtualAddress != 0 && base_reloc->SizeOfBlock != 0) {
    full_reloc.Base = *base_reloc;
    auto* entry = reinterpret_cast<BaseRelocationEntry*>(base_reloc + 1);
    // parse until entry points to end of block
    while (entry != reinterpret_cast<BaseRelocationEntry*>(
             reinterpret_cast<char*>(base_reloc)
             + base_reloc->SizeOfBlock)) {
      full_reloc.Entries.push_back(*entry);
      entry++;
    }
    file_mapping_.relocations.push_back(std::move(full_reloc));
    base_reloc = reinterpret_cast<BaseRelocation*>(entry);
  }
}

RVA PE::GetImageBase() const {
  return static_cast<RVA>(file_mapping_.ImageBase());
}

RVA PE::GetEntrypoint() const {
  return file_mapping_.Entrypoint();
}

Code* PE::OpenCodeSection(const std::string& name) {
  for (const auto& scn : sections_) {
    if (scn->GetName() == name) {
      if (!scn->OnDisk())
        throw section_not_found_error(name);
      return scn->getCodeContainer(); // throw if not code
    }
  }
  // (somehow?) section has been deleted
  throw section_not_found_error(name);
}

Section* PE::OpenSection(const std::string& name) {
  for (const auto& scn : sections_) {
    if (scn->GetName() == name)
      return scn.get();
  }
  throw section_not_found_error(name);
}

Section* PE::AddSection(const std::string& name, const SectionType type) {
  using namespace stitch::pe;
  if (name.length() > 7)
    throw invalid_section_name_error();
  for (const auto& scn : sections_) {
    if (scn->GetName() == name) {
      throw section_exists_error();
    }
  }
  PESectionInfo si{};
  name.copy(si.header.Name, sizeof(si.header.Name) - 1);
  if (type == SectionType::Code) {
    si.header.Characteristics =
        IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE;
  } else if (type == SectionType::Data) {
    si.header.Characteristics =
        IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ |
        IMAGE_SCN_MEM_WRITE;
  } else if (type == SectionType::ROData) {
    si.header.Characteristics =
        IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ;
  } else if (type == SectionType::BSS) {
    throw section_error("multiple bss-like sections are not supported");
  }
  addSectionHeader();
  si.header.VirtualAddress = getNewSectionRVA();
  si.header.PointerToRawData = getNewSectionRawPointer();
  file_mapping_.nt_headers32.FileHeader.NumberOfSections++;
  auto scn = std::make_unique<PESection>(si,
                                         type,
                                         std::vector<uint8_t>{},
                                         this);
  if (type == SectionType::Code) {
    auto code_container = std::make_unique<X86Code>(scn.get(),
                                                    file_mapping_.architecture);
    scn->setCodeContainer(std::move(code_container));
  }
  sections_.push_back(std::move(scn));
  return sections_.back().get();
}

/// PointerToRawData for each header field must be updated to fit the new
/// space within the header. This field must be a multiple of FileAlignment
/// as per the docs. Align this and update each PointerToRawData accordingly.
/// https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_section_header
void PE::addSectionHeader() {
  constexpr unsigned size = sizeof(pe::SectionHeader);
  using namespace stitch::pe;
  const DWORD file_alignment = file_mapping_.FileAlignment();

  // calculate new header size
  DWORD size_old_sec_headers_align = sections_.size() * size;
  size_old_sec_headers_align = utils::RoundToBoundary(
      size_old_sec_headers_align, file_alignment);

  DWORD size_new_sec_headers_align = (sections_.size() + 1) * size;
  size_new_sec_headers_align = utils::RoundToBoundary(
      size_new_sec_headers_align, file_alignment);

  const DWORD new_offset = size_new_sec_headers_align -
                           size_old_sec_headers_align;
  if (new_offset != 0) {
    for (const auto& section : sections_) {
      section->GetSectionInfo().header.PointerToRawData += new_offset;
    }
  }
  if (NtDataDirectory* ct = getCertTable()) {
    ct->VirtualAddress += new_offset;
  }
  const uint64_t old_v_size_headers = utils::RoundToBoundary(
      file_mapping_.SizeOfHeaders(), file_mapping_.SectionAlignment());

  file_mapping_.SizeOfHeaders() = file_mapping_.SizeOfHeaders()
                                  - size_old_sec_headers_align
                                  + size_new_sec_headers_align;

  const DWORD v_size_headers = utils::RoundToBoundary(
      file_mapping_.SizeOfHeaders(), file_mapping_.SectionAlignment());
  file_mapping_.SizeOfImage() = file_mapping_.SizeOfImage()
                                - old_v_size_headers
                                + v_size_headers;
}

RVA PE::getNewSectionRVA() {
  RVA largest_rva = 0;
  pe::DWORD largest_vsize = 0;
  for (const auto& section : sections_) {
    const PESectionInfo& si = section->GetSectionInfo();
    if (si.header.VirtualAddress > largest_rva) {
      largest_rva = si.header.VirtualAddress;
      largest_vsize = si.header.Misc.VirtualSize;
    }
  }
  const RVA section_alignment = file_mapping_.SectionAlignment();
  const RVA size_of_headers = file_mapping_.SizeOfHeaders();

  // if no sections present
  if (largest_rva == 0)
    return utils::RoundToBoundary(size_of_headers, section_alignment);

  // new section comes right after section loaded at the highest memory address
  return utils::RoundToBoundary(largest_rva + largest_vsize, section_alignment);
}

RVA PE::getNewSectionRawPointer() {
  RVA largest_offset = 0;
  pe::DWORD largest_size = 0;
  for (const auto& section : sections_) {
    const PESectionInfo& si = section->GetSectionInfo();
    if (si.header.PointerToRawData > largest_offset) {
      largest_offset = si.header.PointerToRawData;
      largest_size = si.header.SizeOfRawData;
    }
  }
  const RVA file_alignment = file_mapping_.FileAlignment();
  const RVA size_of_headers = file_mapping_.SizeOfHeaders();

  if (largest_offset == 0) {
    return utils::RoundToBoundary(size_of_headers, file_alignment);
  }
  if (largest_size == 0) {
    return largest_offset; // always aligned
  }
  return utils::RoundToBoundary(largest_offset + largest_size, file_alignment);
}

// Adjusts the raw data pointer sections following the resized section.
void PE::growSectionRawSize(const std::string& section_name,
                            const int64_t amount) {
  // Round up growth size to FileAlignment
  const int64_t new_amount = utils::RoundToBoundary(
      amount, static_cast<int64_t>(file_mapping_.FileAlignment()));
  if (new_amount == 0)
    return;
  bool resize = false;
  SectionType ty = {};
  for (const auto& section : sections_) {
    if (section->GetName() == section_name) {
      section->GetSectionInfo().header.SizeOfRawData += new_amount;
      ty = section->GetType();
      resize = true;
      continue;
    }
    PESectionInfo& si = section->GetSectionInfo();
    // only adjust pointers for sections after adjusted section
    if (resize && si.header.PointerToRawData > 0) {
      si.header.PointerToRawData += new_amount;
    }
  }
  if (ty == SectionType::Code) {
    file_mapping_.SizeOfCode() += amount;
  } else if (ty == SectionType::Data || ty == SectionType::ROData) {
    file_mapping_.SizeOfInitializedData() += amount;
  }
  // adjust cert table position if present
  if (pe::NtDataDirectory* cert_table = getCertTable())
    cert_table->VirtualAddress += new_amount;
}

void PE::growSectionVirtualSize(const std::string& section_name,
                                const int64_t old,
                                const int64_t amount) {
  int pos = 0;
  bool found = false;
  const int64_t new_size = old + amount;
  PESection* s = nullptr;
  for (const auto& section : sections_) {
    pos++;
    if (section->GetName() == section_name) {
      s = section.get();
      found = true;
      break;
    }
  }
  if (!found) return;

  // round new section size to SectionAlignment and use for SizeOfImage.
  // if section didn't grow up to SectionAlignment, SizeOfImage doesn't change
  const int64_t old_v_size = utils::RoundToBoundary(
      old, static_cast<uint64_t>(file_mapping_.SectionAlignment())
      );

  const int64_t new_v_size = utils::RoundToBoundary(
      new_size, static_cast<uint64_t>(file_mapping_.SectionAlignment())
      );
  file_mapping_.SizeOfImage() = file_mapping_.SizeOfImage() - old_v_size +
                                new_v_size;

  // update virtual addresses for following sections
  if (new_v_size > old_v_size) {
    for (auto i = sections_.begin() + pos; i != sections_.end(); ++i) {
      (*i)->Relocate(new_v_size - old_v_size);
    }
  }
  s->GetSectionInfo().header.Misc.VirtualSize = new_size;
  if (s->GetType() == SectionType::BSS) {
    file_mapping_.SizeOfUninitializedData() += amount;
  }
}

pe::NtDataDirectory* PE::getCertTable() {
  using namespace stitch::pe;
  if (file_mapping_.cert_table.empty())
    return nullptr;
  NtDataDirectory* cert_table = file_mapping_.Is32Bit()
                                  ? &file_mapping_.nt_headers32.OptionalHeader.
                                                   DataDirectory[
                                    IMAGE_DIRECTORY_ENTRY_SECURITY]
                                  : &file_mapping_.nt_headers64.OptionalHeader.
                                                   DataDirectory[
                                    IMAGE_DIRECTORY_ENTRY_SECURITY];
  return cert_table;
}

void PE::fixRelocation(const VA old_loc, const VA new_loc) {
  using namespace pe;
  const RVA old_loc_rva = old_loc - GetImageBase();
  bool fixed = false;
  for (auto it = file_mapping_.relocations.begin();
       it != file_mapping_.relocations.end();
       ++it) {
    // search in block with address range that old_loc would be in
    FullBaseRelocation& reloc_block = *it;
    if (old_loc_rva >= reloc_block.Base.VirtualAddress
        &&
        old_loc_rva < reloc_block.Base.VirtualAddress + 0x1000) {
      for (BaseRelocationEntry& entry : reloc_block.Entries) {
        const RVA move_delta = new_loc - old_loc;

        // if we find an entry for old_loc
        if (GetImageBase() + reloc_block.Base.VirtualAddress + entry.Offset
            == old_loc) {
          const RVA new_patch_loc = reloc_block.Base.VirtualAddress
                                    + entry.Offset
                                    + move_delta;
          // if new loc falls outside this current block, then add relocation
          // in the appropriate block
          if (new_patch_loc < reloc_block.Base.VirtualAddress ||
              new_patch_loc >= reloc_block.Base.VirtualAddress + 0x1000) {
            // entry needs moving, SizeOfBlock has changed
            reloc_block.Base.SizeOfBlock -= sizeof(BaseRelocationEntry);
            addRelocation(new_patch_loc, entry.Type);
            file_mapping_.relocations.erase(it);
            fixed = true;
            break;
          }
          // if new lock exists in current block then update the existing entry
          entry.Offset += move_delta;
          fixed = true;
          break;
        }
      }
      if (fixed) {
        rebuildRelocations();
        return;
      }
    }
  }
}

// only called from fixupRelocation. total size of reloc section should not change at all
void PE::addRelocation(const RVA loc, const uint16_t type) {
  using namespace pe;
  for (FullBaseRelocation& reloc_block : file_mapping_.relocations) {
    // find which block to add new relocation to
    if (loc >= reloc_block.Base.VirtualAddress
        &&
        loc < reloc_block.Base.VirtualAddress + 0x1000) {
      reloc_block.Base.SizeOfBlock += sizeof(BaseRelocationEntry);
      reloc_block.Entries.emplace_back(loc - reloc_block.Base.VirtualAddress,
                                       type);
    }
  }
}

void PE::rebuildRelocations() {
  using namespace pe;
  PESection* relocations = findRelocations();
  if (relocations == nullptr) {
    return;
  }
  std::vector<uint8_t> new_data;
  for (FullBaseRelocation& reloc_block : file_mapping_.relocations) {
    new_data.insert(
        new_data.end(),
        reinterpret_cast<uint8_t*>(&reloc_block.Base),
        reinterpret_cast<uint8_t*>(&reloc_block.Base) + sizeof(BaseRelocation)
        );
    for (BaseRelocationEntry entry : reloc_block.Entries) {
      new_data.insert(
          new_data.end(),
          reinterpret_cast<uint8_t*>(&entry),
          reinterpret_cast<uint8_t*>(&entry) + sizeof(BaseRelocationEntry)
          );
    }
  }
  relocations->setData(new_data);
}

void PE::Save() {
  if (!open_ || !parsed_)
    return;
  file_stream_.close();
  // clear, as we are rebuilding the PE
  file_stream_ = std::fstream(file_name_,
                              std::ios::in
                              | std::ios::out
                              | std::ios::trunc
                              | std::ios::binary);
  std::vector<char> pe_file;
  rebuild(pe_file);
  file_stream_.write(pe_file.data(), static_cast<uint32_t>(pe_file.size()));
}

void PE::SaveAs(const std::string& file_name) {
  std::vector<char> pe_file;
  rebuild(pe_file);

  std::ofstream ofs(file_name, std::ios::binary);
  ofs.write(pe_file.data(), static_cast<uint32_t>(pe_file.size()));
  ofs.close();
}

void PE::rebuild(std::vector<char>& data) {
  using namespace stitch::pe;
  const auto p_dos_header = reinterpret_cast<char*>(&file_mapping_.dos_header);
  const auto p_nt_headers = reinterpret_cast<char*>(&file_mapping_.
    nt_headers32);
  // DOS header
  data.insert(data.end(), p_dos_header, p_dos_header + sizeof(DosHeader));
  // DOS stub
  data.insert(data.end(), file_mapping_.dos_stub.begin(),
              file_mapping_.dos_stub.end());
  // NT headers
  file_mapping_.SizeOfImage() = utils::RoundToBoundary(
      file_mapping_.SizeOfImage(), file_mapping_.SectionAlignment());

  DWORD& cbHeaders = file_mapping_.SizeOfHeaders();
  cbHeaders = utils::RoundToBoundary(cbHeaders, file_mapping_.FileAlignment());

  if (file_mapping_.Is32Bit()) {
    data.insert(data.end(), p_nt_headers, p_nt_headers + sizeof(NtHeaders32));
  } else if (file_mapping_.Is64Bit()) {
    data.insert(data.end(), p_nt_headers, p_nt_headers + sizeof(NtHeaders64));
  }
  // binary size is by default the end of the last section
  DWORD binary_size = 0;
  for (const auto& section : sections_) {
    PESectionInfo& si = section->GetSectionInfo();
    if (si.header.SizeOfRawData == 0) {
      if (section->GetType() != SectionType::BSS)
        throw section_error("section " + section->GetName() + " is empty");
      // don't allow useless bss sections
      if (si.header.Misc.VirtualSize == 0)
        throw section_error("section " + section->GetName() + " is empty");
    }
    const DWORD section_end = si.header.PointerToRawData + si.header.
                              SizeOfRawData;
    if (section_end > binary_size) {
      binary_size = section_end;
    }
    const auto p_section_header = reinterpret_cast<char*>(&si.header);
    data.insert(data.end(),
                p_section_header,
                p_section_header + sizeof(SectionHeader));
  }
  // ... unless certificate table is present
  const NtDataDirectory* cert_table = getCertTable();
  if (cert_table) {
    binary_size = cert_table->VirtualAddress + cert_table->Size;
  }
  // grow to fit entire binary, in case raw pointers don't increase sequentially
  data.resize(binary_size);
  // section data
  for (const auto& section : sections_) {
    const PESectionInfo& si = section->GetSectionInfo();
    if (si.header.PointerToRawData)
      // insert raw section data in
      std::ranges::copy(section->GetData(),
                        data.begin() + si.header.PointerToRawData);
  }
  if (cert_table) {
    std::ranges::copy(file_mapping_.cert_table,
                      data.begin() + cert_table->VirtualAddress);
  }
}
}