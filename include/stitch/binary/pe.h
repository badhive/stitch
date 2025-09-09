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

#ifndef STITCH_BINARY_PE_H_
#define STITCH_BINARY_PE_H_

#include <map>
#include <memory>

#include "stitch/binary/binary.h"
#include "stitch/misc/utils.h"
#include "stitch/target/target.h"

namespace stitch {
namespace pe {
using BYTE = std::uint8_t;
using WORD = std::uint16_t;
using DWORD = std::uint32_t;
using QWORD = std::uint64_t;

using CHAR = char;
using SHORT = short;
using LONG = long;
using LONGLONG = std::int64_t;

using UCHAR = std::uint8_t;
using USHORT = std::uint16_t;
using ULONG = std::uint32_t;
using ULONGLONG = std::uint64_t;

constexpr DWORD IMAGE_DOS_SIGNATURE = 0x5A4D;
constexpr DWORD IMAGE_NT_SIGNATURE = 0x00004550;
constexpr DWORD IMAGE_NUMBEROF_DIRECTORY_ENTRIES = 16;
constexpr DWORD IMAGE_SIZEOF_SHORT_NAME = 8;
constexpr DWORD IMAGE_NT_OPTIONAL_HDR32_MAGIC = 0x10b;
constexpr DWORD IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20b;
constexpr DWORD IMAGE_SCN_CNT_CODE = 0x00000020;
constexpr DWORD IMAGE_SCN_CNT_INITIALIZED_DATA = 0x00000040;
constexpr DWORD IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x00000080;
constexpr DWORD IMAGE_SCN_MEM_EXECUTE = 0x20000000;
constexpr DWORD IMAGE_SCN_MEM_READ = 0x40000000;
constexpr DWORD IMAGE_SCN_MEM_WRITE = 0x80000000;

// architectures
constexpr DWORD IMAGE_FILE_MACHINE_I386 = 0x0000014c;
constexpr DWORD IMAGE_FILE_MACHINE_AMD64 = 0x00008664;
constexpr DWORD IMAGE_FILE_MACHINE_ARM = 0x000001c0;
constexpr DWORD IMAGE_FILE_MACHINE_ARM64 = 0x0000aa64;

// dir entries
constexpr char IMAGE_DIRECTORY_ENTRY_EXPORT = 0;
constexpr char IMAGE_DIRECTORY_ENTRY_IMPORT = 1;
constexpr char IMAGE_DIRECTORY_ENTRY_SECURITY = 4;
constexpr char IMAGE_DIRECTORY_ENTRY_BASERELOC = 5;

constexpr ULONGLONG IMAGE_ORDINAL_FLAG64 = 0x8000000000000000ULL;
constexpr ULONGLONG IMAGE_ORDINAL_FLAG32 = 0x80000000;

// section flags
constexpr unsigned code_flags =
    IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;
constexpr unsigned data_flags =
    IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;
constexpr unsigned bss_flags =
    IMAGE_SCN_CNT_UNINITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;

struct DosHeader {
  WORD e_magic;
  WORD e_cblp;
  WORD e_cp;
  WORD e_crlc;
  WORD e_cparhdr;
  WORD e_minalloc;
  WORD e_maxalloc;
  WORD e_ss;
  WORD e_sp;
  WORD e_csum;
  WORD e_ip;
  WORD e_cs;
  WORD e_lfarlc;
  WORD e_ovno;
  WORD e_res[4];
  WORD e_oemid;
  WORD e_oeminfo;
  WORD e_res2[10];
  DWORD e_lfanew;
};

struct NtFileHeader {
  WORD Machine;
  WORD NumberOfSections;
  DWORD TimeDateStamp;
  DWORD PointerToSymbolTable;
  DWORD NumberOfSymbols;
  WORD SizeOfOptionalHeader;
  WORD Characteristics;
};

struct NtDataDirectory {
  DWORD VirtualAddress;
  DWORD Size;
};

struct NtOptionalHeader32 {
  WORD Magic;
  BYTE MajorLinkerVersion;
  BYTE MinorLinkerVersion;
  DWORD SizeOfCode;
  DWORD SizeOfInitializedData;
  DWORD SizeOfUninitializedData;
  DWORD AddressOfEntryPoint;
  DWORD BaseOfCode;
  DWORD BaseOfData;
  DWORD ImageBase;
  DWORD SectionAlignment;
  DWORD FileAlignment;
  WORD MajorOperatingSystemVersion;
  WORD MinorOperatingSystemVersion;
  WORD MajorImageVersion;
  WORD MinorImageVersion;
  WORD MajorSubsystemVersion;
  WORD MinorSubsystemVersion;
  DWORD Win32VersionValue;
  DWORD SizeOfImage;
  DWORD SizeOfHeaders;
  DWORD CheckSum;
  WORD Subsystem;
  WORD DllCharacteristics;
  DWORD SizeOfStackReserve;
  DWORD SizeOfStackCommit;
  DWORD SizeOfHeapReserve;
  DWORD SizeOfHeapCommit;
  DWORD LoaderFlags;
  DWORD NumberOfRvaAndSizes;
  NtDataDirectory DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
};

struct NtOptionalHeader64 {
  WORD Magic;
  BYTE MajorLinkerVersion;
  BYTE MinorLinkerVersion;
  DWORD SizeOfCode;
  DWORD SizeOfInitializedData;
  DWORD SizeOfUninitializedData;
  DWORD AddressOfEntryPoint;
  DWORD BaseOfCode;
  LONGLONG ImageBase;
  DWORD SectionAlignment;
  DWORD FileAlignment;
  WORD MajorOperatingSystemVersion;
  WORD MinorOperatingSystemVersion;
  WORD MajorImageVersion;
  WORD MinorImageVersion;
  WORD MajorSubsystemVersion;
  WORD MinorSubsystemVersion;
  DWORD Win32VersionValue;
  DWORD SizeOfImage;
  DWORD SizeOfHeaders;
  DWORD CheckSum;
  WORD Subsystem;
  WORD DllCharacteristics;
  ULONGLONG SizeOfStackReserve;
  ULONGLONG SizeOfStackCommit;
  ULONGLONG SizeOfHeapReserve;
  ULONGLONG SizeOfHeapCommit;
  DWORD LoaderFlags;
  DWORD NumberOfRvaAndSizes;
  NtDataDirectory DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
};

struct NtHeaders32 {
  DWORD Signature;
  NtFileHeader FileHeader;
  NtOptionalHeader32 OptionalHeader;
};

struct NtHeaders64 {
  DWORD Signature;
  NtFileHeader FileHeader;
  NtOptionalHeader64 OptionalHeader;
};

struct SectionHeader {
  CHAR Name[IMAGE_SIZEOF_SHORT_NAME];

  union {
    DWORD PhysicalAddress;
    DWORD VirtualSize;
  } Misc;

  DWORD VirtualAddress;
  DWORD SizeOfRawData;
  DWORD PointerToRawData;
  DWORD PointerToRelocations;
  DWORD PointerToLineNumbers;
  WORD NumberOfRelocations;
  WORD NumberOfLineNumbers;
  DWORD Characteristics;
};

struct ExportDataDirectory {
  DWORD Characteristics;
  DWORD TimeDateStamp;
  WORD MajorVersion;
  WORD MinorVersion;
  DWORD Name;
  DWORD Base;
  DWORD NumberOfFunctions;
  DWORD NumberOfNames;
  DWORD AddressOfFunctions;     // RVA from base of image
  DWORD AddressOfNames;         // RVA from base of image
  DWORD AddressOfNameOrdinals;  // RVA from base of image
};

struct ExportInfo {
  std::string name;
  DWORD address;
};

struct ImageImportDescriptor {
  union {
    DWORD Characteristics;    /* 0 for terminating null import descriptor  */
    DWORD OriginalFirstThunk; /* RVA to original unbound IAT */
  };
  DWORD TimeDateStamp;  /* 0 if not bound,
                         * -1 if bound, and real date\time stamp
                         *    in IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT
                         * (new BIND)
                         * otherwise date/time stamp of DLL bound to
                         * (Old BIND)
                         */
  DWORD ForwarderChain; /* -1 if no forwarders */
  DWORD Name;
  /* RVA to IAT (if bound this IAT has actual addresses) */
  DWORD FirstThunk;
};

struct ImageImportByName {
  USHORT Hint;
  CHAR Name[1];
};

struct ImageThunkData64 {
  union {
    ULONGLONG ForwarderString;  // PBYTE
    ULONGLONG Function;         // PDWORD
    ULONGLONG Ordinal;
    ULONGLONG AddressOfData;  // PIMAGE_IMPORT_BY_NAME
  };
};

struct ImageThunkData32 {
  union {
    DWORD ForwarderString;  // PBYTE
    DWORD Function;         // PDWORD
    DWORD Ordinal;
    DWORD AddressOfData;  // PIMAGE_IMPORT_BY_NAME
  };
};

struct ImportInfo {
  std::string name;
  std::string module;
  VA iat_entry;  // absolute address of IAT entrypoint
};

struct BaseRelocationEntry {
  WORD Offset : 12;
  WORD Type : 4;
};

struct BaseRelocation {
  DWORD VirtualAddress;
  DWORD SizeOfBlock;
};

struct FullBaseRelocation {
  BaseRelocation base;
  std::vector<BaseRelocationEntry> entries;
};
}  // namespace pe

struct PESectionInfo {
  pe::SectionHeader header;
  std::vector<uint8_t> data;
};

struct PEFormat {
  pe::DWORD size_of_raw_headers;
  TargetArchitecture architecture;

  pe::DosHeader dos_header;
  std::vector<char> dos_stub;

  union {
    pe::NtHeaders32 nt_headers32;
    pe::NtHeaders64 nt_headers64;
  };

  // Map of section names to basic section information
  std::vector<PESectionInfo> sections;

  pe::ExportDataDirectory export_info;
  std::vector<pe::DWORD> exports;

  std::map<VA, pe::ImportInfo> imports;

  std::vector<pe::FullBaseRelocation> relocations;

  // certificate table is usually the last
  std::vector<char> cert_table;

  /// Parse a PE file into the structure. The method may throw an I/O error in
  /// the case of a malformed PE file.
  /// @param stream file stream of the open PE file
  /// @param format empty PE mapping object
  /// @throw invalid_binary_format_error the open file is not a Windows PE
  static void Parse(std::fstream& stream, PEFormat& format);

  bool Is64Bit() const;
  bool Is32Bit() const;

  /// Get basic information about the given section
  /// @param name Name of section
  /// @return a PESectionInfo structure containing details about the chosen
  /// section
  /// @throw section_not_found_error the section doesn't exist
  const PESectionInfo& GetSectionInfo(const std::string& name);

  pe::DWORD Entrypoint() const;
  intptr_t ImageBase() const;
  pe::DWORD FileAlignment() const;
  pe::DWORD SectionAlignment() const;
  pe::DWORD& SizeOfHeaders();
  pe::DWORD& SizeOfImage();
  pe::DWORD& SizeOfInitializedData();
  pe::DWORD& SizeOfUninitializedData();
  pe::DWORD& SizeOfCode();
  pe::NtDataDirectory& DataDirectory(char id);
};

class PESection final : public Section {
  friend class PE;

  PESectionInfo si_;
  std::vector<std::unique_ptr<GlobalRef>> refs;

  void growRaw(int64_t old, int64_t amount) const;
  void growVirtual(int64_t old, int64_t amount) const;

  // expose setData to PE
  void setData(const std::vector<uint8_t>& data) override {
    Section::setData(data);
  }

 public:
  using Section::Write;

  PESection(const PESectionInfo& si, const SectionType type,
            const std::vector<uint8_t>& data, Binary* parent,
            const bool existed = false)
      : Section(si.header.Name, type, data, parent, existed), si_(si) {}

  void Write(const std::vector<uint8_t>& data) override;

  PESectionInfo& GetSectionInfo() { return si_; }

  unsigned Characteristics() const;

  void SetCharacteristics(unsigned ch);

  RVA GetAddress() const override { return si_.header.VirtualAddress; }

  void Relocate(const int64_t delta) override {
    Section::Relocate(delta);
    si_.header.VirtualAddress += delta;
  }
};

class PE final : public Binary {
  friend class PESection;

  bool parsed_;
  PEFormat file_mapping_ = {};
  std::vector<std::unique_ptr<PESection>> sections_;
  char bit_size_;
  static constexpr uint16_t kMaxPESections = 96;

  void parse();
  void parseRelocations();
  template <typename T = pe::ImageThunkData64>
  void parseImports();
  void parseExports();
  void rebuild(std::vector<char>& data);
  void addSectionHeader();
  RVA getNewSectionRVA();
  RVA getNewSectionRawPointer();
  void growSectionRawSize(const std::string& section_name, int64_t amount);
  void growSectionVirtualSize(const std::string& section_name, int64_t old,
                              int64_t amount);
  pe::NtDataDirectory* getCertTable();
  void* getContentAt(RVA rva) const;

 public:
  explicit PE() : Binary(Platform::Windows), parsed_(false), bit_size_(0) {}

  explicit PE(const std::string& file_name, const bool no_analyze = false)
      : Binary(file_name, Platform::Windows), parsed_(false) {
    PE::Open(file_name);
    if (!no_analyze) OpenCode()->AnalyzeFrom(GetEntrypoint());
  }

  void Open(const std::string& file_name) override {
    Binary::Open(file_name);
    parse();
  }

  /// Opens a section
  /// @param name name of section
  /// @return section object
  /// @throw section_not_found_error
  Section* OpenSection(const std::string& name) const override;

  /// Opens the section that the specified virtual address falls into
  /// @param address virtual address
  /// @return section or nullptr
  Section* OpenSectionAt(VA address) const override;

  /// Creates a new section in the PE.
  /// This results in the PointerToRawData for each section being updated
  /// to make space for the new section's header.
  /// @param name name of new section
  /// @param type type of new section
  /// @throw section_error bad name provided
  Section* AddSection(const std::string& name, SectionType type) override;

  TargetArchitecture GetArchitecture() const {
    return file_mapping_.architecture;
  }

  VA GetImageBase() const override;

  /// Returns the VA of the entrypoint. This is used as the start point
  /// for code analysis.
  VA GetEntrypoint() const override;

  void Save() override;

  void SaveAs(const std::string& file_name) override;

  char GetBitSize() const override { return bit_size_; }

  const PEFormat& GetFileMapping() { return file_mapping_; }

  /// Returns the name of the import for the provided IAT entry address, which
  /// is dereferenced in code when called.
  /// @param address address of IAT entry
  /// @return name of the import
  std::string GetImportForAddress(const VA address) const override {
    if (file_mapping_.imports.contains(address))
      return file_mapping_.imports.at(address).name;
    return "";
  }

  /// Returns the iat entry address of an imported function, or 0 if the
  /// function isn't imported
  /// @param import name of imported function
  /// @return address of iat entry of imported function
  VA GetAddressForImport(const std::string& import) const override {
    for (const auto& [_, import_info] : file_mapping_.imports) {
      if (utils::tolower(import_info.name) == utils::tolower(import))
        return import_info.iat_entry;
    }
    return 0;
  }
};
}  // namespace stitch

#endif  // STITCH_BINARY_PE_H_