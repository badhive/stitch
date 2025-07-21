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

#include <cassert>
#include <cstring>

#include "stitch/binary/pe.h"

using namespace stitch;

int main() {
  PE pe("pe_simple.bin");
  Section* rdata = pe.AddSection(".vmp1", SectionType::ROData);
  rdata->Write("Hello, world!");
  Section* text = pe.AddSection(".vmp2", SectionType::Code);
  text->Write(std::vector<uint8_t>{0xc3});

  assert(pe.OpenCodeSection(".text"));

  pe.SaveAs("new_pe_test.bin");
  pe.Close();

  std::fstream fs("new_pe_test.bin");
  PEFormat format;
  PEFormat::Parse(fs, format);
  fs.close();
  std::remove("new_pe_test.bin");

  const PESectionInfo& dsi = format.GetSectionInfo(".vmp1");
  assert(
      strcmp(reinterpret_cast<const char*>(dsi.data.data()), "Hello, world!") ==
      0);
  assert(dsi.header.Misc.VirtualSize == sizeof("Hello, world!"));
  assert(dsi.header.Characteristics == (pe::IMAGE_SCN_MEM_READ |
    pe::IMAGE_SCN_CNT_INITIALIZED_DATA));

  const PESectionInfo& csi = format.GetSectionInfo(".vmp2");
  assert(csi.data.front() == 0xc3);
  assert(csi.header.Characteristics == (pe::IMAGE_SCN_MEM_READ |
    pe::IMAGE_SCN_MEM_EXECUTE |
    pe::IMAGE_SCN_CNT_CODE));
}