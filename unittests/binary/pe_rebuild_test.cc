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

  pe.SaveAs("new_pe_test.bin");
  pe.Close();

  std::fstream fs("new_pe_test.bin");
  PEFormat format;
  PEFormat::Parse(fs, format);
  fs.close();
  std::remove("new_pe_test.bin");

  const PESectionInfo& dsi = format.GetSectionInfo(".vmp1");
  assert(strcmp(reinterpret_cast<const char*>(dsi.data.data()),
                "Hello, world!") == 0);
  assert(dsi.header.Misc.VirtualSize == sizeof("Hello, world!"));
  assert(dsi.header.Characteristics ==
         (pe::IMAGE_SCN_MEM_READ | pe::IMAGE_SCN_CNT_INITIALIZED_DATA));

  const PESectionInfo& csi = format.GetSectionInfo(".vmp2");
  assert(csi.data.front() == 0xc3);
  assert(csi.header.Characteristics ==
         (pe::IMAGE_SCN_MEM_READ | pe::IMAGE_SCN_MEM_EXECUTE |
          pe::IMAGE_SCN_CNT_CODE));
}