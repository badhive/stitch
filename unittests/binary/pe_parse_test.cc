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

#include <fstream>

#include "stitch/binary/pe.h"

using namespace stitch;

int main() {
  std::fstream fs("pe_simple.bin");
  PEFormat format{};
  PEFormat::Parse(fs, format);

  format.GetSectionInfo(".CRT");
  format.GetSectionInfo(".bss");
  format.GetSectionInfo(".data");
  format.GetSectionInfo(".idata");
  format.GetSectionInfo(".pdata");
  format.GetSectionInfo(".rdata");
  format.GetSectionInfo(".reloc");
  format.GetSectionInfo(".reloc");
  format.GetSectionInfo(".text");
  format.GetSectionInfo(".tls");
  format.GetSectionInfo(".xdata");
  format.GetSectionInfo(".xdata");

  fs.close();
}
