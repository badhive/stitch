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
#include "stitch/target/x86.h"

int main() {
  // shellcode will set off av so won't include it
  try {
    stitch::Shellcode shc("shellcode_simple.bin",
                          stitch::TargetArchitecture::AMD64,
                          stitch::Platform::Windows);
    auto* code = shc.OpenCode<stitch::X86Code>();
    auto* fn = dynamic_cast<stitch::X86Function*>(code->EditFunction(0x46, ""));
    fn->Finish();
    shc.SaveAs("target/obf.shellcode.bin");
    shc.Close();
  } catch (const std::exception& _) {
    return 0;
  }
}
