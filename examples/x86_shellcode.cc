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
