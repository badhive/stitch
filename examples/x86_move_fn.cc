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

int main() {
  stitch::PE pe("binary/pe_test.bin");
  stitch::Code* code = pe.OpenCode();
  constexpr stitch::RVA fn_main = 0x00000001400015A1;
  stitch::Function* fn = code->EditFunction(fn_main, "");
  fn->Finish();
  pe.SaveAs("target/pe_moved_fn.bin");
  pe.Close();
}
