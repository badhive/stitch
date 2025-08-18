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
#include "stitch/target/x86.h"

const std::vector regs = {
    zasm::x86::rdi,
    zasm::x86::rsi,
    zasm::x86::rcx,
    zasm::x86::rdx,
    zasm::x86::r8,
    zasm::x86::r9,
    zasm::x86::r10,
};

auto& getRandomReg() {
  auto& reg = regs[rand() % regs.size()];
  return reg;
}

int main() {
  srand(time(nullptr));
  stitch::PE pe("pe_branching.bin");
  auto* code = dynamic_cast<stitch::X86Code*>(pe.OpenCode());
  constexpr stitch::RVA fn_main = 0x00000001400015A1;
  auto* fn = dynamic_cast<stitch::X86Function*>(code->EditFunction(
      fn_main, ""));
  fn->Instrument([&fn](zasm::x86::Assembler& as) {
    for (const stitch::X86Inst& inst : fn->GetOriginalCode()) {
      const bool to_insert = rand() % 2;
      const zasm::InstructionDetail& detail = inst.RawInst();
      if (detail.getMnemonic() != zasm::x86::Mnemonic::Ret && to_insert) {
        zasm::Label last_label = as.createLabel();
        const auto& reg = getRandomReg();
        as.setCursor(inst.GetPos());
        as.pushf();
        as.push(reg);
        as.xor_(reg, zasm::Imm(rand()));
        as.js(last_label);
        as.jns(last_label);
        as.bind(last_label);
        as.pop(reg);
        as.popf();
      }
    }
  });
  pe.SaveAs("target/pe_opaque_predicates.bin");
  pe.Close();
}