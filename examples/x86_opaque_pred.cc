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
    zasm::x86::rdi, zasm::x86::rsi, zasm::x86::rcx, zasm::x86::rdx,
    zasm::x86::r8,  zasm::x86::r9,  zasm::x86::r10,
};

auto& getRandomReg() {
  auto& reg = regs[rand() % regs.size()];
  return reg;
}

int main() {
  srand(time(nullptr));
  stitch::PE pe("pe_branching.bin");
  const auto code = pe.OpenCode();
  constexpr stitch::RVA fn_main = 0x00000001400015A1;
  const auto fn =
      dynamic_cast<stitch::X86Function*>(code->EditFunction(fn_main, ""));
  fn->Instrument([](stitch::X86Function* fo, zasm::x86::Assembler& as) {
    for (const stitch::X86Inst& inst : fo->GetOriginalCode()) {
      const bool to_insert = rand() % 2;
      const zasm::InstructionDetail& detail = inst.RawInst();
      if (detail.getMnemonic() != zasm::x86::Mnemonic::Ret && to_insert) {
        zasm::Label last_label = as.createLabel();

        bool auto_reg = true;
        auto reg = inst.GetAvailableRegister<zasm::x86::Gp64>();
        if (!reg.has_value()) {
          auto_reg = false;
          reg = getRandomReg();
          as.push(*reg);
        }
        as.setCursor(inst.GetPos());

        if (!inst.CommonFlagsAvailable()) as.pushf();

        as.xor_(*reg, zasm::Imm(rand()));
        as.js(last_label);
        as.jns(last_label);
        as.bind(last_label);

        if (!inst.CommonFlagsAvailable()) as.popf();

        if (!auto_reg) as.pop(*reg);
      }
    }
  });
  pe.SaveAs("target/pe_opaque_predicates.bin");
  pe.Close();
}