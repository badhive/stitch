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

#include <stitch/binary/pe.h>
#include <stitch/target/x86.h>

#include <algorithm>
#include <iostream>
#include <map>

const std::vector regs = {
    zasm::x86::rdi, zasm::x86::rsi, zasm::x86::rcx, zasm::x86::rdx,
    zasm::x86::r8,  zasm::x86::r9,  zasm::x86::r10,
};

const std::vector<zasm::InstrMnemonic> mnemonics = {
    zasm::x86::Mnemonic::Mov, zasm::x86::Mnemonic::Sub,
    zasm::x86::Mnemonic::Xor, zasm::x86::Mnemonic::Add};

const std::map<zasm::InstrMnemonic, zasm::InstrMnemonic> branches = {
    {zasm::x86::Mnemonic::Jz, zasm::x86::Mnemonic::Jnz},
    {zasm::x86::Mnemonic::Jb, zasm::x86::Mnemonic::Jnb},
    {zasm::x86::Mnemonic::Jo, zasm::x86::Mnemonic::Jno},
    {zasm::x86::Mnemonic::Jl, zasm::x86::Mnemonic::Jnl},
    {zasm::x86::Mnemonic::Jp, zasm::x86::Mnemonic::Jnp},
    {zasm::x86::Mnemonic::Jle, zasm::x86::Mnemonic::Jnle}};

const auto& getRandomReg() {
  auto& reg = regs[rand() % regs.size()];
  return reg;
}

const auto& getRandomMnemonic() {
  auto& reg = mnemonics[rand() % mnemonics.size()];
  return reg;
}

const auto& getRandomBranch() {
  auto it = branches.begin();
  std::advance(it, rand() % mnemonics.size());
  return *it;
}

int getRandomInt() {
  return rand() % (0x1000 + 1);
}

int main() {
  srand(time(nullptr));
  stitch::PE pe("pe_branching.bin");
  stitch::Code* code = pe.OpenCode();
  constexpr stitch::RVA fn_main = 0x00000001400015A1;
  auto* fn =
      dynamic_cast<stitch::X86Function*>(code->EditFunction(fn_main, ""));
  fn->Instrument([&fn](zasm::x86::Assembler& as) {
    for (const stitch::X86Inst& inst : fn->GetOriginalCode()) {
      if (inst.RawInst().getCategory() != zasm::x86::Category::Ret) {
        const auto cursor = as.getCursor();
        as.setCursor(inst.GetPos());
        if (!inst.CommonFlagsAvailable())
          continue;  // we won't use pushf and popf at all
        // if no regs available, we'll use any random register
        auto reg = inst.GetAvailableRegister();
        auto dummy = getRandomReg();
        as.push(dummy);

        bool reg_pushed = false;
        if (!reg.has_value()) {
          reg = zasm::x86::rax;
          as.push(*reg);
          reg_pushed = true;
        }

        auto label = as.createLabel();
        const auto pair1 = getRandomBranch();
        const auto pair2 = getRandomBranch();

        as.emit(getRandomMnemonic(), *reg, zasm::Imm(getRandomInt()));
        as.emit(pair1.first, label);
        for (int i = 0; i < getRandomInt() % 10; i++) {
          as.emit(getRandomMnemonic(), *reg, zasm::Imm(getRandomInt()));
        }
        as.emit(pair2.first, label);
        as.emit(pair2.second, label);
        as.bind(label);
        if (reg_pushed) as.pop(zasm::x86::rax);
        as.pop(dummy);
        as.setCursor(cursor);
      }
    }
  });
  pe.SaveAs("target/pe_complex_obf.bin");
  pe.Close();
}