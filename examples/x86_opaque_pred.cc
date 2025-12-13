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