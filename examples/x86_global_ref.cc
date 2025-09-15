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

int main() {
  stitch::PE pe("pe_branching.bin");
  auto* code = pe.OpenCode<stitch::X86Code>();
  constexpr stitch::RVA fn_main = 0x00000001400015A1;
  stitch::Section* scn = pe.AddSection(".st0", stitch::SectionType::ROData);
  const stitch::GlobalRef* str_ref = scn->WriteWithRef("Hello, world!\n");
  auto* fn =
      dynamic_cast<stitch::X86Function*>(code->EditFunction(fn_main, ".st1"));
  fn->Instrument([&](stitch::X86Function* fo, zasm::x86::Assembler& as) {
    for (const stitch::X86Inst& inst : fo->GetOriginalCode()) {
      const zasm::InstructionDetail& detail = inst.RawInst();
      const zasm::Mem* target_op = nullptr;
      int target_op_pos = -1;
      for (int i = 0; i < detail.getOperandCount(); i++) {
        try {
          const auto& op = detail.getOperand<zasm::Mem>(i);
          // replace known string addr with GlobalRef to our new string
          if (op.getDisplacement() == 0x0000000140009000) {
            target_op = &op;
            target_op_pos = i;
            break;
          }
        } catch (const std::exception& _) {
        }
      }
      if (target_op) {
        auto new_inst = detail;
        zasm::Node* after = inst.GetPos()->getPrev();
        fo->GetProgram().destroy(inst.GetPos());
        zasm::Node* end = as.getCursor();
        as.setCursor(after);
        new_inst.setOperand(target_op_pos,
                            code->AddressOperand(str_ref->GetValue()));
        as.emit(new_inst);
        as.setCursor(end);
        break;
      }
    }
  });
  pe.SaveAs("target/pe_global_ref.bin");
  pe.Close();
}