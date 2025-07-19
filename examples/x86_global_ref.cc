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
  stitch::PE pe("target/pe_branching.bin");
  stitch::Code* code = pe.OpenCode();
  constexpr stitch::RVA fn_main = 0x00000001400015A1;
  stitch::Section* scn = pe.AddSection(".st0", stitch::SectionType::ROData);
  const stitch::GlobalRef* str_ref = scn->WriteWithRef("Hello, world!\n");
  auto* fn = dynamic_cast<stitch::X86Function*>(
    code->EditFunction(fn_main, ".st1")
  );
  fn->Instrument([&](zasm::Program& pr, zasm::x86::Assembler& as) {
    for (stitch::X86Inst& inst : fn->GetOriginalCode()) {
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
        pr.destroy(inst.GetPos());
        zasm::Node* end = as.getCursor();
        as.setCursor(after);
        zasm::Mem new_op = *target_op;
        new_op.setDisplacement(str_ref->GetValue());
        new_inst.setOperand(target_op_pos, new_op);
        as.emit(new_inst);
        as.setCursor(end);
        break;
      }
    }
  });
  pe.SaveAs("target/pe_global_ref.bin");
  pe.Close();
}