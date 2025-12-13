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