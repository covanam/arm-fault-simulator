#pragma once

#include "armory/instruction_fault_model.h"
#include "armory/register_fault_model.h"
#include "armory_cli/configuration.h"
#include "m-ulator/disassembler.h"

namespace armory_cli
{
    void print_instruction_fault(const armory::InstructionFault& f, const Configuration& ctx, mulator::Disassembler& disasm);

    void print_register_fault(const armory::RegisterFault& f);
}    // namespace armory_cli
