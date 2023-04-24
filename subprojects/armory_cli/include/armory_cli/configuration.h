#pragma once

#include "armory/context.h"

namespace armory_cli
{
    struct CodeSection
    {
        std::string name;
        std::vector<u8> bytes;
        u32 offset;
    };

    struct Configuration
    {
        mulator::Architecture arch;

        armory::Context faulting_context;
        u32 num_threads;
    };
}    // namespace armory_cli
