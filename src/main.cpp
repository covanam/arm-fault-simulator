#include "armory/fault_tracer.h"
#include "armory_cli/fault_models.h"
#include "armory_cli/armory_cli.h"
#include "termcolor.h"

#include <chrono>
#include <cstring>
#include <iostream>

#include "elfio/elfio.hpp"

using namespace armory;

static Emulator setup_simulator(const std::string& elf_file, u32 *firmware_addr) {
    Emulator emu(mulator::ARMv7M);
    emu.set_flash_region(0, 0x40000);
    emu.set_ram_region(0x20000000, 0x10000);

    ELFIO::Elf64_Addr entry_address = 0xffffffff;

    ELFIO::elfio reader;

    if (false == reader.load(elf_file))
        throw std::runtime_error("Can't open file " + elf_file);

    for (int i = 0; i < reader.sections.size(); ++i) {
		ELFIO::section* psec = reader.sections[i];

        ELFIO::Elf_Xword flags = psec->get_flags();
        ELFIO::Elf_Half type = psec->get_type();
        if ((flags & ELFIO::SHF_ALLOC) && type == ELFIO::SHT_PROGBITS) {
            emu.write_memory(
                psec->get_address(),
                (const u8*)psec->get_data(),
                psec->get_size()
            );
        }

        if (psec->get_name() == ".symtab") {
            ELFIO::symbol_section_accessor symbols(reader, psec);

            for (unsigned int i = 1; i < symbols.get_symbols_num(); ++i) {
                std::string name;
                ELFIO::Elf64_Addr value;
                ELFIO::Elf_Xword size;
                unsigned char bind;
                unsigned char type;
                ELFIO::Elf_Half section_index;
                unsigned char other;
                symbols.get_symbol(i, name, value, size, bind, type,
                    section_index, other);
                
                if (name == "main") {
                    entry_address = value & ~((decltype(value))1);
                }
                else if (name == "firmware") {
                    *firmware_addr = value;
                }
            }
        }
    }

    if (entry_address == 0xffffffff)
        throw std::runtime_error("Can't find entry function");

    uint32_t stack_pointer;
    emu.read_memory(0, (uint8_t*)&stack_pointer, 4);

    emu.write_register(Register::SP, stack_pointer);
    emu.write_register(Register::PC, entry_address);
    emu.write_register(Register::LR, 0xFFFFFFFF);

    uint32_t test_mem = 0xffffffff;
    emu.write_memory(0x20008000, (uint8_t*)&test_mem, 4);

    return emu;
}

static void check_completion(Emulator& emu, u32, u32, void* ptr) {
    uint32_t test_mem;
    emu.read_memory(0x20008000, (uint8_t*)&test_mem, 4);
    if (test_mem != 0xffffffff) {
        emu.stop_emulation();

        if (ptr != nullptr) {
            uint32_t *ptr_test_mem = static_cast<uint32_t*>(ptr);
            *ptr_test_mem = test_mem;
        }
    }
}

static u32 compute_timeout(const Emulator& main_emulator)
{
    Emulator timeout_emu(main_emulator);

    timeout_emu.before_fetch_hook.add(check_completion, nullptr);
    timeout_emu.emulate(1000000);

    return 2 * timeout_emu.get_emulated_time();
}

int main(int argc, char** argv)
{
    armory_cli::Configuration config = armory_cli::parse_arguments(argc - 1, argv);

    struct SecureBootExploitabilityModel : ExploitabilityModel
    {
        std::unique_ptr<ExploitabilityModel> clone() override
        {
            return std::make_unique<SecureBootExploitabilityModel>(*this);
        }

        Decision evaluate(const Emulator& emu, const Context&, u32) override
        {
            uint32_t test_mem;
            emu.read_memory(0x20008000, (uint8_t*)&test_mem, 4);
            if (test_mem == 0xcafebabe)
                return Decision::EXPLOITABLE;
            else
                return Decision::NOT_EXPLOITABLE;
        };
    };

    SecureBootExploitabilityModel model;
    config.faulting_context.exploitability_model = &model;

    u32 firmware_addr = 0xffffffff;
    Emulator main_emulator = setup_simulator(argv[argc - 1], &firmware_addr);
    if (firmware_addr == 0xffffffff)
        throw std::runtime_error("Can't find firmware");
    
    std::cout << "Firmware is at address 0x" << std::hex << firmware_addr << std::dec << '\n'; 

    // test correctness:
    {
        {
            Emulator emu(main_emulator);

            uint32_t test_mem;

            emu.before_fetch_hook.add(check_completion, &test_mem);

            auto ret = emu.emulate(1000000);
            if (ret != ReturnCode::STOP_EMULATION_CALLED)
            {
                std::cout << "ERROR: " << ret << std::endl;
                return 1;
            }
            if (test_mem != 0xcafebabe)
            {
                std::cout << "ERROR: correct firmware was not executed" << std::endl;
                return 1;
            }
        }
        std::cout << "Positive test passed!" << std::endl;
    }

    /* simulate firmware get hacked */
    u8 buf[4] = {0, 0, 0, 0};
    main_emulator.write_memory(firmware_addr, buf, 4);

    {
        Emulator emu(main_emulator);

        uint32_t test_mem;

        emu.before_fetch_hook.add(check_completion, &test_mem);

        auto ret = emu.emulate(1000000);
        if (ret != ReturnCode::STOP_EMULATION_CALLED)
        {
            std::cout << "ERROR: " << ret << std::endl;
            return 1;
        }
        if (test_mem != 0xdeadbeef)
        {
            std::cout << "ERROR: hacked firmware was executed" << std::endl;
            return 1;
        }
        std::cout << "Negative test passed!" << std::endl;
    }

    config.faulting_context.emulation_timeout = compute_timeout(main_emulator);

    std::cout << "simulation begin at " << main_emulator.get_time() << std::endl;

    u32 total_faults = 0;
    auto start       = std::chrono::steady_clock::now();

    for (const auto& spec : fault_models::all_fault_models)
    {
        // inject the model 1 time
        auto model_injection = std::make_pair(spec, 1);

        // inject the model 2 times
        // auto model_injection = std::make_pair(spec, 2);

        auto exploitable_faults = armory_cli::find_exploitable_faults(main_emulator, config, {model_injection});
        total_faults += exploitable_faults.size();
    }

    auto end       = std::chrono::steady_clock::now();
    double seconds = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count() / 1000.0;

    std::cout << "_______________________________________" << std::endl;
    std::cout << "All tested models combined: " << std::dec << total_faults << " exploitable faults" << std::endl;
    std::cout << "Total time: " << seconds << " seconds" << std::endl << std::endl;

    return 0;
}
