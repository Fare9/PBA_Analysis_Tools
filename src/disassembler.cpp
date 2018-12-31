#include "disassembler.h"

namespace disassembler {

    Disassembler::Disassembler(const char *filename)
    {
        loader_v = std::make_unique<loader::Loader>(filename, loader::Binary::BIN_TYPE_AUTO);

        loader_v->load_binary();

        binary_v = loader_v->getBinary();
    }
    
    Disassembler::Disassembler(loader::Binary *binary_v)
    {
        this->binary_v = binary_v;
    }

    void Disassembler::init_disassembler()
    {
        if (binary_v == nullptr)
            throw exception_t::error("incorrect binary");

        // now init disassembler of capstone
        if (binary_v->getBits() == loader::Binary::X86_32)
        {
            if (cs_open(CS_ARCH_X86, CS_MODE_32, &dis) != CS_ERR_OK)
                throw exception_t::error("failed to open capstone");
        }
        else if (binary_v->getBits() == loader::Binary::X86_64)
        {
            if (cs_open(CS_ARCH_X86, CS_MODE_64, &dis) != CS_ERR_OK)
                throw exception_t::error("failed to open capstone");
        }
        else
            throw exception_t::error("not recognized or not supported binary class");
    }

    cs_insn* Disassembler::linear_disassembly(const char *section_name)
    {
        char error_message[1000];
        size_t i;

        memset(error_message, 0, 1000);

        if (section_name == nullptr)
            throw exception_t::error("incorrect section name");
        
        if (strlen(section_name) == 0)
            throw exception_t::error("incorrect section name");
        
        for (i = 0; i < binary_v->getSections().size(); i++)
        {
            if (!strcmp(binary_v->getSections()[i].getName(), section_name))
            {
                section = &(binary_v->getSections()[i]);
                break;
            }
        }

        instruction_size = cs_disasm(dis, reinterpret_cast<const uint8_t*>(section->getBytes()), section->getSize(), section->getVMA(), 0, &instructions);

        if ( instruction_size  <= 0 )
        {
            snprintf(error_message, 999,
                "Disassembly error: %s", cs_strerror(cs_errno(dis)));
            throw exception_t::error(error_message);
        }

        return instructions;
    }

    void Disassembler::destroy_instructions()
    {
        cs_free(instructions, instruction_size);
        instruction_size = 0;
        instructions = nullptr;
    }

    void Disassembler::destroy_disassembler()
    {
        cs_close(&dis);
    }

    size_t Disassembler::get_instructions_number()
    {
        return instruction_size;
    }
}