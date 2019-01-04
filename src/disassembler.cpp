#include "disassembler.h"

namespace disassembler {

    Disassembler::Disassembler(const char *filename) : instructions(nullptr),
                                                        instruction_size(0),
                                                        section(0),
                                                        pc(nullptr),
                                                        addr(0),
                                                        offset(0),
                                                        target(0)
    {
        loader_v = std::make_unique<loader::Loader>(filename, loader::Binary::BIN_TYPE_AUTO);

        loader_v->load_binary();

        binary_v = loader_v->getBinary();
    }
    
    Disassembler::Disassembler(loader::Binary *binary_v) : instructions(nullptr),
                                                        instruction_size(0),
                                                        section(0),
                                                        pc(nullptr),
                                                        addr(0),
                                                        offset(0),
                                                        target(0)
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

    const std::vector<cs_insn *>& Disassembler::recursive_disassembly()
    {
        char error_message[1000];

        memset(error_message, 0, 1000);

        // get text section, where entry point is supposed to be
        section = binary_v->get_text_sections();
        if (section == nullptr)
        {
            throw exception_t::error("Nothing to disassemble");
        }

        cs_option(dis, CS_OPT_DETAIL, CS_OPT_ON);

        addr = binary_v->getEntryPoint();

        if (section->contains(addr))
            Q.push(addr);

        fprintf(stdout, "Entry Point: 0x%016jx\n", addr);

        for (auto &sym : binary_v->getSymbols())
        {
            if (sym.getSymbolType() == loader::Symbol::SYM_TYPE_FUNC
                && section->contains(sym.getAddr()))
            {
                Q.push(sym.getAddr());
                fprintf(stdout, "Function symbol: 0x%016jx\n", sym.getAddr());
            }
        }

        while (!Q.empty())
        {
            addr = Q.front();
            Q.pop();

            // if we've already seen that address
            if (seen[addr])
                continue;
            
            offset              = addr - section->getVMA();
            pc                  = section->getBytes() + offset;
            remainder_size      = section->getSize() - offset;

            instructions = cs_malloc(dis);
            if (!instructions)
            {
                throw exception_t::error("Error calling cs_malloc, out of memory");
            }

            while (cs_disasm_iter(
                dis,
                &pc,
                &remainder_size,
                &addr,
                instructions
            ))
            {
                instructions_vector.push_back(instructions);

                if (instructions->id == X86_INS_INVALID ||
                    instructions->size == 0)
                    break;

                instructions = cs_malloc(dis);
                if (!instructions)
                {
                    throw exception_t::error("Error calling cs_malloc, out of memory");
                }
            }

            seen[instructions->address] = true;

            if (is_cs_cflow_ins(instructions))
            {
                target = get_cs_ins_immediate_target(instructions);

                if (target && !seen[target] && section->contains(target))
                {
                    Q.push(target);
                    printf("   -> new target: 0x%016jx\n", target);    
                }
                if (is_cs_unconditional_cflow_ins(instructions))
                    break;
            } else if (instructions->id == X86_INS_HLT)
                break;
        }

        return instructions_vector;
    }

    void Disassembler::destroy_instructions_vector()
    {
        size_t i, vector_size = instructions_vector.size();
        
        for (i = 0;i < vector_size; i++)
            cs_free(instructions_vector[i], 1);

        instructions_vector.clear();
    }

    void Disassembler::destroy_instructions()
    {
        if (instruction_size > 0)
        {
            cs_free(instructions, instruction_size);
            instruction_size = 0;
            instructions = nullptr;
        }
    }

    void Disassembler::destroy_disassembler()
    {
        cs_close(&dis);
    }

    size_t Disassembler::get_instructions_number()
    {
        return instruction_size;
    }

    bool Disassembler::is_cs_cflow_group(std::uint8_t g)
    /*
    *   Check if the instruction group is inside of 
    *   one of the control flow instruction groups
    */
    {
        return (g == CS_GRP_JUMP) || (g == CS_GRP_CALL)
                || (g == CS_GRP_RET) || (g == CS_GRP_IRET);
    }

    bool Disassembler::is_cs_cflow_ins(cs_insn *ins)
    /*
    *   Check if an instruction is a control flow instruction
    */
    {
        for (size_t i = 0; i < ins->detail->groups_count; i++)
        {
            if (is_cs_cflow_group(ins->detail->groups[i]))
                return true;
        }

        return false;
    }

    bool Disassembler::is_cs_unconditional_cflow_ins(cs_insn *ins)
    {
        switch(ins->id)
        {
        case X86_INS_JMP:
        case X86_INS_LJMP:
        case X86_INS_RET:
        case X86_INS_RETF:
        case X86_INS_RETFQ:
            return true;
        default:
            return false;
        }
    }

    std::uint64_t Disassembler::get_cs_ins_immediate_target(cs_insn *ins)
    {
        cs_x86_op *cs_op;

        for (size_t i = 0; i < ins->detail->groups_count; i++)
        {
            if (is_cs_cflow_group(ins->detail->groups[i]))
            {
                for(size_t j = 0; j < ins->detail->x86.op_count; j++)
                {
                    cs_op = &ins->detail->x86.operands[i];
                    if (cs_op->type == X86_OP_IMM)
                        return cs_op->imm;
                }
            }
        }

        return 0;
    }
}