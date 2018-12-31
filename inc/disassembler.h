/***
 * Disassembler classes and functions,
 * it will use the loader to get the data
 * 
 */

#ifndef DISASSEMBLER_H
#define DISASSEMBLER_H

#include "incs.h"
#include "loader.h"
#include "error.h"
#include <capstone/capstone.h>

namespace disassembler {

class Disassembler
{
public:


    Disassembler(const char *filename);
    Disassembler(loader::Binary *binary_v);

    void init_disassembler();

    cs_insn* linear_disassembly(const char *section_name);

    void destroy_instructions();
    void destroy_disassembler();

    size_t get_instructions_number();
private:
    loader::Binary*                     binary_v;
    std::unique_ptr<loader::Loader>     loader_v;
    csh                                 dis;
    cs_insn*                            instructions;
    size_t                              instruction_size;
    loader::Section*                    section;
};


}
#endif