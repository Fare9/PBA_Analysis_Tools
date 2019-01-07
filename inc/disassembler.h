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

    typedef std::map<std::string, std::vector<std::uint64_t>> rop_gadget_t;

    Disassembler(const char *filename);
    Disassembler(loader::Binary *binary_v);

    void init_disassembler();

    cs_insn* linear_disassembly(const char *section_name);
    const std::vector<cs_insn *>& recursive_disassembly();
    const rop_gadget_t& find_rop_gadgets();


    void destroy_instructions_vector();
    void destroy_instructions();
    void destroy_disassembler();

    size_t get_instructions_number();
private:
    // private functions for recursive disassembly
    bool is_cs_cflow_group(std::uint8_t g);
    bool is_cs_cflow_ins(cs_insn *ins);
    bool is_cs_unconditional_cflow_ins(cs_insn *ins);
    std::uint64_t get_cs_ins_immediate_target(cs_insn *ins);
    // private functions for find rop gadgets
    void find_rop_gadgets_at_root(std::uint64_t root);
    bool is_cs_ret_ins(cs_insn *ins);
    bool is_cs_valid_ins(cs_insn *ins);

    loader::Binary*                                     binary_v;
    std::unique_ptr<loader::Loader>                     loader_v;
    csh                                                 dis;
    cs_insn*                                            instructions;
    size_t                                              instruction_size;
    loader::Section*                                    section;

    // recursive disassembler variables
    const std::uint8_t*                                 pc; // program counter pointer
    std::uint64_t                                       addr,
                                                        offset,
                                                        target;
    std::queue<std::uint64_t>                           Q;
    std::map<std::uint64_t,bool>                        seen;
    size_t                                              remainder_size;
    std::vector<cs_insn *>                              instructions_vector;
    cs_insn*                                            instruction;

    // find rop gadgets variables
    rop_gadget_t                                        rop_gadgets;
    std::list<std::uint8_t>                             x86_opc_ret = {0xC3, 0xC2};
};


}
#endif