/***
 * 
 *  Interface for binary loader, this file will define
 *  the interface to manage binaries.
 *  Don't confuse this loader with OS loader, this will
 *  be a static loader to manage binaries.
 *
 */

#ifndef LOADER_H
#define LOADER_H

#include "incs.h"
#include <bfd.h>
#include "error.h"

namespace loader {

// classes to manage binaries

class Symbol;
class Section;
class Binary;
class Loader;

class Symbol
{
public:
    
    /* enum type for symbols */
    enum SymbolType
    {
        SYM_TYPE_UKN = 0,
        SYM_TYPE_FUNC = 1,
        SYM_TYPE_DATA = 2
    };

    // generic constructor
    Symbol();

    // setters
    void setSymbolType(SymbolType new_type);
    void setName(std::string new_name);
    void setAddr(std::uint64_t new_addr);
    // getters
    SymbolType getSymbolType();
    const char* getName();
    std::uint64_t getAddr();

private:
    SymbolType      type;
    std::string     name;
    std::uint64_t   addr;
};


class Section
{
public:

    /* What does that section is */
    enum SectionType
    {
        SEC_TYPE_NONE = 0,
        SEC_TYPE_CODE = 1,
        SEC_TYPE_DATA = 2
    };

    // generic constructor
    Section();

    // setters
    void setBinary(std::shared_ptr<Binary>& new_binary);
    void setNewName(std::string new_name);
    void setNewSectionType(SectionType new_type);
    void setNewVMA(std::uint64_t new_vma);
    void setNewSize(std::uint64_t new_size);
    void setNewBytes(std::uint64_t size);
    // getters
    Binary *getBinary();
    const char* getName();
    SectionType getSectionType();
    std::uint64_t getVMA();
    std::uint64_t getSize();
    std::uint8_t* getBytes();
    // functionalities
    bool contains (std::uint64_t addr);

private:
    std::shared_ptr<Binary> binary;
    std::string             name;
    SectionType             type;
    std::uint64_t           vma;    // starting address of the section
    std::uint64_t           size;   // size in bytes
    std::uint8_t*           bytes;
};

class Binary
{
/*
*   Binary class represents a complete binary
*/
public:
    enum BinaryType
    {
        BIN_TYPE_AUTO   = 0,
        BIN_TYPE_ELF    = 1,
        BIN_TYPE_PE     = 2
    };
    enum BinaryArch
    {
        ARCH_NONE   = 0,
        ARCH_X86    = 1     // X86 include x32 and x64
    };
    enum BinaryClass
    {
        X86_32      = 32,
        X86_64      = 64
    };

    Binary();

    Section* get_text_sections();

    // setters
    void setFileName(const char* filename);
    void setType(BinaryType type);
    void setTypeStr(const char* type_str);
    void setBinaryArch(BinaryArch arch);
    void setBinaryArchStr(const char* arch_str);
    void setBits(std::uint32_t bits);
    void setEntryPoint(std::uint64_t entry);
    // getters
    const char*             getFileName();
    BinaryType              getType();
    const char*             getTypeStr();
    BinaryArch              getBinaryArch();
    const char*             getBinaryArchStr();
    std::uint32_t           getBits();
    std::uint64_t           getEntryPoint();
    std::vector<Section>&   getSections();
    std::vector<Symbol>&    getSymbols();


private:
    std::string             filename;
    BinaryType              type;
    std::string             type_str;
    BinaryArch              arch;
    std::string             arch_str;
    std::uint32_t           bits;
    std::uint64_t           entry;
    // to access sections and symbols through vectors
    std::vector<Section>    sections;
    std::vector<Symbol>     symbols;
};


class Loader
{
public:
    Loader(const char* file_name, Binary::BinaryType bin_type);

    void load_binary();
    void unload_binary();
    
    Binary* getBinary();
private:
    bool                        bfd_inited;
    std::string                 fname;
    bfd*                        bfd_h;
    std::shared_ptr<Binary>     bin;
    Binary::BinaryType          type;
    const bfd_arch_info_type*   bfd_info;

    // private function
    void open_bfd();
    void load_binary_bfd();
    void load_symbols_bfd();
    void load_dynsym_bfd();
    void load_sections_bfd();
    void remove_symbol_by_name(const char* name);
};


}


#endif // LOADER_H
