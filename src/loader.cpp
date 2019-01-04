#include "loader.h"

namespace loader {

    /*
    *   Symbol functions
    */

    Symbol::Symbol() : type(SYM_TYPE_UKN), 
                    name(), 
                    addr(0) 
    {}

    void Symbol::setSymbolType(SymbolType new_type)
    {
        if (new_type != SYM_TYPE_UKN && 
            new_type != SYM_TYPE_FUNC &&
            new_type != SYM_TYPE_DATA)
        {
            throw exception_t::error("Error symbol type incorrect");
        }
        else
        {
            this->type = new_type;
        }
    }

    void Symbol::setName(std::string new_name)
    {
        this->name = new_name;
    }

    void Symbol::setAddr(std::uint64_t new_addr)
    {
        this->addr = new_addr;
    }

    Symbol::SymbolType Symbol::getSymbolType()
    {
        return this->type;
    }

    const char* Symbol::getName()
    {
        return this->name.c_str();
    }

    std::uint64_t Symbol::getAddr()
    {
        return this->addr;
    }

    /*
    *   Section functions
    */

    Section::Section() : type(SEC_TYPE_NONE),
                        vma(0),
                        size(0),
                        bytes(NULL)
    {
        binary = std::make_shared<Binary>();
    }

    void Section::setBinary(std::shared_ptr<Binary>& new_binary)
    {
        this->binary = new_binary;
    }

    void Section::setNewName(std::string new_name)
    {
        this->name = new_name;
    }

    void Section::setNewSectionType(SectionType new_type)
    {
        if (new_type != SEC_TYPE_NONE &&
            new_type != SEC_TYPE_CODE &&
            new_type != SEC_TYPE_DATA)
        {
            throw exception_t::error("Error section type incorrect");
        }
        else
        {
            this->type = new_type;
        }
    }

    void Section::setNewVMA(std::uint64_t new_vma)
    {
        this->vma = new_vma;
    }

    void Section::setNewSize(std::uint64_t new_size)
    {
        this->size = new_size;
    }

    void Section::setNewBytes(std::uint64_t size)
    {
        this->bytes = (std::uint8_t*) malloc (size);
    }

    Binary* Section::getBinary()
    {
        return this->binary.get();
    }

    const char* Section::getName()
    {
        return this->name.c_str();
    }

    Section::SectionType Section::getSectionType()
    {
        return this->type;
    }

    std::uint64_t Section::getVMA()
    {
        return this->vma;
    }

    std::uint64_t Section::getSize()
    {
        return this->size;
    }

    std::uint8_t* Section::getBytes()
    {
        return this->bytes;
    }

    bool Section::contains(std::uint64_t addr)
    {
        return (addr >= vma) && ((addr-vma) < size);
    }

    /*
    *   Binary functions
    */

    Binary::Binary() : type(BIN_TYPE_AUTO),
                      arch(ARCH_NONE),
                      bits(0),
                      entry(0)
    {}

    Section* Binary::get_text_sections()
    {
        for (auto &s : sections)
        {
            if (strcmp(s.getName(),".text") == 0)
                return &s;
        }
        return nullptr;
    }


    void Binary::setFileName(const char* filename)
    {
        this->filename = filename;
    }

    void Binary::setType(BinaryType type)
    {
        this->type = type;
    }

    void Binary::setTypeStr(const char* type_str)
    {
        this->type_str = std::string(type_str);
    }

    void Binary::setBinaryArch(BinaryArch arch)
    {
        this->arch = arch;
    }

    void Binary::setBinaryArchStr(const char* arch_str)
    {
        this->arch_str = std::string(arch_str);
    }

    void Binary::setBits(std::uint32_t bits)
    {
        this->bits = bits;
    }

    void Binary::setEntryPoint(std::uint64_t entry)
    {
        this->entry = entry;
    }

    const char* Binary::getFileName()
    {
        return this->filename.c_str();
    }

    Binary::BinaryType Binary::getType()
    {
        return this->type;
    }

    const char* Binary::getTypeStr()
    {
        return this->type_str.c_str();
    }

    Binary::BinaryArch Binary::getBinaryArch()
    {
        return this->arch;
    }

    const char* Binary::getBinaryArchStr()
    {
        return this->arch_str.c_str();
    }

    std::uint32_t Binary::getBits()
    {
        return this->bits;
    }

    std::uint64_t Binary::getEntryPoint()
    {
        return this->entry;
    }

    std::vector<Section>& Binary::getSections()
    {
        return this->sections;
    }

    std::vector<Symbol>& Binary::getSymbols()
    {
        return this->symbols;
    }

    /*
    *   Loader functions
    */
    Loader::Loader(const char* file_name, Binary::BinaryType bin_type) : bfd_inited(false),
                                      fname(file_name),
                                      bfd_h(nullptr),
                                      type(bin_type)
    {
        bin = std::make_shared<Binary>();
    }

    
    /*
    *   public functions
    */
    void Loader::load_binary()
    {
        load_binary_bfd();
    }

    void Loader::unload_binary()
    {
        size_t i;
        Section *sec;

        for (i = 0; i < bin->getSections().size(); i++)
        {
            sec = &bin->getSections()[i];
            if (sec->getBytes())
            {
                free(sec->getBytes());
            }
        }
    }

    Binary* Loader::getBinary()
    {
        return this->bin.get();
    }

    /*
    *   Private functions
    */
    void Loader::open_bfd()
    {
        char error_message[1000];

        memset(error_message,0,1000);

        if (!bfd_inited)
        {
            bfd_init();
            bfd_inited = true;
        }

        bfd_h = bfd_openr(fname.c_str(), NULL);

        if (!bfd_h)
        {
            snprintf(error_message,999,"failed to open binary '%s' (%s)", 
                fname.c_str(),
                bfd_errmsg(bfd_get_error()));

            throw exception_t::error(error_message);
        }

        /*
        *   The second argument of bfd_check_format could be:
        *       bfd_object
        *       bfd_archive
        *       bfd_core
        */
        if (!bfd_check_format(bfd_h, bfd_object)) 
        {
            snprintf(error_message, 999, "file '%s' does not look like an executable (%s)\n",
                fname.c_str(),
                bfd_errmsg(bfd_get_error()));

            throw exception_t::error(error_message);
        }

        /*
        *   Some bfd_check_format versions set wrong_format error even before detecting
        *   the format and then neglect to unset this error value once the format has 
        *   been detected. Unset it manually to prevent problems
        */
        bfd_set_error(bfd_error_no_error);

        /*
        *   bfd_get_flavour get type of binary we are opening:
        *       ELF
        *       PE
        *       etc
        */
        if (bfd_get_flavour(bfd_h) == bfd_target_unknown_flavour)
        {
            snprintf(error_message, 999, "unrecognized format for binary '%s' (%s)",
                fname.c_str(),
                bfd_errmsg(bfd_get_error()));

            throw exception_t::error(error_message);
        }
    }

    void Loader::load_binary_bfd()
    {
        // initialize bfd object
        char error_message[1000];

        memset(error_message, 0, 1000);

        open_bfd();

        bin->setFileName(fname.c_str());

        bin->setEntryPoint(static_cast<std::uint64_t>(bfd_get_start_address(bfd_h)));
        bin->setTypeStr(bfd_h->xvec->name);

        switch (bfd_h->xvec->flavour)
        {
        case bfd_target_elf_flavour:
            bin->setType(Binary::BIN_TYPE_ELF);
            break;
        case bfd_target_coff_flavour:
            bin->setType(Binary::BIN_TYPE_PE);
            break;
        case bfd_target_unknown_flavour:
        default:
            snprintf(error_message,999, "unsupported binary type (%s)\n", bfd_h->xvec->name);
            throw exception_t::error(error_message);
        }

        bfd_info = bfd_get_arch_info(bfd_h);
        bin->setBinaryArchStr(bfd_info->printable_name);

        switch (bfd_info->mach)
        {
        case bfd_mach_i386_i386:
            bin->setBinaryArch(Binary::ARCH_X86);
            bin->setBits(Binary::X86_32);
            break;
        case bfd_mach_x86_64:
            bin->setBinaryArch(Binary::ARCH_X86);
            bin->setBits(Binary::X86_64);
            break;
        default:
            snprintf(error_message, 999, "unsupported architecture (%s)\n", bfd_info->printable_name);
            throw exception_t::error(error_message);
        }

        /* Symbol handling is best-effort only (they may not even be present) */
        load_symbols_bfd();
        load_dynsym_bfd();

        load_sections_bfd();

        if (bfd_h)
            bfd_close(bfd_h);
    }

    void Loader::load_symbols_bfd()
    {
        long n, nsyms, i;
        asymbol **bfd_symtab;
        Symbol *sym;
        char error_message[1000];
        std::vector<std::string> weak_names;

        memset(error_message, 0, 1000);

        bfd_symtab = nullptr;

        n = bfd_get_symtab_upper_bound(bfd_h);

        if (n < 0)
        {
            snprintf(error_message, 999, "failed to read symtab (%s)",
                bfd_errmsg(bfd_get_error()));
            throw exception_t::error(error_message);
        }
        else if (n)
        {
            bfd_symtab = (asymbol**) malloc (n);
            if (!bfd_symtab)
            {
                throw exception_t::error("Error allocating memory for symbols");
            }

            nsyms = bfd_canonicalize_symtab(bfd_h, bfd_symtab);
            if (nsyms < 0)
            {
                snprintf(error_message, 999, "failed to read symtab (%s)",
                    bfd_errmsg(bfd_get_error()));
                throw exception_t::error(error_message);
            }

            for (i = 0; i < nsyms; i++)
            {
                if (std::find(weak_names.begin(), weak_names.end(), std::string(bfd_symtab[i]->name)) != weak_names.end())
                {
                    remove_symbol_by_name(bfd_symtab[i]->name);
                    weak_names.erase(
                        std::remove(weak_names.begin(), weak_names.end(), std::string(bfd_symtab[i]->name)), 
                        weak_names.end());
                }

                if (bfd_symtab[i]->flags & BSF_WEAK)
                {
                    weak_names.push_back(std::string(bfd_symtab[i]->name));
                }

                if (bfd_symtab[i]->flags & BSF_FUNCTION)
                {
                    bin->getSymbols().push_back(Symbol());
                    sym = &bin->getSymbols().back();
                    sym->setSymbolType(Symbol::SYM_TYPE_FUNC);
                    sym->setName(std::string(bfd_symtab[i]->name));
                    sym->setAddr(static_cast<std::uint64_t>(bfd_asymbol_value(bfd_symtab[i])));
                }
                else if (((bfd_symtab[i]->flags & BSF_LOCAL) ||
                          (bfd_symtab[i]->flags & BSF_GLOBAL)) &&
                          bfd_symtab[i]->flags & BSF_OBJECT)
                {
                    bin->getSymbols().push_back(Symbol());
                    sym = &bin->getSymbols().back();
                    sym->setSymbolType(Symbol::SYM_TYPE_DATA);
                    sym->setName(std::string(bfd_symtab[i]->name));
                    sym->setAddr(static_cast<std::uint64_t>(bfd_asymbol_value(bfd_symtab[i])));
                }
            }
        }

        if (bfd_symtab)
            free(bfd_symtab);
    }

    void Loader::load_dynsym_bfd()
    {
        long n, nsyms, i;
        asymbol** bfd_dynsym;
        Symbol *sym;
        std::vector<std::string> weak_names;
        char error_message[1000];

        memset(error_message, 0, 1000);
        bfd_dynsym = nullptr;

        n = bfd_get_dynamic_symtab_upper_bound(bfd_h);
        if (n < 0)
        {
            snprintf(error_message, 999, "failed to read dynamic symtab (%s)",
                bfd_errmsg(bfd_get_error()));
            throw exception_t::error(error_message);
        }
        else if (n)
        {
            bfd_dynsym = (asymbol**) malloc (n);
            if (!bfd_dynsym)
                throw exception_t::error("Not possible to allocate memory for dynamic symbols");

            nsyms = bfd_canonicalize_dynamic_symtab(bfd_h, bfd_dynsym);
            if (nsyms < 0)
            {
                snprintf(error_message, 999, "failed to read dynamic symtab (%s)",
                    bfd_errmsg(bfd_get_error()));
                throw exception_t::error(error_message);
            }

            for (i = 0; i < nsyms; i++)
            {
                if (std::find(weak_names.begin(), weak_names.end(), std::string(bfd_dynsym[i]->name)) != weak_names.end())
                {
                    remove_symbol_by_name(bfd_dynsym[i]->name);
                    weak_names.erase(
                        std::remove(weak_names.begin(), weak_names.end(), std::string(bfd_dynsym[i]->name)), 
                        weak_names.end());
                }

                if (bfd_dynsym[i]->flags & BSF_WEAK)
                {
                    weak_names.push_back(std::string(bfd_dynsym[i]->name));
                }

                if (bfd_dynsym[i]->flags & BSF_FUNCTION)
                {
                    bin->getSymbols().push_back(Symbol());
                    sym = &bin->getSymbols().back();
                    sym->setSymbolType(Symbol::SYM_TYPE_FUNC);
                    sym->setName(std::string(bfd_dynsym[i]->name));
                    sym->setAddr(static_cast<std::uint64_t>(bfd_asymbol_value(bfd_dynsym[i])));
                }else if (((bfd_dynsym[i]->flags & BSF_LOCAL) ||
                          (bfd_dynsym[i]->flags & BSF_GLOBAL)) &&
                          bfd_dynsym[i]->flags & BSF_OBJECT)
                {
                    bin->getSymbols().push_back(Symbol());
                    sym = &bin->getSymbols().back();
                    sym->setSymbolType(Symbol::SYM_TYPE_DATA);
                    sym->setName(std::string(bfd_dynsym[i]->name));
                    sym->setAddr(static_cast<std::uint64_t>(bfd_asymbol_value(bfd_dynsym[i])));
                }
            }
        }

        if (bfd_dynsym)
            free (bfd_dynsym);
    }

    void Loader::load_sections_bfd()
    {
        int bfd_flags;
        std::uint64_t vma, size;
        const char *secname;
        asection* bfd_sec;
        Section *sec;
        Section::SectionType sectype;
        char error_message[1000];

        memset(error_message, 0, 1000);

        for (bfd_sec = bfd_h->sections; bfd_sec; bfd_sec = bfd_sec->next)
        {
            bfd_flags = bfd_get_section_flags(bfd_h, bfd_sec);

            sectype = Section::SEC_TYPE_NONE;
            if (bfd_flags & SEC_CODE)
                sectype = Section::SEC_TYPE_CODE;
            else if (bfd_flags & SEC_DATA)
                sectype = Section::SEC_TYPE_DATA;
            else
                continue;

            vma     = bfd_section_vma(bfd_h, bfd_sec);
            size    = bfd_section_size(bfd_h, bfd_sec);
            secname = bfd_section_name(bfd_h, bfd_sec);
            if (!secname)
                secname = "<unnamed>";

            bin->getSections().push_back(Section());
            sec = &bin->getSections().back();

            sec->setBinary(bin);
            sec->setNewName(std::string(secname));
            sec->setNewSectionType(sectype);
            sec->setNewVMA(vma);
            sec->setNewSize(size);
            sec->setNewBytes(size);
            if (sec->getBytes() == nullptr)
            {
                throw exception_t::error("Error allocating bytes for section data");
            }

            if (!bfd_get_section_contents(bfd_h, bfd_sec, sec->getBytes(), 0, size))
            {
                snprintf(error_message, 999, "failed to read section '%s' (%s)",
                    secname, bfd_errmsg(bfd_get_error()));
                throw exception_t::error(error_message);
            }
        }
    }

    void Loader::remove_symbol_by_name(const char* name)
    {
        size_t i;

        for (i = 0; i < bin->getSymbols().size(); i++)
        {
            if (strcmp(bin->getSymbols()[i].getName(), name) == 0)
            {
                bin->getSymbols().erase(bin->getSymbols().begin() + i);
                break;
            }
        }
    }
} // loader