#include <stdio.h>
#include <stdint.h>
#include <string>
#include <iostream>
#include <memory> // for smart pointers
#include "loader.h"
#include "error.h"

int main (int argc, char **argv)
{
	std::unique_ptr<loader::Loader> loader_v;
    loader::Binary* binary_v;
	std::string fname;
	size_t i, j;
    loader::Section* sec;
    loader::Symbol* sym;


	if (argc < 2)
	{
		fprintf(stderr,"USAGE: %s <binary> [<section_name>]\n", argv[0]);
		return 1;
	}

	fname.assign(argv[1]);

	fprintf(stdout, "file: %s\n", fname.c_str());
	try
	{
		loader_v = std::make_unique<loader::Loader>(fname.c_str(), loader::Binary::BIN_TYPE_AUTO);

		loader_v->load_binary();

        binary_v = loader_v->getBinary();

        fprintf(stdout, "[!] loaded binary '%s' %s%s (%u bits) entry@0x%016jx\n",
            binary_v->getFileName(),
            binary_v->getTypeStr(),
            binary_v->getBinaryArchStr(),
            binary_v->getBits(),
            binary_v->getEntryPoint());

        fprintf(stdout, "[+] Sections table:\n");
        for (i = 0; i < binary_v->getSections().size(); i++)
        {
            sec = &binary_v->getSections()[i];
            fprintf(stdout,"  0x%016jx %-8ju %-20s %s\n",
                sec->getVMA(), sec->getSize(), sec->getName(),
                sec->getSectionType() == loader::Section::SEC_TYPE_CODE ? "CODE" : "DATA");
        }
        
        if (binary_v->getSymbols().size())
        {
            fprintf (stdout, "[+] Symbol tables:\n");
            for (i = 0; i < binary_v->getSymbols().size(); i++)
            {
                sym = &binary_v->getSymbols()[i];
                fprintf(stdout, " %-40s 0x%016jx %s\n",
                sym->getName(),
                sym->getAddr(),
                (sym->getSymbolType() & loader::Symbol::SYM_TYPE_FUNC) ? "FUNC": (
                 (sym->getSymbolType() & loader::Symbol::SYM_TYPE_DATA) ? "DATA": "")
                );
            }
        }
        
        if (argc == 3)
        {
            fprintf (stdout, "\n[+] Section %s dump:\n", argv[2]);
            for (i = 0; i < binary_v->getSections().size(); i++)
            {
                sec = &binary_v->getSections()[i];
                if (strcmp(sec->getName(), argv[2]) == 0)
                {
                    fprintf(stdout, "%*s", 12, "");
                    for (j = 0; j < 0x10; j++)
                        fprintf(stdout, " %02X ", j);
                    for (j = 0; j < sec->getSize(); j++)
                    {
                        if (j % 0x10 == 0)
                            fprintf(stdout, "\n0x%08X: ", j);

                        fprintf(stdout, " %02X ", sec->getBytes()[j]);
                    }
                    fprintf(stdout,"\n");
                    break;
                }
            }
        }
        

        loader_v->unload_binary();
	}catch (std::exception &exc)
	{
		fprintf(stderr, "ERROR: %s\n",exc.what());
		return -1;
	}

	return 0;
}