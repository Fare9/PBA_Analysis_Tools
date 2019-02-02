/*
*   Compile: make PIN_ROOT="<path_to_pin>"
*/
#include "unpacker.h"

/******************* Data for the unpacker *******************/
FILE *logfile; // log file handler
std::map<ADDRINT, mem_access_t> shadow_mem; // map memory addresses with memory
                                            // access permissions.
std::vector<mem_cluster_t> clusters;    // vector to store all the unpacked memory
                                        // clusters found
ADDRINT saved_addr; // temporary variable needed for storing state between
                    // two analysis routines

/***
 *  Note we use a vector for clusters
 *  because it is possible to have multiple 
 *  layers of packing. So when we detect a 
 *  control transfer to a previously written
 *  memory region, there's no way to know
 *  if we are jumping to the OEP or simply
 *  jump to bootstrap code of next packer
 */
        

/*
*   KNOB class to create arguments with PIN
*   on this case, we will create an argument
*   string for the user if wants to save
*   logs in a file.
*/
KNOB<string> KnobLogFile(
    KNOB_MODE_WRITEONCE,
    "pintool",
    "l", // command acepted (-l)
    "unpacker.log", // value of the command, log file name
    "log file"
);

/******************* unpacker funcionts *******************/
static void fini(INT32 code, void *v);
static void print_clusters();
static bool cmp_cluster_size(const mem_cluster_t &c, const mem_cluster_t &d);
static void fsize_to_str(unsigned long size, char *buf, unsigned len);

static void instrument_mem_cflow(INS ins, void *v);
static void queue_memwrite(ADDRINT addr);
static void log_memwrite(UINT32 size);
static void check_indirect_ctransfer(ADDRINT ip, ADDRINT target);
static void mem_to_file(mem_cluster_t *c, ADDRINT entry);
static void set_cluster(ADDRINT target, mem_cluster_t *c);
static bool in_cluster(ADDRINT target);

int main (int argc, char *argv[])
{
    /*
    *   Function to initialize the Pintool
    *   always called before almost any other PIN 
    *   function (only PIN_InitSymbols can be before)
    */
   if (PIN_Init(argc, argv) != 0)
   {
       fprintf(stderr, "PIN_Init failed\n");
       return 1;
   }

    // open log file to append
    logfile = fopen(KnobLogFile.Value().c_str(), "a");
    if (!logfile)
    {
        fprintf(stderr, "failed to open '%s'\n", KnobLogFile.Value().c_str());
        return 1;
    }

    fprintf(logfile, "------ unpacking binary ------\n");

    /*
    *   Add instrumentation function at Instruction tracer level
    *   in opposite to TRACE instrumentation, this goes to an 
    *   instruction granularity.
    */
    INS_AddInstrumentFunction(instrument_mem_cflow, NULL);

    /*
    *   Add the fini function
    */
    PIN_AddFiniFunction(fini, NULL);

    /*
    *   RUN the program and never return
    */
    PIN_StartProgram();

    return 1;
}


static void fini(INT32 code, void *v)
/*
*   Function that will be executed at the end
*   of the execution or when PIN detachs from
*   the process.
*/
{
    print_clusters();
    // save final log and close file
    fprintf(logfile, "------ unpacking complete ------\n");
    fclose(logfile);
}

static void print_clusters()
/*
*   Function to print the finish end data
*   to the log file
*/
{
    ADDRINT addr, base;
    unsigned long size;
    bool w, x;
    unsigned j, n, m;
    char buf[32];
    std::vector<mem_cluster_t> clusters;
    std::map<ADDRINT, mem_access_t>::iterator i;

    /* create the consecutive clusters with shadow_mem */
    base = 0;
    size = 0;
    w    = false;
    x    = false;

    for (i = shadow_mem.begin(); i != shadow_mem.end(); i++)
    {
        addr = i->first;
        if (addr == base + size)
        {
            if (i->second.w)
                w = true;
            if (i->second.x)
                x = true;
            size++;
        } else 
        {
            if (base > 0)
            {
                clusters.push_back(mem_cluster_t(base, size, w, x));
            }
            base    = addr;
            size    = 1;
            w       = i->second.w;
            x       = i->second.x;
        }
    }

    // find the largest cluster, as this will be the size  of the memory
    size = 0;
    for (j = 0; j < clusters.size(); j++)
    {
        if (clusters[j].size > size)
        {
            size = clusters[j].size;
        }
    }

    /* sort by largest cluster */
    std::sort(clusters.begin(), clusters.end(), cmp_cluster_size);

    // print cluster bar graph
    fprintf(logfile, "****** Memory access clusters ******\n");
    for (j = 0; j < clusters.size(); j++) 
    {
        n = ((float) clusters[j].size/size) * 80;
        fsize_to_str(clusters[j].size, buf, 32);
        fprintf(logfile, "0x%016jx (%9s) %s%s: ",
                clusters[j].base, buf,
                clusters[j].w ? "w" : "-", clusters[j].x ? "x" : "-");
        for (m = 0; m < n; m++)
        {
            fprintf(logfile, "=");
        }
        fprintf(logfile, "\n");
    }
}

static bool cmp_cluster_size(const mem_cluster_t &c, const mem_cluster_t &d)
/*
*   Easy, compares two values from two structures...
*/
{
    return c.size > d.size;
}

static void fsize_to_str(unsigned long size, char *buf, unsigned len)
{
    int i;
    double d;
    const char *units[] = {"B", "kB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB"};

    i = 0;
    d = (double)size;
    while (d > 1024)
    {
        d /= 1024;
        i++;
    }

    if (!strcmp(units[i], "B"))
    {
        snprintf(buf, len, "%.0f%s", d, units[i]);
    }
    else
    {
        snprintf(buf, len, "%.1f%s", d, units[i]);
    }
}

static void instrument_mem_cflow(INS ins, void *v)
/*
*   Function to instrument each instruction
*   we will use this function to record the
*   written memory, and the jumps to those 
*   memory.
*/
{
    if (    INS_IsMemoryWrite(ins)      // check if the instruction writes to memory
        &&  INS_hasKnownMemorySize(ins) // if memory size is known
    )
    {
        // this first three callbacks will be used for tracking memory writes

        /*
        *   This callback will be used to track only the address of the destination
        *   unfortunately only it's possible to know this data before of instruction
        *   execution, so we will use it to save  address of destination in one of
        *   the global variables.
        */
        INS_InsertPredicatedCall(
            ins,
            IPOINT_BEFORE,              // execute function before instruction
            (AFUNPTR) queue_memwrite,   // function to execute
            IARG_MEMORYWRITE_EA,        // argument = memory where it is going to write
            IARG_END                    // no more arguments
        );

        /*
        *   Once we have the address, we can copy the data to our 
        *   shadow_mem with the size of the copy. So for that reason
        *   we insert the callback even if copy it has a fall through
        *   instruction, or it is branch or call.
        */

        // In case branch has another block of code when jump is not taken
        if (INS_HasFallThrough(ins))
        {
            INS_InsertPredicatedCall(
                ins,
                IPOINT_AFTER,           // execute callback after instruction
                (AFUNPTR)log_memwrite,  // function to execute
                IARG_MEMORYWRITE_SIZE,  // argument, written size
                IARG_END                // no more arguments
            );
        }

        // check if instruction is branch or call
        if (INS_IsBranchOrCall(ins))
        {
            INS_InsertPredicatedCall(
                ins,
                IPOINT_TAKEN_BRANCH,        // execute callback only if branch is taken
                (AFUNPTR)log_memwrite,      // function to execute
                IARG_MEMORYWRITE_SIZE,      // argument = size of the written memory
                IARG_END                    // no more arguments
            );
        }
    }

    /*
    *   As our purpose is to detect when the control is transfered to 
    *   the original entry point and dump the unpacked binary.
    *   We insert a callback for indirect branches and calls, to check
    *   if the branch target it is a previously writable memory region
    *   and if so, marks it as a possible jump to OEP.
    */
    if (INS_IsIndirectBranchOrCall(ins)
        &&  (INS_OperandCount(ins) > 0))
    {
        // like INS_InsertPredicatedCall but always called
        INS_InsertCall(
            ins,
            IPOINT_BEFORE,                      // call callback before execute instruction
            (AFUNPTR)check_indirect_ctransfer,  // argument = callback to call
            IARG_INST_PTR,                      // argument = address of this branch
            IARG_BRANCH_TARGET_ADDR,            // argument = address where is going to jump
            IARG_END                            // no more arguments
        );
    }
}

static void queue_memwrite(ADDRINT addr)
/*
*   Function which will save for a moment the address
*   of the instruction which will copy memory.
*   This is necessary as only before of the instruction
*   execution is possible to record the address
*/
{
    saved_addr = addr;
}

static void log_memwrite(UINT32 size)
/*
*   Function to log in shared_mem the address and the size of
*   copied data from a copy instruction
*/
{
    ADDRINT addr = saved_addr;

    for (ADDRINT i = addr; i < addr+size; i++)
    {
        // record each address from the memory, to know which
        // address had the write permission
        shadow_mem[i].w = true;
        PIN_SafeCopy(&(shadow_mem[i].val), (const void*)i, 1); // copy the value from that memory
    }
}

static void check_indirect_ctransfer(ADDRINT ip, ADDRINT target)
/*
*   Function to detect the jump to the OEP and dump the unpacked code.
*   we will use the shadow_mem to detect if a memory was used as a target
*   of a copy, we will taint that memory as possible OEP.
*/
{
    mem_cluster_t c;

    // set memory target as executable
    shadow_mem[target].x = true;

    // check if the target was writable, and it hasn't been dumped before.
    if (shadow_mem[target].w && !in_cluster(target))
    {
        /* control transfer to a once-writeable memory region, suspected transfer
        *  to original entry point of an unpacked binary */
       set_cluster(target, &c);
       clusters.push_back(c);
       /* dump the new cluster containing the unpacked region to file */
       mem_to_file(&c, target);
       /* don't stop here as might be multiple unpacking stages */
    }
}

static void mem_to_file(mem_cluster_t *c, ADDRINT entry)
{
    FILE *f;
    char buf[128];

    fsize_to_str(c->size, buf, 128);
    fprintf(logfile, "extracting unpacked region 0x%016jx (%9s) %s%s entry 0x%016jx\n", 
          c->base, buf, c->w ? "w" : "-", c->x ? "x" : "-", entry);

    snprintf(buf, sizeof(buf), "unpacked.0x%jx-0x%jx_entry-0x%jx", 
           c->base, c->base+c->size, entry);

    f = fopen(buf, "wb");

    if(!f) 
    {
        fprintf(logfile, "failed to open file '%s' for writing\n", buf);
    } 
    else 
    {
        for(ADDRINT i = c->base; i < c->base+c->size; i++) 
        {
            if(fwrite((const void*)&shadow_mem[i].val, 1, 1, f) != 1) 
            {
                fprintf(logfile, "failed to write unpacked byte 0x%jx to file '%s'\n", i, buf);
            }
        }
        fclose(f);
    }
}

static void set_cluster(ADDRINT target, mem_cluster_t *c)
/*
*   Calculate memory cluster using target and shadow_mem
*   it will calculate base address and size.
*/
{
    ADDRINT addr, base;
    unsigned long size;
    bool w, x;
    std::map<ADDRINT, mem_access_t>::iterator i, j;

    j = shadow_mem.find(target);
    assert(j != shadow_mem.end());

    /* scan back to base of cluster */
    base = target;
    w    = false;
    x    = false;

    for (i = j; ; i--)
    {
        addr = i->first;

        if (addr == base)
        {
            /*
            *   If the address from the shadow mem it is the same
            *   to the one on base, it means we're still inside of 
            *   same memory chunk, move the base one backward to check
            *   the memory again.
            */
            if (i->second.w)
                w = true;
            if (i->second.x)
                x = true;
            base--;
        }
        else
        {
            /*
            *   If the memory it is not the same it means we got some
            *   shadow_mem wich it is not part of this memory chunk so
            *   finally we have the real base - 1 of the memory chunk.
            */
            base++; // fix base
            break;
        }

        if (i == shadow_mem.begin())
        {
            /*
            *   Uhhhh big problem, we are in the beginning
            *   of the shadow_mem map, so this should be the
            *   base address
            */
            base++;
            break;
        }
    }

    /* scan forward to end of cluster
    also get the size of the memory chunk */
    size = target-base;
    for (i = j; i != shadow_mem.end(); i++)
    {
        addr = i->first;
        if (addr == base+size)
        {
            /*
            *   Check if the address from shadow_mem
            *   is in the memory chunk
            */
            if (i->second.w)
                w = true;
            if (i->second.x)
                x = true;
            size++;
        }
        else
        {
            // if it's not in the range, leave
            break;
        }
    }

    // finally write information in the mem cluster
    c->base = base;
    c->size = size;
    c->w    = w;
    c->x    = x;
}

static bool in_cluster(ADDRINT target)
/*
*   Function to check target address is inside of
*   any memory cluster.
*/
{
    mem_cluster_t *c;

    for (unsigned i = 0; i < clusters.size(); i++)
    {
        c = &clusters[i];

        if (c->base <= target &&
            target < c->base + c->size)
        {
            return true;
        }
    }

    return false;
}