// necessary in every file to access the Pin API.
// It provides the entire API
#include "pin.H"

#include <iostream>
#include <cstdio>
#include <string>

/*
*   Pin observes the program from the first instruction,
*   also those belonged to the dynamic loader and shared
*   libraries.
*/

/*
*   Pintools can implement specific command line options
*   called knobs in Pin.
*   The Pin API includes a dedicated KNOB class to create a
*   command line options. Here we have two Boolean options 
*   (KNOB<bool>) called ProfileCalls and ProfileSyscalls.
*   The options use mode KNOB_MODE_WRITEONCE because they're
*   Boolean flags that are set only once when you supply the flag.
*   Both options by default have value 0, meaning they're false
*   if we don't pass flag.
*/
KNOB<bool> ProfileCalls(
    KNOB_MODE_WRITEONCE, // check only for the flag (no more values)
    "pintool",
    "c", // flag should be "-c"
    "0", // default value
    "Profile function calls"
);

KNOB<bool> ProfileSyscalls(
    KNOB_MODE_WRITEONCE,
    "pintool",
    "s", // flag should be "-s"
    "0",
    "Profile syscalls"
);

/*
*   Structures and counters for the program.
*   cflows and calls: map addresses of control flow targets
*   to another map that in turn tracks the addresses of
*   the control flow instructions (jumps, calls, etc) that
*   invoked each target and counts how often that control
*   transfer was taken.
*   syscall map tracks how often each syscall number was
*   invoked.
*   funcnames maps function addresses to symbolic names.
*/
std::map<ADDRINT, std::map<ADDRINT, unsigned long> > cflows;
std::map<ADDRINT, std::map<ADDRINT, unsigned long> > calls;
std::map<ADDRINT, unsigned long> syscalls;
std::map<ADDRINT, std::string> funcnames;

/*
*   This counters track the total number of executed instructions,
*   control flow instructions, calls, and syscalls.
*/
unsigned long insn_count    = 0;
unsigned long cflow_count   = 0;
unsigned long call_count    = 0;
unsigned long syscall_count = 0;

// declaration of functions
static void print_usage();
static void print_results(INT32 code, void *v);
static void parse_funcsyms(IMG img, void *v);
static void instrument_trace(TRACE trace, void *v);
static void instrument_bb(BBL bb);
static void instrument_insn(INS ins, void *v);
static void count_bb_insns (UINT32 n);
static void count_cflow ( ADDRINT ip, ADDRINT target);
static void count_call( ADDRINT ip, ADDRINT target);
static void log_syscall ( THREADID tid, CONTEXT *ctxt, SYSCALL_STANDARD std, VOID *v);

int main (int argc, char *argv[])
{
    // this function causes Pin to read the application's
    // symbol tables. If we want to use symbols It is 
    // necessary to call this function.
    PIN_InitSymbols();

    // This function initializes Pin and must be called before
    // almost any other Pin function. Returns true if anything
    // went wrong during initialization
    // This function also processes Pin's command line options
    // as well as Pintool's options as specified by the KNOBs
    // we created.
    if (PIN_Init( argc, argv))
    {
        print_usage();
        return 1;
    }

    /*
    *   Now we register three instrumentation routines.
    *   The first function parse_funcsyms instruments
    *   at image granularity, instrument_trace at trace
    *   granularity and instrument_insn instrument at 
    *   instruction granularity.
    * 
    *   This three functions take an IMG, a TRACE, and an
    *   INS object as their first parameter. Additionally,
    *   they all take a void* as second parameter, which allows
    *   us to pass a Pintool-specific data structure that
    *   we specify when we register the instrumentation routines
    *   using *_AddInstrumentFunction. We will use NULL for the moment.
    */

    IMG_AddInstrumentFunction(parse_funcsyms, NULL);
    TRACE_AddInstrumentFunction(instrument_trace, NULL);
    INS_AddInstrumentFunction(instrument_insn, NULL);

    
    if (ProfileSyscalls.Value()) // check if ProfileSyscalls was given as argument
    {
        /*
        *   Pin also allows us to register function called before or
        *   after every syscall.
        *   To register the funcion log_syscall before a syscall, we
        *   use PIN_AddSyscallEntryFunction.
        */
        PIN_AddSyscallEntryFunction(log_syscall, NULL);
    }

    /*
    *   Register a Fini function called when the
    *   application exits or when we detach Pin from it.
    *   Fini function recieves an exit_status_code (INT32)
    *   and a user-defined void*. So to register the function
    *   print_results we use PIN_AddFiniFunction.
    */
    PIN_AddFiniFunction(print_results, NULL);

    /*
    *   Finally execute the program.
    */
    // Never returns
    PIN_StartProgram();

    return 0;
}

/***************************************************
 * Function to print the usage of the tool
 * ************************************************/
static void print_usage()
{
  std::string help = KNOB_BASE::StringKnobSummary();

  fprintf(stderr, "\nProfile call and jump targets\n");
  fprintf(stderr, "%s\n", help.c_str());
}

/***************************************************
 * Function to print the results of the profiler
 * ************************************************/
static void print_results(INT32 code, void *v)
{
  ADDRINT ip, target;
  unsigned long count;
  std::map<ADDRINT, std::map<ADDRINT, unsigned long> >::iterator i;
  std::map<ADDRINT, unsigned long>::iterator j;

  printf("executed %lu instructions\n\n", insn_count);

  printf("******* CONTROL TRANSFERS *******\n");
  for(i = cflows.begin(); i != cflows.end(); i++) 
  {
    target = i->first;
    for(j = i->second.begin(); j != i->second.end(); j++) {
      ip = j->first;
      count = j->second;
      printf("0x%08jx <- 0x%08jx: %3lu (%0.2f%%)\n", 
             target, ip, count, (double)count/cflow_count*100.0);
    } 
  }

  if(!calls.empty()) {
    printf("\n******* FUNCTION CALLS *******\n");
    for(i = calls.begin(); i != calls.end(); i++) {
      target = i->first;

      for(j = i->second.begin(); j != i->second.end(); j++) {
        ip = j->first;
        count = j->second;
        printf("[%-30s] 0x%08jx <- 0x%08jx: %3lu (%0.2f%%)\n", 
               funcnames[target].c_str(), target, ip, count, (double)count/call_count*100.0);
      } 
    }
  }

  if(!syscalls.empty()) {
    printf("\n******* SYSCALLS *******\n");
    for(j = syscalls.begin(); j != syscalls.end(); j++) {
      count = j->second;
      printf("%3ju: %3lu (%0.2f%%)\n", j->first, count, (double)count/syscall_count*100.0);
    }
  }
}


/***************************************************************/

/***************************************************
 * Function to parse function symbols at an IMAGE granularity
 * this are functions that are called when a new image (an executable
 * or shared library) loads, allowing us to instrument the image as a
 * whole. This lets us loop over all the functions in the image
 * and add analysis routines that run before or after after each function.
 * Function instrumentation is reliably only if the binary contains symbolic
 * information, and after-function instrumentation doesn't work with some
 * optimizations such as tail calls. But in this case we don't add
 * any instrumentation at all. We inspect the symbolic names of all
 * functions in the image. Profiles saves these names so it can read them
 * back later to show human readable function names in the output.
 * ************************************************/
static void parse_funcsyms(IMG img, void *v)
{
    if (!IMG_Valid(img)) // check if image is correct
        return;

    // SEC object represents all the sections.
    // IMG_SecHead get first section
    // SEC_Next get next section
    // SEC_Valid check section is correct (or last).
    for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec))
    {
        // RTN represent each function (routine)
        // SEC_RtnHead gives us first function
        // RTN_Next gives us next function
        // RTN_Valid check if function is valid (or last).
        for (RTN rtn = SEC_RtnHead(sec); RTN_Valid(rtn); rtn = RTN_Next(rtn))
        {
            // RTN_Address get function address
            // RTN_Name get function name
            funcnames[RTN_Address(rtn)] = RTN_Name(rtn);
        }
    }
}

/***************************************************************/

/*
 *   One of the things this profiler records is the number of
 *   instructions the program executes. To that end, the profiler
 *   instruments every basic block with a call to an analysis function
 *   that increases the instruction counter by the number of instructions
 *   in the basic block.
*/

/*
 *   Notes about Basic Blocks in PIN
 *
 *   Pin discovers basic blocks dynamically, the basic blocks that PIN
 *   finds may differ what we would find based on static analysis.
 *   Pin may initially find a large basic block, only to later discover a
 *   jump into the middle of that basic block, forcing Pin to renew its
 *   decision, break the basic block in two, and reinstrument both basic
 *   blocks. This doesn't matter for the profiler since it doesn't care
 *   about the shape of basic blocks, only the number of executes 
 *   instructions.
 *   And alternative implementation would be increment insn_count on every
 *   instruction. But that would be significantly slower than the basic
 *   block-level implementation, because it requires one callback per
 *   instruction.
 *   When writing a Pintool, it's important to optimize the analysis
 *   routines as much as possible.
*/

/***************************************************
 *  Function to instrument Pin basic blocks, as there's no
 *  BBL_AddInstrumentFunction. To instrument basic blocks, 
 *  we have to add a trace-level instrumentation routine, and 
 *  then loop over all the basic blocks in the trace, instrumenting
 *  each one
 * ************************************************/
static void instrument_trace(TRACE trace, void *v)
{
    // Get image by address of trace.
    IMG img = IMG_FindByAddress(TRACE_Address(trace));

    // check if image is the main executable, if not, return
    // this is done to avoid shared objects code
    if (!IMG_Valid(img) || !IMG_IsMainExecutable(img))
        return;

    // If trace is valid and part of the main application, 
    // profiler loops over all the basic blocks (BBL objects).
    // For each BBL, it calls instrument_bb, which performs the
    // instrumentation of each BBL.
    for (BBL bb = TRACE_BblHead(trace); BBL_Valid(bb); bb = BBL_Next(bb))
    {
        instrument_bb(bb);
    }
}

/***************************************************
 *   To instrument a given BBL, this function calls BBL_InsertCall. This takes
 *   three mandatory arguments: the basic block to instrument (bb), an insertion
 *   point, and a function pointer to the analysis routine we want to add.
 *   Insertion point determines where in the basic block Pin inserts the analysis callback.
 *   In this case, insertion point is IPOINT_ANYWHERE because it doesn't matter at what
 *   point in the basic block the instruction counter is updated. This allows PIN to optimize
 *   the placement of the callback.
 *   IPOINT_BEFORE: before instrumented object (Always valid)
 *   IPOINT_AFTER: On fallthrough edge (branch or "regular" instruction) (If INS_HasFallthrough is true)
 *   IPOINT_ANYWHERE: Anywhere in instrumented object (For TRACE or BBL only)
 *   IPOINT_TAKEN_BRANCH: On taken edge of branch (If INS_IsBranchOrCall is true)
 *   
 *   count_bb_insns will be the name of the analysis routine, PIN provides an AFUNPTR type that you
 *   should cast function pointers when passing them to PIN API functions.
 *   AFter mandatory arguments, you can add optional arguments to pass to analysis routine. In this
 *   case, there's optional argument of type IARG_UINT32 with value BBL_NumIns.
 *   So the function count_bb_insns receives a UINT32 arguments containing the number of instructions
 *   in the basic block so it can increment the instruction counter.
 *   Finally we pass argument IARG_END to inform that the argument list is complete.
* ************************************************/
static void instrument_bb(BBL bb)
{
    BBL_InsertCall(
        bb,
        IPOINT_ANYWHERE,
        (AFUNPTR) count_bb_insns,
        IARG_UINT32,
        BBL_NumIns(bb),
        IARG_END
    );
}

/***************************************************************/

/***************************************************
 * Function to count the number of control flow transfers
 * and optionally the number of calls. It uses the instruction
 * level instrumentation routine.
 * This function uses INS_InsertPredicatedCall instead of INS_InsertCall, because
 * conditional moves (cmov) and string operations with rep prefoxes, have built-in predicates
 * that cause the instruction to repeat if certain conditions hold.
 * Callbacks inserted with INS_InsertPredicatedCall are called only if that condition holds and 
 * the instruction is executed. In contrast, callbacks with INS_InsertCall are called even if the
 * repeat condition doesn't hold.
 * ************************************************/
static void instrument_insn(INS ins, void *v)
{
    if (!INS_IsBranchOrCall(ins)) // check if instruction is branch instruction or call
        return;
    
    IMG img = IMG_FindByAddress(INS_Address(ins)); // get image from instruction address

    if (!IMG_Valid(img) || !IMG_IsMainExecutable(img))
        return;
    
    // in case branch is taken
    INS_InsertPredicatedCall(
        ins,
        IPOINT_TAKEN_BRANCH, // set callback only in those taken branch
        (AFUNPTR)count_cflow,
        IARG_INST_PTR, // argument it is a PTR
        IARG_BRANCH_TARGET_ADDR, // parameter will be the target of the branch
        IARG_END
    );

    // In case branch has another block of code when jump is not taken
    if (INS_HasFallThrough(ins))
    {
        INS_InsertPredicatedCall(
            ins,
            IPOINT_AFTER,
            (AFUNPTR)count_cflow,
            IARG_INST_PTR,
            IARG_FALLTHROUGH_ADDR,
            IARG_END
        );
    }

    if (INS_IsCall(ins)) // if the instruction is a call instruction
    {
        if (ProfileCalls.Value()) // and -c was given as argument
        {
            INS_InsertCall(
                ins,
                IPOINT_BEFORE,
                (AFUNPTR)count_call,
                IARG_INST_PTR,
                IARG_BRANCH_TARGET_ADDR,
                IARG_END
            );
        }
    }
}

/***************************************************************/

/****
 * Methods to count instructions, control transfers and syscalls
 * */

// called when a basic block executes, increments instruction counts
// by the number of instructions of the basic block.
static void count_bb_insns (UINT32 n)
{
    insn_count += n;
}

// increments the counter of control flow instructions
// each time a control flow instruction is executed.
// also It records those instructions by target and address
static void count_cflow ( ADDRINT ip, ADDRINT target)
{
    cflows[target][ip]++;
    cflow_count++;
}

static void count_call( ADDRINT ip, ADDRINT target)
{
    calls[target][ip]++;
    call_count++;
}

// Log how often eac syscall is called
static void log_syscall ( THREADID tid, CONTEXT *ctxt, SYSCALL_STANDARD std, VOID *v)
{
    syscalls[PIN_GetSyscallNumber(ctxt, std)]++;
    syscall_count++;
}