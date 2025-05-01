# Here is the pseudo-code of main from IDA Pro:
#   int __cdecl main(int argc, const char **argv, const char **envp)
#   {
#     printf("Enter the password: ");
#     read_input();
#     puts("Try again.");
#     return 0;
#   }
#
# Here is the pseudo-code of read_input():
#   int read_input()
#   {
#     _BYTE v1[32]; // [esp+28h] [ebp-20h] BYREF
#   
#     return __isoc99_scanf("%s", v1);
#   }
#
# => This is a classic Buffer Overflow problem, where we will
#    overwrite the return address (eip) of read_input() to the address
#    of print_good() function.
#
# To do this in ANGR, we perform an "arbitrary jump", where we will make 
# eip (instruction pointer) as a symbolic variable (can be controlled by user).
# Then, we will include a constraint so that our symbolic variable (eip) must be 
# equal to the address of print_good() function.
#
#   +) Why we say "symbolic variable can be controlled by user"?
#   => Let's have a look at the stack of read_input():
#
#      [ebp + 0x04] <-- return address of read_input()
#      [ebp - 0x00]
#      [ebp - 0x04]
#      [ebp - 0x08]         
#      [ebp - 0x0C]
#      [ebp - 0x10]            
#      [ebp - 0x14]
#      [ebp - 0x18]
#      [ebp - 0x1C]
#      [ebp - 0x20] <-- v1[32]
#     
#      Clearly, v1[32] has size of 32-byte 
#   => When providing input "greater than 32-byte", we will overwrite the return address.
#
#   +) Why can this be solved with ANGR?
#   => With ANGR, we can suppose eip (return address) as symbolic, meaning it can 
#      contain any possible values, a.k.a "uncontrained state". 
# 
#      This means the program can jump to anywhere, and we will add a constraint 
#      to make "eip" equal to the address of print_good().
#
#      However, by default, those "unconstrained states" will be discarded by ANGR, 
#      and we don't want that to happen. So latter, we have a solution for this :>
#
# So, basically, our strategy is as follow:
#   1) Create symbolic variable for "eip"
#   2) Ensure "unconstrained states" won't be discarded
#       * When saying "unconstrained states", this refers to symbolic "eip".
#   3) Whenever encounter symbolic "eip" (unconstrained states)
#       * Add a constraint to ensure "eip" equal to print_good() address.
#
# Note:
#   +) We will define our "custom stashes" into Simulation Manager
#   => Further reading: https://docs.angr.io/en/latest/core-concepts/pathgroups.html

import angr
import logging 
import claripy

logging.getLogger("angr").setLevel(logging.INFO)

def hook(l=None):
    if l:
        locals().update(l)
    import IPython
    IPython.embed(banner1='', exit_msg='', confirm_exit=False)
    exit(0)

def main():
    proj = angr.Project("../problems/17_angr_arbitrary_jump")
    init_state = proj.factory.entry_state()

    # Create SimProcedure for scanf(), and make a reference to symbolic v1
    # for our future solution password.
    class ReplaceScanf(angr.SimProcedure):
        def run(self, format_string, scanf0_addr):
            password0 = claripy.BVS("password0", 64*8) # Larger input_buffer :D

            # Ensure password0 only contains printable ASCII characters
            for char in password0.chop(bits=8):
                self.state.add_constraints(char >= '0', char <= 'z')

            # Write password into scanf0_addr
            # Since password0 is string => Don't care about endianess
            self.state.memory.store(scanf0_addr, password0)

            self.state.globals['solution'] = password0
    
    scanf_symbol = "__isoc99_scanf"
    proj.hook_symbol(scanf_symbol, ReplaceScanf())

    # Create simulation with "custom stashes"
    # Note:
    #   +) Each stash is a list of states
    simulation = proj.factory.simgr(
        init_state, 
        save_unconstrained=True, # Ensure ANGR doesn't discard "unconstrained states"
        stashes={
            'active':[init_state],
            'unconstrained':[],
            'found':[],
            'not_needed':[]
        }
    )

    while((simulation.active or simulation.unconstrained) and (not simulation.found)):
        # Our goal is finding "unconstrained state".
        # When encountering that state => move it into "found state"
        if(len(simulation.unconstrained) > 0):
            simulation.move(from_stash='unconstrained', to_stash='found')
        
        # When there are states in "active stash"
        # => Continue to step() to explore further with the goal
        #    of fiding "unconstrained state".
        simulation.step()

    # NOT FOUND
    if not simulation.found:
        print("NOT FOUND")
        hook(locals())

    # FOUND
    # => add constraints to "unconstrained state" (have been moved into "found state")
    #    to force ANGR to find a solution where "eip == print_good() addr"
    for solution_state in simulation.found:
        # Add constraints
        print_good_addr = 0x42585249
        solution_state.add_constraints(solution_state.regs.eip == print_good_addr)

        # Now, ANGR should figure our the solution password
        # => Concretize to get the solution password
        solution_password = solution_state.solver.eval(
            solution_state.globals['solution'],
            cast_to=bytes
        )
        
        print("Flag:", solution_password)

if __name__=="__main__":
    main()