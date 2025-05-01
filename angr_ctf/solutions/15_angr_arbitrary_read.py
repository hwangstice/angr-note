# Here is the pseudo-code of main from IDA Pro
# 
# int __cdecl main(int argc, const char **argv, const char **envp)
# {
#   char v4; // [esp+Ch] [ebp-1Ch] BYREF
#   char *s; // [esp+1Ch] [ebp-Ch]
# 
#   s = try_again;
#   printf("Enter the password: ");
#   __isoc99_scanf("%u %20s", &key, &v4);
#   if ( key == 41810812 )
#     puts(s);
#   else
#     puts(try_again);
#   return 0;
# }
#
# Clearly, at scanf(), there is vulnerability where v4 is of type "char" (4 bytes),
# but we are reading input of 20 bytes "%20s". This is a type of OVERFLOW
# 
# If we look closely, v4 is at ebp-0x1C, and *s is at ebp-0xC. 
# [ebp - 0x0C] <-- s         
# [ebp - 0x10]
# [ebp - 0x14]            
# [ebp - 0x18]
# [ebp - 0x1C] <-- v4
# This means, if we write 20 bytes, then *s will be overwritten.
# Look at the pseudo-code, it is obvious that *s will always be "try_again",
# which prints the string "Try Again."
# But what if we overwrite it with the string "Good Job."? :D
#
# That is greate, and to make your exploit faster, angr will help us finding
# the value of 2 input variables (key and v4).
#
# So our strategy with angr is as follow:
# 1) Determine whether the argument for "puts" is controlled by user or not. 
#    If yes, we can set the argument to be the location of "Goob Job." string.
# 2) Search for the call of "puts", which will be exploited to print "Good Job."
# 3) Solve the symbolic input to get the solution


import angr 
import logging 
import claripy

logging.getLogger('angr').setLevel(logging.INFO)

def hook(l=None):
    if l:
        locals().update(l)
    import IPython
    IPython.embed(banner1='', exit_msg='', confirm_exit=False)
    exit(0)

def main():
    proj = angr.Project("../problems/15_angr_arbitrary_read")
    init_state = proj.factory.entry_state()

    # First of all, let's create a SimProcedure for scanf(), as well as
    # the symbolic variables for scanf() arguments.
    class ReplaceScanf(angr.SimProcedure):
        def run(self, format_string, arg0_addr, arg1_addr):
            password0 = claripy.BVS("password0", 4*8)  # %u
            password1 = claripy.BVS("password1", 20*8) # %20s

            # With password1, we should make sure each character is printable.
            # We can still leave it raw, and get the solution, but it contains
            # character that we can't copy, paste, or even type into terminal.
            # So... Why put ourselves into the deadend? :D
            for char in password1.chop(bits=8):
                self.state.add_constraints(char >= '0', char <= 'z')

            # Remember, with numbers, when storing into memory, 
            # we have to consider the "endianess"
            self.state.memory.store(arg0_addr, password0, endness=proj.arch.memory_endness)
            self.state.memory.store(arg1_addr, password1)
 
            self.state.globals['solution0'] = password0
            self.state.globals['solution1'] = password1

    scanf_symbol = "__isoc99_scanf"
    proj.hook_symbol(scanf_symbol, ReplaceScanf())


    # The next thing to do is checking whether arguments passed into "puts"
    # can be controlled by user or not.
    # 
    # The term "controlled by user" means that depends on user input, 
    # the argument passed into "puts" can be changed. Like in our case:
    # if ( key == 41810812 )
    #     puts(s);
    # else
    #     puts(try_again);
    # With different value of "key", arguments for "puts" can be "s" or "try_again"

    def check_puts(state):
        # Here is how the stack looks like when "puts" is called:
        # 
        # esp + 7 -> /----------------\
        # esp + 6 -> |      puts      |
        # esp + 5 -> |    parameter   |
        # esp + 4 -> \----------------/
        # esp + 3 -> /----------------\
        # esp + 2 -> |     return     |
        # esp + 1 -> |     address    |
        #     esp -> \----------------/

        # Since argument for "puts" are pointer to string, which means it 
        # is address => we have to consider endianess
        puts_argument = state.memory.load(state.regs.esp + 4, 4, endness=proj.arch.memory_endness)

        if state.solver.symbolic(puts_argument):
            good_job_addr = 0x484F4A47

            copied_state = state.copy()

            copied_state.add_constraints(puts_argument == good_job_addr)

            if(copied_state.satisfiable()):
                state.add_constraints(puts_argument == good_job_addr)
                return True
            else:
                return False
        else:
            return False
        
    # Now, let's search for call of "puts"
    simulation = proj.factory.simgr(init_state)

    def success(state):
        puts_addr = 0x08048370

        if(state.addr == puts_addr):
            return check_puts(state)
        else:
            return False
        
    simulation.explore(find=success)

    # NOT FOUND
    if not simulation.found:
        print("NOT FOUND")
        hook(locals())

    for solution_state in simulation.found:
        solution0 = solution_state.solver.eval(solution_state.globals['solution0'])
        solution1 = solution_state.solver.eval(solution_state.globals['solution1'], cast_to=bytes)
        print("Flag:", solution0, solution1)

if __name__=="__main__":
    main()