# Here is the pseudo-code from IDA Pro
#
# int __cdecl main(int argc, const char **argv, const char **envp)
# {
#   char s[16]; // [esp+Ch] [ebp-1Ch] BYREF
#   char *dest; // [esp+1Ch] [ebp-Ch]
# 
#   dest = unimportant_buffer;
#   memset(s, 0, sizeof(s));
#   strncpy(password_buffer, "PASSWORD", 0xCu);
#   printf("Enter the password: ");
#   __isoc99_scanf("%u %20s", &key, s);
#   if ( key == 11604995 )
#     strncpy(dest, s, 0x10u);
#   else
#     strncpy(unimportant_buffer, s, 0x10u);
#   if ( !strncmp(password_buffer, "NDYNWEUJ", 8u) )
#     puts("Good Job.");
#   else
#     puts("Try again.");
#   return 0;
# }
#
# Look at the pseudo-code, we can easily see that it will always print "Try again." 
# since our input "s" is written to "dest", or "unimportant_buffer" based on the "key" value.
#
# So, can we make "password_buffer" equal to "NDYNWEUJ"? That's seem impossible right!?
#
# Well, the answer is yes! :>
# => With the help of ANGR
#
# Here's why:
#
#  1) Look at this: __isoc99_scanf("%u %20s", &key, s);
#   We can see that we are entering an input of 20 bytes into "s", 
#   Furthermore, "s" is at ebp-0x1c, and "*dest" is at ebp-0xc.
#   [ebp - 0x0C] <-- *dest         
#   [ebp - 0x10]
#   [ebp - 0x14]            
#   [ebp - 0x18]
#   [ebp - 0x1C] <-- s
#   Clearly, we can overflow "*dest" with "s" by providing a 20-byte input
#   => With ANGR, we can make "s" contains arbitrary data, then add a CONSTRAINT
#      to make it include "NDYNWEUJ".
#
#  2) But, we have another problem where "*dest" doesn't point to "password_buffer".
#   => Luckily, we have ANGR, we can symbolically control "*dest" to make it point 
#      to the address of "password_buffer", using a constraint.
# 
# => The idea is to write arbitrary data (source contents) into arbitrary 
# location (destination pointer)
#
# And our idea perfectly fits the working of "strncpy()" function, where it writes content
# of source into destination address.
# => strncpy(destination_pointer, source_contents);
#
# When strncpy() is called, we can:
#  1) Control the source contents (not the source pointer!)
#     * This will allow us to write arbitrary data to the destination.
#  2) Control the destination pointer
#     * This will allow us to write to an arbitrary location.
#
# => "source contents" and "destination pointer" must be symbolic. This means it depends
# on user input, in this case is the value of "key".
#   if ( key == 11604995 )
#     strncpy(dest, s, 0x10u);
#   else
#     strncpy(unimportant_buffer, s, 0x10u);

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
    proj = angr.Project("../problems/16_angr_arbitrary_write")
    init_state = proj.factory.entry_state()

    # Create a SimProcedure for scanf() to get our solution password
    class ReplaceScanf(angr.SimProcedure):
        def run(self, format_string, scanf0_addr, scanf1_addr):
            password0 = claripy.BVS("password0", 4*8)   # %u
            password1 = claripy.BVS("password1", 20*8)  # %20s

            # Make sure password1 includes printable ASCII characters
            for char in password1.chop(bits=8):
                self.state.add_constraints(char >= '0', char <= 'z')
            
            # Remember endianess for number
            self.state.memory.store(scanf0_addr, password0, endness=proj.arch.memory_endness)
            self.state.memory.store(scanf1_addr, password1)

            # Make reference to solution
            self.state.globals['solution0'] = password0
            self.state.globals['solution1'] = password1
    
    scanf_symbol = "__isoc99_scanf"
    proj.hook_symbol(scanf_symbol, ReplaceScanf())


    # Whenever strncpy() is called, check if "source contents" and "destination pointer"
    # are symbolic or not
    # If yes, add constraint
    def check_strncpy(state):
        # This is how the stack looks like when strncpy() is called
        # ...          ________________
        # esp + 15 -> /                \
        # esp + 14 -> |     param2     |
        # esp + 13 -> |      len       |
        # esp + 12 -> \________________/
        # esp + 11 -> /                \
        # esp + 10 -> |     param1     |
        #  esp + 9 -> |      src       |
        #  esp + 8 -> \________________/
        #  esp + 7 -> /                \
        #  esp + 6 -> |     param0     |
        #  esp + 5 -> |      dest      |
        #  esp + 4 -> \________________/
        #  esp + 3 -> /                \
        #  esp + 2 -> |     return     |
        #  esp + 1 -> |     address    |
        #      esp -> \________________/

        # Values store in memory based on the architecture endianess
        # => make sure we load it correctly based on the endianess
        strncpy_dest = state.memory.load(state.regs.esp + 4, 4, endness=proj.arch.memory_endness)
        strncpy_src = state.memory.load(state.regs.esp + 8, 4, endness=proj.arch.memory_endness)
        strncpy_len = state.memory.load(state.regs.esp + 12, 4, endness=proj.arch.memory_endness)

        # src is a pointer, dereference it to get the "src content"
        src_content = state.memory.load(strncpy_src, strncpy_len)

        # Check if "destination pointer" and "source content" are symbolic
        if state.solver.symbolic(strncpy_dest) and state.solver.symbolic(src_content):
            password_string = "NDYNWEUJ"
            buffer_addr = 0x57584344 # address of "password_buffer"

            # Is "destination pointer" point to "password_buffer"?
            destination_pointer_constraint = (strncpy_dest == buffer_addr)

            # Is "source content" contains "NDYNWEUJ"?
            # 
            # Since "source content" is bitvector, to get the specific characters
            # from left to right, we use this formula: 
            #               bitvector[-1, -8*N]
            # Where: N is the number of characters we want
            source_content_constraint = (src_content[-1:-64] == password_string)

            copied_state = state.copy()
            
            copied_state.add_constraints(destination_pointer_constraint, source_content_constraint)

            if(copied_state.satisfiable()):
                state.add_constraints(destination_pointer_constraint, source_content_constraint)
                return True
            else:
                return False
        else:
            return False

    # Check strncpy() whenever encounter it and prepare simulation
    simulation = proj.factory.simgr(init_state)

    def success(state):
        strncpy_addr = 0x08048410
        if(state.addr == strncpy_addr):
            return check_strncpy(state)
        else:
            return False
        
    simulation.explore(find=success)

    # NOT FOUND
    if not simulation.found:
        print("NOT FOUND")
        hook(locals())

    # FOUND => read solution password
    for solution_state in simulation.found:
        solution_password0 = solution_state.solver.eval(solution_state.globals['solution0'])
        soluiton_password1 = solution_state.solver.eval(solution_state.globals['solution1'], cast_to=bytes)
        print("Flag:", solution_password0, soluiton_password1)

if __name__=="__main__":
    main()