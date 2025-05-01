import angr 
import logging 
import claripy
import sys

logging.getLogger("angr").setLevel(logging.INFO)

def hook(l=None):
    if l:
        locals().update(l)
    import IPython
    IPython.embed(banner1='', exit_msg='', confirm_exit=False)
    exit(0)

def custom_check_function(state):
    # Load the value from user input, (in program, it is stored inside the variable "buffer")
    buffer_addr = 0x0804A054
    buffer_size_in_bytes = 0x10
    load_buffer = state.memory.load(buffer_addr, buffer_size_in_bytes)

    # Hard-coded password
    hard_coded_password = "XYMKBKUHNIQYNQXE"

    # Return value of our custom_check_function
    state.regs.eax = claripy.If(
        load_buffer == hard_coded_password,
        claripy.BVV(1, 32), # true
        claripy.BVV(0, 32)  # false
    )

def success_message(state):
    return b"Good Job." in state.posix.dumps(sys.stdout.fileno())

def failure_message(state):
    return b"Try again." in state.posix.dumps(sys.stdout.fileno())

def main():
    proj = angr.Project("../problems/09_angr_hooks")


    # ---------------------------------- IDEA -----------------------------------
    # In this program, it asks us to enter two password for double check verification
    
    # The first comparision checks between user_data and hard-coded password
    # The second comparision checks between obfuscated hard-coded password and new user_data

    # To make the program more efficient, we should hook the function check the password, which is check_equals_XYMKBKUHNIQYNQXE()
    # This can be done by a hook, which creates our own custom function :D

    # Reason: check_equals_XYMKBKUHNIQYNQXE() uses for loop for checking character by character, which creates exponential branches => slow, inefficient



    # ----------------------------------- SOLUTION ---------------------------------

    # First of all, let's create a hook to our current binary

    # We can do hook like this:
    # proj.hook(
    #     addr=0x080486B3, 
    #     hook=custom_check_function, 
    #     length=5
    # ) 


    # OR 
    
    addr_to_hook = 0x080486A9 # address at the sub instruction
    length_to_skip_in_bytes = 18 # skip from 0x080486A9 to 0x080486BB

    # Right at 0x080486BB, we want to return a value from our hook
    proj.hook(
        addr=addr_to_hook, 
        hook=custom_check_function, 
        length=length_to_skip_in_bytes
    ) 

    # Should create entry_state because it loads everything from scratch
    # If we use blank_state, we have to pre-defined most of the stack, heap, ...
    # and the program is prone to crash if we don't handle that precisely :D
    init_state = proj.factory.entry_state(add_options={
        angr.options.UNICORN,
        angr.options.LAZY_SOLVES
    })

    # Prepare simulation to the success path
    simulation = proj.factory.simgr(init_state)
    simulation.explore(find=success_message, avoid=failure_message)

    # NOT FOUND
    if not simulation.found:
        print("NOT FOUND")
        hook(locals())

    # FOUND => concretize to get the password
    for solution_state in simulation.found:
        print(solution_state.posix.stdin.concretize())

if __name__=="__main__":
    main()