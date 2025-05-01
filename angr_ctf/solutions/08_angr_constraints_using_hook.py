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

# Custom function to overwrite check_equals_AUPDNNPROEZRJWKB()
def custom_check_equal(state):
    # Load value of user_data
    user_data_addr = 0x0804A050
    load_user_data = state.memory.load(user_data_addr, size=0x10)

    # Password string
    password_str = "AUPDNNPROEZRJWKB"

    # Return value
    state.regs.eax = claripy.If(
        load_user_data == password_str, 
        claripy.BVV(1, 32), # true
        claripy.BVV(0, 32)  # false
    )

def success_message(state):
    return b"Good Job." in state.posix.dumps(sys.stdout.fileno())

def failure_message(state):
    return b"Try again." in state.posix.dumps(sys.stdout.fileno())

def main():
    proj = angr.Project("../problems/08_angr_constraints")

    # ----------------------------- IDEA ---------------------------------
    # Since the loop for check_equals_AUPDNNPROEZRJWKB(user_data, 16) 
    # compares character by character => This will create tons of branches 
    # in ANGR, which means ANGR creates exponentionally 2 possible states (True and False)

    # This will slow down our working process => Need to avoid

    # To fix this, we can create a hook, which replace the function check_equals_AUPDNNPROEZRJWKB()
    # with our custom function, which contains the constraint of 
    # forcing ANGR into thinking that our input must be equal to
    # the password "AUPDNNPROEZRJWKB". 

    # When stepping into the function check_equals_AUPDNNPROEZRJWKB(),
    # instead of comparing character by character, we will make 
    # ANGR force the input to be the only option that satisfy the constraint



    # ----------------------------- SOLUTION ---------------------------------

    # Create hook for our custom function
    addr_to_hook = 0x08048673
    proj.hook(addr=addr_to_hook, hook=custom_check_equal, length=5)

    # Should create entry_state because it loads everything from scratch
    # If we use blank_state, we have to pre-defined most of the stack, heap, ...
    # and the program is prone to crash if we don't handle that precisely :D
    init_state = proj.factory.entry_state(add_options={
        angr.options.LAZY_SOLVES
    })

    # Prepare simulation to the success path
    simulation = proj.factory.simgr(init_state)
    simulation.explore(find=success_message, avoid=failure_message)

    # NOT FOUND
    if not simulation.found:
        print("NOT FOUND")
        hook(locals())

    for solution_state in simulation.found:
        print(solution_state.posix.stdin.concretize())

if __name__=="__main__":
    main()