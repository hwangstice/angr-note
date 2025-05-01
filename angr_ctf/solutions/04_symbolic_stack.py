import angr 
import logging
import sys

logging.getLogger("angr").setLevel(logging.INFO)

def hook(l=None):
    if l:
        locals().update(l)
    import IPython
    IPython.embed(banner1='', exit_msg='', confirm_exit=False)
    exit(0)

def success_message(state):
    return b"Good Job." in state.posix.dumps(sys.stdout.fileno())

def failure_message(state):
    return b"Try again." in state.posix.dumps(sys.stdout.fileno())

def main():
    proj = angr.Project("../problems/04_angr_symbolic_stack")

    # Create init_state with start address after stack clean up and scanf because we don't want to make symbolic scanf :>
    start_addr = 0x08048697
    init_state = proj.factory.blank_state(addr=start_addr)

    # Create 2 symbolic variables holding symbolic values :P
    # These 2 variables will replace 2 stack slots
    size_in_bytes = 4
    password1 = init_state.solver.BVS("password1", size_in_bytes*8)
    password2 = init_state.solver.BVS("password2", size_in_bytes*8)

    # Stack looks like this:
    #    -----------
    #   |           | ebp - 0x4
    #    -----------
    #   |           | ebp - 0x8
    #    -----------
    #   | password1 | ebp - 0xC
    #    -----------
    #   | password2 | ebp - 0x10
    #    -----------
    #
    # ===> padding for password1 in stack is 0x8 :>


    # Setup the stack
    init_state.regs.ebp = init_state.regs.esp
    stack_padding = 0x8
    init_state.regs.esp -= stack_padding

    # Insert password1 and password2 into stack
    init_state.stack_push(password1)
    init_state.stack_push(password2)

    # Up to this point, stack is ok
    # => Prepare simulation and find the success message
    simulation = proj.factory.simgr(init_state)
    simulation.explore(find=success_message, avoid=failure_message)

    # NOT FOUND
    if not simulation.found:
        print("NOT FOUND")
        hook(locals())

    # FOUND => print value in the stack from 2 symbolic variables
    for s in simulation.found:
        solution_password1 = s.solver.eval(password1)
        solution_password2 = s.solver.eval(password2)
        print("Flag: ", solution_password1, solution_password2)

if __name__=="__main__":
    main()