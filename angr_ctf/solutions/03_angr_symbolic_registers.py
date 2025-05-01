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
    proj = angr.Project("../problems/03_angr_symbolic_registers")

    # Create init_state from address after get_user_input()
    start_addr = 0x08048980
    init_state = proj.factory.blank_state(addr=start_addr)

    # Create 3 symbolic variables for simulation (registers)
    size_in_bytes = 4
    password1 = init_state.solver.BVS("password1", size_in_bytes*8)
    password2 = init_state.solver.BVS("password2", size_in_bytes*8)
    password3 = init_state.solver.BVS("password3", size_in_bytes*8)

    # Write 3 symbolic variables to 3 registers in current state
    init_state.regs.eax = password1
    init_state.regs.ebx = password2
    init_state.regs.edx = password3

    # Up till now, our state is ready
    # Let's prepare simulation and find the success message
    simulation = proj.factory.simgr(init_state)
    simulation.explore(find=success_message, avoid=failure_message)

    # NOT FOUND
    if not simulation.found:
        print("NOT FOUND")
        hook(locals())

    # FOUND ==> Read the password from our 3 pre-created symbolic variables (value inside registers)
    for s in simulation.found:
        solution_password1 = s.solver.eval(password1)
        solution_password2 = s.solver.eval(password2)
        solution_password3 = s.solver.eval(password3)

        # Print solutions in hex because __isoc99_scanf("%x %x %x", &v1, &v2, v3);
        print("Flag: ", hex(solution_password1), hex(solution_password2), hex(solution_password3))

if __name__=="__main__":
    main()