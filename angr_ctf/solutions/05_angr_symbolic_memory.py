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
    proj = angr.Project("../problems/05_angr_symbolic_memory")

    # Create init_state with starting address after the scanf() and stack cleanup
    start_addr = 0x08048601
    init_state = proj.factory.blank_state(addr=start_addr, add_options={angr.options.UNICORN, angr.options.LAZY_SOLVES})

    # Create 4 symbolic variables for this:
    # __isoc99_scanf("%8s %8s %8s %8s", user_input, &unk_A1BA1C8, &unk_A1BA1D0, &unk_A1BA1D8);
    size_in_bytes = 0x8
    password1 = init_state.solver.BVS("password1", size_in_bytes*8)
    password2 = init_state.solver.BVS("password2", size_in_bytes*8)
    password3 = init_state.solver.BVS("password3", size_in_bytes*8)
    password4 = init_state.solver.BVS("password4", size_in_bytes*8)

    # Using these 4 symbolic variables to overwrite 4 memory slots (memory of those 4 variables in actual program)
    init_state.memory.store(0x0A1BA1C0, password1)
    init_state.memory.store(0x0A1BA1C8, password2)
    init_state.memory.store(0x0A1BA1D0, password3)
    init_state.memory.store(0x0A1BA1D8, password4)

    # Prepare simulation
    simulation = proj.factory.simgr(init_state, veritesting=True)
    simulation.explore(find=success_message, avoid=failure_message)

    # NOT FOUND
    if not simulation.found:
        print("NOT FOUND")
        hook(locals())

    # FOUND => print string from symbolic variables (using cast_to=bytes)
    for s in simulation.found:
        solution_password1 = s.solver.eval(password1, cast_to=bytes)
        solution_password2 = s.solver.eval(password2, cast_to=bytes)
        solution_password3 = s.solver.eval(password3, cast_to=bytes)
        solution_password4 = s.solver.eval(password4, cast_to=bytes)
        print("Flag: ", solution_password1, solution_password2, solution_password3, solution_password4)

if __name__=="__main__":
    main()