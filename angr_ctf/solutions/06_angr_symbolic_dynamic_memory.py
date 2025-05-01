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
    proj = angr.Project("../problems/06_angr_symbolic_dynamic_memory")

    # Create init_state with start address after call to scanf() and stack clean up
    start_addr = 0x08048699
    init_state = proj.factory.blank_state(addr=start_addr, add_options={angr.options.UNICORN, angr.options.LAZY_SOLVES})


    # ------------------- IDEA --------------------
    # We can't overwrite memory with symbolic variables
    # because in this challenge, variables are dynamically allocated
    
    # Instead, we can overwrite the pointer
    # This means, overwriting the pointer to make it point to our symbolic variables

    # This can be achieved by creating fake heap addresses,
    # link our symbolic variables to that fake heap addresses.
    # Make dynamic pointers point to our fake heap addresses.


    # Address of 2 dynamic pointers + fake heap address (unuse memory in hex views)
    fake_heap_addr = 0x0ABCC8C0
    buffer0_addr = 0x0ABCC8A4
    buffer1_addr = 0x0ABCC8AC

    # Create 2 symbolic variables
    size_in_bytes = 0x8
    password1 = init_state.solver.BVS("password1", size_in_bytes*8)
    password2 = init_state.solver.BVS("password2", size_in_bytes*8)

    # Make 2 dynamic pointers point to our fake heap address (remember the endianess)
    init_state.memory.store(buffer0_addr, fake_heap_addr, endness=proj.arch.memory_endness)
    init_state.memory.store(buffer1_addr, fake_heap_addr+9, endness=proj.arch.memory_endness)

    # Link symbolic variables to fake heap address memory
    init_state.memory.store(fake_heap_addr, password1)
    init_state.memory.store(fake_heap_addr+9, password2)

    # Now everything is ready, let's prepare simulation and run
    simulation = proj.factory.simgr(init_state, veritesting=True)
    simulation.explore(find=success_message, avoid=failure_message)

    # NOT FOUND
    if not simulation.found:
        print("NOT FOUND")
        hook(locals())

    # FOUND => print string input from symbolic variables
    for s in simulation.found:
        solution_password1 = s.solver.eval(password1, cast_to=bytes)
        solution_password2 = s.solver.eval(password2, cast_to=bytes)
        print("Flag: ", solution_password1, solution_password2)

if __name__=="__main__":
    main()