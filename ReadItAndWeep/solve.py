import angr 
import logging 
import sys
import claripy
import string

logging.getLogger("angr").setLevel(logging.INFO)

def hook(l=None):
    if l:
        locals().update(l)
    import IPython
    IPython.embed(banner1='', exit_msg='', confirm_exit=False)
    exit(0)

def failure_message(state):
    return b"Sorry, that's not correct!" in state.posix.dumps(sys.stdout.fileno())

def success_message(state):
    return b"Correct! Here is your flag:" in state.posix.dumps(sys.stdout.fileno())

def main():
    proj = angr.Project("./read_it")

    user_data_in_bytes = 64
    user_data = claripy.BVS("message", user_data_in_bytes*8)

    init_state = proj.factory.entry_state(stdin=user_data, add_options={angr.options.LAZY_SOLVES, angr.options.UNICORN})

    # Ensure user_data is printable
    for i in range(user_data_in_bytes):
        init_state.solver.add(
            claripy.Or(*(
                user_data.get_byte(i) == x
                for x in string.printable.encode('utf-8')
            ))
        )

    # Prepare simulation
    simulation = proj.factory.simgr(init_state, veritesting=True)

    # Get address of read_and_print_flag function
    print_flag_addr = proj.loader.find_symbol("read_and_print_flag").rebased_addr
    simulation.explore(find=print_flag_addr, avoid=failure_message)

    # Another way:
    # simulation.explore(find=success_message, avoid=failure_message)

    if not simulation.found:
        print("NOT FOUND")
        hook(locals())
    
    for s in simulation.found:
        solution = s.solver.eval(user_data, cast_to=bytes)
        # solution = s.posix.stdin.concretize()
        print(solution)

if __name__=="__main__":
    main()