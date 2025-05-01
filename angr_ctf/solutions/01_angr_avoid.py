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

def failure_message(state):
    return b"Try again." in state.posix.dumps(sys.stdout.fileno())

def success_message(state):
    return b"Good Job." in state.posix.dumps(sys.stdout.fileno())

def main():
    proj = angr.Project("../problems/01_angr_avoid")

    # Prepare simulation
    init_state = proj.factory.entry_state(add_options={angr.options.UNICORN, angr.options.LAZY_SOLVES})
    simulation = proj.factory.simgr(init_state, veritesting=True)

    # avoid_me() address
    avoid_me_addr = proj.loader.find_symbol("avoid_me").rebased_addr

    # Run simulation, avoid avoid_me() and failure message
    simulation.explore(find=success_message, avoid=[avoid_me_addr, failure_message])

    if not simulation.found:
        print("NOT FOUND")
        hook(locals())

    for s in simulation.found:
        solution = s.posix.stdin.concretize()
        print("Flag: ", solution)

if __name__=="__main__":
    main()