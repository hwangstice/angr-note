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
    proj = angr.Project("../problems/02_angr_find_condition")

    # Prepare simualtion
    init_state = proj.factory.entry_state(add_options={angr.options.UNICORN, angr.options.LAZY_SOLVES})
    simulation = proj.factory.simgr(init_state, veritesting=True)

    # Run simulation to find path to success message
    simulation.explore(find=success_message, avoid=failure_message)

    # Not found
    if not simulation.found:
        print("NOT FOUND")
        hook(locals())

    # Found => Print input from stdin in simulation
    for s in simulation.found:
        solution = s.posix.stdin.concretize()
        print("Flag: ", solution)

if __name__=="__main__":
    main()