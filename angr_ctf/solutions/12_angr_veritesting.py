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
    proj = angr.Project("../problems/12_angr_veritesting")

    # Create init_state

    # LAZY_SOLVES => Explore more new states, prevent spending in one state for too long
    init_state = proj.factory.entry_state(add_options={
        angr.options.LAZY_SOLVES
    })

    # Prepare simulation

    # Need veritesting => because of this:
    # for ( i = 0; i <= 31; ++i )
    # {
    #     v3 = *((char *)v19 + i + 3);
    #     if ( v3 == complex_function(75, i + 93) )
    #     ++v15;
    # }
    # 
    # Would take exponentially states for each True and False branch!

    simulation = proj.factory.simgr(init_state, veritesting=True)
    simulation.explore(find=success_message, avoid=failure_message)

    # NOT FOUND 
    if not simulation.found:
        print("NOT FOUND")
        hook(locals())

    # FOUND => concretize stdin 
    for solution_state in simulation.found:
        print(solution_state.posix.stdin.concretize())

if __name__=="__main__":
    main()