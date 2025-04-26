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

def success_message(state):
    return b"Flag Captured!" in state.posix.dumps(sys.stdout.fileno())

def failure_message(state):
    return b"Wrong!" in state.posix.dumps(sys.stdout.fileno())

def nop(state):
    state.regs.rax = 64 # Return value (where the "/n" will be placed when hook) of strcspn()

def main():
    proj = angr.Project("./metaverse")

    # No need to create symbolic user_data because we have to handle strcspn(), where
    # we have to provide the "/n" at the end => This function make angr slow and not efficient => Need to discard that function
    
    # To handle that -> create a hook to overwrite that function

    # Using hook to overwrite strcspn()
    addr_to_hook = 0x400FEF
    proj.hook(addr=addr_to_hook, hook=nop, length=5) # create custom function to overwrite 5 bytes in hex of strcspn()

    # Prepare simulation with optimization
    init_state = proj.factory.entry_state(add_options={angr.options.LAZY_SOLVES, angr.options.UNICORN})
    simulation = proj.factory.simgr(init_state, veritesting=True)

    # Find success message
    simulation.explore(find=success_message, avoid=failure_message)

    if not simulation.found:
        print("NOT FOUND")
        hook(locals())

    for s in simulation.found:
        solution = s.posix.stdin.concretize()
        print(solution)

if __name__=="__main__":
    main()