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

proj = angr.Project("./chall")

# Start address
start_addr = 0x41C072
init_state = proj.factory.blank_state(
    addr=start_addr, add_options={
        angr.options.LAZY_SOLVES, 
        angr.options.UNICORN
    }
)

# Symbolic variable "buffer"
size = 0x10
password = claripy.BVS("password", size*8)

buffer_addr = 0x41F050
init_state.memory.store(buffer_addr, password)

# Simulation manager
simgr = proj.factory.simgr(init_state)
def is_success(state):
    return b"Good Job." in state.posix.dumps(1)
def is_failure(state):
    return b"Try again." in state.posix.dumps(1)

simgr.explore(find=is_success, avoid=is_failure)

print(simgr.found[0].solver.eval(password, cast_to=bytes))

hook(locals())