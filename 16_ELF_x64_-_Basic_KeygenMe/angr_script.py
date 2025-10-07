import angr 
import logging 
import claripy

logging.getLogger("angr").setLevel(logging.INFO)

def hook(l=None):
    if l:
        locals().update(l)
    import IPython
    IPython.embed(banner1='', exit_msg='', confirm_exit=False)
    exit(0)

proj = angr.Project("./ch36.bin")

# Start address
start_addr = 0x4001C0
init_state = proj.factory.blank_state(addr=start_addr)

# Store input
input = claripy.BVV("root-me.org")
init_state.memory.store(0x600260, input)

# Simulation manager
simgr = proj.factory.simgr(init_state)
simgr.explore(find=0x400232, avoid=0x400215)

if not simgr.found:
    print("Not found")
    hook(locals())

print(simgr.found[0].posix.dumps(3))