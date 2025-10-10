# angr script
# 
# Hook sys_ptrace

import angr 
import sys

def success(state):
    return b"C'est correct !" in state.posix.dumps(sys.stdout.fileno())

def failure(state):
    return b"Essaie encore !" in state.posix.dumps(sys.stdout.fileno())

proj = angr.Project("./ch73.bin", auto_load_libs=False)

# Hook sys_ptrace
def SysPtraceHook(state):
    state.regs.rax = 0

addr_to_hook = 0x4011A1
proj.hook(addr=addr_to_hook, hook=SysPtraceHook, length=2)

init_state = proj.factory.full_init_state()

# print(hex(proj.loader.main_object.min_addr))      # -> 0x400000

# Simulation Manager & find success state
simgr = proj.factory.simgr(init_state)
simgr.explore(find=success, avoid=failure)

if not simgr.found:
    print("Not found")

print(simgr.found[0].posix.stdin.concretize())