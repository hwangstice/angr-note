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

proj = angr.Project("./chall")

# Start address
start_addr = 0x41A378
init_state = proj.factory.blank_state(addr=start_addr, add_options={angr.options.LAZY_SOLVES})

# Symbolic password
size = 0x10
password = claripy.BVS("password", size*8)

# Stack setup
init_state.regs.rbp = init_state.regs.rsp
padding = 0x18
init_state.regs.rsp -= padding

# Push value to stack
init_state.stack_push(password)

# Simulation manager
simgr = proj.factory.simgr(init_state)
simgr.explore(find=0x41A3AB, avoid=0x41A392)

solution_state = simgr.found[0]

# Ensure password is printable
for i in range(size):
    byte = password.get_byte(i)
    solution_state.solver.add(byte >= 0x20, byte <= 0x7e)

print(solution_state.solver.eval(password, cast_to=bytes))

hook(locals())