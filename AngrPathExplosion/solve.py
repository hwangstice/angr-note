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

# Start address
start_addr = 0x1A561
proj = angr.Project("./chall", main_opts={'base_addr': 0x0}) 

init_state = proj.factory.entry_state(
    addr=start_addr,
    add_options={
        angr.options.LAZY_SOLVES,
        angr.options.UNICORN
    }
)

# Symbolic variable "buffer"
size = 0x10
password = claripy.BVS("password", size*8)

buffer_addr = 0x1D060
init_state.memory.store(buffer_addr, password)

# Hook path_explosion_loop
def PathExplosionHook(state):
    input_addr = state.regs.rdi
    ks_0_addr = 0x1B060
    bss_start_addr = 0x1D050

    for i in range(16):
        input_byte = state.memory.load(input_addr + i, 1)
        ks_0_byte = state.memory.load(ks_0_addr + i, 1)
        output_byte = input_byte ^ ks_0_byte
        state.memory.store(bss_start_addr + i, output_byte)

    # Return value
    state.regs.rax = 0

addr_to_hook = 0x1A4D9
proj.hook(addr=addr_to_hook, hook=PathExplosionHook, length=5)

# Simulation manager
simgr = proj.factory.simgr(init_state)
simgr.explore(find=0x1A594, avoid=0x1A57E)

if not simgr.found:
    print("Not found")
    hook(locals())

print(simgr.found[0].solver.eval(password, cast_to=bytes))