import angr 
import logging 
import sys
import claripy
import string

# logging.getLogger("angr").setLevel(logging.INFO)

def hook(l=None):
    if l:
        locals().update(l)
    import IPython
    IPython.embed(banner1='', exit_msg='', confirm_exit=False)
    exit(0)

def success(state):
    return b"C'est correct !" in state.posix.dumps(sys.stdout.fileno())

def failure(state):
    return b"Essaie encore !" in state.posix.dumps(sys.stdout.fileno())

proj = angr.Project("./ch73.bin")

# Hook _do_global_ctors_aux
def DoGlobalCtorsAuxHook(state):
    key_addr = 0x404048
    key = state.memory.load(key_addr, 8, endness=proj.arch.memory_endness)
    # print("hehe pass")
    # print("key", hex(state.solver.eval(key)))

    xor_val = claripy.BVV(0x119011901190119, 64)
    new_key = key ^ xor_val
    # print("new key", hex(state.solver.eval(new_key)))
    state.memory.store(key_addr, new_key)
    # test_new_key = state.memory.load(key_addr, 8, endness=proj.arch.memory_endness)
    # print("new key", hex(state.solver.eval(test_new_key)))

    state.regs.rax = key

addr_to_hook = proj.loader.find_symbol("__do_global_ctors_aux").rebased_addr
proj.hook(addr=addr_to_hook, hook=DoGlobalCtorsAuxHook, length=0x40120A-addr_to_hook)


# Start address
start_addr = 0x40135D
init_state = proj.factory.entry_state(addr=start_addr)

# Call the hook
DoGlobalCtorsAuxHook(init_state)

# Symbolic input
size = 0x8
input = claripy.BVS("input", size*8)

# Printable input
for i in range(size):
    init_state.solver.add(
        claripy.Or(*(
            input.get_byte(i) == x
            for x in string.printable.encode('utf-8')
        ))
    )

# Store symbolic input into rax
init_state.regs.rax = input

# Check again value of key
key_addr = 0x404048
key = init_state.memory.load(key_addr, 8, endness=proj.arch.memory_endness)
print("hehe pass")
print("key", hex(init_state.solver.eval(key)))

# Perform the XOR in check()
after_xor_bytes = []
for i in range(8):
    key_byte = init_state.memory.load(key_addr + i, 1)
    input_byte = input.get_byte(i)
    after_xor_bytes.append(key_byte ^ input_byte)

after_xor = claripy.Concat(*after_xor_bytes)

# Ensure after_xor == 0xA377AD570465FDF9
target = claripy.BVV(0xA377AD570465FDF9, 64)
print("target", hex(init_state.solver.eval(target)))

init_state.solver.add(after_xor == target)
print("after xor", hex(init_state.solver.eval(after_xor)))

# Simulation manager
simgr = proj.factory.simgr(init_state)
simgr.explore(find=success, avoid=failure)

if not simgr.found:
    print("Not found")
    hook(locals())

# Since binary is Little-endian => print password in reverse order
password = simgr.found[0].solver.eval(input, cast_to=bytes)
print(password[::-1])
