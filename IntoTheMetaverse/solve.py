
import angr, claripy
import logging

logging.getLogger('angr').setLevel(logging.INFO)

from string import printable

def hook(l=None):
    if l:
        locals().update(l)
    import IPython
    IPython.embed(banner1='', exit_msg='', confirm_exit=False)
    exit(0)

p = angr.Project("./metaverse")

addr_to_hook = 0x400FEF

def nop(state):
    state.regs.rax = 36

p.hook(addr=addr_to_hook, hook=nop, length=5)

# User unicorn to optimize code
s = p.factory.entry_state(add_options=angr.options.unicorn)
sm = p.factory.simulation_manager(s, veritesting=True) # Also veritesting for optimization

sm.explore(find=0x400F67, avoid=0x400F75)

if sm.found:
    print(sm.found[0].posix.stdin.concretize())

# Run hook
hook(locals())


