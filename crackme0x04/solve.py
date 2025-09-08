import angr
import logging 

logging.getLogger("angr").setLevel(logging.INFO)

def hook(l=None):
    if l:
        locals().update(l)
    import IPython
    IPython.embed(banner1='', exit_msg='', confirm_exit=False)
    exit(0)

proj = angr.Project("./crackme0x04", load_options={'auto_load_libs': False}, main_opts={'base_addr': 0x8048000})

cfg = proj.analyses.CFGFast()

exit_addr = cfg.kb.functions.function(name='exit').addr

init_state = proj.factory.entry_state()
simgr = proj.factory.simgr(init_state)

simgr.explore(find=exit_addr, avoid=0x08048502)

if not simgr.found:
    print("Not found")
    hook(locals())

print(simgr.found[0].posix.stdin.concretize())