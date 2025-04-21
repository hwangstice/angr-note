
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

p = angr.Project("./liblibrary_card.so")

print_flag_addr = p.loader.find_symbol('print_flag').rebased_addr
print_flag = p.factory.callable(print_flag_addr)
print_flag(2084, 0x82C, 2091)

if not print_flag:
    print("print_flag funtion not found!")
    hook(locals())

print(print_flag.result_state.posix.stdout.concretize())

# Run hook
hook(locals())


