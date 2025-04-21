import angr, claripy
import logging
from string import printable

logging.getLogger('angr').setLevel(logging.INFO)

def hook(l=None):
    if l:
        locals().update(l)
    import IPython
    IPython.embed(banner1='', exit_msg='', confirm_exit=False)
    exit(0)

p = angr.Project("./read_it")

USER_DATA_LENGTH = 36

user_data = claripy.BVS('user_data', USER_DATA_LENGTH*8)
s = p.factory.entry_state(stdin=user_data)
for i in range(USER_DATA_LENGTH):
    s.solver.add(
        claripy.Or(*(
            user_data.get_byte(i) == x 
            for x in printable.encode('utf-8')  
        ))
    )

sm = p.factory.simgr(s, veritesting=True)

# Find function address "read_and_print_flag"
print_flag = p.loader.find_symbol("read_and_print_flag").rebased_addr
sm.explore(find=print_flag, avoid=0x00C24)

if not sm.found[0]:
    print("NOT FOUND")
    hook(locals())

print(sm.found[0].posix.stdin.concretize())

# Run hook
hook(locals())