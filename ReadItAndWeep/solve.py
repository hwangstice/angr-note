import angr, logging, claripy, string

logging.getLogger("angr").setLevel(logging.INFO)

def hook(l=None):
    if l:
        locals().update(l)
    import IPython
    IPython.embed(banner1='', exit_msg='', confirm_exit=False)
    exit(0)

p = angr.Project('./read_it')

# Set state for user data
USER_DATA_LENGTH = 32
user_data = claripy.BVS("user_data", USER_DATA_LENGTH * 8)

# state start when user input data
s = p.factory.entry_state(stdin=user_data) 

# Ensure input are printable
for i in range(USER_DATA_LENGTH):
    s.solver.add(
        claripy.Or(*(
            user_data.get_byte(i) == x 
            for x in string.printable.encode('utf-8')  
        ))
    )

sm = p.factory.simulation_manager(s, veritesting=True) # veritesting for optimization

# Find addr of read_and_print_flag function
print_flag_addr = p.loader.find_symbol("read_and_print_flag").rebased_addr
sm.explore(find=print_flag_addr, avoid=0x400C24)

# Check if not found
if not sm.found:
    print("NOT FOUND")
    hook(locals())

print(sm.found[0].posix.dumps(0))