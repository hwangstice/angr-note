import angr 
import logging 
import claripy
import string

logging.getLogger("angr").setLevel(logging.INFO)

def hook(l=None):
    if l:
        locals().update(l)
    import IPython
    IPython.embed(banner1='', exit_msg='', confirm_exit=False)
    exit(0)


def main():
    base_addr = 0x40000000
    proj = angr.Project(
        './a.out',
        load_options={
            'main_opts' : {
                'custom_base_addr' : base_addr
            }
        }
    )

    # Symbolic input
    size = 15
    password = claripy.BVS("password", size*8)

    init_state = proj.factory.entry_state(stdin=password)
    
    # Ensure input is printable
    for i in range(size):
        init_state.solver.add(
        claripy.Or(*(
            password.get_byte(i) == x
            for x in string.printable.encode('utf-8')
        ))
    )
        
    simgr = proj.factory.simgr(init_state)

    success_addr = base_addr + 0x1124
    failure_addr = base_addr + 0x110D
    simgr.explore(find=success_addr, avoid=failure_addr)

    if not simgr.found:
        print("Not found")
        hook(locals()) 

    print(simgr.found[0].solver.eval(password, cast_to=bytes))

if __name__=="__main__":
    main()