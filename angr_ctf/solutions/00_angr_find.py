import angr
import logging 

logging.getLogger("angr").setLevel(logging.INFO)

def hook(l=None):
    if l:
        locals().update(l)
    import IPython
    IPython.embed(banner1='', exit_msg='', confirm_exit=False)
    exit(0)

def main():
    proj = angr.Project("../problems/00_angr_find")

    # Prepare simulation
    init_state = proj.factory.entry_state()
    simulation = proj.factory.simgr(init_state)

    # Find success message
    print_success_addr = 0x0804867D
    print_failure_addr = 0x0804866B
    simulation.explore(find=print_success_addr, avoid=print_failure_addr)

    # If found -> Read the input from stdin
    if simulation.found:
        for s in simulation.found:
            flag = s.posix.stdin.concretize()
            print("Flag: ", flag)
    else:
        print("NOT FOUND")
        hook(locals())

if __name__=="__main__":
    main()