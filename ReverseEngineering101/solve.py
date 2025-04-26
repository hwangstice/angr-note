import angr 
import logging 

logging.getLogger('angr').setLevel(logging.INFO)

def hook(l=None):
    if l:
        locals().update(l)
    import IPython
    IPython.embed(banner1='', exit_msg='', confirm_exit=False)
    exit(0)

def main():
    proj = angr.Project("./RE101")

    # Prepare simulation
    start_addr = 0x080480B8
    init_state = proj.factory.blank_state(addr=start_addr)

    # We only do one step, because our program starts at "_start"
    # and the flag is stored in a variable.
    # We just need to make one step, to make sure that variable has the value
    # Then read the value from that variable
    simulation = proj.factory.simgr(init_state)
    simulation.step()

    if not simulation.active:
        print("NOT FOUND")
        hook(locals())

    # Find flag
    flag = simulation.active[0].mem[0x0804911A].string.concrete
    print("Flag: ", flag)

if __name__=="__main__":
    main()