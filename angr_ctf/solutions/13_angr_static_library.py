import angr 
import logging 
import sys

logging.getLogger("angr").setLevel(logging.INFO)

def hook(l=None):
    if l:
        locals().update(l)
    import IPython
    IPython.embed(banner1='', exit_msg='', confirm_exit=False)
    exit(0)

def success_message(state):
    return b"Good Job." in state.posix.dumps(sys.stdout.fileno())

def failure_message(state):
    return b"Try again." in state.posix.dumps(sys.stdout.fileno())

def main():
    proj = angr.Project("../problems/13_angr_static_binary")



    # ------------------------------------ IDEA ---------------------------------------
    # The binary is a static binary:
    
    # ❯ file 13_angr_static_binary
    # 13_angr_static_binary: ELF 32-bit LSB executable, Intel 80386, version 1 (GNU/Linux), statically linked, for GNU/Linux 2.6.32, BuildID[sha1]=89d11f111deddc580fac3d22a1f6c352d1883cd5, not stripped

    # ❯ ldd 13_angr_static_binary
    #     not a dynamic executable

    # When ANGR runs the binary, if it is a DYNAMIC BINARY, ANGR will replace the "libc"
    # and "glibc" functions with its own SimProcedures
    # => Make ANGR faster and efficient

    # If it is STATIC BINARY, the functions from "libc" and "glibc" is linked into the binary
    # This means ANGR will run the actual code instead of SimProcedure for those functions
    # => Make ANGR slow

    # To resolve this problem for STATIC BINARY, we must HOOK those functions to 
    # SimProcedures in ANGR.



    # -------------------------------------- SOLUTION ----------------------------------

    # "libc" functions address linked in the STATIC BINARY
    # (strncmp is in PLT section) => No need to find the address
    printf_addr = 0x0804ED40
    scanf_addr = 0x0804ED80
    puts_addr = 0x0804F350

    # "glibc" function address linked in the STATIC BINARY
    __libc_start_main_addr = 0x08048D10

    # HOOK "libc" and "glibc" functions to SimProcedures in ANGR
    # 
    # Remember the "()" at the end of each SimProcedures
    # - Without "()" it just points out where the function is in SimProcedure, not creating an instance of that function from SimProcedure
    # - With "()", creating an instace from SimProcedure and overwrite it into memory
    proj.hook(printf_addr, angr.SIM_PROCEDURES["libc"]["printf"]())
    proj.hook(scanf_addr, angr.SIM_PROCEDURES["libc"]["scanf"]())
    proj.hook(puts_addr, angr.SIM_PROCEDURES["libc"]["puts"]())
    proj.hook(__libc_start_main_addr, angr.SIM_PROCEDURES["glibc"]["__libc_start_main"]())

    # Create init_state
    init_state = proj.factory.entry_state()

    # Prepare simulation
    simulation = proj.factory.simgr(init_state)
    simulation.explore(find=success_message, avoid=failure_message)

    # NOT FOUND 
    if not simulation.found:
        print("NOT FOUND")
        hook(locals())

    # FOUND => concretize the input
    for solution_state in simulation.found:
        print("Flag: ", solution_state.posix.stdin.concretize())

if __name__=="__main__":
    main()