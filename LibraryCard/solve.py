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
    proj = angr.Project("./liblibrary_card.so")

    # Find address of print_flag() in the binary

    # No need to create an initial_state because "callable" has done that for us
    # We basically tell angr to find the function "print_flag" and give us the output
    # when we give the arugments to the function "print_flag"

    # This is like a blackbox -> We tell angr "hey, find this function, 
    # and give me the output" => Not need for init_state
    print_flag_addr = proj.loader.find_symbol("print_flag").rebased_addr
    print_flag = proj.factory.callable(print_flag_addr)
    print_flag(2084, 0x82C, 2091) # Call print_flag function with arguments

    if not print_flag:
        print("print_flag function not found")
        hook(locals())  

    # print_flag function is called successfully
    # --> print out its output
    solution = print_flag.result_state.posix.stdout.concretize()
    print("Flag: ", solution)

if __name__=="__main__":
    main()