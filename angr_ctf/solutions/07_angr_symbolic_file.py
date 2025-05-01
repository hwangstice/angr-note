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
    proj = angr.Project("../problems/07_angr_symbolic_file")

    # Create init_state with start address after scanf() and stack clean up
    start_addr = 0x080488D3
    init_state = proj.factory.blank_state(addr=start_addr)

    # -------------------- IDEA ---------------------
    # We need to create symbolic variables which is the file content of OJKSQYDP.txt
    # Furthermore, we have to abort failure message

    # ignore_me() writes input into OJKSQYDP.txt => SHOULD NOT ABORT
    # So, our idea is to write symbolic content into this file
    # When file contains symbolic content, it becomes symbolic file :P

    # Then create symbolic file, link this file content to our symbolic variable
    # After angr find path to success message, we just need to read value 
    # from symbolic variable and we win the challenge :>


    # File name & file size
    file_name = "OJKSQYDP.txt"
    file_size = 0x40

    # Create symbolic variable (content of our symbolic file)
    size_in_bytes = 0x8
    password = init_state.solver.BVS("password", size_in_bytes*8) # because strncmp(buffer, "AQWLCTXB", 9u)

    # Create symbolic file, link file's content to symbolic variable
    password_file = angr.SimFile(name=file_name, content=password, size=file_size)

    # Add SymFile into our state file system
    # where there is a link between file_name and symbolic file
    # => When angr does things like open(file_name) => it will dereference the symbolic file :D
    init_state.fs.insert(file_name, password_file)

    # Prepare simulation
    simulation = proj.factory.simgr(init_state)
    simulation.explore(find=success_message, avoid=failure_message)

    # NOT FOUND
    if not simulation.found:
        print("NOT FOUND")
        hook(locals())

    # FOUND => print file "OJKSQYDP.txt" content from symbolic variable (symbolic file content)
    for s in simulation.found:
        solution_file_content = s.solver.eval(password, cast_to=bytes)
        print("Flag: ", solution_file_content)

if __name__=="__main__":
    main()