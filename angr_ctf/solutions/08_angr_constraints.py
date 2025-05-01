import angr 
import logging 
import sys
import claripy

logging.getLogger("angr").setLevel(logging.INFO)

def hook(l=None):
    if l:
        locals().update(l)
    import IPython
    IPython.embed(banner1='', exit_msg='', confirm_exit=False)
    exit(0)

def failure_message(state):
    return b"Try again." in state.posix.dumps(sys.stdout.fileno())

def main():
    proj = angr.Project("../problems/08_angr_constraints")

    # ----------------------------- IDEA ---------------------------------
    # Since the loop for check_equals_AUPDNNPROEZRJWKB(user_data, 16) 
    # compares character by character => This will create tons of branches 
    # in ANGR, which means ANGR creates exponentionally 2 possible states (True and False)

    # This will slow down our working process => Need to avoid

    # To fix this, we can put a constraint before check_equals_AUPDNNPROEZRJWKB() to replace it!
    # Meaning, we replace the check_equals_AUPDNNPROEZRJWKB() function with our constraint in ANGR.
    # Instead of comparing character by character, we will force ANGR into choosing the only synbolic variable that holds the value that is equal to our actual password, which is "AUPDNNPROEZRJWKB"

    
    # ----------------------------- Solution ------------------------------


    # Create init_state after the call to scanf() and stack clean up
    start_addr = 0x08048625
    init_state = proj.factory.blank_state(addr=start_addr)

    # Create symbolic variable for user_data
    size_in_bytes = 0x10
    password = claripy.BVS("password", size_in_bytes*8) 
    # OR 
    # password = init_state.solver.BVS("password", size_in_bytes*8)


    # Write symbolic variable into memory of user_data in program
    user_data_addr = 0x0804A050
    init_state.memory.store(user_data_addr, password)


    # Here, we must specify the address before check_equals_AUPDNNPROEZRJWKB()
    # to be our check_point_addr. 
    #
    # This check_point_addr will be the placeholder so that we can replae
    # check_equals_AUPDNNPROEZRJWKB() with our manual constraints


    # Prepare simulation to find the check_point_addr
    check_point_addr = 0x08048669 # before call to check_equals_AUPDNNPROEZRJWKB()
    simulation = proj.factory.simgr(init_state)
    simulation.explore(find=check_point_addr, avoid=failure_message)

    
    # NOT FOUND
    if not simulation.found:
        print("NOT FOUND")
        hook(locals())

    # FOUND => create our constraint to make angr 
    for solution_state in simulation.found:
        # Here comes the constraint where ANGR will give out the only possible 
        # symbolic value that meet our condition in the constraint!
        
        load_user_data = solution_state.memory.load(user_data_addr, size_in_bytes)
        solution_state.add_constraints(load_user_data == "AUPDNNPROEZRJWKB")

        # Now ANGR must give us the correct value for our symbolic variable
        # Let's concretize it :>
        solution_password = solution_state.solver.eval(password, cast_to=bytes)
        print("Flag: ", solution_password)

if __name__=="__main__":
    main()