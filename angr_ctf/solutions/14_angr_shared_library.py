import angr 
import logging 
import claripy

logging.getLogger("angr").setLevel(logging.INFO)

def hook(l=None):
    if l:
        locals().update(l)
    import IPython
    IPython.embed(banner1='', exit_msg='', confirm_exit=False)
    exit(0)

def main():


    # ------------------------------ IDEA ----------------------------
    # 
    # The idea here is to load the library ".so" with a fake base address.
    #
    # Then from the base address, we will find the address of function 
    # validate(), which can be interpreted as: "base + offset"
    #
    # Rememeber that the arguments off validate(), it contains the input password
    # So we can basically create a symbolic variable and let ANGR find that for us :D


    # ----------------------------- SOLUTION --------------------------


    # Load the ".so" library
    base = 0x40000000 # Fake base address :>
    proj = angr.Project(
        "../problems/lib14_angr_shared_library.so",
        load_options={
            'main_opts' : {
                'custom_base_addr' : base
            }
        }
    )

    # Based on the function format:
    # _BOOL4 __cdecl validate(char *s1, int a2)
    # 
    # We must create an fake address (*s1), the length (a2)
    # and address of validate = base + offset
     
    validate_addr = base + 0x6D7
    buffer_pointer = claripy.BVV(0x90000000, 32) # act as a pointer to the later symbolic password
    length = claripy.BVV(0x8, 32)
    

    # Here is the key:
    
    # Our state will start from the call to function validate()
    # because inside validate(), (*s1) is actually our password
    # => just create the symbolic variable for (*s1) and we are done :D

    # This means that we can create a symbolic variable linked to the pointer (buffer_pointer)

    # This is like a function call => validate(char *s1, int a2)
    init_state = proj.factory.call_state(validate_addr, buffer_pointer, length)


    # Now, we will create symbolic password, where it is stored into the buffer_pointer
    size_in_bytes = 0x8
    password = claripy.BVS("password", size_in_bytes*8)

    # Write symbolic password into buffer_pointer
    init_state.memory.store(buffer_pointer, password)

    # After finishing the set up, we can start our simulation
    # But where should our simulation explore?
    #
    # => The smart thing is that we explore to the end of validate() 
    # and put a constraint for only the True => ANGR will discard those "password" 
    # that doesn't match the True :>
    #
    # Then concretize the password (symbolic variable) :P
    simulation = proj.factory.simgr(init_state)

    check_point_addr = base + 0x783 # the end of validate()
    simulation.explore(find=check_point_addr)

    # NOT FOUND 
    if not simulation.found:
        print("NOT FOUND")
        hook(locals())

    # FOUND => Add constraint to get the "password" for the True
    for solution_state in simulation.found:
        # Add constraint that the function return must be true
        solution_state.add_constraints(solution_state.regs.eax != 0)

        solution_password = solution_state.solver.eval(password, cast_to=bytes)
        print("Flag: ", solution_password)

if __name__=="__main__":
    main()