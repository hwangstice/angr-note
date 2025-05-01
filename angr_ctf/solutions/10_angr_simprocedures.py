import angr 
import logging 
import claripy
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
    proj = angr.Project("../problems/10_angr_simprocedures")

    # -------------------------------- IDEA ----------------------------------
    # We create a SimProcedure to hook the function check_equals_ORSDDWXHZURJRBDH()

    # For further reading, please checking those docs out :D
    # 1. https://docs.angr.io/en/latest/extending-angr/simprocedures.html#quick-start
    # 2. https://docs.angr.io/en/latest/api.html#angr.SimProcedure



    # --------------------------------- SOLUTION -----------------------------


    # Create init_state
    init_state = proj.factory.entry_state(add_options={
        angr.options.LAZY_SOLVES
    })


    # Create SimProcedure
    class Sim_Procedure_Replace_Check(angr.SimProcedure):
        # Arguments "user_data_addr" and "length" come from 
        # the function that we hook, in this case is check_equals_ORSDDWXHZURJRBDH()
        def run(self, user_data_addr, length):

            # Load user_data from memory
            load_user_data = self.state.memory.load(user_data_addr, length)

            # Hard-coded password
            hard_coded_password = "ORSDDWXHZURJRBDH"

            # Return value 
            return claripy.If(
                load_user_data == hard_coded_password,
                claripy.BVV(1, 32), # true
                claripy.BVV(0, 32)  # false
            )
        

    check_equals_symbol = "check_equals_ORSDDWXHZURJRBDH"
    proj.hook_symbol(check_equals_symbol, Sim_Procedure_Replace_Check())

    # Prepare simulation and explore the success path
    simulation = proj.factory.simgr(init_state)
    simulation.explore(find=success_message, avoid=failure_message)

    # NOT FOUND 
    if not simulation.found:
        print("NOT FOUND")
        hook(locals())

    # FOUND => concretize to get the password
    for solution_state in simulation.found:
        print("Flag: ", solution_state.posix.stdin.concretize())

if __name__=="__main__":
    main()