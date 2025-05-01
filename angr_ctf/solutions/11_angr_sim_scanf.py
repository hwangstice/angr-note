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
    proj = angr.Project("../problems/11_angr_sim_scanf")

    # SimProcedure to replace scanf
    class ReplaceScanf(angr.SimProcedure):
        def run(self, format_string, addr1, addr2):
            # Create 2 symbolic variables for our input
            size_in_bytes = 0x4
            password1 = claripy.BVS("password1", size_in_bytes*8)
            password2 = claripy.BVS("password2", size_in_bytes*8)

            # Write the 2 symbolic variables into memory
            # Since we are writing number into address => remember endianness
            self.state.memory.store(addr1, password1, endness=proj.arch.memory_endness)
            self.state.memory.store(addr2, password2, endness=proj.arch.memory_endness)

            # Store 2 symbolic variables into global "dict" 
            # so that we can reference it outside the SimProcedure
            self.state.globals["solutions"] = (password1, password2)

    scanf_symbol = "__isoc99_scanf"
    proj.hook_symbol(symbol_name=scanf_symbol, simproc=ReplaceScanf())

    # Create entry state
    init_state = proj.factory.entry_state()

    # Prepare simulation
    simulation = proj.factory.simgr(init_state)
    simulation.explore(find=success_message, avoid=failure_message)

    # NOT FOUND
    if not simulation.found:
        print("NOT FOUND")
        hook(locals())

    for solution_state in simulation.found:
        real_password = solution_state.globals["solutions"]
        print("Flag", solution_state.solver.eval(real_password[0]), solution_state.solver.eval(real_password[1]))

if __name__=="__main__":
    main()