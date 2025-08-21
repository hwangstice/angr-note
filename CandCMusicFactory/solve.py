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

def rebase(addr):
    return 0x7ffff78016ac - 0x16AC + addr

proj = angr.Project("./core.1747")

# addr      return
# 0xF4C     17
# 0x1647    32, 115
# 0x13aa    16, 4294967169
# 0x1547    112, 4294967185
# 0x157b    4294967233, 0
# 0x1020    4294967232, 4294967251

def perform_check(state):
    # Check if rdx is symbolic
    check_func = state.regs.rdx
    if state.solver.symbolic(check_func):
        print("Symbolic rdx")
        hook(locals())

    # Create symbolic return values
    check_func = state.solver.eval_one(check_func)
    print("rdx = {:016x}".format(check_func))
    ret_val = claripy.BVS("ret_val_{:016x}".format(check_func), 8*8)
    state.regs.rax = ret_val
    collection = state.globals.get('return_values', []).copy()
    collection.append(ret_val)
    state.globals['return_values'] = collection

    # Mapping between function call (rdx) and return value (rax)
    if check_func == rebase(0xF4C):
        state.solver.add(ret_val == 17)
    elif check_func == rebase(0x1647):
        state.solver.add(claripy.Or(
            ret_val == 32, 
            ret_val == 115
        ))
    elif check_func == rebase(0x13aa):
        state.solver.add(
            claripy.Or(
                ret_val == 16,
                ret_val == 4294967169
            )
        )
    elif check_func == rebase(0x1547):
        state.solver.add(claripy.Or(
            ret_val == 112,
            ret_val == 4294967185
        ))
    elif check_func == rebase(0x157b):
        state.solver.add(claripy.Or(
            ret_val == 0,
            ret_val == 4294967233
        ))
    elif check_func == rebase(0x1020):
        state.solver.add(claripy.Or(
            ret_val == 4294967232,
            ret_val == 4294967251
        ))
    else:
        print("No return value")
        hook(locals())


# Hook
proj.hook(rebase(0x16CE), perform_check, 2)

# target = rebase(0x16CE)
target = rebase(0x1731)
simgr = proj.factory.simgr()
simgr.explore(find=target)

hook(locals())