import angr

p = angr.Project("./RE101")
sm = p.factory.simulation_manager()
sm.step()

# After passing through the start entry -> read mem from specific address of edata
s = sm.active[0]
print(s.mem[0x804911A].string.concrete)