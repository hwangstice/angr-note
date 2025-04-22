# These are my notes about **ANGR** helper.

## Run angr 
>[!NOTE]
>Place this and binary in ./files/

```
sudo docker run -v "$(pwd)"/files:/mnt -it angr/angr
```

### https://docs.angr.io/examples
### https://www.youtube.com/playlist?list=PL-nPhof8EyrGKytps3g582KNiJyIAOtBG

```
import angr
import claripy
import sys
import logging

PROGRAM = "./crackme1"
```

## Change logging level to see where we get stuck 
```
logging.getLogger("angr").setLevel(logging.INFO)
```

## Project to wrap the EXE. Maybe don't want to go into SO code
### https://docs.angr.io/built-in-analyses/cfg#shared-libraries

```
proj = angr.Project(PROGRAM)
proj = angr.Project(PROGRAM, load_options={"auto_load_libs": False})
```

## Creating a symbolic variable for input

```
byte_length = 32
input_data = claripy.BVS("input_data", byte_length * 8)
```

## Create a state for the simulation manager
### https://docs.angr.io/appendix/options#options

### stdin

```
initial_state = proj.factory.entry_state(stdin=input_data) 
```

### argv1

```
initial_state = proj.factory.entry_state(args=[PROGRAM, input_data]) 
initial_state = proj.factory.entry_state(args=[PROGRAM, input_data], add_options={angr.options.LAZY_SOLVES})
initial_state = proj.factory.entry_state(args=[PROGRAM, input_data], add_options={angr.options.LAZY_SOLVES, "BYPASS_UNSUPPORTED_SYSCALL"})
```

## Making a callable function can also be useful

```
start_func = p.loader.find_sybol("win_func").rebased_addr # find function address in binary
func = proj.factory.callable(start_func) # or use address
func(args_go_here)
initial_state = func.result_state
```

## Now you can cheeck stdin, stdout, etc

### Increase length if we need more bytes for input/add constraints ###

### Default is 60
```
if byte_length >= 60:
    initial_state.libc.buf_symbolic_bytes=byte_length + 1
```

### All input is in string.printable
```
import string
for i in range(USER_DATA_LENGTH):
    s.solver.add(
        claripy.Or(*(
            user_data.get_byte(i) == x 
            for x in printable.encode('utf-8')  
        ))
    )
```

## Can add more constraints for certain letters if you know the beginning

```
initial_state.add_constraints(argv1.chop(8)[0] == 'C')
```


## Make sure none of the input bytes are NULL (May not be good if the given string is null terminated)
```
for byte in input_data.chop(8):
    initial_state.add_constraints(byte != 0)
```

## Create simulation manager ##
>Simulation managers are a basic building block of the symbolic execution engine.<br>
>They track a group of states as the binary is executed, and allows for easier
>management, pruning, and so forth of those states

```
sm = proj.factory.simulation_manager(initial_state)
sm = proj.factory.simulation_manager(initial_state, veritesting=True)
```

## There are several ways to run through the program ##

```
# sm.run()

# flag_locate = p.loader.find_symbol("win_func").rebased_addr
# sm.explore(find=flag_locate, avoid=0x00000)

# Can also have lists for arguments
sm.explore(find=0x400830, avoid=0x400850)

# found this for looking for string printout messages: https://pwndiary.com/0ctf-2020-happytree
sm.explore(
        find=lambda s: b"Success!" in s.posix.dumps(1),
        avoid=lambda s: b"Failure!" in s.posix.dumps(1),
        step_func=lambda lsm: lsm.drop(stash='avoid'))

# Here's an example of breaking up a big problem into smaller ones
sm.explore(find=0x4016A3).unstash(from_stash='found', to_stash='active')
sm.explore(find=0x4016B7, avoid=[0x4017D6, 0x401699, 0x40167D]).unstash(from_stash='found', to_stash='active')
sm.explore(find=0x4017CF, avoid=[0x4017D6, 0x401699, 0x40167D]).unstash(from_stash='found', to_stash='active')
sm.explore(find=0x401825, avoid=[0x401811])

# might be more items in list, so check
print(len(sm.found))
found = sm.found[0]
print(found)
solution = found.solver.eval(input_data, cast_to=bytes)
print(solution)
# solution = solution[:solution.find(b"}")+1] # Trim off the null bytes at the end of the flag (if any).

print(sm.found)
print(sm.found[0].posix.stdin.concretize())
print(sm.found[0].posix.stdout.concretize())
```

### https://docs.angr.io/examples
### https://github.com/angr/angr-doc/blob/master/docs/more-examples.md