## Solution

The `main` function is easy! It asks for a **16-byte input** and stores in variable `buffer`. After that, the input (`buffer`) is passed to `complex_function` to do some math. If the return value from `eax` is `0`, I get the **"Good Job."** string.

<img width="922" height="874" alt="image" src="https://github.com/user-attachments/assets/cd33d4f8-90c1-4c5c-a78a-c0bc3be624d9" />

Since `complex_function` is really long, and tedious to reverse the whole logic, I use **angr**, where I start from the address of instruction `lea rax, buffer`.

<img width="960" height="137" alt="image" src="https://github.com/user-attachments/assets/a18f3821-8066-40bf-8fd3-2aacfef2b2d7" />

That instruction is at offset `0x1C072`, and **angr** loads the binary with base `0x400000`, so the start address for the binary in my script is `0x41C072`. Here, I also use the `UNICORN` to optimize the conrete math calculation in `complex_function`.

```python
# Start address
start_addr = 0x41C072
init_state = proj.factory.blank_state(
    addr=start_addr, add_options={
        angr.options.LAZY_SOLVES, 
        angr.options.UNICORN
    }
)
```

Next, I create a symbolic variable for `buffer` as the input for the program.

```python
# Symbolic variable "buffer"
size = 0x10
password = claripy.BVS("password", size*8)

buffer_addr = 0x41F050
init_state.memory.store(buffer_addr, password)
```

Finally, I start the **Simulation Manager**, and explore the path to **success message**.

```python
# Simulation manager
simgr = proj.factory.simgr(init_state)
def is_success(state):
    return b"Good Job." in state.posix.dumps(1)
def is_failure(state):
    return b"Try again." in state.posix.dumps(1)

simgr.explore(find=is_success, avoid=is_failure)
```

With all of this, run the script, and get the flag!

Flag: `DH{B4s3PlusF1nd}`
