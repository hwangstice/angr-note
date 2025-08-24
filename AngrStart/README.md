## Solution

The `main` function is easy to understand. It asks for a **16-byte input** and stores on the stack. After that, the **input** is passed into function `complex_function`. If the return value of `eax` is `0`, I get the string **"Good Job."**.

<img width="727" height="878" alt="image" src="https://github.com/user-attachments/assets/ed954609-a6d4-4e42-8f82-b33787462704" />

My idea is that I start from the instruction `lea rax, [rbp+s]`, and simulate the stack's behaviour, where my input is read from (`rbp+s`).

<img width="336" height="187" alt="image" src="https://github.com/user-attachments/assets/05f23db1-6161-4baf-bacf-104fed2497f2" />

Here, the instruciton `lea rax, [rbp+s]` is at address `0x41A378`

<img width="961" height="141" alt="image" src="https://github.com/user-attachments/assets/f839107e-5daf-420e-8ae9-d5a16294a2b4" />

```python
# Start address
start_addr = 0x41A378
init_state = proj.factory.blank_state(addr=start_addr, add_options={angr.options.LAZY_SOLVES})
```

Now, let's simulate the stack. The picture below shows the local variables (from stack).

<img width="256" height="101" alt="image" src="https://github.com/user-attachments/assets/eb063939-c413-46d8-9eb7-95ebf5a05ea3" />

Here is how the stack looks like.

```
 --------
|        | rbp - 0x8
 -------- 
|        | rbp - 0x10
 --------
|        | rbp - 0x18
 --------
|        | rbp - 0x20 <===== s
 --------
```

The input is stored into the local variable `s`, so the padding is `0x18`. Here is how the code looks like.

```python
# Stack setup
init_state.regs.rbp = init_state.regs.rsp
padding = 0x18
init_state.regs.rsp -= padding
```

Now, I create a symbolic variable for input, and push that to the stack.

```python
# Symbolic password
size = 0x10
password = claripy.BVS("password", size*8)

# Push value to stack
init_state.stack_push(password)
```

Finally, I create a **Simulation Manager** to find **success path**. Also, I add the constraint where input must be printable.

```python
# Simulation manager
simgr = proj.factory.simgr(init_state)
simgr.explore(find=0x41A3AB, avoid=0x41A392)

solution_state = simgr.found[0]

# Ensure password is printable
for i in range(size):
    byte = password.get_byte(i)
    solution_state.solver.add(byte >= 0x20, byte <= 0x7e)
```

Sit back and see **angr** does magic!

<img width="280" height="29" alt="image" src="https://github.com/user-attachments/assets/1a7690dd-2a1e-44e3-adde-8ea574de9b63" />

That is the flag, and it is in reverse order.

Flag: `DH{4ngrEzW4rmup}`
