## Solution

### Overview

Here is the information about the binary.

```shell
❯ file chall
chall: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=7a93d441dd0941f950536a6569c5c22f9ede6750, for GNU/Linux 4.4.0, not stripped
```

It is an **ELF 64-bit binary**.

Let's run it.

```shell
❯ ./chall
Enter the password: haha
Incorrect length!
```

Looks like there is also a **password-length check** condition in the binary.

### Initial Thought

Let's load it into IDA.

<img width="1093" height="5091" alt="image" src="https://github.com/user-attachments/assets/d2f604bb-1a5d-4bc3-a3d6-89b0133edf54" />

Here, the `main` function reads **a 16-byte password** into `buffer`, checks its length with `strlen`, runs `complex_function`, then prints either success or failure.

To bypass the `strlen`, I start from the instruction `lea rax, buffer`.

<img width="334" height="154" alt="image" src="https://github.com/user-attachments/assets/ac57ef5d-f070-4f57-b2a6-16e48fa70bcf" />

The address is `0x1A561`.

<img width="962" height="138" alt="image" src="https://github.com/user-attachments/assets/fa1c0864-5603-4615-afe8-e47a009877a2" />

It is a pain for myself when I first look at the function `complex_function`. It is super long...

<img width="94" height="292" alt="image" src="https://github.com/user-attachments/assets/9686b33f-16b7-4564-adc7-6ebf92350c98" />

Despite its size, the function is simple. It runs many math-heavy blocks, each ending with a check. The image below shows the check in the first block.

<img width="655" height="63" alt="image" src="https://github.com/user-attachments/assets/b87c5360-9102-4ad5-90af-b2c251db2abb" />

**angr** can easily handle these math-heavy blocks with option `UNICORN`, so it is not a big problem.

At the end, the function calls `path_explosion_loop`.

<img width="476" height="170" alt="image" src="https://github.com/user-attachments/assets/4bde9545-8b0c-4757-b91a-acb035a616e9" />

As its name suggests, `path_explosion_loop` causes **path explosion** in **angr** because of its nested loops. Below is its pseudo-code.

```c
__int64 __fastcall path_explosion_loop(_QWORD *input)
{
  __int64 v1; // rdx
  char v3; // [rsp+17h] [rbp-39h]
  int tmp_1; // [rsp+18h] [rbp-38h]
  int tmp_2; // [rsp+1Ch] [rbp-34h]
  int tmp_3; // [rsp+20h] [rbp-30h]
  int i; // [rsp+24h] [rbp-2Ch]
  int j; // [rsp+28h] [rbp-28h]
  int k; // [rsp+2Ch] [rbp-24h]
  _QWORD ptr[4]; // [rsp+30h] [rbp-20h] BYREF

  ptr[3] = __readfsqword(0x28u);
  v1 = input[1];
  ptr[0] = *input;
  ptr[1] = v1;
  tmp_1 = 305419896;
  tmp_2 = -1640531527;
  tmp_3 = 0;
  for ( i = 0; i <= 1023; ++i )
  {
    for ( j = 0; j <= 15; ++j )
    {
      v3 = i + tmp_3 + tmp_2 + tmp_1 + j;
      tmp_1 += *((unsigned __int8 *)ptr + j) + 2135587861;
      tmp_2 ^= (*((unsigned __int8 *)ptr + j) << (j & 7)) | (*((unsigned __int8 *)ptr + j) >> (~(_BYTE)j & 7));
      tmp_3 += __ROL4__(tmp_2, 1) + i * (j + 1);
      *((_BYTE *)ptr + j) ^= v3;
    }
  }
  for ( k = 0; k <= 15; ++k )
    *((_BYTE *)ptr + k) = ks_0[k] ^ *((_BYTE *)input + k);
  fwrite(ptr, 1u, 0x10u, _bss_start);
  fputc(10, _bss_start);
  return 0;
}
```

I first thought the option `veritesting` could handle this, but it didn't work as intended *:(*

### First Attempt

As mentioned, I start execution at `0x1A561` to skip `strlen`. Since **angr** rebases the binary, I set its base address to `0x0`.

```python
# Start address
start_addr = 0x1A561
proj = angr.Project("./chall", main_opts={'base_addr': 0x0}) 

init_state = proj.factory.entry_state(
    addr=start_addr,
    add_options={
        angr.options.LAZY_SOLVES,
        angr.options.UNICORN
    }
)
```

Now, I create a symbolic variable for input (`buffer`).

```python
# Symbolic variable "buffer"
size = 0x10
password = claripy.BVS("password", size*8)

buffer_addr = 0x1D060
init_state.memory.store(buffer_addr, password)
```

To boost the speed of the script, I constrain the input to match the flag format `DH{...}`.

```python
# Input constraints to flag format DH{...}
init_state.solver.add(password.get_byte(0) == ord('D'))
init_state.solver.add(password.get_byte(1) == ord('H'))
init_state.solver.add(password.get_byte(2) == ord('{'))
init_state.solver.add(password.get_byte(15) == ord('}'))

for i in range(3, 15):
    byte = password.get_byte(i)
    init_state.solver.add(byte >= 0x30) # '0'
    init_state.solver.add(byte <= 0x7a) # 'z'
```

I start the **Simulation Manager** with `veritesting` to tackle the path explosion problem.

```python
# Use veritesting to avoid Path Explosion
simgr = proj.factory.simgr(init_state, veritesting=True)
simgr.explore(find=0x1A594, avoid=0x1A57E)
```

Even after two hours, the script hasn't finished... `veritesting` alone can't handle the nested loops in `path_explosion_loop`.

### Second Attempt

This time, I focus on reversing `complex_function` and `path_explosion_loop`.

- `complex_function` only performs math on the password without modifying it. If all block checks pass, execution reaches `path_explosion_loop`, so no hooks or extra constraints are needed for this function.

- In `path_explosion_loop`, the nested loop doesn't affect the input. The only part that matters is the final loop, which XORs the input with `ks_0` and writes the result to `_bss_start`. This is the section I need to hook.

<img width="1253" height="841" alt="image" src="https://github.com/user-attachments/assets/9a8fa01d-9209-4787-81d9-ee89c3f55021" />

Here is my hook.

```python
# Hook path_explosion_loop
def PathExplosionHook(state):
    input_addr = state.regs.rdi
    ks_0_addr = 0x1B060
    bss_start_addr = 0x1D050

    for i in range(16):
        input_byte = state.memory.load(input_addr + i, 1)
        ks_0_byte = state.memory.load(ks_0_addr + i, 1)
        output_byte = input_byte ^ ks_0_byte
        state.memory.store(bss_start_addr + i, output_byte)

    # Return value
    state.regs.rax = 0

addr_to_hook = 0x1A4D9
proj.hook(addr=addr_to_hook, hook=PathExplosionHook, length=5)
```

Just run the script [here](./solve.py), and get the password!

<img width="287" height="38" alt="image" src="https://github.com/user-attachments/assets/dd6ed8d4-7d78-4b21-842c-7457ec18fbe3" />

Enter the password and get the flag.

<img width="1691" height="155" alt="image" src="https://github.com/user-attachments/assets/211b199c-5944-458e-84dc-7e5718003cd6" />

Flag: `DH{T00M4nyL00ps}`

### Additional Note

Wait, why does the flag print here, when the only visible `stdout` output seems to be the one in the image?

<img width="659" height="665" alt="image" src="https://github.com/user-attachments/assets/e8352338-f766-4fc2-9c09-b9221197285d" />

This happens because the final loop in `path_explosion_loop` decodes the password with **XOR**, producing the flag.

<img width="646" height="113" alt="image" src="https://github.com/user-attachments/assets/beb28206-2723-4f5d-a940-daf5de323ee3" />

It then writes the flag to `_bss_start`, which is an alternative name for `stdout` in `glibc`.

<img width="1109" height="161" alt="image" src="https://github.com/user-attachments/assets/f00ffc9f-9af2-4e85-ad12-6b0466c1151c" />
