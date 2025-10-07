## TL;DR 

This is a **Cracking** challenge from **Root Me**.

Here is the link to challenge: https://www.root-me.org/en/Challenges/Cracking/ELF-x64-Basic-KeygenMe

## Description

```
Find the serial for the "root-me.org" user.

The validation password is the serial’s sha256 hash.
```

## Analysis

It is an **ELF-64**.

```shell
❯ file ch36.bin
ch36.bin: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, stripped
```

Initial run.

```shell
❯ ./ch36.bin
[!] x64 NASM Keygen-Me
[A] root-me
[?] Login : hehehaha

[.|..] THE GAME
```

Let's check the strings.

```
❯ strings ch36.bin
[!] x64 NASM Keygen-Me
[A] root-me
[?] Login : [?] Key :
[\o/] Yeah, good job bro, now write a keygen :)
[.|..] THE GAME
.m.key
t9PH
.bss
.data:
.shstrtab
.text:
```

The output from `strings` command contains **NASM** (https://www.nasm.us/). This means the program was written in assembly language and assembled into object code using NASM assembler.

This also suggests that the code might use **sys calls**, instead of standard library functions. Then it is ideal to have **Linux System Call Table** by your side (https://chromium.googlesource.com/chromiumos/docs/+/master/constants/syscalls.md#x86_64-64_bit)

Let's load the binary into **IDA**.

The binary is surprisingly short (only 3 functions)!

<img width="207" height="70" alt="image" src="https://github.com/user-attachments/assets/b43644e4-f837-4caa-829c-b3524eacc8fd" />

Here is the pseudo-code of `start`.

```c
void __noreturn start()
{
  signed __int64 v0; // rax
  signed __int64 v1; // rax
  int v2; // edx
  signed __int64 v3; // rax
  signed __int64 v4; // rax
  signed __int64 v5; // rax
  signed __int64 v6; // rax
  signed __int64 v7; // rax

  v0 = sys_write(
         1u,
         "[!] x64 NASM Keygen-Me\n"
         "[A] root-me   \n"
         "[?] Login : [?] Key : \n"
         "[\\o/] Yeah, good job bro, now write a keygen :)\n"
         "\n"
         "[.|..] THE GAME\n"
         ".m.key",
         0x32u);
  v1 = sys_read(0, input, 0x20u);
  v3 = sys_open(".m.key", 0, v2);
  if ( v3 == -2 || (v4 = sys_read(v3, &input[32], 0x20u), sub_400146((__int64)input, 6292096)) )
    v5 = sys_write(1u, "\n[.|..] THE GAME\n.m.key", 0x11u);
  else
    v6 = sys_write(1u, "\n[\\o/] Yeah, good job bro, now write a keygen :)\n\n[.|..] THE GAME\n.m.key", 0x31u);
  v7 = sys_exit(0);
}
```

The flow is easy to understand: 

```
Read input --> Open .m.key --> Read .m.key to input[32] --> Call sub_400146() --> Condition checking
```

This means that I also need to create the file `.m.key`.

```shell
❯ echo "content of .m.key" > .m.key
```

The two parameters passing to `sub_400146` look interesting!

<img width="475" height="303" alt="image" src="https://github.com/user-attachments/assets/02be5316-50b9-4b8b-9fc2-6585505c5fd8" />

<img width="819" height="510" alt="image" src="https://github.com/user-attachments/assets/e8cdc058-06de-4c78-a678-4b7aad38c3f7" />

So, it is passing the input, and content of `.m.key` into function `sub_400146`.

Here is how `sub_400146` looks like.

<img width="1129" height="954" alt="image" src="https://github.com/user-attachments/assets/8032d606-e23a-4be2-a6e0-879cced96914" />

- Firstly, it calculates the length of input via `len_400135`. If the length is `1`, it returns `0x1337`, which triggers the false message!

  ```c
  __int64 __fastcall sub_400135(__int64 input)
  { 
    __int64 result; // rax

    for ( result = 0; *(_BYTE *)(input + result); ++result )
      ;
    return result;
  }
  ```

- After that, it creates a loop, which iterates `len - 1` times to compare `input[i] - i + 0x14` with `.m.key[i]`. The below is how it looks like.

  ```c
  for (int i = 0; i < len - 1; ++i) {
      if ((input[i] - i + 0x14) != .m.key[i])
          return 0x1337; 
  }
  return 0;
  ```

The goal is to trigger the success message, and this can only be achieved when the function `sub_400146` returns `0` (when input matches `.m.key`).

From the description, I get the correct login is `root-me.org`, and my job is to find the serial (content of `.m.key` calculated from input). Finally, I just need to calculate the **SHA256** of this serial.

## Solution

I use angr.

```python
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

proj = angr.Project("./ch36.bin")

# Start address
start_addr = 0x4001C0
init_state = proj.factory.blank_state(addr=start_addr)

# Store input
input = claripy.BVV("root-me.org\n")
init_state.memory.store(0x600260, input)

# Simulation manager
simgr = proj.factory.simgr(init_state)
simgr.explore(find=0x400232, avoid=0x400215)

if not simgr.found:
    print("Not found")
    hook(locals())

print(simgr.found[0].posix.dumps(3))
```

Here, I dump from **file descriptor** `3`. This is because file descriptor `0`, `1`, `2` are `stdin`, `stdout`, `stderr` respsectively. Since `0` ~ `2` are already occupied, when the binary opens a file `.m.key` and do something with this file, it is assigned to the file descriptor `3`.

This is the output from the script.

<img width="414" height="41" alt="image" src="https://github.com/user-attachments/assets/7f40afa1-19ca-4f6c-9fb0-b889feae7a13" />

Let's put this into `.m.key`, and I get the success message.

```shell
❯ echo -ne "\x86\x82\x81\x85=|s;{}q" > .m.key

❯ ./ch36.bin
[!] x64 NASM Keygen-Me
[A] root-me
[?] Login : root-me.org

[\o/] Yeah, good job bro, now write a keygen :)
```

The content of `.m.key` is the serial for the `root-me.org` user.

Let's get the the **SHA256**.

<img width="2040" height="737" alt="image" src="https://github.com/user-attachments/assets/bf62352e-4347-44e2-8bad-04087f12c2b9" />

SHA256: `5c58dde9f9c213485fb1863492e0760d0427809eb88aaec06100f64add822c26`

<img width="2080" height="565" alt="image" src="https://github.com/user-attachments/assets/00df6327-2b6e-4e44-9a1f-a196aeb0d0d3" />


