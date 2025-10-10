# Solution

## Analysis

This is an **ELF-64**, **little-endian**. 

```shell
❯ file ch73.bin
ch73.bin: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=ac274df65ec4dd41156824695e8f610864d08ab6, for GNU/Linux 4.4.0, not stripped
```

Here is the `main` from **IDA**.

<img width="607" height="935" alt="image" src="https://github.com/user-attachments/assets/bfb52968-8dc1-4437-8ca4-cb0f39d3cf38" />

It asks for the key from `check` function. Here, I have the pseudo-code of `check` function.

```c
int __fastcall check(const char *input)
{
  int i; // [rsp+1Ch] [rbp-14h]

  for ( i = 0; i < strlen(input); ++i )
    input[i] ^= key[i % 8];
  if ( *(_QWORD *)input == 0xA377AD570465FDF9LL )
    return puts("C'est correct !");
  else
    return puts("Essaie encore !");
}
```

It is easy to understand. It performs XORs between input and key. If the after XOR output is equal to `0xA377AD570465FDF9`, I get the success message.

This is the content of `key`.

<img width="953" height="92" alt="image" src="https://github.com/user-attachments/assets/010f3e6e-d115-43b2-a0de-dace63a27ab0" />

With simple inverse XOR operation, I can get the key.

```python
key = [0xA8, 0x96, 0x4F, 0x7F, 0x3E, 0x94, 0x0A, 0x95]
out = [0xf9, 0xfd, 0x65, 0x04, 0x57, 0xad, 0x77, 0xa3]

for i in range(len(key)):
    print(chr(key[i % 8] ^ out[i]), end='')
```

This gives me `Qk*{i9}6` as output. 

When I validate the key with `strace`, it works fine.

<img width="910" height="488" alt="image" src="https://github.com/user-attachments/assets/a679c605-1984-45b7-8401-b2bf93249b91" />

However, when I run the binary, my key is wrong!

```shell
❯ ./ch73.bin
Key: Qk*{i9}6
Essaie encore !
```

Look closely at the output of `strace`, there is a system call to `ptrace`.

<img width="584" height="47" alt="image" src="https://github.com/user-attachments/assets/766d0492-8792-4f2a-afc0-a9915dc3e5c4" />

The function `__do_global_ctors_aux` is the one that calls `ptrace`.

```c
signed __int64 __fastcall _do_global_ctors_aux()
{
  unsigned __int64 v0; // r10
  signed __int64 result; // rax
  int i; // [rsp+0h] [rbp-10h]
  _QWORD *v3; // [rsp+8h] [rbp-8h]

  result = sys_ptrace(0, 0, 0, v0);
  result = (unsigned int)result;
  if ( (_DWORD)result != -1 )
  {
    result = (signed __int64)&data_start;
    v3 = &data_start;
    for ( i = 0; i <= 255; ++i )
    {
      result = 0x950A943E7F4F96A8LL;
      if ( *v3 == 0x950A943E7F4F96A8LL )
      {
        result = (signed __int64)v3;
        *v3 ^= 0x119011901190119uLL;
        return result;
      }
      ++v3;
    }
  }
  return result;
}
```

This function alters the value of `key` in memory based on the return value of `ptrace`. If there is not debugger, `ptrace` returns `0` and change the value in `key`.

So, the problem that I have to bypass here is making `ptrace` returns `0`.

## Hook `ptrace`

Here, I have an angr script to hook `ptrace`.

```python
import angr 
import sys

def success(state):
    return b"C'est correct !" in state.posix.dumps(sys.stdout.fileno())

def failure(state):
    return b"Essaie encore !" in state.posix.dumps(sys.stdout.fileno())

proj = angr.Project("./ch73.bin", auto_load_libs=False)

# Hook sys_ptrace
def SysPtraceHook(state):
    state.regs.rax = 0

addr_to_hook = 0x4011A1
proj.hook(addr=addr_to_hook, hook=SysPtraceHook, length=2)

init_state = proj.factory.full_init_state()

# print(hex(proj.loader.main_object.min_addr))      # -> 0x400000

# Simulation Manager & find success state
simgr = proj.factory.simgr(init_state)
simgr.explore(find=success, avoid=failure)

if not simgr.found:
    print("Not found")

print(simgr.found[0].posix.stdin.concretize())
```

This is the output of the script.

<img width="289" height="31" alt="image" src="https://github.com/user-attachments/assets/989bbd01-f092-4a01-9264-457d177381e0" />

Validate the key and get the success message.

```shell
❯ ./ch73.bin
Key: Hj3zp8d7
C'est correct !
```

## Hook `__do_global_ctors_aux`

This is my hook to simulate the working of `__do_global_ctors_aux`.

```python
# Hook _do_global_ctors_aux
def DoGlobalCtorsAuxHook(state):
    key_addr = 0x404048
    key = state.memory.load(key_addr, 8, endness=proj.arch.memory_endness)
    # print("hehe pass")
    # print("key", hex(state.solver.eval(key)))

    xor_val = claripy.BVV(0x119011901190119, 64)
    new_key = key ^ xor_val
    # print("new key", hex(state.solver.eval(new_key)))
    state.memory.store(key_addr, new_key)
    # test_new_key = state.memory.load(key_addr, 8, endness=proj.arch.memory_endness)
    # print("new key", hex(state.solver.eval(test_new_key)))

    state.regs.rax = key

addr_to_hook = proj.loader.find_symbol("__do_global_ctors_aux").rebased_addr
proj.hook(addr=addr_to_hook, hook=DoGlobalCtorsAuxHook, length=0x40120A-addr_to_hook)
```

Since the function `__do_global_ctors_aux` is not called from `_start`, so I have to call the hook after `entry_state`, `full_init_state`.



In `full_init_state`, it calls from `_start`, and all others shared libraries...

<img width="1227" height="115" alt="image" src="https://github.com/user-attachments/assets/5a2cdaa0-ab8d-4943-bb6a-84d6ea33abd9" />

But since `_start` doesn't call `__do_global_ctors_aux`, I have to call the hook after `full_init_state`.

```c
// positive sp value has been detected, the output may be wrong!
void __fastcall __noreturn start(__int64 a1, __int64 a2, void (*a3)(void))
{
  __int64 v3; // rax
  int v4; // esi
  __int64 v5; // [rsp-8h] [rbp-8h] BYREF
  char *retaddr; // [rsp+0h] [rbp+0h] BYREF

  v4 = v5;
  v5 = v3;
  _libc_start_main((int (*)(int, char **, char **))main, v4, &retaddr, 0, 0, a3, &v5);
  __halt();
}
```

However, I get some errors when running with `full_init_state` with angr in this binary, so I use `entry_state` to start from the `main` function.

```python
# Start address
start_addr = 0x40135D
init_state = proj.factory.entry_state(addr=start_addr)

# Call the hook
DoGlobalCtorsAuxHook(init_state)
```

Here is the start address.

<img width="738" height="146" alt="image" src="https://github.com/user-attachments/assets/5efbbb69-74da-4093-8411-3ba68fc3e74f" />

After that, I simulate all the process of `check` function.

```python
# Check again value of key
key_addr = 0x404048
key = init_state.memory.load(key_addr, 8, endness=proj.arch.memory_endness)
print("hehe pass")
print("key", hex(init_state.solver.eval(key)))

# Perform the XOR in check()
after_xor_bytes = []
for i in range(8):
    key_byte = init_state.memory.load(key_addr + i, 1)
    input_byte = input.get_byte(i)
    after_xor_bytes.append(key_byte ^ input_byte)

after_xor = claripy.Concat(*after_xor_bytes)

# Ensure after_xor == 0xA377AD570465FDF9
target = claripy.BVV(0xA377AD570465FDF9, 64)
print("target", hex(init_state.solver.eval(target)))

init_state.solver.add(after_xor == target)
print("after xor", hex(init_state.solver.eval(after_xor)))
```

Now, everything is ready, I create Simulation Manger and run the script.

```python
# Simulation manager
simgr = proj.factory.simgr(init_state)
simgr.explore(find=success, avoid=failure)

if not simgr.found:
    print("Not found")
    hook(locals())

# Since binary is Little-endian => print password in reverse order
password = simgr.found[0].solver.eval(input, cast_to=bytes)
print(password[::-1])
```

Here is the output of the script.

<img width="545" height="544" alt="image" src="https://github.com/user-attachments/assets/6a0552e7-c6e5-4c0d-8c86-1dd882404785" />

Valide the key, and get success message.

```shell
❯ ./ch73.bin
Key: Hj3zp8d7
C'est correct !
```
