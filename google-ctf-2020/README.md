## Overview

This is a challenge from **Google CTF 2020**, it is simple.

## Analysis 

```
❯ file a.out
a.out: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=e3a5d8dc3eee0e960c602b9b2207150c91dc9dff, for GNU/Linux 3.2.0, not stripped
```

It is an **ELF 64-bit binary**.

```
❯ ./a.out
Flag: haha
FAILURE
```

It asks for flag. If it is not correct, string **FAILURE** is printed.

This is the pseudo-code from IDA.

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  int v3; // r12d
  __m128i v5; // [rsp+0h] [rbp-38h] BYREF
  char s2[16]; // [rsp+10h] [rbp-28h] BYREF

  printf("Flag: ");
  __isoc99_scanf("%15s", &v5);
  *(__m128i *)s2 = _mm_xor_si128(
                     _mm_add_epi32(_mm_shuffle_epi8(_mm_load_si128(&v5), (__m128i)SHUFFLE), (__m128i)ADD32),
                     (__m128i)XOR);
  if ( !strncmp(v5.m128i_i8, s2, 0x10u) && (v3 = strncmp(s2, EXPECTED_PREFIX, 4u)) == 0 )
  {
    puts("SUCCESS");
  }
  else
  {
    v3 = 1;
    puts("FAILURE");
  }
  return v3;
}
```

We are asked to enter 15-byte input, and our input is encoded via **shuffle**, and some **XOR**, **ADD** tricks... In the end, we have to pass two comparisions to get the string **SUCCESS**.

This is an ideal scenario for **angr**. We create **symbolic input**, and let angr figure the correct concrete value of input for us!

In this method, I use a custom base address `0x40000000`. Also, I use `explore` in **Simulation Manager** with `success_addr` is `base + offset`. The same case applies to `failure_addr`.

```
.text:000000000000111D loc_111D:                               ; CODE XREF: main+7E↑j
.text:000000000000111D                 lea     rdi, aSuccess   ; "SUCCESS"
.text:0000000000001124                 call    _puts


.text:0000000000001100 loc_1100:                               ; CODE XREF: main+63↑j
.text:0000000000001100                 lea     rdi, s          ; "FAILURE"
.text:0000000000001107                 mov     r12d, 1
.text:000000000000110D                 call    _puts
```

Here is the source code:

```python
import angr 
import logging 
import claripy
import string

logging.getLogger("angr").setLevel(logging.INFO)

def hook(l=None):
    if l:
        locals().update(l)
    import IPython
    IPython.embed(banner1='', exit_msg='', confirm_exit=False)
    exit(0)


def main():
    base_addr = 0x40000000
    proj = angr.Project(
        './a.out',
        load_options={
            'main_opts' : {
                'custom_base_addr' : base_addr
            }
        }
    )

    # Symbolic input
    size = 15
    password = claripy.BVS("password", size*8)

    init_state = proj.factory.entry_state(stdin=password)
    
    # Ensure input is printable
    for i in range(size):
        init_state.solver.add(
        claripy.Or(*(
            password.get_byte(i) == x
            for x in string.printable.encode('utf-8')
        ))
    )
        
    simgr = proj.factory.simgr(init_state)

    success_addr = base_addr + 0x1124
    failure_addr = base_addr + 0x110D
    simgr.explore(find=success_addr, avoid=failure_addr)

    if not simgr.found:
        print("Not found")
        hook(locals()) 

    print(simgr.found[0].solver.eval(password, cast_to=bytes))

if __name__=="__main__":
    main()
```

Run the script and get the flag.

Flag: `CTF{S1MDf0rM3!}`