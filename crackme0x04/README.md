# Solution

## TL;DR

In this challenge, I use **CFG** to tackle. It is really fun and an amazing learning experience! :D

## Analyze

The binary is an **ELF 32-bit**.

```shell
❯ file crackme0x04
crackme0x04: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.9, not stripped
```

I check the strings and find some interesting hints.

```shell
❯ strings crackme0x04
...
Password OK!
Password Incorrect!
IOLI Crackme Level 0x04
Password:
...
```

Let's run it.

```shell
❯ ./crackme0x04
IOLI Crackme Level 0x04
Password: haha
Password Incorrect!
```

Let's load the binary to IDA, and start analysis.

The `main` is simple to understand. What catches my attention is the `check` function.

<img width="467" height="523" alt="image" src="https://github.com/user-attachments/assets/a02600fe-ff0d-467a-9035-22fed8d14f38" />

This is the pseudo-code of the `check` function.

```c
int __cdecl check(char *input)
{
  size_t v1; // eax
  char tmp; // [esp+1Bh] [ebp-Dh] BYREF
  size_t i; // [esp+1Ch] [ebp-Ch]
  int sum; // [esp+20h] [ebp-8h]
  int target; // [esp+24h] [ebp-4h] BYREF

  sum = 0;
  for ( i = 0; ; ++i )
  {
    v1 = strlen(input);
    if ( i >= v1 )
      break;
    tmp = input[i];
    sscanf(&tmp, "%d", &target);
    sum += target;
    if ( sum == 15 )
    {
      printf("Password OK!\n");
      exit(0);
    }
  }
  return printf("Password Incorrect!\n");
}
```

The program just sums up all the characters from the input. It uses `sscanf` to convert each character to a number and adds them to a `sum` variable. If `sum` equals `15`, it prints the success message.

So technically, I could just pick numbers whose digits add up to `15` and solve it easily. But, where is the fun? Instead, I use **angr**.

## CFG

Here, I use **static CFG (CFGFast)**. Below is how I setup it in my angr script.

```python
proj = angr.Project("./crackme0x04", load_options={'auto_load_libs': False}, main_opts={'base_addr': 0x8048000})

cfg = proj.analyses.CFGFast()
```

Why I use `auto_load_libs: False` here?

In a **CFG**, basic blocks are nodes and jumps/calls are edges. Using `auto_load_libs=False` replaces all `libc/glibc` calls with **SimProcedures**, so calls just point to **a SimProcedure stub** instead of exploring the full library. This keeps the CFG smaller and faster by avoiding thousands of extra nodes and edges.

This is the representation when running the code.

<img width="1937" height="285" alt="image" src="https://github.com/user-attachments/assets/eb821613-ac1d-479b-9d4e-f6f4e2662603" />

Another view from another angle :D

```
WITH LIBC LOADED:                   WITH SIMPROCEDURE:
┌─────┐                             ┌─────┐
│main │                             │main │
└──┬──┘                             └──┬──┘
   │                                   │
   ▼                                   ▼
┌───────┐                           ┌──────────┐
│ call  │───▶ dozens of nodes       │ SimProc  │
│ printf│     + edges in libc       │ printf() │
└───────┘                           └──────────┘
```

It is perfect, the number of edges has been reduced, and CFG is much faster when option `auto_load_libs=False` is used.

Next, I used the CFG's Function Manager to quickly look up the address of `exit` by its name.

<img width="1723" height="824" alt="image" src="https://github.com/user-attachments/assets/a1bff95a-cde4-4e59-9d92-e4462b3e2ff1" />

Here is how I code looks like.

```python
# Find exit's addr
exit_addr = cfg.kb.functions.function(name='exit').addr
```

Here are some references to explain the syntax :P

- https://docs.angr.io/en/latest/api.html#angr.KnowledgeBase

- https://docs.angr.io/en/latest/api.html#angr.knowledge_plugins.functions.function_manager.FunctionManager.function

- https://docs.angr.io/en/latest/api.html#angr.knowledge_plugins.Function.addr

I highly recommend checking out the **angr docs** and **API Reference**. They are just too good, a gold mine there!

Now, the final thing is to start **Simulation Manager** to find `exit_addr` and get the correct password.

```python
init_state = proj.factory.entry_state()
simgr = proj.factory.simgr(init_state)

simgr.explore(find=exit_addr, avoid=0x08048502) # avoid failure message

if not simgr.found:
    print("Not found")
    hook(locals())

print(simgr.found[0].posix.stdin.concretize())
```

Run the script and win the challenge.

<img width="1960" height="242" alt="image" src="https://github.com/user-attachments/assets/7521de28-d4fe-4a0c-9f07-d45d0a2c3ee8" />

## Reference

- https://docs.angr.io/en/latest/analyses/cfg.html
