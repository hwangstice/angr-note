# C&C Music Factory

## Description

We've recovered a portion of the payload of a targeted malware campaign aimed at recording executives. Can you pull out the server it is trying to exfiltrate data to?

### Hints

* Only submit the subdomain as the flag
* Some of the control flow looks pretty convoluted... maybe you can patch your way through it instead?

## Analyze Binary `music_factory`

The challenge gives a binary `music_factory`.

```
❯ file music_factory
music_factory: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=3e9f77fbea88aa6595f107d25751f910d6378bb3, not stripped
```

Let's run the binary.

```
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

```
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

```
(gdb) b * 0x0000555555400cd2
Breakpoint 2 at 0x555555400cd2
(gdb) c
Continuing.
[Inferior 1 (process 4140) exited with code 0377]
```

In the **Description**, it states that the binary is a form of **malware**. This means there must be **an anti-debug technique**.

Luckily enough, I easily find it out from the pseudo-code of `libc_csu_init_` function.

```c
  v8 = __readfsqword(0x28u);
  if ( ptrace(PTRACE_TRACEME, 0, 1, 0) == -1 )
    exit(-1);
```
