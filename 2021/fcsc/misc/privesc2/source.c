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
