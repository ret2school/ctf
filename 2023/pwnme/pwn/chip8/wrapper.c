#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>

#define MAX_ROM_CODE	0x200
#define EMULATOR_PATH   "./c8emu"
#define ROM_PATH		"./rom.ch8"
#define MESSAGE         "Enter ROM code: "

void main()
{
	int nb, fd, tty;
	char rom_code[MAX_ROM_CODE] = {0};

	char *exec_argv[] = {
		EMULATOR_PATH,
		ROM_PATH,
		NULL
	};

	unlink(ROM_PATH);

	if ((fd = open(ROM_PATH, O_RDWR | O_CREAT, S_IWUSR | S_IWRITE | S_IRUSR | S_IREAD)) < 0) {
		puts("Failed to open() rom");
		exit(-1);
	}

	memset(rom_code, 0, MAX_ROM_CODE);

	write(1, MESSAGE, strlen(MESSAGE));

	nb = read(STDIN_FILENO, rom_code, MAX_ROM_CODE);

	write(fd, rom_code, nb);

	for (size_t i = 0; i < MAX_ROM_CODE; i++) {
		printf("%c ", rom_code[i]);
	}

	printf("\n");

	alarm(45);

	execve(EMULATOR_PATH, exec_argv, NULL);

	close(fd);
}
