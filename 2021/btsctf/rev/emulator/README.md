---
title: "[BTS CTF 2021 - RE] : Emulator"
date: 2021-03-12 17:14:00
---

Hi, I'm r0da.

Last day I did a CTF called BTSCTF, and a challenge called `BtS emulator`. As I'm still working on VMP virtualization currently, I'm kind good with VM stuff.

First I noticed that the binary has all its symbols in it, so easier to reverse. Then I saw that the dispatcher routine seems pretty clean.

![](https://whereisr0da.github.io/blog/post_images/emulator/Screenshot_721.png)

We found the opcode related to it :

```C
const uint8_t opcode_buffer[256] =
{
	0xf2, 0x72, 0x45, 0x8a, 0x72, 0xf2, 0x72, 0x6e, 0x8a, 0x72, 0xf2, 0x72, 0x74, 0x8a, 0x72, 0xf2,
	0x72, 0x65, 0x8a, 0x72, 0xf2, 0x72, 0x72, 0x8a, 0x72, 0xf2, 0x72, 0x20, 0x8a, 0x72, 0xf2, 0x72,
	0x70, 0x8a, 0x72, 0xf2, 0x72, 0x61, 0x8a, 0x72, 0xf2, 0x72, 0x73, 0x8a, 0x72, 0xf2, 0x72, 0x73,
	.....
}
```

After a bit we can find the VM structure :

```C++
uint8_t r1;
uint8_t r2;
uint8_t r3;
uint8_t sp;
uint8_t ip;
uint8_t ef;

std::vector<uint8_t> stack;
```

So from here, I directly started to reverse each handles to create a dissasembler (sorry for Windows tabs) :

```C++
void CMP() {
	printf("CMP r1, r2\r\n");
	ef += ((r1 - r2) != 0);
	ip += 1;
}

void PUSH() {
	printf("PUSH ");
	uint8_t reg = opcode_buffer[ip + 1];
	uint8_t reg_value = read_register(reg);
	stack.push_back(reg_value);
	sp = stack.size();
	printf("\r\n");
	ip += 2;
}

void POP() {
	printf("POP ");
	uint8_t reg = opcode_buffer[ip + 1];
	uint8_t value = stack.back();
	stack.pop_back();
	write_register(value, reg);
	printf("\r\n");
	ip += 2;
}

void JMPIF() {
	uint8_t offset = opcode_buffer[ip + 1];
	printf("JMPIF 0x%x\r\n", offset);
	(ef != 0) ? ip += 2 : ip = offset;
}

void MOVIMM() {
	printf("MOVIMM ");
	uint8_t value = opcode_buffer[ip + 2];
	uint8_t target_reg = opcode_buffer[ip + 1];
	write_register(value, target_reg);
	printf("\r\n");
	ip += 3;
}

void SYS() {
	uint8_t imm = opcode_buffer[ip + 1];
	printf("SYS 0x%x\r\n", imm);

	switch (imm)
	{
	case 0x3c:
		if (r1 == 0) {
			printf("Correct Password\r\n");
		}
		else {
			printf("Wrong Password\r\n");
		}
		exit(0);

		break;
	case 0:
		if (stack.size() < r2 + r3) {
			stack.resize(r2 + r3);
		}
		char input[256];
		fgets(input, r3, __acrt_iob_func(r1));
		for (size_t i = r2; i < r3; i++)
			stack.push_back(input[i]);
		ip += 2;

		break;
	case 1:
		char output[256];
		for (size_t i = r2; i < r3; i++)
			output[i] = stack[i];
		fwrite(output, 1, r3, __acrt_iob_func(r1));
		ip += 2;

		break;
	default:
		printf("[-] Fail to dispatch imm in SYS\r\n");
		exit(1);
		break;
	}

}
```

After my recode of each handles, we can just execute the opcode and see what it's look like :

```ASM
MOVIMM r3 0x45		// push each byte of "Enter password" 
PUSH
MOVIMM r3 0x6e
PUSH
...
MOVIMM r3 0xa	
PUSH
MOVIMM r1 0x1		// stdout
MOVIMM r3 0xf		// print len
SYS 0x1			// print "Enter password" 
MOVIMM r1 0x0		// stdin
MOVIMM r3 0x19		// input flag len 
SYS 0x0			// read for 0x19 char
MOVIMM r1 0x33		// get flag byte
POP r2			// get input char
CMP r1, r2		// compare it to input
MOVIMM r1 0x6c		// repeat for each char of the flag...
POP r2
CMP r1, r2
...
JMPIF 0xf8		// jump if correct flag
MOVIMM r1 0x1
SYS 0x3c		// print "Wrong Password"
```

From the code we can get the pass : `c0rr3cth0r$38@tt3ry$t@pl3`

And here is the flag for the server : `BtS-CTF{WAIT_IT'S_ALL_ASSEMBLY??}`

Pretty easy to be honest...

# ~r0da