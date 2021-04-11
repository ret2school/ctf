// BTSCTF 2021 : BtS emulator solve by r0da

#include <iostream>
#include <vector>
#include <iostream>
#include <fcntl.h> 
#include <stdio.h> 
#include <string.h>
#include <istream>
#include <Windows.h>
#include <string>

const uint8_t opcode_buffer[256] =
{
	0xf2, 0x72, 0x45, 0x8a, 0x72, 0xf2, 0x72, 0x6e, 0x8a, 0x72, 0xf2, 0x72, 0x74, 0x8a, 0x72, 0xf2,
	0x72, 0x65, 0x8a, 0x72, 0xf2, 0x72, 0x72, 0x8a, 0x72, 0xf2, 0x72, 0x20, 0x8a, 0x72, 0xf2, 0x72,
	0x70, 0x8a, 0x72, 0xf2, 0x72, 0x61, 0x8a, 0x72, 0xf2, 0x72, 0x73, 0x8a, 0x72, 0xf2, 0x72, 0x73,
	0x8a, 0x72, 0xf2, 0x72, 0x77, 0x8a, 0x72, 0xf2, 0x72, 0x6f, 0x8a, 0x72, 0xf2, 0x72, 0x72, 0x8a,
	0x72, 0xf2, 0x72, 0x64, 0x8a, 0x72, 0xf2, 0x72, 0x0a, 0x8a, 0x72, 0xf2, 0x5f, 0x01, 0xf2, 0x72,
	0x0f, 0xe5, 0x01, 0xf2, 0x5f, 0x00, 0xf2, 0x72, 0x19, 0xe5, 0x00, 0xf2, 0x5f, 0x33, 0xbf, 0x33,
	0x06, 0xf2, 0x5f, 0x6c, 0xbf, 0x33, 0x06, 0xf2, 0x5f, 0x70, 0xbf, 0x33, 0x06, 0xf2, 0x5f, 0x40,
	0xbf, 0x33, 0x06, 0xf2, 0x5f, 0x74, 0xbf, 0x33, 0x06, 0xf2, 0x5f, 0x24, 0xbf, 0x33, 0x06, 0xf2,
	0x5f, 0x79, 0xbf, 0x33, 0x06, 0xf2, 0x5f, 0x72, 0xbf, 0x33, 0x06, 0xf2, 0x5f, 0x33, 0xbf, 0x33,
	0x06, 0xf2, 0x5f, 0x74, 0xbf, 0x33, 0x06, 0xf2, 0x5f, 0x74, 0xbf, 0x33, 0x06, 0xf2, 0x5f, 0x40,
	0xbf, 0x33, 0x06, 0xf2, 0x5f, 0x38, 0xbf, 0x33, 0x06, 0xf2, 0x5f, 0x33, 0xbf, 0x33, 0x06, 0xf2,
	0x5f, 0x24, 0xbf, 0x33, 0x06, 0xf2, 0x5f, 0x72, 0xbf, 0x33, 0x06, 0xf2, 0x5f, 0x30, 0xbf, 0x33,
	0x06, 0xf2, 0x5f, 0x68, 0xbf, 0x33, 0x06, 0xf2, 0x5f, 0x74, 0xbf, 0x33, 0x06, 0xf2, 0x5f, 0x63,
	0xbf, 0x33, 0x06, 0xf2, 0x5f, 0x33, 0xbf, 0x33, 0x06, 0xf2, 0x5f, 0x72, 0xbf, 0x33, 0x06, 0xf2,
	0x5f, 0x72, 0xbf, 0x33, 0x06, 0xf2, 0x5f, 0x30, 0xbf, 0x33, 0x06, 0xf2, 0x5f, 0x63, 0xbf, 0x33,
	0x06, 0x8c, 0xf8, 0xf2, 0x5f, 0x01, 0xe5, 0x3c, 0xf2, 0x5f, 0x00, 0xe5, 0x3c, 0x00, 0x00, 0x00
};

uint8_t r1 = 0x0;
uint8_t r2 = 0x0;
uint8_t r3 = 0x0;
uint8_t sp = 0x0;
uint8_t ip = 0x0;
uint8_t ef = 0x0;

std::vector<uint8_t> stack;

char flag[256];

byte read_register(byte reg) {

	byte result = 0;

	switch (reg)
	{
	case 0xfa:
		result = ef;
		break;
	case 0xc3:
		result = sp;
		break;
	case 0x72:
		result = r3;
		break;
	case 0x5f:
		result = r1;
		break;
	case 0x33:
		result = r2;
		break;
	case 0x46:
		result = ip;
		break;
	default:
		printf("[-] Fail to read_register\r\n");
		exit(1);
		break;
	}

	return result;
}

void write_register(byte value, byte reg) {

	switch (reg)
	{
	case 0xfa:
		ef = value;
		printf("ef ");
		break;
	case 0xc3:
		sp = value;
		printf("sp ");
		break;
	case 0x72:
		r3 = value;
		printf("r3 ");
		break;
	case 0x5f:
		r1 = value;
		printf("r1 ");
		break;
	case 0x33:
		r2 = value;
		printf("r2 ");
		break;
	case 0x46:
		ip = value;
		printf("ip ");
		break;
	default:
		printf("[-] Fail to write_register\r\n");
		exit(1);
		break;
	}
}

void SYS() {
	byte imm = opcode_buffer[ip + 1];

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

		printf("%s\r\n",flag);

		exit(0);

		break;
	case 0:

		if (stack.size() < r2 + r3) {
			stack.resize(r2 + r3);
		}

		char input[256];

		fgets(input, r3, __acrt_iob_func(r1));

		for (size_t i = r2; i < r3; i++)
		{
			stack.push_back(input[i]);
		}

		ip += 2;
		break;
	case 1:

		char output[256];

		for (size_t i = r2; i < r3; i++)
		{
			output[i] = stack[i];
		}

		fwrite(output, 1, r3, __acrt_iob_func(r1));

		ip += 2;
		break;
	default:
		break;
	}

}

int flag_ip = 0;

void MOVIMM() {
	byte value = opcode_buffer[ip + 2];
	byte target_reg = opcode_buffer[ip + 1];

	printf("MOVIMM ");

	write_register(value, target_reg);

	printf("0x%x ", value);

	flag[flag_ip++] = (char)value;

	printf("\r\n");

	ip += 3;
}

void POP() {

	printf("POP ");

	byte reg = opcode_buffer[ip + 1];

	byte value = stack.back();
	stack.pop_back();

	write_register(value, reg);

	printf("\r\n");

	ip += 2;
}

void JMPIF() {
	byte offset = opcode_buffer[ip + 1];

	printf("JMPIF 0x%x\r\n", offset);

	if (ef != 0) {
		ip += 2;
	}
	else {
		ip = offset;
	}
}

void CMP() {
	printf("CMP r1, r2\r\n");

	ef += ((r1 - r2) != 0);

	ip += 1;

}

void PUSH() {
	byte reg_0 = opcode_buffer[ip + 1];

	printf("PUSH ");

	byte reg_value = read_register(reg_0);

	stack.push_back(reg_value);

	sp = stack.size();

	ip += 2;

	printf("\r\n");
}

int main()
{

	ZeroMemory(flag, 200);

	while (ip < 256) {

		byte opcode = opcode_buffer[ip];

		switch (opcode)
		{
		case 0xf2:

			MOVIMM();

			break;
		case 0xe5:

			SYS();

			break;

		case 0xbf:

			POP();

			break;
		case 0x8c:

			JMPIF();

			break;
		case 0x6:
			CMP();
			break;
		case 0x8a:

			PUSH();
			break;
		default:
			printf("[-] Fail to dispatch\r\n");
			exit(1);
			break;
		}
	}
}