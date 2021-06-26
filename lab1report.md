# Lab 1 Report: Huang Yong, 1500017709@pku.edu.cn

[TOC]

## Environment Configuration

```
Hardware Environment:
Memory:         16GB
Processor:      AMD Ryzen 5 2600 CPU @ 3.9GHz × 12
Graphics:       GP104 [GeForce GTX 1070]
OS Type:        64 bit
Disk:           250GB

Software Environment:
OS:             Ubuntu 20.04 LTS(x86_64)
Gcc:            GCC 9.3.0
Make:           GNU Make 4.2.1
Gdb:            GNU gdb 9.2
```

### Test Compiler Toolchain

```shell
$ objdump -i   # the 5th line say elf32-i386
$ gcc -m32 -print-libgcc-file-name
/usr/lib/gcc/x86_64-linux-gnu/9/libgcc.a
```

### QEMU Emulator

```shell
 # Clone the IAP 6.828 QEMU git repository
 $ git clone https://github.com/geofft/qemu.git -b 6.828-1.7.0
 $ cd qemu
 $ ./configure --disable-kvm --target-list="i386-softmmu x86_64-softmmu"
 $ make
 $ sudo make install
```

## Exercise 1

skip

## Exercise 2

skip

## Exercise 3

https://stackoverflow.com/questions/21078932/why-test-port-0x64-in-a-bootloader-before-switching-into-protected-mode

> Status Register - PS/2 Controller
> Bit Meaning
> 0   Output buffer status (0 = empty, 1 = full) (must be set before attempting to read data from IO port 0x60)
>
> 1   Input buffer status (0 = empty, 1 = full) (must be clear before attempting to write data to IO port 0x60 or IO port 0x64)
>
> 2   System Flag - Meant to be cleared on reset and set by firmware (via. PS/2 Controller Configuration Byte) if the system passes self tests (POST)
>
> 3   Command/data (0 = data written to input buffer is data for PS/2 device, 1 = data written to input buffer is data for PS/2 controller command)
>
> 4   Unknown (chipset specific) - May be "keyboard lock" (more likely unused on modern systems)
>
> 5   Unknown (chipset specific) - May be "receive time-out" or "second PS/2 port output buffer full"
>
> 6   Time-out error (0 = no error, 1 = time-out error)
>
> 7   Parity error (0 = no error, 1 = parity error)

https://blog.csdn.net/Great_Enterprise/article/details/104063004

mentioned why we use PS/2 port to enable A20 address line

https://wiki.osdev.org/Protected_Mode

> Enabling Protected Mode unleashes the real power of your CPU. However, it will prevent you from using most of the BIOS interrupts, since these work in Real Mode

```assembly
# boot.asm
# obj/boot/boot.out:     file format elf32-i386


Disassembly of section .text:

00007c00 <start>:
.set CR0_PE_ON,      0x1         # protected mode enable flag

.globl start
	# 0. a little question: why the start is loaded at 0x7c00?
start:
  .code16                     # Assemble for 16-bit mode
  # 1. break * 0x7c00, start from here
  cli                         # Disable interrupts
    7c00:	fa                   	cli    
  cld                         # String operations increment
    7c01:	fc                   	cld    

  # Set up the important data segment registers (DS, ES, SS).
  xorw    %ax,%ax             # Segment number zero
    7c02:	31 c0                	xor    %eax,%eax
  movw    %ax,%ds             # -> Data Segment
    7c04:	8e d8                	mov    %eax,%ds
  movw    %ax,%es             # -> Extra Segment
    7c06:	8e c0                	mov    %eax,%es
  movw    %ax,%ss             # -> Stack Segment
    7c08:	8e d0                	mov    %eax,%ss

00007c0a <seta20.1>:
  # Enable A20:
  #   For backwards compatibility with the earliest PCs, physical
  #   address line 20 is tied low, so that addresses higher than
  #   1MB wrap around to zero by default.  This code undoes this.
  # port 0x64: IO port of the keyboard controller
	# Keyboard controller has two ports 0x64 and 0x60
	# Port 0x64 (Command Port) is used for sending commands to keyboard controllers (PS/2)
	# Port 0x60 (Data Port) is used for sending data to/from PS/2 controller or the PS/2 device itself.
seta20.1:
  inb     $0x64,%al               # Get status
    7c0a:	e4 64                	in     $0x64,%al
  testb   $0x2,%al               	# Busy?
    7c0c:	a8 02                	test   $0x2,%al
  jnz     seta20.1
    7c0e:	75 fa                	jne    7c0a <seta20.1>

  movb    $0xd1,%al
    7c10:	b0 d1                	mov    $0xd1,%al
  outb    %al,$0x64               # 0xd1 -> port 0x64
    7c12:	e6 64                	out    %al,$0x64

00007c14 <seta20.2>:

seta20.2:
  inb     $0x64,%al               # Get status
    7c14:	e4 64                	in     $0x64,%al
  testb   $0x2,%al               	# Busy?
    7c16:	a8 02                	test   $0x2,%al
  jnz     seta20.2
    7c18:	75 fa                	jne    7c14 <seta20.2>

  movb    $0xdf,%al
    7c1a:	b0 df                	mov    $0xdf,%al
  outb    %al,$0x60               # 0xdf -> port 0x60
    7c1c:	e6 60                	out    %al,$0x60

  # Switch from real to protected mode, using a bootstrap GDT
  # and segment translation that makes virtual addresses 
  # identical to their physical addresses, so that the 
  # effective memory map does not change during the switch.
  lgdt    gdtdesc
   # instruction "lgdt" will not enable the GDT immediately until the next "ljmp" instruction been executed.
    7c1e:	0f 01 16             	lgdtl  (%esi)
    7c21:	64                   	fs
    7c22:	7c 0f                	jl     7c33 <protcseg+0x1>
  movl    %cr0, %eax
    7c24:	20 c0                	and    %al,%al
  orl     $CR0_PE_ON, %eax
    7c26:	66 83 c8 01          	or     $0x1,%ax
  movl    %eax, %cr0
    7c2a:	0f 22 c0             	mov    %eax,%cr0
  
  # Jump to next instruction, but in 32-bit code segment.
  # Switches processor into 32-bit mode.
  ljmp    $PROT_MODE_CSEG, $protcseg
  # Jump to next instruction, but in 32-bit code segment.
  # Switches processor into 32-bit mode.
    7c2d:	ea 32 7c 08 00 66 b8 	ljmp   $0xb866,$0x87c32 # jump to protcseq

00007c32 <protcseg>:

  .code32                     # Assemble for 32-bit mode
protcseg:
  # Set up the protected-mode data segment registers
  movw    $PROT_MODE_DSEG, %ax    # Our data segment selector
    7c32:	66 b8 10 00          	mov    $0x10,%ax
  movw    %ax, %ds                # -> DS: Data Segment
    7c36:	8e d8                	mov    %eax,%ds
  movw    %ax, %es                # -> ES: Extra Segment
    7c38:	8e c0                	mov    %eax,%es
  movw    %ax, %fs                # -> FS
    7c3a:	8e e0                	mov    %eax,%fs
  movw    %ax, %gs                # -> GS
    7c3c:	8e e8                	mov    %eax,%gs
  movw    %ax, %ss                # -> SS: Stack Segment
    7c3e:	8e d0                	mov    %eax,%ss
  
  # Set up the stack pointer and call into C.
  movl    $start, %esp
    7c40:	bc 00 7c 00 00       	mov    $0x7c00,%esp
  call bootmain
    7c45:	e8 c1 00 00 00       	call   7d0b <bootmain> # jump to bootmain

00007c4a <spin>:

  # If bootmain returns (it shouldn't), loop.
spin:
  jmp spin
    7c4a:	eb fe                	jmp    7c4a <spin>

00007c4c <gdt>:
	...
    7c54:	ff                   	(bad)  
    7c55:	ff 00                	incl   (%eax)
    7c57:	00 00                	add    %al,(%eax)
    7c59:	9a cf 00 ff ff 00 00 	lcall  $0x0,$0xffff00cf
    7c60:	00 92 cf 00 17 00    	add    %dl,0x1700cf(%edx)

00007c64 <gdtdesc>:
    7c64:	17                   	pop    %ss
    7c65:	00 4c 7c 00          	add    %cl,0x0(%esp,%edi,2)
    7c69:	00 90 90 55 89 e5    	add    %dl,-0x1a76aa70(%eax)

00007c6c <waitdisk>:
	}
}

void
waitdisk(void)
{
    7c6c:	55                   	push   %ebp
    7c6d:	89 e5                	mov    %esp,%ebp

static inline uint8_t
inb(int port)
{
	uint8_t data;
	asm volatile("inb %w1,%0" : "=a" (data) : "d" (port));
    7c6f:	ba f7 01 00 00       	mov    $0x1f7,%edx
    7c74:	ec                   	in     (%dx),%al
	// wait for disk reaady
	while ((inb(0x1F7) & 0xC0) != 0x40)
    7c75:	25 c0 00 00 00       	and    $0xc0,%eax
    7c7a:	83 f8 40             	cmp    $0x40,%eax
    7c7d:	75 f5                	jne    7c74 <waitdisk+0x8>
		/* do nothing */;
}
    7c7f:	5d                   	pop    %ebp
    7c80:	c3                   	ret    

00007c81 <readsect>:

void
readsect(void *dst, uint32_t offset)
{
    7c81:	55                   	push   %ebp
    7c82:	89 e5                	mov    %esp,%ebp
    7c84:	57                   	push   %edi
    7c85:	8b 7d 0c             	mov    0xc(%ebp),%edi
	// wait for disk to be ready
	waitdisk();
    7c88:	e8 df ff ff ff       	call   7c6c <waitdisk>
}

static inline void
outb(int port, uint8_t data)
{
	asm volatile("outb %0,%w1" : : "a" (data), "d" (port));
    7c8d:	ba f2 01 00 00       	mov    $0x1f2,%edx
    7c92:	b0 01                	mov    $0x1,%al
    7c94:	ee                   	out    %al,(%dx)
    7c95:	b2 f3                	mov    $0xf3,%dl
    7c97:	89 f8                	mov    %edi,%eax
    7c99:	ee                   	out    %al,(%dx)
	//0x1f2: number of sector to read
	outb(0x1F2, 1);		// count = 1, read 1 sector once a time
	// 0x1f3-0x1f6: address for LBA mode
	outb(0x1F3, offset);
	outb(0x1F4, offset >> 8);
    7c9a:	89 f8                	mov    %edi,%eax
    7c9c:	c1 e8 08             	shr    $0x8,%eax
    7c9f:	b2 f4                	mov    $0xf4,%dl
    7ca1:	ee                   	out    %al,(%dx)
	outb(0x1F5, offset >> 16);
    7ca2:	89 f8                	mov    %edi,%eax
    7ca4:	c1 e8 10             	shr    $0x10,%eax
    7ca7:	b2 f5                	mov    $0xf5,%dl
    7ca9:	ee                   	out    %al,(%dx)
	outb(0x1F6, (offset >> 24) | 0xE0);// the combination of these 4 lines is set to locate the sector in the disk.
    7caa:	c1 ef 18             	shr    $0x18,%edi
    7cad:	89 f8                	mov    %edi,%eax
    7caf:	83 c8 e0             	or     $0xffffffe0,%eax
    7cb2:	b2 f6                	mov    $0xf6,%dl
    7cb4:	ee                   	out    %al,(%dx)
    7cb5:	b2 f7                	mov    $0xf7,%dl
    7cb7:	b0 20                	mov    $0x20,%al
    7cb9:	ee                   	out    %al,(%dx)
	outb(0x1F7, 0x20);	// cmd 0x20 - read sectors
	// 0x1f7: status and command register
	// wait for disk to be ready
	waitdisk();
    7cba:	e8 ad ff ff ff       	call   7c6c <waitdisk>
}

static inline void
insl(int port, void *addr, int cnt)
{
	asm volatile("cld\n\trepne\n\tinsl"
    7cbf:	8b 7d 08             	mov    0x8(%ebp),%edi
    7cc2:	b9 80 00 00 00       	mov    $0x80,%ecx
    7cc7:	ba f0 01 00 00       	mov    $0x1f0,%edx
    7ccc:	fc                   	cld    
    7ccd:	f2 6d                	repnz insl (%dx),%es:(%edi)

	// read a sector
	insl(0x1F0, dst, SECTSIZE/4);// 0x1f0: read port
}
    7ccf:	5f                   	pop    %edi
    7cd0:	5d                   	pop    %ebp
    7cd1:	c3                   	ret    

00007cd2 <readseg>:

// Read 'count' bytes at 'offset' from kernel into physical address 'pa'.
// Might copy more than asked
void
readseg(uint32_t pa, uint32_t count, uint32_t offset)
{
    7cd2:	55                   	push   %ebp
    7cd3:	89 e5                	mov    %esp,%ebp
    7cd5:	57                   	push   %edi
    7cd6:	56                   	push   %esi
    7cd7:	53                   	push   %ebx
    7cd8:	8b 5d 08             	mov    0x8(%ebp),%ebx
    7cdb:	8b 75 10             	mov    0x10(%ebp),%esi
	uint32_t end_pa;

	end_pa = pa + count;
    7cde:	8b 7d 0c             	mov    0xc(%ebp),%edi
    7ce1:	01 df                	add    %ebx,%edi

	// round down to sector boundary
	pa &= ~(SECTSIZE - 1);// = -(pa % 512)
    7ce3:	81 e3 00 fe ff ff    	and    $0xfffffe00,%ebx

	// translate from bytes to sectors, and kernel starts at sector 1
	offset = (offset / SECTSIZE) + 1;// the number of the sector
    7ce9:	c1 ee 09             	shr    $0x9,%esi
    7cec:	46                   	inc    %esi

	// If this is too slow, we could read lots of sectors at a time.
	// We'd write more to memory than asked, but it doesn't matter --
	// we load in increasing order.
	while (pa < end_pa) {
    7ced:	eb 10                	jmp    7cff <readseg+0x2d>
		// Since we haven't enabled paging yet and we're using
		// an identity segment mapping (see boot.S), we can
		// use physical addresses directly.  This won't be the
		// case once JOS enables the MMU.
		readsect((uint8_t*) pa, offset);
    7cef:	56                   	push   %esi
    7cf0:	53                   	push   %ebx
    7cf1:	e8 8b ff ff ff       	call   7c81 <readsect>
		pa += SECTSIZE;
    7cf6:	81 c3 00 02 00 00    	add    $0x200,%ebx
		offset++;
    7cfc:	46                   	inc    %esi
    7cfd:	58                   	pop    %eax
    7cfe:	5a                   	pop    %edx
	offset = (offset / SECTSIZE) + 1;// the number of the sector

	// If this is too slow, we could read lots of sectors at a time.
	// We'd write more to memory than asked, but it doesn't matter --
	// we load in increasing order.
	while (pa < end_pa) {
    7cff:	39 fb                	cmp    %edi,%ebx
    7d01:	72 ec                	jb     7cef <readseg+0x1d>
		// case once JOS enables the MMU.
		readsect((uint8_t*) pa, offset);
		pa += SECTSIZE;
		offset++;
	}
}
    7d03:	8d 65 f4             	lea    -0xc(%ebp),%esp
    7d06:	5b                   	pop    %ebx
    7d07:	5e                   	pop    %esi
    7d08:	5f                   	pop    %edi
    7d09:	5d                   	pop    %ebp
    7d0a:	c3                   	ret    

00007d0b <bootmain>:
void readsect(void*, uint32_t);
void readseg(uint32_t, uint32_t, uint32_t);

void
bootmain(void)
{
    7d0b:	55                   	push   %ebp
    7d0c:	89 e5                	mov    %esp,%ebp
    7d0e:	56                   	push   %esi
    7d0f:	53                   	push   %ebx
	struct Proghdr *ph, *eph;

	// read 1st page off disk
	readseg((uint32_t) ELFHDR, SECTSIZE*8, 0);// read the first 8 sectors and map into the ELFHDR address in memory.
    7d10:	6a 00                	push   $0x0
    7d12:	68 00 10 00 00       	push   $0x1000
    7d17:	68 00 00 01 00       	push   $0x10000
    7d1c:	e8 b1 ff ff ff       	call   7cd2 <readseg>

	// is this a valid ELF?
	if (ELFHDR->e_magic != ELF_MAGIC)
    7d21:	83 c4 0c             	add    $0xc,%esp
    7d24:	81 3d 00 00 01 00 7f 	cmpl   $0x464c457f,0x10000
    7d2b:	45 4c 46 
    7d2e:	75 39                	jne    7d69 <bootmain+0x5e>
		goto bad;

	// load each program segment (ignores ph flags)
	ph = (struct Proghdr *) ((uint8_t *) ELFHDR + ELFHDR->e_phoff);
	# pointer to the begin of program headers = the beginning of the ELFHDR + offset
    7d30:	8b 1d 1c 00 01 00    	mov    0x1001c,%ebx
    7d36:	81 c3 00 00 01 00    	add    $0x10000,%ebx
	eph = ph + ELFHDR->e_phnum;
	# pointer to the end of program headers = ph(pointer) + number of phs
    7d3c:	0f b7 05 2c 00 01 00 	movzwl 0x1002c,%eax
    7d43:	c1 e0 05             	shl    $0x5,%eax
    7d46:	8d 34 03             	lea    (%ebx,%eax,1),%esi
	for (; ph < eph; ph++)# iterating
    7d49:	eb 14                	jmp    7d5f <bootmain+0x54>
		// p_pa is the load address of this segment (as well
		// as the physical address)
		readseg(ph->p_pa, ph->p_memsz, ph->p_offset); # each program header provides the physical address where this section should be loaded and the memory size. Offset shows the disk location of this section.
    7d4b:	ff 73 04             	pushl  0x4(%ebx)
    7d4e:	ff 73 14             	pushl  0x14(%ebx)
    7d51:	ff 73 0c             	pushl  0xc(%ebx)
    7d54:	e8 79 ff ff ff       	call   7cd2 <readseg>
		goto bad;

	// load each program segment (ignores ph flags)
	ph = (struct Proghdr *) ((uint8_t *) ELFHDR + ELFHDR->e_phoff);
	eph = ph + ELFHDR->e_phnum;
	for (; ph < eph; ph++)
    7d59:	83 c3 20             	add    $0x20,%ebx
    7d5c:	83 c4 0c             	add    $0xc,%esp
    7d5f:	39 f3                	cmp    %esi,%ebx
    7d61:	72 e8                	jb     7d4b <bootmain+0x40>
		// as the physical address)
		readseg(ph->p_pa, ph->p_memsz, ph->p_offset);

	// call the entry point from the ELF header
	// note: does not return!
	((void (*)(void)) (ELFHDR->e_entry))();
    7d63:	ff 15 18 00 01 00    	call   *0x10018
    # NOTICE: ELFHDR is loaded in 0x10000, and the e_entry is fixed at ELFHDR + 0x18, which means, the entry of the kernel is recorded at 0x10018 and is determined as soon as the ELFHDR is loaded, all the process had been done before all the sections have been loaded to the memory. (in this case, the recorded address in 0x10018 is 0x10000c.)
}

static inline void
outw(int port, uint16_t data)
{
	asm volatile("outw %0,%w1" : : "a" (data), "d" (port));
    7d69:	ba 00 8a 00 00       	mov    $0x8a00,%edx
    7d6e:	b8 00 8a ff ff       	mov    $0xffff8a00,%eax
    7d73:	66 ef                	out    %ax,(%dx)
    7d75:	b8 00 8e ff ff       	mov    $0xffff8e00,%eax
    7d7a:	66 ef                	out    %ax,(%dx)
    7d7c:	eb fe                	jmp    7d7c <bootmain+0x71>


```

```C
// main.c
#include <inc/x86.h>
#include <inc/elf.h>

/**********************************************************************
 * This a dirt simple boot loader, whose sole job is to boot
 * an ELF kernel image from the first IDE hard disk.
 *
 * DISK LAYOUT
 *  * This program(boot.S and main.c) is the bootloader.  It should
 *    be stored in the first sector of the disk.
 *
 *  * The 2nd sector onward holds the kernel image.
 *
 *  * The kernel image must be in ELF format.
 *
 * BOOT UP STEPS
 *  * when the CPU boots it loads the BIOS into memory and executes it
 *
 *  * the BIOS intializes devices, sets of the interrupt routines, and
 *    reads the first sector of the boot device(e.g., hard-drive)
 *    into memory and jumps to it.
 *
 *  * Assuming this boot loader is stored in the first sector of the
 *    hard-drive, this code takes over...
 *
 *  * control starts in boot.S -- which sets up protected mode,
 *    and a stack so C code then run, then calls bootmain()
 *
 *  * bootmain() in this file takes over, reads in the kernel and jumps to it.
 **********************************************************************/

#define SECTSIZE	512
#define ELFHDR		((struct Elf *) 0x10000) // scratch space

void readsect(void*, uint32_t);
void readseg(uint32_t, uint32_t, uint32_t);

void
bootmain(void)
{
	struct Proghdr *ph, *eph;
	// ELFHDR is a static pointer, ELF * 0x10000
	// read 1st page off disk
	readseg((uint32_t) ELFHDR, SECTSIZE*8, 0);// read the first 8 sectors and map into the ELFHDR address in memory.

	// is this a valid ELF?
	if (ELFHDR->e_magic != ELF_MAGIC)
		goto bad;

	// load each program segment (ignores ph flags)
	ph = (struct Proghdr *) ((uint8_t *) ELFHDR + ELFHDR->e_phoff);
  // ph = elfhdr + offset, the start address of (next, system) boot binary
	eph = ph + ELFHDR->e_phnum;
  // eph = the end of the address of boot binary.
	for (; ph < eph; ph++)
		// p_pa is the load address of this segment (as well
		// as the physical address)
		readseg(ph->p_pa, ph->p_memsz, ph->p_offset);// read from disk to memory

	// call the entry point from the ELF header
	// note: does not return!
	((void (*)(void)) (ELFHDR->e_entry))(); // call the system boot binary

bad:
	outw(0x8A00, 0x8A00);
	outw(0x8A00, 0x8E00);
	while (1)
		/* do nothing */;
}

// Read 'count' bytes at 'offset' from kernel into physical address 'pa'.
// Might copy more than asked
void
readseg(uint32_t pa, uint32_t count, uint32_t offset)
{
	uint32_t end_pa;

	end_pa = pa + count;

	// round down to sector boundary
	pa &= ~(SECTSIZE - 1);// = -(pa % 512)

	// translate from bytes to sectors, and kernel starts at sector 1
	offset = (offset / SECTSIZE) + 1;// the number of the sector

	// If this is too slow, we could read lots of sectors at a time.
	// We'd write more to memory than asked, but it doesn't matter --
	// we load in increasing order.
	while (pa < end_pa) {
		// Since we haven't enabled paging yet and we're using
		// an identity segment mapping (see boot.S), we can
		// use physical addresses directly.  This won't be the
		// case once JOS enables the MMU.
		readsect((uint8_t*) pa, offset);
		pa += SECTSIZE;
		offset++;
	}
}

void
waitdisk(void)
{
	// wait for disk reaady
	while ((inb(0x1F7) & 0xC0) != 0x40)
		/* do nothing */;
}

void
readsect(void *dst, uint32_t offset)
{
	// wait for disk to be ready
	waitdisk();
	//0x1f2: number of sector to read
	outb(0x1F2, 1);		// count = 1, read 1 sector once a time
	// 0x1f3-0x1f6: address for LBA mode
	outb(0x1F3, offset);
	outb(0x1F4, offset >> 8);
	outb(0x1F5, offset >> 16);
	outb(0x1F6, (offset >> 24) | 0xE0);// the combination of these 4 lines is set to locate the sector in the disk.
	outb(0x1F7, 0x20);	// cmd 0x20 - read sectors
	// 0x1f7: status and command register
	// wait for disk to be ready
	waitdisk();

	// read a sector
	insl(0x1F0, dst, SECTSIZE/4);// read sectsize/4 bytes to the memory address dst from port 0x1f0
}
```

> ### Question
>
> - At what point does the processor start executing 32-bit code? What exactly causes the switch from 16- to 32-bit mode?
>
> ```assembly
>   lgdt    gdtdesc   	            # instruction "lgdt" will not enable the GDT immediately until the next "ljmp" instruction been executed.
>   movl    %cr0, %eax
>   orl     $CR0_PE_ON, %eax
>   movl    %eax, %cr0
>   # Jump to next instruction, but in 32-bit code segment.
>   # Switches processor into 32-bit mode.
>   ljmp    $PROT_MODE_CSEG, $protcseg
>   7c2d:       ea 32 7c 08 00 66 b8    ljmp   $0xb866,$0x87c32
> ```
>
> first, set the gdp pointer, then set the %cr0 register to 0x1, at the end, use ljmp instruction to enable the 32-bit mode.
>
> - What is the *last* instruction of the boot loader executed, and what is the *first* instruction of the kernel it just loaded?
>
> ```assembly
>         // call the entry point from the ELF header
>         // note: does not return!
>         ((void (*)(void)) (ELFHDR->e_entry))();
>     7d63:       ff 15 18 00 01 00       call   *0x10018 # the called address is stored at 0x10018, which is 0x10000c
>     # this is the last instruction of the boot loader and will never return.
> ```
>
> The first instruction locates at 0x10000c, whose address is stored at 0x10018.
>
> ```assembly
> => 0x7d63:	call   *0x10018
> 
> Breakpoint 3, 0x00007d63 in ?? ()
> (gdb) si
> => 0x10000c:	movw   $0x1234,0x472
> 0x0010000c in ?? ()
> ```
>
> - *Where* is the first instruction of the kernel?
>
> > kern/entry.S
> >
> > kern/kernel.asm
>
> - How does the boot loader decide how many sectors it must read in order to fetch the entire kernel from disk? Where does it find this information?
>
> ```c
> ELFHDR->e_phnum
> ```
>
> this number tells us the number of sectors to read.

## Exercise 4

Skip..

## Exercise 5

> ### Question
>
> The BIOS loads the boot sector into memory starting at address 0x7c00, so this is the boot sector's load address. This is also where the boot sector executes from, so this is also its link address. We set the link address by passing `-Ttext 0x7C00` to the linker in `boot/Makefrag`, so the linker will produce the correct memory addresses in the generated code.
>
> Trace through the first few instructions of the boot loader again and identify the first instruction that would "break" or otherwise do the wrong thing if you were to get the boot loader's link address wrong. Then change the link address in `boot/Makefrag` to something wrong, run make clean, recompile the lab with make, and trace into the boot loader again to see what happens. Don't forget to change the link address back and make clean again afterward!
>
> ### Answer
>
> > the BIOS still load the boot loader at 0x7c00, but once we pass a wrong link address, 0x8c00 to the linker in boot/Makefrag, all the relative address will be generated wrong. The first error we met lies in:
> >
> > ```assembly
> > # wrong:
> > 0x7c2d:	ljmp   $0xb866,$0x88c32
> > # correct:
> > 7c2d:	ea 32 7c 08 00 66 b8 	ljmp   $0xb866,$0x87c32
> > # before link:
> > ljmp    $PROT_MODE_CSEG, $protcseg
> > ```
> >
> > the passed address affects the relocated items, among which 0x88c32 points to an invalid position, the loader will crush and reboot again and again.

Why the boot sector's loaded at 0x7c00? It is specified by the BIOS, and we cannot change this setting.

## Exercise 6

> ### Question
>
> We can examine memory using GDB's x command. The [GDB manual](https://sourceware.org/gdb/current/onlinedocs/gdb/Memory.html) has full details, but for now, it is enough to know that the command x/*N*x *ADDR* prints *`N`* words of memory at *`ADDR`*. (Note that both '`x`'s in the command are lowercase.) *Warning*: The size of a word is not a universal standard. In GNU assembly, a word is two bytes (the 'w' in xorw, which stands for word, means 2 bytes).
>
> Reset the machine (exit QEMU/GDB and start them again). Examine the 8 words of memory at 0x00100000 at the point the BIOS enters the boot loader, and then again at the point the boot loader enters the kernel. Why are they different? What is there at the second breakpoint? (You do not really need to use QEMU to answer this question. Just think.)
>
> ### Answer
>
> > Before the boot loader executing, memory at 0x100000 is zeros. after the boot loader enters the kernel, this area of memory is loaded with executable codes, because the just runned boot loader loaded them into the memory.

## Exercise 7

> ### Question
>
>  Use QEMU and GDB to trace into the JOS kernel and stop at the `movl %eax, %cr0`. Examine memory at 0x00100000 and at 0xf0100000. Now, single step over that instruction using the stepi GDB command. Again, examine memory at 0x00100000 and at 0xf0100000. Make sure you understand what just happened.
>
> What is the first instruction *after* the new mapping is established that would fail to work properly if the mapping weren't in place? Comment out the `movl %eax, %cr0` in `kern/entry.S`, trace into it, and see if you were right.
>
> ### Answer
>
> ```assembly
> # entry.S
> .globl entry
> entry:
> 	movw	$0x1234,0x472			# warm boot
> 
> 	# We haven't set up virtual memory yet, so we're running from
> 	# the physical address the boot loader loaded the kernel at: 1MB
> 	# (plus a few bytes).  However, the C code is linked to run at
> 	# KERNBASE+1MB.  Hence, we set up a trivial page directory that
> 	# translates virtual addresses [KERNBASE, KERNBASE+4MB) to
> 	# physical addresses [0, 4MB).  This 4MB region will be
> 	# sufficient until we set up our real page table in mem_init
> 	# in lab 2.
> 
> 	# Load the physical address of entry_pgdir into cr3.  entry_pgdir
> 	# is defined in entrypgdir.c.
> 	movl	$(RELOC(entry_pgdir)), %eax
>   15:   b8 00 00 00 10          mov    $0x10000000,%eax
> 	movl	%eax, %cr3
> 	# Turn on paging.
> 	movl	%cr0, %eax
> 	orl	$(CR0_PE|CR0_PG|CR0_WP), %eax
> 	movl	%eax, %cr0
> ```
>
> ```C
> // Control Register flags
> #define CR0_PE          0x00000001      // Protection Enable
> #define CR0_MP          0x00000002      // Monitor coProcessor
> #define CR0_EM          0x00000004      // Emulation
> #define CR0_TS          0x00000008      // Task Switched
> #define CR0_ET          0x00000010      // Extension Type
> #define CR0_NE          0x00000020      // Numeric Errror
> #define CR0_WP          0x00010000      // Write Protect
> #define CR0_AM          0x00040000      // Alignment Mask
> #define CR0_NW          0x20000000      // Not Writethrough
> #define CR0_CD          0x40000000      // Cache Disable
> #define CR0_PG          0x80000000      // Paging
> ```
>
> ```assembly
> 	# Now paging is enabled, but we're still running at a low EIP
> 	# (why is this okay?).  Jump up above KERNBASE before entering
> 	# C code.
> 	mov	$relocated, %eax
>  0x100028:	mov    $0xf010002f,%eax
>  # but why the symbol "relocated" is relocated to high address 0xf010002f?
>  # also a question, if all the address locates well before the cr0 turns on, how they still works well after the VM turns on? if it's simply copying the code, then the absolute address will make errors. Does that mean the process of mapping has also a reverse-translation from physical address to virtual memory address?
>  
>  # what is in $0xf010002f?:
>  # (gdb) x/10i 0xf010002f
>  # 0xf010002f <relocated>:	mov    $0x0,%ebp
>  # 0xf0100034 <relocated+5>:	mov    $0xf0117000,%esp
>  # 0xf0100039 <relocated+10>:	call   0xf010009d <i386_init>
>  # 0xf010003e <spin>:	jmp    0xf010003e <spin>
>  # 0xf0100040 <test_backtrace>:	push   %ebp
>  # 0xf0100041 <test_backtrace+1>:	mov    %esp,%ebp
>  # 0xf0100043 <test_backtrace+3>:	push   %ebx
>  # 0xf0100044 <test_backtrace+4>:	sub    $0x14,%esp
>  # 0xf0100047 <test_backtrace+7>:	mov    0x8(%ebp),%ebx
>  # 0xf010004a <test_backtrace+10>:	mov    %ebx,0x4(%esp
>  # jmp	*%eax
> relocated:
> 
> 	# Clear the frame pointer register (EBP)
> 	# so that once we get into debugging C code,
> 	# stack backtraces will be terminated properly.
> 	movl	$0x0,%ebp			# nuke frame pointer
> 
> 	# Set the stack pointer
> 	movl	$(bootstacktop),%esp
> 
> 	# now to C code
> 	call	i386_init
> 
> 	# Should never get here, but in case we do, just spin.
> spin:	jmp	spin
> ```
>
> 
>
> Before executing `mov $eax, $cr0`:
>
> ```assembly
> (gdb) b * 0x100025
> Breakpoint 2 at 0x100025
> (gdb) c
> Continuing.
> => 0x100025:	mov    %eax,%cr0
> 
> Breakpoint 2, 0x00100025 in ?? ()
> (gdb) x/10i 0x100000
>    0x100000:	add    0x1bad(%eax),%dh
>    0x100006:	add    %al,(%eax)
>    0x100008:	decb   0x52(%edi)
>    0x10000b:	in     $0x66,%al
>    0x10000d:	movl   $0xb81234,0x472
>    0x100017:	jo     0x10002a
>    0x100019:	add    %cl,(%edi)
>    0x10001b:	and    %al,%bl
>    0x10001d:	mov    %cr0,%eax
>    0x100020:	or     $0x80010001,%eax
> (gdb) x/10i 0xf0100000
>    0xf0100000 <_start-268435468>:	Cannot access memory at address 0xf0100000
> (gdb)
> ```
>
> After:
>
> ```assembly
> (gdb) si
> => 0x100028:	mov    $0xf010002f,%eax
> 0x00100028 in ?? ()
> (gdb) x/10i 0x100000
>    0x100000:	add    0x1bad(%eax),%dh
>    0x100006:	add    %al,(%eax)
>    0x100008:	decb   0x52(%edi)
>    0x10000b:	in     $0x66,%al
>    # Load the physical address of entry_pgdir into cr3.  entry_pgdir
>    # is defined in entrypgdir.c.
>    0x10000d:	movl   $0xb81234,0x472 
>    						movl    $(RELOC(entry_pgdir)), %eax
>    0x100017:	jo     0x10002a
>    0x100019:	add    %cl,(%edi)
>    0x10001b:	and    %al,%bl
>    0x10001d:	mov    %cr0,%eax
>    0x100020:	or     $0x80010001,%eax
> (gdb) x/10i 0xf0100000
>    0xf0100000 <_start-268435468>:	add    0x1bad(%eax),%dh
>    0xf0100006 <_start-268435462>:	add    %al,(%eax)
>    0xf0100008 <_start-268435460>:	decb   0x52(%edi)
>    0xf010000b <_start-268435457>:	in     $0x66,%al
>    0xf010000d <entry+1>:	movl   $0xb81234,0x472
>    0xf0100017 <entry+11>:	jo     0xf010002a <entry+30>
>    0xf0100019 <entry+13>:	add    %cl,(%edi)
>    0xf010001b <entry+15>:	and    %al,%bl
>    0xf010001d <entry+17>:	mov    %cr0,%eax
>    0xf0100020 <entry+20>:	or     $0x80010001,%eax
> (gdb)
> ```
>
> Comment out the `movl %eax, %cr0`:
>
> ```assembly
> => 0x10001d:	mov    %cr0,%eax
> 0x0010001d in ?? ()
> (gdb) 
> => 0x100020:	or     $0x80010001,%eax
> 0x00100020 in ?? ()
> (gdb) 
> => 0x100025:	mov    $0xf010002c,%eax
> 0x00100025 in ?? ()
> (gdb) 
> => 0x10002a:	jmp    *%eax
> 0x0010002a in ?? ()
> (gdb) 
> => 0xf010002c <relocated>:	Error while running hook_stop:
> Cannot access memory at address 0xf010002c
> relocated () at kern/entry.S:74
> 74		movl	$0x0,%ebp			# nuke frame pointer
> (gdb) 
> ```
>
> Which gave me all kinds of "cannot access" errors.
>
> ```assembly
> (gdb) 
> => 0xf010002e <relocated+2>:	Error while running hook_stop:
> Cannot access memory at address 0xf010002e
> 
> 0xf010002e	74		movl	$0x0,%ebp			# nuke frame pointer
> (gdb) 
> => 0xf0100030 <relocated+4>:	Error while running hook_stop:
> Cannot access memory at address 0xf0100030
> 
> 0xf0100030	74		movl	$0x0,%ebp			# nuke frame pointer
> (gdb) 
> => 0xf0100032 <relocated+6>:	Error while running hook_stop:
> Cannot access memory at address 0xf0100032
> 
> 0xf0100032	77		movl	$(bootstacktop),%esp
> (gdb) 
> => 0xf0100034 <relocated+8>:	Error while running hook_stop:
> Cannot access memory at address 0xf0100034
> 
> 0xf0100034	77		movl	$(bootstacktop),%esp
> (gdb) 
> => 0xf0100036 <relocated+10>:	Error while running hook_stop:
> Cannot access memory at address 0xf0100036
> 80		call	i386_init
> (gdb) 
> => 0xf0100038 <relocated+12>:	Error while running hook_stop:
> Cannot access memory at address 0xf0100038
> 
> 0xf0100038	80		call	i386_init
> (gdb) 
> => 0xf010003a <relocated+14>:	Error while running hook_stop:
> Cannot access memory at address 0xf010003a
> 
> 0xf010003a	80		call	i386_init
> (gdb) 
> => 0xf010003c <spin+1>:	Error while running hook_stop:
> Cannot access memory at address 0xf010003c
> 0xf010003c in spin () at kern/entry.S:83
> 83	spin:	jmp	spin
> (gdb) 
> => 0xf010003e <spin+3>:	Error while running hook_stop:
> Cannot access memory at address 0xf010003e
> 0xf010003e	83	spin:	jmp	spin
> (gdb) 
> => 0xf0100040 <test_backtrace>:	Error while running hook_stop:
> Cannot access memory at address 0xf0100040
> test_backtrace (x=0) at kern/init.c:13
> ```

## Exercise 8

> ### Question
>
> We have omitted a small fragment of code - the code necessary to print octal numbers using patterns of the form "%o". Find and fill in this code fragment.
>
> ### Answer
>
> ```c
> // printfmt.c
> 		// (signed) decimal
> 		case 'd':
> 			num = getint(&ap, lflag);
> 			if ((long long) num < 0) {
> 				putch('-', putdat);
> 				num = -(long long) num;
> 			}
> 			base = 10;
> 			goto number;
> 
> 		// unsigned decimal
> 		case 'u':
> 			num = getuint(&ap, lflag);
> 			base = 10;
> 			goto number;
> 
> 		// (unsigned) octal
> 		case 'o':
> 			// Replace this with your code.
> 			num = getint(&ap, lflag);
> 			base = 8;
> 			goto number;
> 			break;
> 
> 		// pointer
> 		case 'p':
> 			putch('0', putdat);
> 			putch('x', putdat);
> 			num = (unsigned long long)
> 				(uintptr_t) va_arg(ap, void *);
> 			base = 16;
> 			goto number;
> 
> 		// (unsigned) hexadecimal
> 		case 'x':
> 			num = getuint(&ap, lflag);
> 			base = 16;
> 		number:
> 			printnum(putch, putdat, num, base, width, padc);
> 			break;
> ```
>
> Be able to answer the following questions:
>
> 1. Explain the interface between `printf.c` and `console.c`. Specifically, what function does `console.c` export? How is this function used by `printf.c`?
>
>    > `console.c` export `void cputchar(int c)` for `printf.c` to display single `char`. Most of the function in `console.c` use packaged `int cprintf(const char *fmt, ...)` to print formed string into screen, it's a high-level IO function. 
>    >
>    > 1. in order to realize an indefinite-length-arguments function, like printf(), we need to use `stdargs.h` and `va_list`, `va_args(pointer, type_to_translate)`, `va_start(first_position, args_pointer)`, `va_end(pointer_to_destroy)`
>    > 2. `cprintf()` deal with the arguments and transfer them to `vcprintf()` by `va_list` pointer
>    > 3. `vcprintf()` bind the single-char-display function `putch()`(from `console.c`) and record the number of chars, then calls `vprintfmt()`.
>    > 4. `vprintfmt()` handle the `"string"` in cases.
>
> 2. Explain the following from`console.c`:
>
>    ```c
>          if (crt_pos >= CRT_SIZE) {
>                  int i;
>                  memmove(crt_buf, crt_buf + CRT_COLS, (CRT_SIZE - CRT_COLS) * sizeof(uint16_t));
>                  for (i = CRT_SIZE - CRT_COLS; i < CRT_SIZE; i++)
>                          crt_buf[i] = 0x0700 | ' ';
>                  crt_pos -= CRT_COLS;
>          }
>    ```
>
>    > ### Answer
>    >
>    > The function `cga_putc(int c)` deal with char one by one, even if `pos > CRT_SIZE`, it must have no useful information (for the reason that this function use `crt_buf[crt_pos++] = c`, which means, when the informative character fills the last position in the buffer, the condition that `crt_pos >= CRT_SIZE` will satisfy. At that time, the last line have no real character, so we can safely cut the first row and create a new blank raw.) 
>
> 3. For the following questions you might wish to consult the notes for Lecture 2. These notes cover GCC's calling convention on the x86.
>
>    Trace the execution of the following code step-by-step:
>
>    ```c
>    int x = 1, y = 3, z = 4;
>    cprintf("x %d, y %x, z %d\n", x, y, z);
>    ```
>
>    - In the call to `cprintf()`, to what does `fmt` point? To what does `ap` point?
>    - List (in order of execution) each call to `cons_putc`, `va_arg`, and `vcprintf`. For `cons_putc`, list its argument as well. For `va_arg`, list what `ap` points to before and after the call. For `vcprintf` list the values of its two arguments.
>
>    > ### Answer
>    >
>    > `fmt` point to the string `"x %d, y %x, z %d\n"`, `ap` point to the first implicit parameter, `x`.
>    >
>    > I have answered the second part in the last question.
>
> 4. Run the following code.
>
>    ```c
>        unsigned int i = 0x00646c72;
>        cprintf("H%x Wo%s", 57616, &i);
>    ```
>
>    What is the output? Explain how this output is arrived at in the step-by-step manner of the previous exercise.[Here's an ASCII table](http://web.cs.mun.ca/~michael/c/ascii-table.html) that maps bytes to characters. The output depends on that fact that the x86 is little-endian. If the x86 were instead big-endian what would you set `i` to in order to yield the same output? Would you need to change `57616` to a different value?
>
>    [Here's a description of little- and big-endian](http://www.webopedia.com/TERM/b/big_endian.html) and [a more whimsical description](http://www.networksorcery.com/enp/ien/ien137.txt).
>
>    > ### Answer
>    >
>    > output: `He110 World`
>    >
>    > 57616 = 0xe110
>    >
>    > 0x64 = d
>    >
>    > 0x6c = l
>    >
>    > 0x72 = r
>    >
>    > if x86 were big-endian, I need to set `i = 0x726c64`
>    >
>    > but `57616` can keep going.
>
> 5. In the following code, what is going to be printed after `y=`? (note: the answer is not a specific value.) Why does this happen?
>
>    ```c
>        cprintf("x=%d y=%d", 3);
>    ```
>
>    > ### Answer
>    >
>    > x=3 y=-267380772
>    >
>    > Because `va_list` is just a pointer and translates a certain memory content to a specified type. In other words, it is a out-of-bounds access.
>
> 6. Let's say that GCC changed its calling convention so that it pushed arguments on the stack in declaration order, so that the last argument is pushed last. How would you have to change `cprintf` or its interface so that it would still be possible to pass it a variable number of arguments?
>
>    > ### Answer
>    >
>    > then the `cprintf()` function would be declared like:
>    >
>    > ```c
>    > int cprintf(..., char * const fmt);
>    > ```

## Challenge

> 1. *Challenge* Enhance the console to allow text to be printed in different colors. The traditional way to do this is to make it interpret [ANSI escape sequences](http://rrbrandt.dee.ufcg.edu.br/en/docs/ansi/) embedded in the text strings printed to the console, but you may use any mechanism you like. There is plenty of information on [the 6.828 reference page](https://pdos.csail.mit.edu/6.828/2018/reference.html) and elsewhere on the web on programming the VGA display hardware. If you're feeling really adventurous, you could try switching the VGA hardware into a graphics mode and making the console draw text onto the graphical frame buffer.
>
>    > ### Answer
>   >
>    > ```c
>   > // my revised void vprintfmt() function
>    > void
>    > vprintfmt(void (*putch)(int, void*), void *putdat, const char *fmt, va_list ap)
>    > {
>    > 	register const char *p;
>    > 	register int ch, err;
>    > 	register int color;
>    > 	unsigned long long num;
>    > 	int base, lflag, width, precision, altflag;
>    > 	char padc;
>    > 
>    > 	color = 0x0700;
>    > 
>    > 	while (1) {
>    > 		while ((ch = *(unsigned char *) fmt++) != '%') {
>    > 			if (ch == '\0')
>    > 				return;
>    > 			else if (ch == '\033'){
>    > 				if( (ch = *(unsigned char *) fmt++ ) == '['){
>    > 					register int cl;
>    > 					register int msk;
>    > 					switch (ch = *(unsigned char *) fmt++) {// should be 3 or 4 or 0;
>    > 						case '0':
>    > 							cl = 0x0700;
>    > 							msk = 0xff00;
>    > 							break;
>    > 						case '3':
>    > 							msk = 0xf00;
>    > 							cl = *(unsigned char *) fmt++ - '0';
>    > 							cl <<= 8;
>    > 							break;
>    > 						case '4':
>    > 							msk = 0xf000;
>    > 							cl = *(unsigned char *) fmt++ - '0';
>    > 							cl <<= 12;
>    > 							break;
>    > 						default://73
>    > 							cl = 0;
>    > 							msk = 0;
>    > 							break;
>    > 					}
>    > 					if ((ch = *(unsigned char *) fmt++ ) == 'm'){
>    > 						color &= ~msk;
>    > 						color |= cl;
>   > 					}
>    > 					// putch(ch | color, putdat);
>   > 					// // cprintf("case fuck\n");
>    > 					// continue;
>   > 				}
>    > 				else{ }
>    > 					// cprintf("Check succeed\n");
>    > 			}
>    > 			else
>    > 				putch(ch | color, putdat);//putdat = putcnt
>    > 		}
>   > 
>    > 		// Process a %-escape sequence
>   > 		padc = ' ';
>    > 		width = -1;
>    > 		precision = -1;
>    > 		lflag = 0;
>    > 		altflag = 0;
>    > 	reswitch:
>    > 		switch (ch = *(unsigned char *) fmt++) {
>    > 
>    > 		// flag to pad on the right
>    > 		case '-':
>   > 			padc = '-';
>    > 			goto reswitch;
>    > 
>    > 		// flag to pad with 0's instead of spaces
>   > 		case '0':
>    > 			padc = '0';
>   > 			goto reswitch;
>    > 
>   > 		// width field
>    > 		case '1':
>    > 		case '2':
>    > 		case '3':
>    > 		case '4':
>   > 		case '5':
>    > 		case '6':
>    > 		case '7':
>   > 		case '8':
>    > 		case '9':
>    > 			for (precision = 0; ; ++fmt) {
>    > 				precision = precision * 10 + ch - '0';
>    > 				ch = *fmt;
>    > 				if (ch < '0' || ch > '9')
>   > 					break;
>    > 			}
>   > 			goto process_precision;
>    > 
>    > 		case '*':
>    > 			precision = va_arg(ap, int);
>    > 			goto process_precision;
>   > 
>    > 		case '.':
>   > 			if (width < 0)
>    > 				width = 0;
>   > 			goto reswitch;
>    > 
>    > 		case '#':
>    > 			altflag = 1;
>    > 			goto reswitch;
>    > 
>    > 		process_precision:
>    > 			if (width < 0)
>    > 				width = precision, precision = -1;
>    > 			goto reswitch;
>    > 
>    > 		// long flag (doubled for long long)
>    > 		case 'l':
>    > 			lflag++;
>    > 			goto reswitch;
>    > 
>   > 		// character
>    > 		case 'c':
>   > 			putch(va_arg(ap, int) | color, putdat);
>    > 			break;
>    > 
>    > 		// error message
>   > 		case 'e':
>    > 			err = va_arg(ap, int);
>    > 			if (err < 0)
>    > 				err = -err;
>    > 			if (err >= MAXERROR || (p = error_string[err]) == NULL)
>    > 				printfmt(putch, putdat, "error %d", err);
>   > 			else
>    > 				printfmt(putch, putdat, "%s", p);
>   > 			break;
>    > 
>    > 		// string
>    > 		case 's':
>    > 			if ((p = va_arg(ap, char *)) == NULL)
>    > 				p = "(null)";
>    > 			if (width > 0 && padc != '-')
>    > 				for (width -= strnlen(p, precision); width > 0; width--)
>   > 					putch(padc | color, putdat);
>    > 			for (; (ch = *p++) != '\0' && (precision < 0 || --precision >= 0); width--)
>   > 				if (altflag && (ch < ' ' || ch > '~'))
>    > 					putch('?' | color, putdat);
>    > 				else
>    > 					putch(ch | color, putdat);
>    > 			for (; width > 0; width--)
>    > 				putch(' ' | color, putdat);
>    > 			break;
>    > 
>    > 		// (signed) decimal
>    > 		case 'd':
>    > 			num = getint(&ap, lflag);
>    > 			if ((long long) num < 0) {
>    > 				putch('-' | color, putdat);
>    > 				num = -(long long) num;
>    > 			}
>    > 			base = 10;
>    > 			goto number;
>    > 
>    > 		// unsigned decimal
>    > 		case 'u':
>    > 			num = getuint(&ap, lflag);
>    > 			base = 10;
>    > 			goto number;
>    > 
>    > 		// (unsigned) octal
>    > 		case 'o':
>    > 			// Replace this with your code.
>    > 			num = getint(&ap, lflag);
>    > 			base = 8;
>    > 			goto number;
>    > 			break;
>    > 
>    > 		// pointer
>    > 		case 'p':
>    > 			putch('0' | color, putdat);
>    > 			putch('x' | color, putdat);
>    > 			num = (unsigned long long)
>    > 				(uintptr_t) va_arg(ap, void *);
>    > 			base = 16;
>    > 			goto number;
>    > 
>    > 		// (unsigned) hexadecimal
>    > 		case 'x':
>    > 			num = getuint(&ap, lflag);
>    > 			base = 16;
>    > 		number:
>    > 			printnum(putch, putdat, num, base, width, padc, color);
>    > 			break;
>    > 
>    > 		// escaped '%' character
>    > 		case '%':
>    > 			putch(ch | color, putdat);
>    > 			break;
>    > 
>    > 		// unrecognized escape sequence - just print it literally
>    > 		default:
>    > 			putch('%', putdat);
>    > 			for (fmt--; fmt[-1] != '%'; fmt--)
>    > 				/* do nothing */;
>    > 			break;
>    > 		}
>    > 	}
>    > }
>    > ```
>    >
>    > I do not know exactly how the ascii code is in accordance with the color, but this function has the ability to print with colorful character and background.

## Exercise 9

> ### Question
>
> Determine where the kernel initializes its stack, and exactly where in memory its stack is located. How does the kernel reserve space for its stack? And at which "end" of this reserved area is the stack pointer initialized to point to?
>
> ### Answer
>
> relocated:
>
> ```assembly
> # Clear the frame pointer register (EBP)
> # so that once we get into debugging C code,
> # stack backtraces will be terminated properly.
> movl	$0x0,%ebp			# nuke frame pointer
> 
> # first %ebp points to address 0x0
> 
> # Set the stack pointer
> movl	$(bootstacktop),%esp
> 
> # esp points to address bootstacktop. In real asm file, the address is 0xf0118000:
> f0100034:       bc 00 80 11 f0          mov    $0xf0118000,%esp
> # which is defined at obj/kern/kernel.sym
> ...
> f011a200 d ctlmap
> f011a100 d shiftmap
> f011a000 d normalmap
> f0119000 D entry_pgtable
> f0118000 D entry_pgdir
> #f0118000 D bootstacktop
> #f0110000 D bootstack
> f010f447 R __STABSTR_END__
> f0106785 R __STABSTR_BEGIN__
> f0106784 R __STAB_END__
> f0102074 R __STAB_BEGIN__
> f0102048 r error_string
> f0101e00 r commands
> f0101b80 r charcode
> f0101a80 r togglecode
> ...
> # the stack ranges from 0xf0118000 (D bootstacktop ) to 0xf0110000 (D bootstack), with the size of only 8000(32768, 32k)
> 
> # also stored at .data section:
> .data
> ###################################################################
> # boot stack
> ###################################################################
> 	.p2align	PGSHIFT		# force page alignment
> 	.globl		bootstack
> bootstack:
> 	.space		KSTKSIZE
> 	.globl		bootstacktop   
> bootstacktop:
> 
> # inc/memlayout.h 
> # Kernel stack.
> #define KSTACKTOP	KERNBASE
> #define KSTKSIZE	(8*PGSIZE)   		// size of a kernel stack
> #define KSTKGAP		(8*PGSIZE)   		// size of a kernel stack guard
> # KERNBASE is defined at:
> 
> #define	KERNBASE	0xF0000000
> 
> # PGSIZE is defined at:
> # inc/mmu.h
> #define PGSIZE          4096            // bytes mapped by a page
> 
> # now to C code
> call	i386_init
> 
> ```
>

## Exercise 10

To become familiar with the C calling conventions on the x86, find the address of the `test_backtrace` function in `obj/kern/kernel.asm`, set a breakpoint there, and examine what happens each time it gets called after the kernel starts. How many 32-bit words does each recursive nesting level of `test_backtrace` push on the stack, and what are those words?

> ### Answer
>
> First time:
>
> ```assembly
> (gdb) info registers esp ebp
> esp            0xf0117fc0          0xf0117fc0
> ebp            0xf0117fd8          0xf0117fd8
> (gdb) x/24x $esp
> 0xf0117fc0:	(esp->)0xf01018f7	0xf0117fe4	0x00000000	0x00010074
> 0xf0117fd0:	0x00010074	0x00010074	(ebp->)0xf0117ff8	0xf01000ea
> 0xf0117fe0:	0x00000005	0x00001aac	0x00000640	0x00000000
> 0xf0117ff0:	0x00000000	0x00000000	(*ebp->)0x00000000	0xf010003e
> ```
>
> Second time:
>
> ```assembly
> (gdb) info registers esp ebp
> esp            0xf0117fa0          0xf0117fa0
> ebp            0xf0117fb8          0xf0117fb8
> (gdb) x/32x $esp
> 0xf0117fa0:	(esp->)0xf01018c0	0xf0117fc4	0x00000000	0x00000000
> 0xf0117fb0:	0x00000000	0x00000005	(ebp->)0xf0117fd8	0xf0100069
> 0xf0117fc0:	0x00000004	0x00000005	0x00000000	0x00010074
> 0xf0117fd0:	0x00010074	0x00010074	(*ebp->)0xf0117ff8	0xf01000ea
> 0xf0117fe0:	0x00000005	0x00001aac	0x00000640	0x00000000
> 0xf0117ff0:	0x00000000	0x00000000	(**ebp->)0x00000000	0xf010003e
> ```
>
> Third time:
>
> ```assembly
> (gdb) info registers esp ebp
> esp            0xf0117f80          0xf0117f80
> ebp            0xf0117f98          0xf0117f98
> (gdb) x/40x $esp
> 0xf0117f80:	(esp->)0xf01018c0	0xf0117fa4	0xf0117fb8	0x00000000
> 0xf0117f90:	0xf01008e4	0x00000004	(ebp->)0xf0117fb8	0xf0100069
> 0xf0117fa0:	0x00000003	0x00000004	0x00000000	0x00000000
> 0xf0117fb0:	0x00000000	0x00000005	(*ebp->)0xf0117fd8	0xf0100069
> 0xf0117fc0:	0x00000004	0x00000005	0x00000000	0x00010074
> 0xf0117fd0:	0x00010074	0x00010074	(**ebp->)0xf0117ff8	0xf01000ea
> 0xf0117fe0:	0x00000005	0x00001aac	0x00000640	0x00000000
> 0xf0117ff0:	0x00000000	0x00000000	(***ebp->)0x00000000	0xf010003e
> ```
>
> Fourth time:
>
> ```assembly
> (gdb) info registers esp ebp
> esp            0xf0117f60          0xf0117f60
> ebp            0xf0117f78          0xf0117f78
> (gdb) x/48x $esp
> 0xf0117f60:	(esp->)0xf01018c0	0xf0117f84	0xf0117f98	0x00000000
> 0xf0117f70:	0xf01008e4	0x00000003	(ebp->)0xf0117f98	0xf0100069
> 0xf0117f80:	0x00000002	0x00000003	0xf0117fb8	0x00000000
> 0xf0117f90:	0xf01008e4	0x00000004	(*ebp->)0xf0117fb8	0xf0100069
> 0xf0117fa0:	0x00000003	0x00000004	0x00000000	0x00000000
> 0xf0117fb0:	0x00000000	0x00000005	(**ebp->)0xf0117fd8	0xf0100069
> 0xf0117fc0:	0x00000004	0x00000005	0x00000000	0x00010074
> 0xf0117fd0:	0x00010074	0x00010074	(***ebp->)0xf0117ff8	0xf01000ea
> 0xf0117fe0:	0x00000005	0x00001aac	0x00000640	0x00000000
> 0xf0117ff0:	0x00000000	0x00000000	(****ebp->)0x00000000	0xf010003e
> ```
>
> Fifth time:
>
> ```assembly
> (gdb) info reg esp ebp
> esp            0xf0117f40          0xf0117f40
> ebp            0xf0117f58          0xf0117f58
> (gdb) x/56x $esp
> 0xf0117f40:	(esp->)0xf01018c0	0xf0117f64	0xf0117f78	0x00000000
> 0xf0117f50:	0xf01008e4	0x00000002	(ebp->)0xf0117f78	0xf0100069
> 0xf0117f60:	0x00000001	0x00000002	0xf0117f98	0x00000000
> 0xf0117f70:	0xf01008e4	0x00000003	(*ebp->)0xf0117f98	0xf0100069
> 0xf0117f80:	0x00000002	0x00000003	0xf0117fb8	0x00000000
> 0xf0117f90:	0xf01008e4	0x00000004	(**ebp->)0xf0117fb8	0xf0100069
> 0xf0117fa0:	0x00000003	0x00000004	0x00000000	0x00000000
> 0xf0117fb0:	0x00000000	0x00000005	(***ebp->)0xf0117fd8	0xf0100069
> 0xf0117fc0:	0x00000004	0x00000005	0x00000000	0x00010074
> 0xf0117fd0:	0x00010074	0x00010074	(****ebp->)0xf0117ff8	0xf01000ea
> 0xf0117fe0:	0x00000005	0x00001aac	0x00000640	0x00000000
> 0xf0117ff0:	0x00000000	0x00000000	(*****ebp->)0x00000000	0xf010003e
> ```
>
> Sixth time:
>
> ```assembly
> (gdb) info registers esp ebp
> esp            0xf0117f20          0xf0117f20
> ebp            0xf0117f38          0xf0117f38
> (gdb) x/64x $esp
> 0xf0117f20:	(esp->)0xf01018c0	0xf0117f44	0xf0117f58	0x00000000
> 0xf0117f30:	0xf01008e4	0x00000001	(ebp->)0xf0117f58	0xf0100069
> 0xf0117f40:	0x00000000	0x00000001	0xf0117f78	0x00000000
> 0xf0117f50:	0xf01008e4	0x00000002	(*ebp->)0xf0117f78	0xf0100069
> 0xf0117f60:	0x00000001	0x00000002	0xf0117f98	0x00000000
> 0xf0117f70:	0xf01008e4	0x00000003	(**ebp->)0xf0117f98	0xf0100069
> 0xf0117f80:	0x00000002	0x00000003	0xf0117fb8	0x00000000
> 0xf0117f90:	0xf01008e4	0x00000004	(***ebp->)0xf0117fb8	0xf0100069
> 0xf0117fa0:	0x00000003	0x00000004	0x00000000	0x00000000
> 0xf0117fb0:	0x00000000	0x00000005	(****ebp->)0xf0117fd8	0xf0100069
> 0xf0117fc0:	0x00000004	0x00000005	0x00000000	0x00010074
> 0xf0117fd0:	0x00010074	0x00010074	(*****ebp->)0xf0117ff8	0xf01000ea
> 0xf0117fe0:	0x00000005	0x00001aac	0x00000640	0x00000000
> 0xf0117ff0:	0x00000000	0x00000000	(******ebp->)0x00000000	0xf010003e
> ```
>
> disassemble code:
>
> ```assembly
> (gdb) disassemble test_backtrace 
> Dump of assembler code for function test_backtrace:
>    0xf0100040 <+0>:	push   %ebp
>    0xf0100041 <+1>:	mov    %esp,%ebp
>    0xf0100043 <+3>:	push   %ebx
>    0xf0100044 <+4>:	sub    $0x14,%esp
>    0xf0100047 <+7>:	mov    0x8(%ebp),%ebx # from the first variable in the last function to ebx
> => 0xf010004a <+10>:	mov    %ebx,0x4(%esp) #from ebx to the first variable in this function
>    0xf010004e <+14>:	movl   $0xf01018c0,(%esp) # const string
>    0xf0100055 <+21>:	call   0xf010092a <cprintf>
>    0xf010005a <+26>:	test   %ebx,%ebx
>    0xf010005c <+28>:	jle    0xf010006b <test_backtrace+43># ebx >=0
>    0xf010005e <+30>:	lea    -0x1(%ebx),%eax
>    0xf0100061 <+33>:	mov    %eax,(%esp)
>    0xf0100064 <+36>:	call   0xf0100040 <test_backtrace>
>    0xf0100069 <+41>:	jmp    0xf0100087 <test_backtrace+71>
>    # call mon_backtrace
>    0xf010006b <+43>:	movl   $0x0,0x8(%esp)
>    0xf0100073 <+51>:	movl   $0x0,0x4(%esp)
>    0xf010007b <+59>:	movl   $0x0,(%esp)
>    0xf0100082 <+66>:	call   0xf01007af <mon_backtrace>
>    
>    0xf0100087 <+71>:	mov    %ebx,0x4(%esp)# save the first argument to call function
>    0xf010008b <+75>:	movl   $0xf01018dc,(%esp)# set the string
>    0xf0100092 <+82>:	call   0xf010092a <cprintf># call
>    0xf0100097 <+87>:	add    $0x14,%esp # clear the memory, return the stack space
>    0xf010009a <+90>:	pop    %ebx # return to old_ebx
>    0xf010009b <+91>:	pop    %ebp # return to old_ebp
>    0xf010009c <+92>:	ret    
> End of assembler dump.
> ```
>
> | <u>0xf0117f20:</u>     | <u>0xf01018c0</u>                     | 0x00000000                                            | 0xf0117f58                                   | 0x00000000                                    |
> | ---------------------- | ------------------------------------- | ----------------------------------------------------- | -------------------------------------------- | --------------------------------------------- |
> | **from**               | `sub $0x14, %esp`                     | `mov    %ebx,0x4(%esp)`                               | uninitialized                                | uninitialized                                 |
> | **content**            | first argument to call next function. | save the ebx_related value in this function           | third argument to call next function(if any) | fourth argument to call next function(if any) |
> | <u>**0xf0117f30:**</u> | 0xf01008e4                            | 0x00000001                                            | **<u>0xf0117f58</u>**                        | 0xf0100069                                    |
> | **from**               | `movl   $0xf01018c0,(%esp)`           | `push %ebx`                                           | `push %ebp`                                  | `call`                                        |
> | **content**            | string address                        | save the old_ebx_related value from the last function | -> %ebp_old                                  | call return address                           |
>
> 8 32-bit words in total were allocated in the stack each time the function is called. The content and source of these words were showed in the table above.

## Exercise 11

Implement the backtrace function as specified above. Use the same format as in the example, since otherwise the grading script will be confused. When you think you have it working right, run make grade to see if its output conforms to what our grading script expects, and fix it if it doesn't. *After* you have handed in your Lab 1 code, you are welcome to change the output format of the backtrace function any way you like.

> ### Answer
>
> ```c
> // monitor.c
> typedef struct Stackframe {
> 	const uint32_t ebp;
> 	const uint32_t eip;
> 	const uint32_t arg[5];
> } Stackframe;
> 
> int
> mon_backtrace(int argc, char **argv, struct Trapframe *tf)
> {
> 	// Your code here.
> 	cprintf("Stack backtrace:\n");
> 	Stackframe * sf = (Stackframe *) read_ebp();
> 	struct Eipdebuginfo info;
> 	do{
> 		cprintf("  ebp %08x ", sf);
> 		cprintf("eip %08x ", sf->eip);
> 		cprintf("args %08x %08x %08x %08x %08x\n", sf->arg[0], sf->arg[1], sf->arg[2], sf->arg[3], sf->arg[4]);
> 	}
> 	while( (sf= (Stackframe *) sf->ebp ) != NULL);
> 	
> 	return 0;
> }
> ```
>

## Exercise 12

Modify your stack backtrace function to display, for each `eip`, the function name, source file name, and line number corresponding to that `eip`.

In `debuginfo_eip`, where do `__STAB_*` come from? This question has a long answer; to help you to discover the answer, here are some things you might want to do:

- look in the file `kern/kernel.ld` for `__STAB_*`
- run objdump -h obj/kern/kernel
- run objdump -G obj/kern/kernel
- run gcc -pipe -nostdinc -O2 -fno-builtin -I. -MD -Wall -Wno-format -DJOS_KERNEL -gstabs -c -S kern/init.c, and look at init.s.
- see if the bootloader loads the symbol table in memory as part of loading the kernel binary

Complete the implementation of `debuginfo_eip` by inserting the call to `stab_binsearch` to find the line number for an address.

Add a `backtrace` command to the kernel monitor, and extend your implementation of `mon_backtrace` to call `debuginfo_eip` and print a line for each stack frame of the form:

```assembly
K> backtrace
Stack backtrace:
  ebp f010ff78  eip f01008ae  args 00000001 f010ff8c 00000000 f0110580 00000000
         kern/monitor.c:143: monitor+106
  ebp f010ffd8  eip f0100193  args 00000000 00001aac 00000660 00000000 00000000
         kern/init.c:49: i386_init+59
  ebp f010fff8  eip f010003d  args 00000000 00000000 0000ffff 10cf9a00 0000ffff
         kern/entry.S:70: <unknown>+0
K> 
```

Each line gives the file name and line within that file of the stack frame's `eip`, followed by the name of the function and the offset of the `eip`from the first instruction of the function (e.g., `monitor+106` means the return `eip` is 106 bytes past the beginning of `monitor`).

Be sure to print the file and function names on a separate line, to avoid confusing the grading script.

Tip: printf format strings provide an easy, albeit obscure, way to print non-null-terminated strings like those in STABS tables.`printf("%.*s", length, string)` prints at most `length` characters of `string`. Take a look at the printf man page to find out why this works.

You may find that some functions are missing from the backtrace. For example, you will probably see a call to `monitor()` but not to `runcmd()`. This is because the compiler in-lines some function calls. Other optimizations may cause you to see unexpected line numbers. If you get rid of the `-O2` from `GNUMakefile`, the backtraces may make more sense (but your kernel will run more slowly).

> ### Answer
>
> 1. `__STAB_*` come from `ld script`:
>
> ```C
> // kernel.ld
> /* Simple linker script for the JOS kernel.
>    See the GNU ld 'info' manual ("info ld") to learn the syntax. */
> 
> OUTPUT_FORMAT("elf32-i386", "elf32-i386", "elf32-i386")
> OUTPUT_ARCH(i386)
> ENTRY(_start)
> 
> SECTIONS
> {
> 	...
> 	.stab : {
> 		PROVIDE(__STAB_BEGIN__ = .);
>     // PROVIDE uses to create an undefined symbol in any other object files. In this line, we set the __STAB_BEGIN__ value to the current virtual memory address, where the .stab section begins.
> 		*(.stab);
> 		PROVIDE(__STAB_END__ = .);
> 		BYTE(0)		/* Force the linker to allocate space
> 				   for this section */
> 	}
> 
> 	.stabstr : {
> 		PROVIDE(__STABSTR_BEGIN__ = .);
> 		*(.stabstr);
> 		PROVIDE(__STABSTR_END__ = .);
> 		BYTE(0)		/* Force the linker to allocate space
> 				   for this section */
> 	}
> 	...
> }
> 
> ```
>
> ```shell
> ➜  lab git:(lab1) ✗ objdump -h obj/kern/kernel 
> 
> obj/kern/kernel:     file format elf32-i386
> 
> Sections:
> Idx Name          Size      VMA       LMA       File off  Algn
>   0 .text         000019d6  f0100000  00100000  00001000  2**2
>                   CONTENTS, ALLOC, LOAD, READONLY, CODE
>   1 .rodata       00000840  f01019e0  001019e0  000029e0  2**5
>                   CONTENTS, ALLOC, LOAD, READONLY, DATA
>   2 .stab         00004861  f0102220  00102220  00003220  2**2
>                   CONTENTS, ALLOC, LOAD, READONLY, DATA
>   3 .stabstr      00008d6f  f0106a80  00106a80  00007a81  2**0
>                   CONTENTS, ALLOC, LOAD, READONLY, DATA
>   4 .data         0000a300  f0110000  00110000  00011000  2**12
>                   CONTENTS, ALLOC, LOAD, DATA
>   5 .bss          00000648  f011a300  0011a300  0001b300  2**5
>                   CONTENTS, ALLOC, LOAD, DATA
>   6 .comment      00000011  00000000  00000000  0001b948  2**0
>                   CONTENTS, READONLY
> ```
>
> Check the `.stab` section at `0xf0102220`:
>
> ```assembly
> The target architecture is assumed to be i8086
> [f000:fff0]    0xffff0:	ljmp   $0xf000,$0xe05b
> 0x0000fff0 in ?? ()
> + symbol-file obj/kern/kernel
> (gdb) b monitor
> Breakpoint 1 at 0xf0100889: file kern/monitor.c, line 158.
> (gdb) c
> Continuing.
> The target architecture is assumed to be i386
> => 0xf0100889 <monitor>:	push   %ebp
> 
> Breakpoint 1, monitor (tf=0x0) at kern/monitor.c:158
> 158	{
> (gdb) x/10x 0xf0102220
> 0xf0102220:	0x01	0x00	0x00	0x00	0x00	0x00	0x05	0x06
> 0xf0102228:	0x16	0x8c
> ```
>
> The data structure `Stab` is defined at `inc/stab.h`:
>
> ```c
> struct Stab {
> 	uint32_t n_strx;	// index into string table of name
> 	uint8_t n_type;         // type of symbol
> 	uint8_t n_other;        // misc info (usually empty)
> 	uint16_t n_desc;        // description field
> 	uintptr_t n_value;	// value of symbol
> };
> ```
>
> Then we check `.stabstr` section at Vitural Memory Address `0xf0106a80`:
>
> ```assembly
> 
> (gdb) x/10s 0xf0106a80
> 0xf0106a80:	 "entry.S"
> 0xf0106a88:	 "kern/entrypgdir.c"
> 0xf0106a9a:	 "gcc2_compiled."
> 0xf0106aa9:	 "int:t(0,1)=r(0,1);-2147483648;2147483647;"
> 0xf0106ad3:	 "char:t(0,2)=r(0,2);0;127;"
> 0xf0106aed:	 "long int:t(0,3)=r(0,3);-2147483648;2147483647;"
> 0xf0106b1c:	 "unsigned int:t(0,4)=r(0,4);0;4294967295;"
> 0xf0106b45:	 "long unsigned int:t(0,5)=r(0,5);0;4294967295;"
> 0xf0106b73:	 "long long int:t(0,6)=r(0,6);-0;4294967295;"
> 0xf0106b9e:	 "long long unsigned int:t(0,7)=r(0,7);0;-1;"
> ```
>
> 2. Entries in `.stab` section have one-to-one corresponding entries in `.stabstr` section. That means, when we find the entry index in `.stab` , then we fill the `info` with the corresponding string in `.stabstr`.
>
> ```C
> // kdebug.c
> int
> debuginfo_eip(uintptr_t addr, struct Eipdebuginfo *info)
> {
> 	...
> 	// Search within [lline, rline] for the line number stab.
> 	// If found, set info->eip_line to the right line number.
> 	// If not found, return -1.
> 	//
> 	// Hint:
> 	//	There's a particular stabs type used for line numbers.
> 	//	Look at the STABS documentation and <inc/stab.h> to find
> 	//	which one.
> 	// Your code here.
> 	stab_binsearch(stabs, &lline, &rline, N_SLINE, addr);
> 	if(lline == rline && lline >= 0){
> 		info->eip_line = stabs[lline].n_desc;
> 	}
> 	else{
> 		info->eip_line = 0;
> 		return -1;
> 	}
>   
>   ...
> 	return 0;
> }
> ```
>
> 3. `backtrace` function:
>
> ```C
> // monitor.c
> int
> mon_backtrace(int argc, char **argv, struct Trapframe *tf)
> {
> 	// Your code here.
> 	cprintf("Stack backtrace:\n");
> 	Stackframe * sf = (Stackframe *) read_ebp();
> 	struct Eipdebuginfo info;
> 	do{
> 		cprintf("  ebp %08x ", sf);
> 		cprintf("eip %08x ", sf->eip);
> 		cprintf("args %08x %08x %08x %08x %08x\n", sf->arg[0], sf->arg[1], sf->arg[2], sf->arg[3], sf->arg[4]);
> 		debuginfo_eip((uintptr_t) sf->eip, &info);
> 		cprintf("\t%s:%d: ", info.eip_file, info.eip_line);
> 		cprintf("%.*s", info.eip_fn_namelen, info.eip_fn_name);
> 		cprintf("+%d\n", (int)(sf->eip - info.eip_fn_addr));
> 	}
> 	while( (sf= (Stackframe *) sf->ebp ) != NULL);
> 	
> 	return 0;
> }
> ```

## Lab Result

```shell
➜  lab git:(lab1) ✗ make qemu
qemu-system-i386 -drive file=obj/kern/kernel.img,index=0,media=disk,format=raw -serial mon:stdio -gdb tcp::26000 -D qemu.log 
unknown keycodes `empty_aliases(qwerty)', please report to qemu-devel@nongnu.org
6828 decimal is 15254 octal!
entering test_backtrace 5
entering test_backtrace 4
entering test_backtrace 3
entering test_backtrace 2
entering test_backtrace 1
entering test_backtrace 0
Stack backtrace:
  ebp f0117f18 eip f0100087 args 00000000 00000000 00000000 00000000 f01009b4
	     kern/init.c:19: test_backtrace+71
  ebp f0117f38 eip f0100069 args 00000000 00000001 f0117f78 00000000 f01009b4
	     kern/init.c:16: test_backtrace+41
  ebp f0117f58 eip f0100069 args 00000001 00000002 f0117f98 00000000 f01009b4
	     kern/init.c:16: test_backtrace+41
  ebp f0117f78 eip f0100069 args 00000002 00000003 f0117fb8 00000000 f01009b4
	     kern/init.c:16: test_backtrace+41
  ebp f0117f98 eip f0100069 args 00000003 00000004 00000000 00000000 00000000
	     kern/init.c:16: test_backtrace+41
  ebp f0117fb8 eip f0100069 args 00000004 00000005 00000000 00010074 00010074
	     kern/init.c:16: test_backtrace+41
  ebp f0117fd8 eip f01000ea args 00000005 00001aac 00000640 00000000 00000000
	     kern/init.c:44: i386_init+77
  ebp f0117ff8 eip f010003e args 00119021 00000000 00000000 00000000 00000000
	     kern/entry.S:85: <unknown>+0
leaving test_backtrace 0
leaving test_backtrace 1
leaving test_backtrace 2
leaving test_backtrace 3
leaving test_backtrace 4
leaving test_backtrace 5
Welcome to the JOS kernel monitor!
Type 'help' for a list of commands.
K> 
```

```shell
➜  lab git:(lab1) ✗ make grade
make clean
make[1]: Entering directory '/home/huangyong/mac/6.828/lab'
rm -rf obj .gdbinit jos.in qemu.log
make[1]: Leaving directory '/home/huangyong/mac/6.828/lab'
./grade-lab1 
make[1]: Entering directory '/home/huangyong/mac/6.828/lab'
+ as kern/entry.S
+ cc kern/entrypgdir.c
+ cc kern/init.c
+ cc kern/console.c
+ cc kern/monitor.c
+ cc kern/printf.c
+ cc kern/kdebug.c
+ cc lib/printfmt.c
+ cc lib/readline.c
+ cc lib/string.c
+ ld obj/kern/kernel
i386-jos-elf-ld: warning: section `.bss' type changed to PROGBITS
+ as boot/boot.S
+ cc -Os boot/main.c
+ ld boot/boot
boot block is 382 bytes (max 510)
+ mk obj/kern/kernel.img
make[1]: Leaving directory '/home/huangyong/mac/6.828/lab'
running JOS: (1.0s) 
  printf: OK 
  backtrace count: OK 
  backtrace arguments: OK 
  backtrace symbols: OK 
  backtrace lines: OK 
Score: 50/50
```

