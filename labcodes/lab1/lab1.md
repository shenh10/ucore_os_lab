c# Lab1 Report


##Excercise 1 

##### Q1: 操作系统镜像文件ucore.img是如何一步一步生成的？(需要比较详细地解释Makefile中每一条相关命令和命令参数的含义，以及说明命令导致的结果)
#####S1:
#### [ ucore.img ]
Makefile 中直接制作ucore.img镜像的命令
``` bash
$(UCOREIMG): $(kernel) $(bootblock)
        $(V)dd if=/dev/zero of=$@ count=10000
        $(V)dd if=$(bootblock) of=$@ conv=notrunc
        $(V)dd if=$(kernel) of=$@ seek=1 conv=notrunc

```
依赖：生成的镜像依赖于kernel、bootblock对象的生成，在后文描述。

解析命令
```bash
  1. $(V)dd if=/dev/zero of=$@ count=10000
  2. $(V)dd if=$(bootblock) of=$@ conv=notrunc
  3. $(V)dd if=$(kernel) of=$@ seek=1 conv=notrunc
```
V='@' 的语法表示执行之后的命令但不打印输出。
1. dd生成一个有10000个块的文件记为$@(指代生成镜像 $(UCOREIMG))，并初始化为0
2. 拷贝bootblock对象到生成镜像第一块
3. 拷贝kernel对象到生成镜像第二个块

#### [ bootblock ]
```bash
$(bootblock): $(call toobj,$(bootfiles)) | $(call totarget,sign)
        @echo + ld $@ 
        # ld 
        #	 -N Set the text and data sections to be readable and writable
        #    -e start 从start处开始执行
        #	-Ttext 0x7c00 $^  Locate section( ".bss", ".data" or ".text")  in the output file at the absolute address 0x7c00
        # 生成obj/bootblock.o文件
        $(V)$(LD) $(LDFLAGS) -N -e start -Ttext 0x7C00 $^ -o $(call toobj,bootblock)
        # 打印obj/bootblock信息到obj/bootblock.asm
        @$(OBJDUMP) -S $(call objfile,bootblock) > $(call asmfile,bootblock)
        # 从obj/bootblock删除所有symbol和relocation信息(-S)并以二进制方式(-O binary)输出生成obj/bootblock.out
        @$(OBJCOPY) -S -O binary $(call objfile,bootblock) $(call outfile,bootblock)
        # 用bin/sign工具处理obj/bootblock.out生成、bin/bootblock执行文件
        @$(call totarget,sign) $(call outfile,bootblock) $(bootblock)

```
依赖：obj/bootasm.o obj/bootmain.o bin/sign
```bash
# 生成bootasm.o bootmain.o的代码段为：
bootfiles = $(call listf_cc,boot) # boot/bootasm.S boot/bootmain.c
$(foreach f,$(bootfiles),$(call cc_compile,$(f),$(CC),$(CFLAGS) -Os -nostdinc))
#------->| define do_cc_compile
#		|	$$(foreach f,$(1),$$(eval $$(call cc_template,$$(f),$(2),$(3),$(4))))
#		| endef
# 将参数消去最终得到的命令为：
# 生成bootasm.o:c
# gcc -Iboot/ -fno-builtin -Wall -ggdb -m32 -gstabs \
# -nostdinc  -fno-stack-protector -Ilibs/ -Os -nostdinc \
# -c boot/bootasm.S -o obj/boot/bootasm.o
# 生成bootmain.o, 命令：
# gcc -Iboot/ -fno-builtin -Wall -ggdb -m32 -gstabs -nostdinc \
# -fno-stack-protector -Ilibs/ -Os -nostdinc \
# -c boot/bootmain.c -o obj/boot/bootmain.o
# 其中用到的参数：
# -Wall: enable all warnings -g: produce debug info -O2: compiling with optimization
# -fno-builtin: Don't recognize built-in functions that do not begin with ‘__builtin_’ as prefix
# -ggdb: Produce debugging information for use by GDB
# -m32: X86 option
# -gstabs: Produce debugging information in stabs format (if that is supported), without GDB extensions
# -nostdinc: Do not search the standard system directories for header files

# 其中名称代换的一些子函数如下所示：
listf_cc = $(call listf,$(1),$(CTYPE)) #$(1) = boot CTYPE= S c
# @ tools/function.mk
# $(filter pattern…,text): 将text中以空格分隔的字符串与pattern匹配，留下match的字段
# $(wildcard pattern): 满足pattern的文件名列表 以空格分隔
# 此处过滤boot/* 下的.c/.s文件（%表示通配符，将.加到c和S上），bootfiles={ boot/*.c, boot/*.S)c
listf = $(filter $(if $(2),$(addprefix %.,$(2)),%),\
                  $(wildcard $(addsuffix $(SLASH)*,$(1)))) # $(2) = S c $(1) = boot
# 生成sign的代码段:
# create 'sign' tools
$(call add_files_host,tools/sign.c,sign,sign)
$(call create_target_host,sign,sign)
# 实际命令为：
# clang -Itools -g -Wall -O2 -c tools/sign.c -o obj/sign/tools/sign.o
# clang -g -Wall -O2 obj/sign/tools/sign.o -o bin/sign
```


#### [ kernel ]
``` bash
$(kernel): $(KOBJS)
        @echo + ld $@
        # @ld -m    elf_i386 -nostdlib -T tools/kernel.ld -o bin/kernel 
        # obj/kern/init/init.o obj/kern/libs/readline.o \
		# obj/kern/libs/stdio.o obj/kern/debug/kdebug.o \
		# obj/kern/debug/kmonitor.o obj/kern/debug/panic.o \
		# obj/kern/driver/clock.o obj/kern/driver/console.o \
		# obj/kern/driver/intr.o obj/kern/driver/picirq.o \
		# obj/kern/trap/trap.o obj/kern/trap/trapentry.o \
		# obj/kern/trap/vectors.o obj/kern/mm/pmm.o \
		# obj/libs/printfmt.o obj/libs/string.o
        $(V)$(LD) $(LDFLAGS) -T tools/kernel.ld -o $@ $(KOBJS)
        # 生成kernel/asm：objdump -S bin/kernel > obj/kernel.asm
        @$(OBJDUMP) -S $@ > $(call asmfile,kernel)
        # 生成kernel.sym objdump -t bin/kernel | sed '1,/SYMBOL TABLE/d; S/ .* / /; /^$$/d' > obj/kernel.sym
        @$(OBJDUMP) -t $@ | $(SED) '1,/SYMBOL TABLE/d; s/ .* / /; /^$$/d' > $(call symfile,kernel)

```
依赖 KOBJS= obj/kern/*/*.o, obj/libs/*/*/.o
```bash
# 生成kernel依赖文件的代码：
$(call add_files_cc,$(call listf_cc,$(KSRCDIR)),kernel,$(KCFLAGS))
# 实际代码为
gcc -Ikern/init,kern/libs,kern/driver,kern/trap,kern/mm -fno-builtin -Wall -ggdb -m32 -gstabs -nostdinc -fno-stack-protector -c ...（与上类似不赘述，生成.o,.d文件在obj/kern和obj/libs对应目录下）
```



##### Q2：一个被系统认为是符合规范的硬盘主引导扇区的特征是什么？
由sign.c来看：
buf[512]--> 引导扇区总长固定为512字节
buf[510] = 0x55;cc
buf[511] = 0xAA; --> 引导扇区最后两位为0x55和0xAAcc


## Excercise 2
##### Q1: 从CPU加电后执行的第一条指令开始，单步跟踪BIOS的执行。
修改gdbinit为
``` bash
file bin/kernelc    # 调试目标文件
set architecture i8086 #设置当前CPU为8086
target remote :1234 # gdb与qemu联调端口
b *0x7c00			# 在地址为0x7c00处设置断点，改地址实为bootloader入口地址，在bootblock.asm中对应start地址		
define hook-stop
x/i $pc				# 每单步反编译得到指令对应汇编
end
```
运行make debug即可进入gdb单步调试
##### Q2: 在初始化位置0x7c00设置实地址断点,测试断点正常。
在gdbinit已设置断点，输出结果如下
``` bash
The target architecture is assumed to be i8086
0x0000fff0 in ?? ()
Breakpoint 1 at 0x7c00
Breakpoint 2 at 0x100000: file kern/init/init.c, line 17.

Breakpoint 1, 0x00007c00 in ?? ()
(gdb) x/5i $pc
=> 0x7c00:      cli    
   0x7c01:      cld    
   0x7c02:      xor    %ax,%ax
   0x7c04:      mov    %ax,%ds
   0x7c06:      mov    %ax,%es

```

##### Q3:从0x7c00开始跟踪代码运行,将单步跟踪反汇编得到的代码与bootasm.S和 bootblock.asm进行比较。
在Makefile debug target命令中添加参数" -d in_asm -D q.log"得到

``` bash
$(V)$(QEMU) -S -s -parallel stdio -d in_asm -D q.log -hda $< -serial null &

```
生成日志文件q.log
``` gas
----------------
IN:
0x00007c00:  cli

----------------
IN:
0x00007c01:  cld
0x00007c02:  xor    %ax,%ax
0x00007c04:  mov    %ax,%ds
0x00007c06:  mov    %ax,%es
0x00007c08:  mov    %ax,%ss

----------------
IN:
0x00007c0a:  in     $0x64,%al

----------------
IN:
0x00007c0c:  test   $0x2,%al
0x00007c0e:  jne    0x7c0a

----------------
IN:
0x00007c10:  mov    $0xd1,%al
0x00007c12:  out    %al,$0x64
0x00007c14:  in     $0x64,%al
0x00007c16:  test   $0x2,%al
0x00007c18:  jne    0x7c14

----------------
IN:
0x00007c1a:  mov    $0xdf,%al
0x00007c1c:  out    %al,$0x60
0x00007c1e:  lgdtw  0x7c6c
0x00007c23:  mov    %cr0,%eax
0x00007c26:  or     $0x1,%eax
0x00007c2a:  mov    %eax,%cr0

----------------
IN:
0x00007c2d:  ljmp   $0x8,$0x7c32
----------------
IN:
0x00007c32:  mov    $0x10,%ax
0x00007c36:  mov    %eax,%ds

----------------
IN:
0x00007c38:  mov    %eax,%es

----------------
IN:
0x00007c3a:  mov    %eax,%fs
0x00007c3c:  mov    %eax,%gs
0x00007c3e:  mov    %eax,%ss

----------------
IN:
0x00007c40:  mov    $0x0,%ebp

----------------
IN:
0x00007c45:  mov    $0x7c00,%esp
0x00007c4a:  call   0x7cd1

----------------
IN:
0x00007cd1:  push   %ebp
0x00007cd2:  mov    %esp,%ebp
0x00007cd4:  push   %edi
0x00007cd5:  push   %esi
0x00007cd6:  push   %ebx
0x00007cd7:  mov    $0x1,%ebx
0x00007cdc:  sub    $0x1c,%esp
0x00007cdf:  lea    0x7f(%ebx),%eax
0x00007ce2:  mov    %ebx,%edx
0x00007ce4:  shl    $0x9,%eax
0x00007ce7:  inc    %ebx
0x00007ce8:  call   0x7c72
...
```
对比bootasm.S和bootblock.asm，发现前者是纯粹的汇编语法，bootblock.asm是已经分配了地址空间的汇编代码，和q.log的反编译结果一致。


##### Q4: 自己找一个bootloader或内核中的代码位置，设置断点并进行测试。
(略)

## Excercise 3
##### Q1: BIOS将通过读取硬盘主引导扇区到内存，并转跳到对应内存中的位置执行bootloader。请分析bootloader是如何完成从实模式进入保护模式的。
###### 1) 为何开启A20，以及如何开启A20
###### 2) 如何初始化GDT表
###### 3) 如何使能和进入保护模式
##### S1:
以实模式下 cs = 0 ip = 7c00　状态进入
为几个寄存器赋值

``` gas
.set PROT_MODE_CSEG,        0x8                     # kernel code segment selector
.set PROT_MODE_DSEG,        0x10                    # kernel data segment selector
.set CR0_PE_ON,             0x1                     # protected mode enable flag

```
从start开始运行，清空中断位，清空字符操作方向位
``` gas
start:
.code16                                             # Assemble for 16-bit mode
    cli                                             # Disable interrupts
    cld                                             # String operations increment
```
段寄存器置零
``` gas
    # Set up the important data segment registers (DS, ES, SS).
    xorw %ax, %ax                                   # Segment number zero
    movw %ax, %ds                                   # -> Data Segment
    movw %ax, %es                                   # -> Extra Segment
    movw %ax, %ss                                   # -> Stack Segment
```
使能A20 Gate.(为向下兼容8086 CPU)，使得CPU可以使用全部32位的地址线
``` gas
# 检查0x64状态寄１bit是否为１，若为１则表示输入寄存器（60h/64h）上有数据，等待
seta20.1:
    inb $0x64, %al                                  # Wait for not busy(8042 input buffer empty).
    testb $0x2, %al
    jnz seta20.1                                    # jump if not zero
＃写Output Port：先向64h发送0d1h命令
    movb $0xd1, %al                                 # 0xd1 -> port 0x64
    outb %al, $0x64                                 # 0xd1 means: write data to 8042's P2 port

seta20.2:
    inb $0x64, %al                                  # Wait for not busy(8042 input buffer empty).
    testb $0x2, %al
    jnz seta20.2
＃写Output Port：后向60h写入Output Port的数据
    movb $0xdf, %al                                 # 0xdf -> port 0x60
    outb %al, $0x60                                 # 0xdf = 11011111, means set P2's A20 bit(the 1 bit) to 1

```
初始化gdt表：
``` gas
    lgdt gdtdesc                                    # load the gdt register
```
表设置见：
``` gas
gdt:
    SEG_NULLASM                                     # null seg
    SEG_ASM(STA_X|STA_R, 0x0, 0xffffffff)           # code seg for bootloader and kernel
    SEG_ASM(STA_W, 0x0, 0xffffffff)                 # data seg for bootloader and kernel

gdtdesc:
    .word 0x17                                      # sizeof(gdt) - 1
    .long gdt                                       # address gdt

```
将cr0寄存器的PE位置１，使进入保护模式
``` gas
   movl %cr0, %eax
    orl $CR0_PE_ON, %eax
    movl %eax, %cr0

# 长跳转，更新代码段寄存器cs基址为kernel code segment selector地址
    ljmp $PROT_MODE_CSEG, $protcseg
```
进入保护模式，首先初始化各个段寄存器。保护模式下段寄存器比8086的四个段寄存器(cs,ds,es,ss)又增加了两个附加段寄存器(fs,gs)
``` gas
.code32                                             # Assemble for 32-bit mode
protcseg:
    # Set up the protected-mode data segment registers
    movw $PROT_MODE_DSEG, %ax                       # Our data segment selector
    movw %ax, %ds                                   # -> DS: Data Segment
    movw %ax, %es                                   # -> ES: Extra Segment
    movw %ax, %fs                                   # -> FS
    movw %ax, %gs                                   # -> GS
    movw %ax, %ss                                   # -> SS: Stack Segment
```
建立堆栈，从实模式到保护模式转换完成，调用bootmain程序
``` gas
    # Set up the stack pointer and call into C. The stack region is from 0--start(0x7c00)
    movl $0x0, %ebp #基址指针寄存器置零
    movl $start, %esp　　＃堆栈指针寄存器（栈地址上限置为0x7c00，则0-0x7c00为栈空间，往上为代码空间）
    call bootmain
```

## Excercise 4
##### Q1: 通过阅读bootmain.c，了解bootloader如何加载ELF文件。通过分析源代码和通过qemu来运行并调试bootloader&OS，

###### 1) bootloader如何读取硬盘扇区的？
###### 2) bootloader是如何加载ELF格式的OS？

##### S1:
1) 
读取硬盘扇区：readseg函数从va指定的起始地址读取count个字节，offset为va与扇区起始处的偏置
``` c
static void
readseg(uintptr_t va, uint32_t count, uint32_t offset) {
    uintptr_t end_va = va + count;

    // round down to sector boundary
    va -= offset % SECTSIZE;

    // translate from bytes to sectors; kernel starts at sector 1
    uint32_t secno = (offset / SECTSIZE) + 1;

    // If this is too slow, we could read lots of sectors at a time.
    // We'd write more to memory than asked, but it doesn't matter --
    // we load in increasing order.
    for (; va < end_va; va += SECTSIZE, secno ++) {
     	# 每个扇区依次读取直到end_va
     	readsect((void *)va, secno);
    }
}

```
readsect函数每次对齐读取从va地址开始的第secno扇区，首先等待disk变为不忙状态(检查0x1F7寄存器)，分别写0x1F0\~0x1F7寄存器。9x1F2表示要读取的扇区数，0x1F3~0x1F6依次保存扇区编号的低位字节到高位字节。0x1F7指定对硬盘的读取命令
``` c
static void
readsect(void *dst, uint32_t secno) {
    // wait for disk to be ready
    waitdisk();

    outb(0x1F2, 1);                         // count = 1
    outb(0x1F3, secno & 0xFF);
    outb(0x1F4, (secno >> 8) & 0xFF);
    outb(0x1F5, (secno >> 16) & 0xFF);
    outb(0x1F6, ((secno >> 24) & 0xF) | 0xE0);
    outb(0x1F7, 0x20);                      // cmd 0x20 - read sectors

    // wait for disk to be ready
    waitdisk();

    // read a sector
    insl(0x1F0, dst, SECTSIZE / 4);
}
```
其中insl为真正的读取操作。它定义在头文件x86.h中，使用内联汇编的方法：cld清空字符串方向位,repne重复之后的操作　%ecx　遍，　insl为x86指令，每次从port端口读取32-bit到内存。因此上述读取扇区的调用中需要设置SECTSIZE/4
``` c
static inline void
insl(uint32_t port, void *addr, int cnt) {
    asm volatile (
            "cld;"
            "repne; insl;"
            : "=D" (addr), "=c" (cnt)
            : "d" (port), "0" (addr), "1" (cnt)
            : "memory", "cc");
}

```
2)
读取elf文件，第一步检查文件有效性：e_magic字段必须为ELF_MAGIC，否则出错
``` c
    // is this a valid ELF?
    if (ELFHDR->e_magic != ELF_MAGIC) {
        goto bad;
    }
```
接着，读取program_header表，加载各个段到内存指定位置，调用elf文件头指定的程序入口函数
``` c
    struct proghdr *ph, *eph;

    // load each program segment (ignores ph flags)
	// program header表的内存地址
	ph = (struct proghdr *)((uintptr_t)ELFHDR + ELFHDR->e_phoff);
    //　表的program_header结构数目
    eph = ph + ELFHDR->e_phnum;
    for (; ph < eph; ph ++) {
        ／／读取每个段到内存指定位置，段大小和偏置由p_memsz和p_offset指定
        readseg(ph->p_va & 0xFFFFFF, ph->p_memsz, ph->p_offset);
    }

    // call the entry point from the ELF header
    // note: does not return
    
    ((void (*)(void))(ELFHDR->e_entry & 0xFFFFFF))();

```
于是bootloader完成了对ucore　os的加载过程。

## Excercise 5
##### Q!: 完成kdebug.c中函数print_stackframe的实现，可以通过函数print_stackframe来跟踪函数调用堆栈中记录的返回地址




