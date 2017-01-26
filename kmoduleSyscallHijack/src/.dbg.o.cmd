cmd_/home/yanfeng/soulAssist/kmoduleSyscallHijack/src/dbg.o := /home/yanfeng/softwares/l36h/kernel/scripts/gcc-wrapper.py arm-linux-androideabi-gcc -Wp,-MD,/home/yanfeng/soulAssist/kmoduleSyscallHijack/src/.dbg.o.d  -nostdinc -isystem /usr/lib/gcc/arm-linux-androideabi/4.7.4/include -I/home/yanfeng/softwares/l36h/kernel/arch/arm/include -Iarch/arm/include/generated -Iinclude  -include /home/yanfeng/softwares/l36h/kernel/include/linux/kconfig.h -D__KERNEL__ -mlittle-endian -Iarch/arm/mach-msm/include -Wall -Wundef -Wstrict-prototypes -Wno-trigraphs -fno-strict-aliasing -fno-common -Werror-implicit-function-declaration -Wno-format-security -fno-delete-null-pointer-checks -Os -marm -fno-dwarf2-cfi-asm -fstack-protector -mabi=aapcs-linux -mno-thumb-interwork -funwind-tables -D__LINUX_ARM_ARCH__=7 -mcpu=cortex-a15 -msoft-float -Uarm -Wframe-larger-than=1024 -Wno-unused-but-set-variable -fomit-frame-pointer -g -Wdeclaration-after-statement -Wno-pointer-sign -fno-strict-overflow -fconserve-stack -fno-pic  -DMODULE  -D"KBUILD_STR(s)=\#s" -D"KBUILD_BASENAME=KBUILD_STR(dbg)"  -D"KBUILD_MODNAME=KBUILD_STR(hook)" -c -o /home/yanfeng/soulAssist/kmoduleSyscallHijack/src/.tmp_dbg.o /home/yanfeng/soulAssist/kmoduleSyscallHijack/src/dbg.c

source_/home/yanfeng/soulAssist/kmoduleSyscallHijack/src/dbg.o := /home/yanfeng/soulAssist/kmoduleSyscallHijack/src/dbg.c

deps_/home/yanfeng/soulAssist/kmoduleSyscallHijack/src/dbg.o := \
  include/linux/string.h \
    $(wildcard include/config/binary/printf.h) \
  include/linux/compiler.h \
    $(wildcard include/config/sparse/rcu/pointer.h) \
    $(wildcard include/config/trace/branch/profiling.h) \
    $(wildcard include/config/profile/all/branches.h) \
    $(wildcard include/config/enable/must/check.h) \
    $(wildcard include/config/enable/warn/deprecated.h) \
  include/linux/compiler-gcc.h \
    $(wildcard include/config/arch/supports/optimized/inlining.h) \
    $(wildcard include/config/optimize/inlining.h) \
  include/linux/compiler-gcc4.h \
  include/linux/types.h \
    $(wildcard include/config/uid16.h) \
    $(wildcard include/config/lbdaf.h) \
    $(wildcard include/config/arch/dma/addr/t/64bit.h) \
    $(wildcard include/config/phys/addr/t/64bit.h) \
    $(wildcard include/config/64bit.h) \
  /home/yanfeng/softwares/l36h/kernel/arch/arm/include/asm/types.h \
  include/asm-generic/int-ll64.h \
  arch/arm/include/generated/asm/bitsperlong.h \
  include/asm-generic/bitsperlong.h \
  include/linux/posix_types.h \
  include/linux/stddef.h \
  /home/yanfeng/softwares/l36h/kernel/arch/arm/include/asm/posix_types.h \
  include/asm-generic/posix_types.h \
  /usr/lib/gcc/arm-linux-androideabi/4.7.4/include/stdarg.h \
  /home/yanfeng/softwares/l36h/kernel/arch/arm/include/asm/string.h \
  include/linux/kernel.h \
    $(wildcard include/config/preempt/voluntary.h) \
    $(wildcard include/config/debug/atomic/sleep.h) \
    $(wildcard include/config/prove/locking.h) \
    $(wildcard include/config/lge/crash/handler.h) \
    $(wildcard include/config/cpu/cp15/mmu.h) \
    $(wildcard include/config/ring/buffer.h) \
    $(wildcard include/config/tracing.h) \
    $(wildcard include/config/numa.h) \
    $(wildcard include/config/compaction.h) \
    $(wildcard include/config/ftrace/mcount/record.h) \
  include/linux/sysinfo.h \
  include/linux/linkage.h \
  /home/yanfeng/softwares/l36h/kernel/arch/arm/include/asm/linkage.h \
  include/linux/bitops.h \
  /home/yanfeng/softwares/l36h/kernel/arch/arm/include/asm/bitops.h \
    $(wildcard include/config/smp.h) \
  include/linux/irqflags.h \
    $(wildcard include/config/trace/irqflags.h) \
    $(wildcard include/config/irqsoff/tracer.h) \
    $(wildcard include/config/preempt/tracer.h) \
    $(wildcard include/config/trace/irqflags/support.h) \
  include/linux/typecheck.h \
  /home/yanfeng/softwares/l36h/kernel/arch/arm/include/asm/irqflags.h \
  /home/yanfeng/softwares/l36h/kernel/arch/arm/include/asm/ptrace.h \
    $(wildcard include/config/cpu/endian/be8.h) \
    $(wildcard include/config/arm/thumb.h) \
  /home/yanfeng/softwares/l36h/kernel/arch/arm/include/asm/hwcap.h \
  include/asm-generic/bitops/non-atomic.h \
  include/asm-generic/bitops/fls64.h \
  include/asm-generic/bitops/sched.h \
  include/asm-generic/bitops/hweight.h \
  include/asm-generic/bitops/arch_hweight.h \
  include/asm-generic/bitops/const_hweight.h \
  include/asm-generic/bitops/lock.h \
  include/asm-generic/bitops/le.h \
  /home/yanfeng/softwares/l36h/kernel/arch/arm/include/asm/byteorder.h \
  include/linux/byteorder/little_endian.h \
  include/linux/swab.h \
  /home/yanfeng/softwares/l36h/kernel/arch/arm/include/asm/swab.h \
  include/linux/byteorder/generic.h \
  include/asm-generic/bitops/ext2-atomic-setbit.h \
  include/linux/log2.h \
    $(wildcard include/config/arch/has/ilog2/u32.h) \
    $(wildcard include/config/arch/has/ilog2/u64.h) \
  include/linux/printk.h \
    $(wildcard include/config/printk.h) \
    $(wildcard include/config/dynamic/debug.h) \
  include/linux/init.h \
    $(wildcard include/config/modules.h) \
    $(wildcard include/config/hotplug.h) \
  include/linux/dynamic_debug.h \
  /home/yanfeng/softwares/l36h/kernel/arch/arm/include/asm/div64.h \
  /home/yanfeng/softwares/l36h/kernel/arch/arm/include/asm/compiler.h \
  /home/yanfeng/softwares/l36h/kernel/arch/arm/include/asm/bug.h \
    $(wildcard include/config/bug.h) \
    $(wildcard include/config/thumb2/kernel.h) \
    $(wildcard include/config/debug/bugverbose.h) \
    $(wildcard include/config/arm/lpae.h) \
  include/asm-generic/bug.h \
    $(wildcard include/config/generic/bug.h) \
    $(wildcard include/config/generic/bug/relative/pointers.h) \
  /home/yanfeng/soulAssist/kmoduleSyscallHijack/src/dbg.h \

/home/yanfeng/soulAssist/kmoduleSyscallHijack/src/dbg.o: $(deps_/home/yanfeng/soulAssist/kmoduleSyscallHijack/src/dbg.o)

$(deps_/home/yanfeng/soulAssist/kmoduleSyscallHijack/src/dbg.o):
