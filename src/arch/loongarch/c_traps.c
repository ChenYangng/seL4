/*
 * Copyright 2022, tyyteam(Qingtao Liu, Yang Lei, Yang Chen)
 * qtliu@mail.ustc.edu.cn, le24@mail.ustc.edu.cn, chenyangcs@mail.ustc.edu.cn
 *
 * Derived from:
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 * Copyright 2015, 2016 Hesham Almatary <heshamelmatary@gmail.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <api/syscall.h>
#include <arch/fastpath/fastpath.h>
#include <arch/kernel/traps.h>
#include <arch/machine.h>
#include <arch/machine/hardware.h>
#include <config.h>
#include <machine/debug.h>
#include <machine/fpu.h>
#include <model/statedata.h>
#include <util.h>
#include <arch/object/vcpu.h>

#include <benchmark/benchmark_track.h>
#include <benchmark/benchmark_utilisation.h>

word_t flag = 1;

/** DONT_TRANSLATE */
void VISIBLE NORETURN restore_user_context(void) {
  word_t cur_thread_reg =
      (word_t)NODE_STATE(ksCurThread)->tcbArch.tcbContext.registers;
#ifdef CONFIG_LOONGARCH_HYPERVISOR_SUPPORT
  // arch_tcb_t * ta UNUSED = &(NODE_STATE(ksCurThread)->tcbArch);
  word_t cur_vcpu UNUSED = (word_t)NODE_STATE(ksCurThread)->tcbArch.tcbVCPU;
  // printf("cur_vcpu: %p\n", (void *)cur_vcpu);
#endif

  c_exit_hook();
  NODE_UNLOCK_IF_HELD;

#ifdef ENABLE_SMP_SUPPORT
  word_t sp;
  asm volatile("csrrd %0, LOONGARCH_CSR_KS3" : "=r"(sp));
  sp -= sizeof(word_t);
  *((word_t *)sp) = cur_thread_reg;
#endif

#ifdef CONFIG_HAVE_FPU
  lazyFPURestore(NODE_STATE(ksCurThread));
  set_tcb_fs_state(NODE_STATE(ksCurThread), isFpuEnable());
#endif

#ifdef CONFIG_LOONGARCH_HYPERVISOR_SUPPORT
  if (cur_vcpu) {
    // uint32_t idx = 0xa;
    // uint32_t cpucfg10 = 0;
    // asm volatile("cpucfg %0, %1" : "=r"(cpucfg10) : "r"(idx) : "memory");
    // printf("cpucfg10: %x\n", cpucfg10);
    // uint64_t val = 0x0;
    // uint64_t reg = 0x5;
    // asm volatile("parse_r __reg, %[val]	\n"
    //              ".word 0x5 << 24 | %[reg] << 10 | 0 << 5 | __reg	\n"
    //              : [val] "+r"(val)
    //              : [reg] "i"(reg)
    //              : "memory");
    // printf("gestat: 0x%llx\n", val);
    if (flag) {
      // uint64_t val = 0xa8;
      // uint64_t reg = 0x0;
      // asm volatile("parse_r __reg, %[val]	\n"
      //              ".word 0x5 << 24 | %[reg] << 10 | 1 << 5 | __reg	\n"
      //              : [val] "+r"(val)
      //              : [reg] "i"(reg)
      //              : "memory");
      // val = 0x0;
      // reg = 0x5;
      // asm volatile("parse_r __reg, %[val]	\n"
      //              ".word 0x5 << 24 | %[reg] << 10 | 1 << 5 | __reg	\n"
      //              : [val] "+r"(val)
      //              : [reg] "i"(reg)
      //              : "memory");
      word_t val = 0xfe00;
      asm volatile(
        "csrwr %0, 0x52 \n"
        : "+r"(val)
        :
        : "memory"
      );
      ((word_t *)cur_thread_reg)[35] = 0x1; 
      flag = 0;
    }
    switch_to_guest(cur_thread_reg, cur_vcpu);
  }
#endif

  asm volatile(
      "move $t0, %[cur_thread]        \n"
      "ld.d  $ra, $t0, 1*%[REGSIZE]   \n"
      /* skip tp */
      "ld.d  $sp, $t0, 3*%[REGSIZE]   \n"
      "ld.d  $a0, $t0, 4*%[REGSIZE]   \n"
      "ld.d  $a1, $t0, 5*%[REGSIZE]   \n"
      "ld.d  $a2, $t0, 6*%[REGSIZE]   \n"
      "ld.d  $a3, $t0, 7*%[REGSIZE]   \n"
      "ld.d  $a4, $t0, 8*%[REGSIZE]   \n"
      "ld.d  $a5, $t0, 9*%[REGSIZE]   \n"
      "ld.d  $a6, $t0, 10*%[REGSIZE]   \n"
      "ld.d  $a7, $t0, 11*%[REGSIZE]  \n"
      /* skip $r12/$t0 */
      /* no-op store conditional to clear monitor state */
      /* this may succeed in implementations with very large reservations, but
         the saved ra is dead */
      "sc.w  $zero, $t0, 0    \n"
      /* skip $r13/$t1 */
      "ld.d  $t2, $t0, 14*%[REGSIZE]  \n"
      "ld.d  $t3, $t0, 15*%[REGSIZE]  \n"
      "ld.d  $t4, $t0, 16*%[REGSIZE]  \n"
      "ld.d  $t5, $t0, 17*%[REGSIZE]  \n"
      "ld.d  $t6, $t0, 18*%[REGSIZE]  \n"
      "ld.d  $t7, $t0, 19*%[REGSIZE]  \n"
      "ld.d  $t8, $t0, 20*%[REGSIZE]  \n"
      // "ld.d  $r21, $t0, 21*%[REGSIZE] \n"
      "ld.d  $fp, $t0, 22*%[REGSIZE]  \n"
      "ld.d  $s0, $t0, 23*%[REGSIZE]  \n"
      "ld.d  $s1, $t0, 24*%[REGSIZE]  \n"
      "ld.d  $s2, $t0, 25*%[REGSIZE]  \n"
      "ld.d  $s3, $t0, 26*%[REGSIZE]  \n"
      "ld.d  $s4, $t0, 27*%[REGSIZE]  \n"
      "ld.d  $s5, $t0, 28*%[REGSIZE]  \n"
      "ld.d  $s6, $t0, 29*%[REGSIZE]  \n"
      "ld.d  $s7, $t0, 30*%[REGSIZE]  \n"
      "ld.d  $s8, $t0, 31*%[REGSIZE]  \n"

      /* Get next restored tp */
      "ld.d  $t1, $t0, 2*%[REGSIZE]   \n"
      /* get restored tp */
      "add.d $tp, $t1, $r0    \n"

#ifndef ENABLE_SMP_SUPPORT
      /* Write back LOONGARCH_CSR_KS3 with cur_thread_reg to get it back on the
         next trap entry */
      "move $t1, $t0          \n"
      "csrwr $t0, 0x33        \n"
      "move $t0, $t1          \n"
#endif
      // load [36*%[REGSIZE]+$t0] to LOONGARCH_CSR_ERA instead of 31*%[REGSIZE]

      "ld.d  $t1, $t0, 33*%[REGSIZE]  \n" // load LOONGARCH_CSR_BADV
      "csrwr $t1, 0x7  \n"

      "ld.d  $t1, $t0, 34*%[REGSIZE]  \n" // load LOONGARCH_CSR_PRMD
      "csrwr $t1, 0x1  \n"

      "ld.d  $t1, $t0, 35*%[REGSIZE]  \n" // load LOONGARCH_CSR_EUEN
      "csrwr $t1, 0x2  \n"

      "ld.d  $t1, $t0, 36*%[REGSIZE]  \n" // load LOONGARCH_CSR_ECFG
      "csrwr $t1, 0x4  \n"

      "ld.d  $t1, $t0, 38*%[REGSIZE]  \n" // load nextIP to LOONGARCH_CSR_ERA
      "csrwr $t1, 0x6   \n"

      "ld.d  $t1, $t0, 13*%[REGSIZE]  \n"
      "ld.d  $t0, $t0, 12*%[REGSIZE]  \n"

      "ertn"
      : /* no output */
      : [REGSIZE] "i"(sizeof(word_t)), [cur_thread] "r"(cur_thread_reg)
      : "memory");

  UNREACHABLE();
}

void VISIBLE NORETURN c_handle_interrupt(word_t is) {
  // if (is != 0x800) {
  //   printf("receive int, IS = 0x%lx\n", is);
  // }
  NODE_LOCK_IRQ_IF(getActiveIRQ() != INTERRUPT_IPI);

  c_entry_hook();

  handleInterruptEntry();

  restore_user_context();
  UNREACHABLE();
}

void VISIBLE NORETURN c_handle_exception(word_t ecode) {
  NODE_LOCK_SYS;

  c_entry_hook();

  // printf("c_handle_exception, ecode: 0x%lx\n", ecode);
  switch (ecode) {
  case LAAddrError:             // ADEF or ADEM
  case LAAddrAlignFault:        // ALE
  case LABoundCheck:            // BCE
  case LALoadPageInvalid:       // PIL
  case LAStorePageInvalid:      // PIS
  case LAFetchPageInvalid:      // PIF
  case LAPageModException:      // PME
  case LAPageNoReadable:        // PNR
  case LAPageNoExecutable:      // PNX
  case LAPagePrivilegeIllegal:  // PPI
    handleVMFaultEvent(ecode); // LoongArch records the bad vaddr in CSR.BADV
    break;
  default:
#ifdef CONFIG_HAVE_FPU
    if (!isFpuEnable()) {
      /* we assume the illegal instruction is caused by FPU first */
      handleFPUFault();
      setNextPC(NODE_STATE(ksCurThread), getRestartPC(NODE_STATE(ksCurThread)));
      break;
    }
#endif
    handleUserLevelFault(ecode, 0);
    break;
  }

  restore_user_context();
  UNREACHABLE();
}

void VISIBLE NORETURN slowpath(syscall_t syscall) {
  if (unlikely(syscall < SYSCALL_MIN || syscall > SYSCALL_MAX)) {
#ifdef TRACK_KERNEL_ENTRIES
    ksKernelEntry.path = Entry_UnknownSyscall;
#endif /* TRACK_KERNEL_ENTRIES */
    /* Contrary to the name, this handles all non-standard syscalls used in
     * debug builds also.
     */
    handleUnknownSyscall(syscall);
  } else {
#ifdef TRACK_KERNEL_ENTRIES
    ksKernelEntry.is_fastpath = 0;
#endif /* TRACK KERNEL ENTRIES */
    handleSyscall(syscall);
  }

  restore_user_context();
  UNREACHABLE();
}

#ifdef CONFIG_FASTPATH
ALIGN(L1_CACHE_LINE_SIZE)
#ifdef CONFIG_KERNEL_MCS
void VISIBLE c_handle_fastpath_reply_recv(word_t cptr, word_t msgInfo,
                                          word_t reply)
#else
void VISIBLE c_handle_fastpath_reply_recv(word_t cptr, word_t msgInfo)
#endif
{
  NODE_LOCK_SYS;

  c_entry_hook();
#ifdef TRACK_KERNEL_ENTRIES
  benchmark_debug_syscall_start(cptr, msgInfo, SysReplyRecv);
  ksKernelEntry.is_fastpath = 1;
#endif /* DEBUG */
#ifdef CONFIG_KERNEL_MCS
  fastpath_reply_recv(cptr, msgInfo, reply);
#else
  fastpath_reply_recv(cptr, msgInfo);
#endif
  UNREACHABLE();
}

ALIGN(L1_CACHE_LINE_SIZE)
void VISIBLE c_handle_fastpath_call(word_t cptr, word_t msgInfo) {
  NODE_LOCK_SYS;

  c_entry_hook();

#ifdef TRACK_KERNEL_ENTRIES
  benchmark_debug_syscall_start(cptr, msgInfo, SysCall);
  ksKernelEntry.is_fastpath = 1;
#endif /* DEBUG */

  fastpath_call(cptr, msgInfo);

  UNREACHABLE();
}
#endif

void VISIBLE NORETURN c_handle_syscall(word_t cptr, word_t msgInfo,
                                       syscall_t syscall) {
  NODE_LOCK_SYS;

  c_entry_hook();
#ifdef TRACK_KERNEL_ENTRIES
  benchmark_debug_syscall_start(cptr, msgInfo, syscall);
  ksKernelEntry.is_fastpath = 0;
#endif /* DEBUG */
  slowpath(syscall);

  UNREACHABLE();
}

#ifdef CONFIG_LOONGARCH_HYPERVISOR_SUPPORT
VISIBLE NORETURN void c_handle_vcpu_fault(word_t ecode)
{
    NODE_LOCK_SYS;

    c_entry_hook();

    // printf("c_handle_vcpu_fault, ecode: 0x%lx\n", ecode);
#ifdef TRACK_KERNEL_ENTRIES
    ksKernelEntry.path = Entry_VCPUFault;
    ksKernelEntry.word = ecode;
#endif
    handleVCPUFault(ecode);
    restore_user_context();
    UNREACHABLE();
}
#endif /* CONFIG_LOONGARCH_HYPERVISOR_SUPPORT */
