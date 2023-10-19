/* 
 * Copyright 2022, tyyteam(Qingtao Liu, Yang Lei, Yang Chen)
 *
 * Derived from:
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 * Copyright 2015, 2016 Hesham Almatary <heshamelmatary@gmail.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#pragma once

#include "hardware.h"

#ifndef __ASSEMBLER__

#include <stdint.h>
#include <util.h>
#include <arch/types.h>

enum _register {

    ra=1,LR=1,
    tp=2,TP=2,TLS_BASE=2,
    sp=3,SP=3,

    a0=4, capRegister = 4, badgeRegister = 4,
    a1=5, msgInfoRegister=5,
    a2=6,
    a3=7,
    a4=8,
    a5=9,
    a6=10,
#ifdef CONFIG_KERNEL_MCS
    replyRegister = 9,
#endif
    a7=11,

    t0=12,
#ifdef CONFIG_KERNEL_MCS
    nbsendRecvDest = 11,
#endif
    t1=13,
    t2=14,
    t3=15,
    t4=16,
    t5=17,
    t6=18,
    t7=19,
    t8=20,

    r21=21,

    fp=22,
    s0=23,
    s1=24,
    s2=25,
    s3=26,
    s4=27,
    s5=28,
    s6=29,
    s7=30,
    s8=31,

    /* End of GP registers, the following are additional kernel-saved state. */

    csr_era=32,FaultIP=32,
    csr_badvaddr=33,
    csr_prmd=34,
    csr_euen=35,
    csr_ecfg=36,
    csr_badi=37,

    NextIP=38,

    n_contextRegisters = 39
};

typedef uint8_t register_t;

enum messageSizes {
    n_msgRegisters = 4,
    n_frameRegisters = 13,
    n_gpRegisters = 18,
    n_exceptionMessage = 2,
    n_syscallMessage = 10,
#ifdef CONFIG_KERNEL_MCS
    n_timeoutMessage = 31,
#endif
};

extern const register_t msgRegisters[] VISIBLE;
extern const register_t frameRegisters[] VISIBLE;
extern const register_t gpRegisters[] VISIBLE;

#ifdef CONFIG_HAVE_FPU

#define LOONGARCH_NUM_FP_REGS   32

#if defined(CONFIG_Loongarch_EXT_D)
typedef uint64_t fp_reg_t;
#elif defined(CONFIG_Loongarch_EXT_F)
typedef uint32_t fp_reg_t;
#else
#error Unknown LOONGARCH FPU extension
#endif

typedef struct user_fpu_state {
    fp_reg_t regs[LOONGARCH_NUM_FP_REGS];
    uint32_t fcsr;
} user_fpu_state_t;

#endif

struct user_context {
    word_t registers[n_contextRegisters];
#ifdef CONFIG_HAVE_FPU
    user_fpu_state_t fpuState;
#endif
};
typedef struct user_context user_context_t;

static inline void Arch_initContext(user_context_t *context)
{
    /* Enable interrupts */
    context->registers[csr_prmd] = CSR_PRMD_PIE|CSR_PRMD_PPLV3;
    // context->registers[csr_ecfg] = (0U << 16);//set vs=0 and enable timer interrupt before dropping into user mode
    context->registers[csr_ecfg] = (0U << 16)|(1<<11);//set vs=0 and enable timer interrupt before dropping into user mode
    context->registers[csr_euen] = 0x0;
}

static inline word_t CONST sanitiseRegister(register_t reg, word_t v, bool_t archInfo)
{
    return v;
}


#define EXCEPTION_MESSAGE \
 {\
    [seL4_UserException_FaultIP] = FaultIP,\
    [seL4_UserException_SP] = SP,\
 }

#define SYSCALL_MESSAGE \
{\
    [seL4_UnknownSyscall_FaultIP] = FaultIP,\
    [seL4_UnknownSyscall_SP] = SP,\
    [seL4_UnknownSyscall_RA] = LR,\
    [seL4_UnknownSyscall_A0] = a0,\
    [seL4_UnknownSyscall_A1] = a1,\
    [seL4_UnknownSyscall_A2] = a2,\
    [seL4_UnknownSyscall_A3] = a3,\
    [seL4_UnknownSyscall_A4] = a4,\
    [seL4_UnknownSyscall_A5] = a5,\
    [seL4_UnknownSyscall_A6] = a6,\
}

#define TIMEOUT_REPLY_MESSAGE \
{\
    [seL4_TimeoutReply_FaultIP] = FaultIP,\
    [seL4_TimeoutReply_LR] = LR, \
    [seL4_TimeoutReply_SP] = SP, \
    [seL4_TimeoutReply_s0] = s0, \
    [seL4_TimeoutReply_s1] = s1, \
    [seL4_TimeoutReply_s2] = s2, \
    [seL4_TimeoutReply_s3] = s3, \
    [seL4_TimeoutReply_s4] = s4, \
    [seL4_TimeoutReply_s5] = s5, \
    [seL4_TimeoutReply_s6] = s6, \
    [seL4_TimeoutReply_s7] = s7, \
    [seL4_TimeoutReply_s8] = s8, \
    [seL4_TimeoutReply_s9] = s9, \
    [seL4_TimeoutReply_a0] = a0, \
    [seL4_TimeoutReply_a1] = a1, \
    [seL4_TimeoutReply_a2] = a2, \
    [seL4_TimeoutReply_a3] = a3, \
    [seL4_TimeoutReply_a4] = a4, \
    [seL4_TimeoutReply_a5] = a5, \
    [seL4_TimeoutReply_a6] = a6, \
    [seL4_TimeoutReply_a7] = a7, \
    [seL4_TimeoutReply_t0] = t0, \
    [seL4_TimeoutReply_t1] = t1, \
    [seL4_TimeoutReply_t2] = t2, \
    [seL4_TimeoutReply_t3] = t3, \
    [seL4_TimeoutReply_t4] = t4, \
    [seL4_TimeoutReply_t5] = t5, \
    [seL4_TimeoutReply_t6] = t6, \
    [seL4_TimeoutReply_t7] = t7, \
    [seL4_TimeoutReply_t8] = t8, \
    [seL4_TimeoutReply_TP] = TP, \
}

#endif /* __ASSEMBLER__ */

