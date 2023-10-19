/*
 * Copyright 2014, General Dynamics C4 Systems
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <config.h>

#ifdef CONFIG_LOONGARCH_HYPERVISOR_SUPPORT

#include <arch/object/vcpu.h>

// BOOT_CODE void vcpu_boot_init(void)
// {
//     loongarch_vcpu_boot_init();
//     gic_vcpu_num_list_regs = VGIC_VTR_NLISTREGS(get_gic_vcpu_ctrl_vtr());
//     if (gic_vcpu_num_list_regs > GIC_VCPU_MAX_NUM_LR) {
//         printf("Warning: VGIC is reporting more list registers than we support. Truncating\n");
//         gic_vcpu_num_list_regs = GIC_VCPU_MAX_NUM_LR;
//     }
//     vcpu_disable(NULL);
//     ARCH_NODE_STATE(armHSCurVCPU) = NULL;
//     ARCH_NODE_STATE(armHSVCPUActive) = false;
//
// }

// static void vcpu_save(vcpu_t *vcpu, bool_t active)
// {
//     // word_t i;
//     // unsigned int lr_num;
//
//     assert(vcpu);
//     dbar();
//     vcpu_save_reg_range(vcpu, )
//     /* If we aren't active then this state already got stored when
//      * we were disabled */
//     // if (active) {
//     //     vcpu_save_reg(vcpu, seL4_VCPUReg_SCTLR);
//     // }
// }

void handleVCPUFault(word_t ecode)
{
    MCS_DO_IF_BUDGET({
        if (loongarch_handleVCPUFault(ecode))
        {
            return;
        }
        current_fault = seL4_Fault_VCPUFault_new(ecode);
        handleFault(NODE_STATE(ksCurThread));
    })
    schedule();
    activateThread();
}

// void vcpu_switch(vcpu_t *new)
// {
//     if (likely(ARCH_NODE_STATE(loongarchHSCurVCPU) != new)) {
//         if (unlikely(new != NULL)) {
//             if (unlikely(ARCH_NODE_STATE(loongarchHSCurVCPU) != NULL)) {
//                 vcpu_save(ARCH_NODE_STATE(loongarchHSCurVCPU), ARCH_NODE_STATE(loongarchHSVCPUActive));
//             }
//             vcpu_restore(new);
//             ARCH_NODE_STATE(loongarchHSCurVCPU) = new;
//             ARCH_NODE_STATE(loongarchHSVCPUActive) = true;
//         } else if (unlikely(ARCH_NODE_STATE(loongarchHSVCPUActive))) {
//             /* leave the current VCPU state loaded, but disable vgic and mmu */
// // #ifdef ARM_HYP_CP14_SAVE_AND_RESTORE_VCPU_THREADS
// //             saveAllBreakpointState(ARCH_NODE_STATE(armHSCurVCPU)->vcpuTCB);
// // #endif
//             vcpu_disable(ARCH_NODE_STATE(loongarchHSCurVCPU));
//             ARCH_NODE_STATE(loongarchHSVCPUActive) = false;
//         }
//     } else if (likely(!ARCH_NODE_STATE(loongarchHSVCPUActive) && new != NULL)) {
//         // isb();
//         vcpu_enable(new);
//         ARCH_NODE_STATE(loongarchHSVCPUActive) = true;
//     }
// }

static word_t readVCPUReg(vcpu_t *vcpu, word_t field)
{
    // if (likely(ARCH_NODE_STATE(armHSCurVCPU) == vcpu)) {
    //     if (vcpu_reg_saved_when_disabled(field) && !ARCH_NODE_STATE(armHSVCPUActive)) {
    //         return vcpu_read_reg(vcpu, field);
    //     } else {
    //         return vcpu_hw_read_reg(field);
    //     }
    // } else {
    //     return vcpu_read_reg(vcpu, field);
    // }
    return vcpu_read_reg(vcpu, field);
}

static void writeVCPUReg(vcpu_t *vcpu, word_t field, word_t value)
{
    // if (likely(ARCH_NODE_STATE(armHSCurVCPU) == vcpu)) {
    //     if (vcpu_reg_saved_when_disabled(field) && !ARCH_NODE_STATE(armHSVCPUActive)) {
    //         vcpu_write_reg(vcpu, field, value);
    //     } else {
    //         vcpu_hw_write_reg(field, value);
    //     }
    // } else {
    //     vcpu_write_reg(vcpu, field, value);
    // }
    vcpu_write_reg(vcpu, field, value);
}

void associateVCPUTCB(vcpu_t *vcpu, tcb_t *tcb)
{
    if (tcb->tcbArch.tcbVCPU) {
        dissociateVCPUTCB(tcb->tcbArch.tcbVCPU, tcb);
    }
    if (vcpu->vcpuTCB) {
        dissociateVCPUTCB(vcpu, vcpu->vcpuTCB);
    }
    tcb->tcbArch.tcbVCPU = vcpu;
    vcpu->vcpuTCB = tcb;

    // if (tcb == NODE_STATE(ksCurThread)) {
    //     vcpu_switch(vcpu);
    // }
}

void dissociateVCPUTCB(vcpu_t *vcpu, tcb_t *tcb)
{
    if (tcb->tcbArch.tcbVCPU != vcpu || vcpu->vcpuTCB != tcb) {
        fail("TCB and VCPU not associated.");
    }
    // if (vcpu == ARCH_NODE_STATE(armHSCurVCPU)) {
    //     vcpu_invalidate_active();
    // }
    tcb->tcbArch.tcbVCPU = NULL;
    vcpu->vcpuTCB = NULL;
// #ifdef ARM_HYP_CP14_SAVE_AND_RESTORE_VCPU_THREADS
//     Arch_debugDissociateVCPUTCB(tcb);
// #endif

    /* sanitize the CPSR as without a VCPU a thread should only be in user mode */
// #ifdef CONFIG_ARCH_AARCH64
//     setRegister(tcb, SPSR_EL1, sanitiseRegister(SPSR_EL1, getRegister(tcb, SPSR_EL1), false));
// #else
//     setRegister(tcb, CPSR, sanitiseRegister(CPSR, getRegister(tcb, CPSR), false));
// #endif
}
exception_t invokeVCPUWriteReg(vcpu_t *vcpu, word_t field, word_t value)
{
    writeVCPUReg(vcpu, field, value);
    return EXCEPTION_NONE;
}

exception_t decodeVCPUWriteReg(cap_t cap, unsigned int length, word_t *buffer)
{
    word_t field;
    word_t value;
    if (length < 2) {
        userError("VCPUWriteReg: Truncated message.");
        current_syscall_error.type = seL4_TruncatedMessage;
        return EXCEPTION_SYSCALL_ERROR;
    }
    field = getSyscallArg(0, buffer);
    value = getSyscallArg(1, buffer);
    if (field >= seL4_VCPUReg_Num) {
        userError("VCPUWriteReg: Invalid field 0x%lx.", (long)field);
        current_syscall_error.type = seL4_InvalidArgument;
        current_syscall_error.invalidArgumentNumber = 1;
        return EXCEPTION_SYSCALL_ERROR;
    }
    setThreadState(NODE_STATE(ksCurThread), ThreadState_Restart);
    return invokeVCPUWriteReg(VCPU_PTR(cap_vcpu_cap_get_capVCPUPtr(cap)), field, value);
}

exception_t invokeVCPUReadReg(vcpu_t *vcpu, word_t field, bool_t call)
{
    tcb_t *thread;
    thread = NODE_STATE(ksCurThread);
    word_t value = readVCPUReg(vcpu, field);
    if (call) {
        word_t *ipcBuffer = lookupIPCBuffer(true, thread);
        setRegister(thread, badgeRegister, 0);
        unsigned int length = setMR(thread, ipcBuffer, 0, value);
        setRegister(thread, msgInfoRegister, wordFromMessageInfo(
                        seL4_MessageInfo_new(0, 0, 0, length)));
    }
    setThreadState(NODE_STATE(ksCurThread), ThreadState_Running);
    return EXCEPTION_NONE;
}

exception_t decodeVCPUReadReg(cap_t cap, unsigned int length, bool_t call, word_t *buffer)
{
    word_t field;
    if (length < 1) {
        userError("VCPUReadReg: Truncated message.");
        current_syscall_error.type = seL4_TruncatedMessage;
        return EXCEPTION_SYSCALL_ERROR;
    }

    field = getSyscallArg(0, buffer);

    if (field >= seL4_VCPUReg_Num) {
        userError("VCPUReadReg: Invalid field 0x%lx.", (long)field);
        current_syscall_error.type = seL4_InvalidArgument;
        current_syscall_error.invalidArgumentNumber = 1;
        return EXCEPTION_SYSCALL_ERROR;
    }

    setThreadState(NODE_STATE(ksCurThread), ThreadState_Restart);
    return invokeVCPUReadReg(VCPU_PTR(cap_vcpu_cap_get_capVCPUPtr(cap)), field, call);
}


exception_t decodeVCPUSetTCB(cap_t cap)
{
    cap_t tcbCap;
    if (current_extra_caps.excaprefs[0] == NULL) {
        userError("VCPU SetTCB: Truncated message.");
        current_syscall_error.type = seL4_TruncatedMessage;
        return EXCEPTION_SYSCALL_ERROR;
    }
    tcbCap  = current_extra_caps.excaprefs[0]->cap;

    if (cap_get_capType(tcbCap) != cap_thread_cap) {
        userError("TCB cap is not a TCB cap.");
        current_syscall_error.type = seL4_IllegalOperation;
        return EXCEPTION_SYSCALL_ERROR;
    }

    setThreadState(NODE_STATE(ksCurThread), ThreadState_Restart);
    return invokeVCPUSetTCB(VCPU_PTR(cap_vcpu_cap_get_capVCPUPtr(cap)), TCB_PTR(cap_thread_cap_get_capTCBPtr(tcbCap)));
}

exception_t invokeVCPUSetTCB(vcpu_t *vcpu, tcb_t *tcb)
{
    associateVCPUTCB(vcpu, tcb);

    return EXCEPTION_NONE;
}

exception_t decodeLOONGARCHVCPUInvocation(
    word_t label,
    unsigned int length,
    cptr_t cptr,
    cte_t *slot,
    cap_t cap,
    bool_t call,
    word_t *buffer
)
{
    switch (label) {
    case LOONGARCHVCPUSetTCB:
        return decodeVCPUSetTCB(cap);
    case LOONGARCHVCPUReadReg:
        return decodeVCPUReadReg(cap, length, call, buffer);
    case LOONGARCHVCPUWriteReg:
        return decodeVCPUWriteReg(cap, length, buffer);
    // case LOONGARCHVCPUInjectIRQ:
    //     return decodeVCPUInjectIRQ(cap, length, buffer);
    // case LOONGARCHVCPUAckVPPI:
    //     return decodeVCPUAckVPPI(cap, length, buffer);
    default:
        userError("VCPU: Illegal operation.");
        current_syscall_error.type = seL4_IllegalOperation;
        return EXCEPTION_SYSCALL_ERROR;
    }
}

#endif
