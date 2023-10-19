/*
 * Copyright 2023, Chen Yangng
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#pragma once

#include <config.h>

#ifdef CONFIG_LOONGARCH_HYPERVISOR_SUPPORT

#include <api/failures.h>
#include <linker.h>
#include <object/structures.h>
#include <machine/registerset.h>
#include <arch/machine.h>

extern void switch_to_guest(word_t cur_thread_reg, word_t cur_vcpu);

typedef struct loongarch_csrs {
   word_t csrs[0x800]; 
} loongarch_csrs_t;

struct vcpu
{
    word_t regs[seL4_VCPUReg_Num];
    /* TCB associated with this VCPU. */
    struct tcb *vcpuTCB;
    // loongarch_csrs_t *csr;
};
typedef struct vcpu vcpu_t;

enum vcpu_fault_type {
    LAGuestSensitivePrivilegeResource = 22,    //GSPR
    LAHypCall  = 23     //HVC     
};
typedef word_t vcpu_fault_type_t;

exception_t decodeVCPUWriteReg(cap_t cap, unsigned int length, word_t *buffer);
exception_t decodeVCPUReadReg(cap_t cap, unsigned int length, bool_t call, word_t *buffer);
exception_t decodeVCPUSetTCB(cap_t cap);
exception_t invokeVCPUWriteReg(vcpu_t *vcpu, word_t field, word_t value);
exception_t invokeVCPUReadReg(vcpu_t *vcpu, word_t field, bool_t call);
exception_t invokeVCPUSetTCB(vcpu_t *vcpu, tcb_t *tcb);
void associateVCPUTCB(vcpu_t *vcpu, tcb_t *tcb);
void dissociateVCPUTCB(vcpu_t *vcpu, tcb_t *tcb);
exception_t decodeLOONGARCHVCPUInvocation(
    word_t label,
    unsigned int length,
    cptr_t cptr,
    cte_t *slot,
    cap_t cap,
    bool_t call,
    word_t *buffer
);

static inline word_t vcpu_read_reg(vcpu_t *vcpu, word_t reg)
{
    if (reg >= seL4_VCPUReg_Num || vcpu == NULL) {
        fail("LOONGARCH/HYP: Invalid register index or NULL VCPU");
        return 0;
    }
    return vcpu->regs[reg];
}

static inline void vcpu_write_reg(vcpu_t *vcpu, word_t reg, word_t value)
{
    if (reg >= seL4_VCPUReg_Num || vcpu == NULL) {
        fail("LOONGARCH/HYP: Invalid register index or NULL VCPU");
        return;
    }
    vcpu->regs[reg] = value;
}

void handleVCPUFault(word_t ecode);

static inline void loongarch_init_gtlb(void)
{
    printf("loongarch init gtlb\n"); 
}

static inline void loongarch_vcpu_boot_init(void)
{
    loongarch_init_gtlb();
}

// static inline word_t emu_csr_read(tcb_t *tcb, uint32_t rd, uint32_t csrid)
// {
//     loongarch_csrs_t *csr = tcb->tcbArch.tcbVCPU.csr; 
//
//     word_t csr_val = csr->csrs[csrid];
//     setRegister(tcb, rd, csr_val);
//
//     return csr_val;
// }
//
// static inline void emu_csr_write(tcb_t *tcb, uint32_t rd, uint32_t csrid)
// {
//     loongarch_csrs_t *csr = tcb->tcbArch.tcbVCPU.csr; 
//
//     word_t csr_val = csr->csrs[csrid];
//     csr->csrs[csrid] = getRegister(tcb, rd);
//     setRegister(tcb, rd, csr_val);
// }
//
// static inline void emu_csr_xchg(tcb_t *tcb, uint32_t rd, uint32_t rj, uint32_t csrid)
// {
//     loongarch_csrs_t *csr = tcb->tcbArch.tcbVCPU.csr; 
//
//     word_t csr_mask = getRegister(tcb, rj);
//     word_t csr_val = csr->csrs[csrid];
//     csr->csrs[csrid] = getRegister(tcb, rd) & csr_mask;
//     setRegister(tcb, rd, csr_val);
// }

static inline void handle_gspr_csr(uint32_t badi, tcb_t *tcb)
{
    // uint32_t rd, rj, csrid;
    // word_t csr_mask;
    // word_t val = 0;
    //
    // rd = badi & 0x1f;
    // rj = (badi >> 5) & 0x1f;
    // csrid = (badi >> 10) & 0x3fff;
    //
    // if (rj == 0) {
    //     /* process csrrd */
    //     val = emu_csr_read(tcb, rd, csrid);
    //     setRegister(tcb, rd, val);
    // } else if (rj == 1) {
    //     /* process csrwr */
    //     val = getRegister(tcb, rd);
    //     emu_csr_write(tcb, rd, csrid);
    // } else {
    //     /* process csrxchg */
    //     val = getRegister(tcb, rd);
    //     csr_mask = getRegister(tcb, rj);
    //     emu_csr_xchg(tcb, rd, rj, csrid);
    // }
    printf("!!!HANDLE_GSPR_CSR!!!\n");
}

static inline void handle_gspr_cacop(uint32_t badi, tcb_t *tcb)
{
 //    uint32_t cache, code, op, rj, offset;
 //    word_t va;
	//
 //    rj = (badi >> 5) & 0x1f;
 //    code = badi & 0x1f;
 //    offset = (badi >> 10) & 0xfff;
 //    cache = code & 0x7;
 //    op = (code >> 3) 0x3;
	//
 //    va = getRegister(tcb, rj) + offset;
	//
 //    printf("GUEST CACOP (cache: %lu, op: %lu, base[%lu]: %lu, offset: %lu, va: %lu)\n", cache, op, rj, getRegister(tcb, rj), offset, va);
	//
 //    /* Secondary or tirtiary cache ops ignored */
 //    if (cache != 0x0 && cache != 0x1) {
 //        return;
 //    }
	//
 //    switch (code) {
	// case Index_Invalidate_I:
	// 	flush_icache_line_indexed(va);
	// 	return EMULATE_DONE;
	// case Index_Writeback_Inv_D:
	// 	flush_dcache_line_indexed(va);
	// 	return EMULATE_DONE;
	// case Hit_Invalidate_I:
	// case Hit_Invalidate_D:
	// 	break;
	// default:
	// 	break;
 //    }

    // printf("GUEST CACOP DONE\n");
    printf("!!!HANDLE_GSPR_CACOP!!!\n");
}

static inline uint32_t handle_gspr_iocsr(uint32_t badi, tcb_t *tcb)
{
    printf("handle gspr iocsr\n");
    uint32_t error = 0;

    uint32_t rd, rj, opcode;
    uint32_t iocsr_num;

    rd = badi & 0x1f;
    rj = (badi >> 5) & 0x1f;
    opcode = badi >> 10;
    iocsr_num = getRegister(tcb, rj);
    printf("rd:%u, rj:%u \n", rd, rj);


    /* Process IOCSR ops */
    switch (opcode) {
        case 0x19200: /* iocsrrdb_op */
            setRegister(tcb, rd, iocsr_readb(rj));
            break;
        case 0x19201: /* iocsrrdh_op */
            setRegister(tcb, rd, iocsr_readh(rj));
            break;
        case 0x19202: /* iocsrrdw_op */
            setRegister(tcb, rd, iocsr_readw(rj));
            break;
        case 0x19203: /* iocsrrdd_op */
            setRegister(tcb, rd, iocsr_readd(rj));
            break;
        case 0x19204: /* iocsrwrb_op */
            iocsr_writeb(getRegister(tcb, rd), iocsr_num);
            break;
        case 0x19205: /* iocsrwrh_op */
            iocsr_writeh(getRegister(tcb, rd), iocsr_num);
            break;
        case 0x19206: /* iocsrwrw_op */
            printf("iocsr writew\n");
            iocsr_writew(getRegister(tcb, rd), iocsr_num);
            break;
        case 0x19207: /* iocsrwrd_op */
            iocsr_writed(getRegister(tcb, rd), iocsr_num);
            break;
        default:
            break;
    }

    return error;
}

static inline void loongarch_emul_idle(tcb_t *tcb)
{
    printf("!!!IDLE!!!\n");
    // suspend(tcb);
}

static inline void handle_gspr(tcb_t *tcb)
{
    printf("handle gspr\n");
    uint32_t res = 0;

    uint32_t rd, rj;
    uint32_t badi = getRegister(tcb, csr_badi);
    uint32_t cpucfg_no;

    switch ((badi >> 24) & 0xff) {
    case 0x0:
        /* cpucfg */
        if ((badi >> 10) == 0x1b) {
            rd = badi & 0x1f;
            rj = (badi >> 5) & 0x1f;
            cpucfg_no = getRegister(tcb, rj);
            setRegister(tcb, rd, read_cpucfg(cpucfg_no));
            /* Ignore VZ for guest */
			if (cpucfg_no == 2) {
                setRegister(tcb, rd, (getRegister(tcb, rd) & ~LOONGSON_CFG2_LVZP));
            } else if (cpucfg_no == 6) {
                setRegister(tcb, rd, (getRegister(tcb, rd) & ~LOONGSON_CFG6_PMP));
            }
        } else {
            res = 1;
        }
        break;
    case 0x4:
        /* csr */
        handle_gspr_csr(badi, tcb);
        break;
    case 0x6:
        /* cacop, iocsr, idle */
        switch ((badi >> 22) & 0x3ff) {
        case 0x18:
            /* cacop */
            handle_gspr_cacop(badi, tcb);
            break;
        case 0x19:
            /* iocsr, idle */
            switch ((badi >> 15) & 0x1ffff) {
            case 0xc90:
                /* iocsr */
                handle_gspr_iocsr(badi, tcb);
                printf("handle gspr iocsr done!\n");
                break;
            case 0xc91:
                /* idle */
                loongarch_emul_idle(tcb);
            default:
                res = 1;
                break;
            }
        
        default:
            res = 1;
            break;
        }
        break;
    default:
        res = 1;
        break;
    }

    if (unlikely(res)) {
        /* TODO: rollback guest pc */
    }

}

static inline bool_t loongarch_handleVCPUFault(word_t ecode)
{
    printf("handleVCPUFault\n");
    switch (ecode) {
    case LAGuestSensitivePrivilegeResource:
        handle_gspr(NODE_STATE(ksCurThread));
        printf("handle gspr done!\n");
        /* code */
        break;
    case LAHypCall:
        /* TODO */
        break;
    default:
        return false;
    }

    return true;
}

#endif
