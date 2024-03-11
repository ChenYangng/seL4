/*
 * Copyright 2022, Chen Yangng
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

; #ifdef CONFIG_LOONGARCH_HYPERVISOR_SUPPORT

#include <config.h>
#include <machine/assembler.h>
#include <arch/asm/regdef.h>
#include <arch/machine.h>

#define REGBYTES (CONFIG_WORD_SIZE / 8)

.global guest_trap_entry
.p2align    12
guest_trap_entry:
    csrwr   t0, LOONGARCH_CSR_KS3

BEGIN_FUNC(handle_vm_exit)

    /* TODO: FPU */

    /* TODO: LSX*/

    /* Disable PVM bit for keeping from into guest */
    ori t0, zero, CSR_GSTAT_PVM
	csrxchg zero, t0, LOONGARCH_CSR_GSTAT

    /* Clear GTLBC.TGID field ？*/
	csrrd	t0, LOONGARCH_CSR_GTLBC
	bstrins.w	t0, zero, CSR_GTLBC_RID_SHIFT + CSR_GTLBC_RID_WIDTH - 1, CSR_GTLBC_RID_SHIFT
	csrwr	t0, LOONGARCH_CSR_GTLBC

    /* Enable Address Map mode ？*/

END_FUNC(handle_vm_exit)


; BEGIN_FUNC(switch_to_guest)
.global switch_to_guest
switch_to_guest:
    /* save host ? */

    /* set host excfg.VS=0, all exceptions share one exception entry */

    /* Load up the new EBASE and refill EBASE ？*/

    /* Set Guest EPC */
    # ld.d    t0, a0, 36 * REGBYTES
    # csrwr   t0, LOONGARCH_CSR_ERA

    /* Save host PGDL ? */

    /* Switch to kvm ？ */

    /* Load guest PGDL */
    # ld.d    t0, a1, 1 * REGBYTES
    # csrwr   t0, LOONGARCH_CSR_PGDL

    /* set GID */
    ld.d    t0, a1, 0 * REGBYTES
    csrrd	t1, LOONGARCH_CSR_GSTAT
    bstrins.w  t1, t0, (CSR_GSTAT_GID_SHIFT + CSR_GSTAT_GID_WIDTH - 1), CSR_GSTAT_GID_SHIFT
    csrwr   t1, LOONGARCH_CSR_GSTAT 
    
    /* Mix GID and RID */
    csrrd   t1, LOONGARCH_CSR_GTLBC
    bstrins.w  t1, t0, (CSR_GTLBC_RID_SHIFT + CSR_GTLBC_RID_WIDTH - 1), CSR_GTLBC_RID_SHIFT
    csrwr   t1, LOONGARCH_CSR_GTLBC

    /*
	 * Switch to guest:
	 *  GSTAT.PGM = 1, ERRCTL.ISERR = 0, TLBRPRMD.ISTLBR = 0
	 *  eret
	 */
    /* Prepare enable Intr before enter guest */
	# ori t0, zero, CSR_PRMD_PIE
	# csrxchg	t0, t0, LOONGARCH_CSR_PRMD

	/* Set PVM bit to setup eret to VZ guest context */
	ori t0, zero, CSR_GSTAT_PVM
	csrxchg t0, t0, LOONGARCH_CSR_GSTAT

	/* Load Guest gprs */

	/* Load KVM_ARCH register ？*/

	/* passthrough 8 hardware interrupts to guest */
    # li.w    t0, CSR_GINTC_HC
    # li.w    t0, CSR_GINTC_VIP
    # li.w    t0, CSR_GINTC_PIP
    # li.w    t0, 0xfe00
    # li.w    t0, 0x0
    # csrwr   t0, LOONGARCH_CSR_GINTC

    invtlb  0x12, $r0, $r0
    jirl    zero, ra, 0    

; END_FUNC(switch_to_guest)

; #endif
