/*
 * Copyright 2022, tyyteam(Qingtao Liu, Yang Lei, Yang Chen)
 * qtliu@mail.ustc.edu.cn, le24@mail.ustc.edu.cn, chenyangcs@mail.ustc.edu.cn
 * 
 * Derived from:
 * Copyright (C) 2020-2021 Loongson Technology Corporation Limited
 *
 * SPDX-License-Identifier: GPL-2.0
 */

 #include <arch/machine.h>
 #include <arch/machine/hardware.h>
 #include <arch/asm/regdef.h>
 #include <arch/asm/stackframe.h> 
 #include <hardware.h>


 .section .text
 .global handle_tlb_load
 .global handle_tlb_store

handle_tlb_load:
	csrwr	t0, LOONGARCH_CSR_KS0
	csrwr	t1, LOONGARCH_CSR_KS1
	csrwr	t2, LOONGARCH_CSR_KS2
	csrwr	ra, LOONGARCH_CSR_KS3

	/*
	 * The vmalloc handling is not in the hotpath.
	 */
	 /* paddr to pptr */
	csrrd	t0, LOONGARCH_CSR_BADV
	li.d  t2, PPTR_BASE_OFFSET
	csrrd	t1, LOONGARCH_CSR_PGDL
	add.d t1, t1, t2
	# bltz	t0, vmalloc_load

vmalloc_done_load:

	/* get pgd offset in bytes */
	bstrpick.d	ra, t0, PTRS_PER_PD_BITS + LOONGARCH_L1PGSHIFT - 1, LOONGARCH_L1PGSHIFT
	alsl.d		t1, ra, t1, 3
#if CONFIG_PT_LEVELS > 3
	# ld.d	t1, t1, 0
	# bstrpick.d	ra, t0, PTRS_PER_PD_BITS + LOONGARCH_L2PGSHIFT - 1, LOONGARCH_L2PGSHIFT
	# alsl.d		t1, ra, t1, 3
#endif
#if CONFIG_PT_LEVELS > 2 
	ld.d	t1, t1, 0
	beqz	t1, nopage_tlb_load
	bstrpick.d	ra, t0, PTRS_PER_PD_BITS + LOONGARCH_L2PGSHIFT - 1, LOONGARCH_L2PGSHIFT
	alsl.d		t1, ra, t1, 3
	/* paddr to pptr */
	add.d t1, t1, t2
#endif
	ld.d	ra, t1, 0
	beqz 	ra, nopage_tlb_load

	/*
	 * For huge tlb entries, pmde doesn't contain an address but
	 * instead contains the tlb pte. Check the PAGE_HUGE bit and
	 * see if we need to jump to huge tlb processing.
	 */
	rotri.d	ra, ra, _PAGE_HUGE_SHIFT + 1
	blt	ra, zero, tlb_huge_update_load

	rotri.d	ra, ra, 64 - (_PAGE_HUGE_SHIFT + 1)
	bstrpick.d	t0, t0, PTRS_PER_PTE_BITS + LOONGARCH_L3PGSHIFT - 1, LOONGARCH_L3PGSHIFT
	alsl.d	t1, t0, ra, _PTE_T_LOG2
	/* paddr to pptr */
	add.d 	t1, t1, t2

#ifdef ENABLE_SMP_SUPPORT
smp_pgtable_change_load:
	# ll.d	t0, t1, 0
#else
	ld.d	t0, t1, 0
#endif
	andi	ra, t0, _PAGE_PRESENT
	beqz	ra, nopage_tlb_load

	ori	t0, t0, _PAGE_VALID
#ifdef ENABLE_SMP_SUPPORT
	# sc.d	t0, t1, 0
	# beqz	t0, smp_pgtable_change_load
#else
	st.d	t0, t1, 0
#endif
	tlbsrch
	bstrins.d	t1, zero, 3, 3
	ld.d	t0, t1, 0
	ld.d	t1, t1, 8
	csrwr	t0, LOONGARCH_CSR_TLBELO0
	csrwr	t1, LOONGARCH_CSR_TLBELO1
	tlbwr
leave_load:
	csrrd	t0, LOONGARCH_CSR_KS0
	csrrd	t1, LOONGARCH_CSR_KS1
	csrrd	t2, LOONGARCH_CSR_KS2
	csrrd	ra, LOONGARCH_CSR_KS3
	move	a0, zero
	jirl	zero, ra, 0
	# ertn
#ifdef CONFIG_64BIT
vmalloc_load:
	# la.abs	t1, swapper_pg_dir
	# b	vmalloc_done_load
#endif

	/*
	 * This is the entry point when build_tlbchange_handler_head
	 * spots a huge page.
	 */
tlb_huge_update_load:
#ifdef ENABLE_SMP_SUPPORT
	ll.d	ra, t1, 0
#endif
	andi	t0, ra, _PAGE_PRESENT
	beqz	t0, nopage_tlb_load

#ifdef ENABLE_SMP_SUPPORT
	ori	t0, ra, _PAGE_VALID
	sc.d	t0, t1, 0
	beqz	t0, tlb_huge_update_load
	ori	t0, ra, _PAGE_VALID
#else
	rotri.d	ra, ra, 64 - (_PAGE_HUGE_SHIFT + 1)
	ori	t0, ra, _PAGE_VALID
	st.d	t0, t1, 0
#endif
	tlbsrch
	/* The type conversion is to avoid uasm warning */
	addu16i.d	t1, zero, -(CSR_TLBIDX_EHINV >> 16)
	addi.d		ra, t1, 0
	csrxchg		ra, t1, LOONGARCH_CSR_TLBIDX
	tlbwr

	csrxchg		zero, t1, LOONGARCH_CSR_TLBIDX

	/*
	 * A huge PTE describes an area the size of the
	 * configured huge page size. This is twice the
	 * of the large TLB entry size we intend to use.
	 * A TLB entry half the size of the configured
	 * huge page size is configured into entrylo0
	 * and entrylo1 to cover the contiguous huge PTE
	 * address space.
	 */
	/* Huge page: Move Global bit */
	xori	t0, t0, _PAGE_HUGE
	lu12i.w	t1, _PAGE_HGLOBAL >> 12
	and	t1, t0, t1
	srli.d	t1, t1, (_PAGE_HGLOBAL_SHIFT - _PAGE_GLOBAL_SHIFT)
	or	t0, t0, t1

	move	ra, t0
	csrwr	ra, LOONGARCH_CSR_TLBELO0

	/* convert to entrylo1 */
	addi.d	t1, zero, 1
	slli.d	t1, t1, (_PAGE_HUGE_SHIFT	 - 1)
	add.d	t0, t0, t1
	csrwr	t0, LOONGARCH_CSR_TLBELO1

	/* Set huge page tlb entry size */
	addu16i.d	t0, zero, (CSR_TLBIDX_PS >> 16)
	addu16i.d	t1, zero, (PS_HUGE_SIZE << (CSR_TLBIDX_PS_SHIFT - 16))
	csrxchg		t1, t0, LOONGARCH_CSR_TLBIDX

	tlbfill

	addu16i.d	t0, zero, (CSR_TLBIDX_PS >> 16)
	addu16i.d	t1, zero, (PS_DEFAULT_SIZE << (CSR_TLBIDX_PS_SHIFT - 16))
	csrxchg		t1, t0, LOONGARCH_CSR_TLBIDX
	csrrd	t0, LOONGARCH_CSR_KS0
	csrrd	t1, LOONGARCH_CSR_KS1
	csrrd	t2, LOONGARCH_CSR_KS2
	csrrd	ra, LOONGARCH_CSR_KS3
	ertn

nopage_tlb_load:
	# dbar	0
	# csrrd	ra, LOONGARCH_CSR_KS2
	# la.abs	t0, tlb_do_page_fault_0
	# jirl	zero, t0, 0
	csrrd	t0, LOONGARCH_CSR_KS0
	csrrd	t1, LOONGARCH_CSR_KS1
	csrrd	t2, LOONGARCH_CSR_KS2
	csrrd	ra, LOONGARCH_CSR_KS3
	addi.d	a0, zero, 1
	jirl	zero, ra, 0


handle_tlb_store:
	csrwr	t0, EXCEPTION_KS0
	csrwr	t1, EXCEPTION_KS1
	csrwr	ra, EXCEPTION_KS2

	/*
	 * The vmalloc handling is not in the hotpath.
	 */
	 /* paddr to pptr */
	li.d  	t0, PPTR_BASE_OFFSET
	csrrd	t1, LOONGARCH_CSR_PGDL
	add.d 	t1, t1, t0
	csrrd	t0, LOONGARCH_CSR_BADV
	# blt	t0, zero, vmalloc_store


vmalloc_done_store:
	/* Get PGD offset in bytes */
	srli.d	t0, t0, LOONGARCH_L1PGSHIFT
	andi	t0, t0, (PTRS_PER_PD - 1)
	slli.d	t0, t0, 3
	add.d	t1, t1, t0

#if CONFIG_PT_LEVELS > 3
	# csrrd	t0, LOONGARCH_CSR_BADV
	# ld.d t1, t1, 0
	# srli.d	t0, t0, PUD_SHIFT
	# andi	t0, t0, (PTRS_PER_PUD - 1)
	# slli.d	t0, t0, 3
	# add.d	t1, t1, t0
#endif
#if CONFIG_PT_LEVELS > 2
	csrrd	t0, LOONGARCH_CSR_BADV
	ld.d	t1, t1, 0
	beqz		t1, nopage_tlb_store
	srli.d	t0, t0, LOONGARCH_L2PGSHIFT
	andi	t0, t0, (PTRS_PER_PD - 1)
	slli.d	t0, t0, 3
	add.d	t1, t1, t0
	/* paddr to pptr */
	li.d  	t0, PPTR_BASE_OFFSET
	add.d 	t1, t1, t0
#endif
	ld.d	ra, t1, 0
	beqz	ra, nopage_tlb_store

	/*
	 * For huge tlb entries, pmde doesn't contain an address but
	 * instead contains the tlb pte. Check the PAGE_HUGE bit and
	 * see if we need to jump to huge tlb processing.
	 */
	andi	t0, ra, _PAGE_HUGE
	bne	t0, zero, tlb_huge_update_store

	csrrd	t0, LOONGARCH_CSR_BADV
	srli.d	t0, t0, LOONGARCH_L3PGSHIFT
	andi	t0, t0, (PTRS_PER_PD - 1)
	slli.d	t0, t0, 3
	add.d	t1, ra, t0
	/* paddr to pptr */
	li.d  	t0, PPTR_BASE_OFFSET
	add.d 	t1, t1, t0

#ifdef ENABLE_SMP_SUPPORT
smp_pgtable_change_store:
#endif
#ifdef ENABLE_SMP_SUPPORT
	ll.d	t0, t1, 0
#else
	ld.d	t0, t1, 0
#endif
	beqz	t0, nopage_tlb_store
	
	tlbsrch

	srli.d	ra, t0, _PAGE_PRESENT_SHIFT
	andi	ra, ra, ((_PAGE_PRESENT | _PAGE_WRITE) >> _PAGE_PRESENT_SHIFT)
	xori	ra, ra, ((_PAGE_PRESENT | _PAGE_WRITE) >> _PAGE_PRESENT_SHIFT)
	bnez	ra, nopage_tlb_store

	ori	t0, t0, (_PAGE_VALID | _PAGE_DIRTY | _PAGE_MODIFIED)
#ifdef ENABLE_SMP_SUPPORT
	sc.d	t0, t1, 0
	beq	t0, zero, smp_pgtable_change_store
#else
	st.d	t0, t1, 0
#endif

	ori		t1, t1, 8
	xori	t1, t1, 8
	ld.d	t0, t1, 0
	ld.d	t1, t1, 8
	csrwr	t0, LOONGARCH_CSR_TLBELO0
	csrwr	t1, LOONGARCH_CSR_TLBELO1
	tlbwr
leave_store:
	csrrd	t0, EXCEPTION_KS0
	csrrd	t1, EXCEPTION_KS1
	csrrd	ra, EXCEPTION_KS2
	move	a0, zero
	jirl	zero, ra, 0
	# ertn
#ifdef CONFIG_64BIT
vmalloc_store:
	# la.abs	t1, swapper_pg_dir
	# b	vmalloc_done_store
#endif

	/*
	 * This is the entry point when build_tlbchange_handler_head
	 * spots a huge page.
	 */
tlb_huge_update_store:
	/* paddr to pptr */
	li.d  	t0, PPTR_BASE_OFFSET
	add.d 	t1, t1, t0
#ifdef ENABLE_SMP_SUPPORT
	ll.d	t0, t1, 0
#else
	ld.d	t0, t1, 0
#endif
	srli.d	ra, t0, _PAGE_PRESENT_SHIFT
	andi	ra, ra, ((_PAGE_PRESENT | _PAGE_WRITE) >> _PAGE_PRESENT_SHIFT)
	xori	ra, ra, ((_PAGE_PRESENT | _PAGE_WRITE) >> _PAGE_PRESENT_SHIFT)
	bnez	ra, nopage_tlb_store

	tlbsrch
	ori	t0, t0, (_PAGE_VALID | _PAGE_DIRTY | _PAGE_MODIFIED)

#ifdef ENABLE_SMP_SUPPORT
	sc.d	t0, t1, 0
	beq	t0, zero, tlb_huge_update_store
	ld.d	t0, t1, 0
#else
	st.d	t0, t1, 0
#endif
	addu16i.d	t1, zero, -(CSR_TLBIDX_EHINV >> 16)
	addi.d	ra, t1, 0
	csrxchg	ra, t1, LOONGARCH_CSR_TLBIDX
	tlbwr

	csrxchg	zero, t1, LOONGARCH_CSR_TLBIDX
	/*
	 * A huge PTE describes an area the size of the
	 * configured huge page size. This is twice the
	 * of the large TLB entry size we intend to use.
	 * A TLB entry half the size of the configured
	 * huge page size is configured into entrylo0
	 * and entrylo1 to cover the contiguous huge PTE
	 * address space.
	 */
	/* Huge page: Move Global bit */
	xori	t0, t0, _PAGE_HUGE
	lu12i.w	t1, _PAGE_HGLOBAL >> 12
	and	t1, t0, t1
	srli.d	t1, t1, (_PAGE_HGLOBAL_SHIFT - _PAGE_GLOBAL_SHIFT)
	or	t0, t0, t1

	addi.d	ra, t0, 0
	csrwr	t0, LOONGARCH_CSR_TLBELO0
	addi.d	t0, ra, 0

	/* Convert to entrylo1 */
	addi.d	t1, zero, 1
	slli.d	t1, t1, (LOONGARCH_L2PGSHIFT - 1)
	add.d	t0, t0, t1
	csrwr	t0, LOONGARCH_CSR_TLBELO1

	/* Set huge page tlb entry size */
	addu16i.d	t0, zero, (PS_MASK >> 16)
	addu16i.d	t1, zero, (PS_HUGE_SIZE << (PS_SHIFT - 16))
	csrxchg		t1, t0, LOONGARCH_CSR_TLBIDX

	tlbfill

	/* Reset default page size */
	addu16i.d	t0, zero, (PS_MASK >> 16)
	addu16i.d	t1, zero, (PS_DEFAULT_SIZE << (PS_SHIFT - 16))
	csrxchg		t1, t0, LOONGARCH_CSR_TLBIDX

nopage_tlb_store:
	# dbar	0
	# csrrd	ra, EXCEPTION_KS2
	# # la.abs	t0, tlb_do_page_fault_1
	# jirl	zero, t0, 0

	csrrd	t0, EXCEPTION_KS0
	csrrd	t1, EXCEPTION_KS1
	csrrd	ra, EXCEPTION_KS2
	addi.d	a0, zero, 1
	jirl	zero, ra, 0
