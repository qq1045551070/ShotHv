#pragma once

#define USE_HV_EPT

#define CallExitVt			0
#define CallHookPage		1
#define CallUnHookPage		2

#define CupidHvCheck		'TXSB'

#if DBG
#define DBG_PRINT(format, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "CPU:[%d] -- " format, KeGetCurrentProcessorNumber(), __VA_ARGS__)
#else
#define DBG_PRINT(...)
#endif

#define MAX_HVCONTEXT_NUMBER 128

#define MAX_EPTHOOK_NUMBER 30

#define PFN(addr)                   (ULONG64)((addr) >> PAGE_SHIFT)

#define ROUNDUP(x,align) ((x + align - 1) & ~(align - 1))
#define SELECTOR_TABLE_INDEX    0x04
#define LODWORD(qword) (((ULONGLONG)(qword)) & 0xFFFFFFFF)
#define HIDWORD(qword) ((((ULONGLONG)(qword)) >> 32) & 0xFFFFFFFF)

#define PML4E_ENTRY_COUNT 512
#define PDPTE_ENTRY_COUNT 512
#define PDE_ENTRY_COUNT   512
#define PTE_ENTRY_COUNT   512
#define _1GB              (1 * 1024 * 1024 * 1024)
#define _2MB              (2 * 1024 * 1024)
#define _4KB              (1024)

/*
	hi:low ×éºÏ³É QWORD
*/
#ifndef MAKEQWORD
#define MAKEQWORD(low, hi) ((((ULONGLONG)low) & 0xFFFFFFFF) | ((((ULONGLONG)hi) & 0xFFFFFFFF) << 32))
#endif

#define PAGE_FAULT_ERROR_READ  0
#define PAGE_FAULT_ERROR_WRITE 1

/**
 * @brief Intel CPU features in CR4
 *
 */
#define X86_CR4_VME        0x0001 /* enable vm86 extensions */
#define X86_CR4_PVI        0x0002 /* virtual interrupts flag enable */
#define X86_CR4_TSD        0x0004 /* disable time stamp at ipl 3 */
#define X86_CR4_DE         0x0008 /* enable debugging extensions */
#define X86_CR4_PSE        0x0010 /* enable page size extensions */
#define X86_CR4_PAE        0x0020 /* enable physical address extensions */
#define X86_CR4_MCE        0x0040 /* Machine check enable */
#define X86_CR4_PGE        0x0080 /* enable global pages */
#define X86_CR4_PCE        0x0100 /* enable performance counters at ipl 3 */
#define X86_CR4_OSFXSR     0x0200 /* enable fast FPU save and restore */
#define X86_CR4_OSXMMEXCPT 0x0400 /* enable unmasked SSE exceptions */
#define X86_CR4_VMXE       0x2000 /* enable VMX */

 /* MSRs */
#define CPU_BASED_VIRTUAL_INTR_PENDING          0x00000004
#define CPU_BASED_USE_TSC_OFFSETING             0x00000008
#define CPU_BASED_HLT_EXITING                   0x00000080
#define CPU_BASED_INVLPG_EXITING                0x00000200
#define CPU_BASED_MWAIT_EXITING                 0x00000400
#define CPU_BASED_RDPMC_EXITING                 0x00000800
#define CPU_BASED_RDTSC_EXITING                 0x00001000
#define CPU_BASED_CR3_LOAD_EXITING		        0x00008000
#define CPU_BASED_CR3_STORE_EXITING		        0x00010000
#define CPU_BASED_CR8_LOAD_EXITING              0x00080000
#define CPU_BASED_CR8_STORE_EXITING             0x00100000
#define CPU_BASED_TPR_SHADOW                    0x00200000
#define CPU_BASED_VIRTUAL_NMI_PENDING		    0x00400000
#define CPU_BASED_MOV_DR_EXITING                0x00800000
#define CPU_BASED_UNCOND_IO_EXITING             0x01000000
#define CPU_BASED_USE_IO_BITMAPS                0x02000000
#define CPU_BASED_MTF_TRAP_EXITING              0x08000000
#define CPU_BASED_ACTIVATE_MSR_BITMAP           0x10000000
#define CPU_BASED_MONITOR_EXITING               0x20000000
#define CPU_BASED_PAUSE_EXITING                 0x40000000
#define CPU_BASED_ACTIVATE_SECONDARY_CONTROLS   0x80000000

#define IA32_FEATURE_CONTROL_CODE				0x03A
#define IA32_SYSENTER_CS                        0x174
#define IA32_SYSENTER_ESP                       0x175
#define IA32_SYSENTER_EIP                       0x176
#define IA32_DEBUGCTL                           0x1D9
#define IA32_VMX_BASIC_MSR_CODE					0x480
#define IA32_VMX_PINBASED_CTLS                  0x481
#define IA32_VMX_PROCBASED_CTLS                 0x482
#define IA32_VMX_EXIT_CTLS                      0x483
#define IA32_VMX_ENTRY_CTLS                     0x484
#define IA32_VMX_MISC                           0x485
#define IA32_VMX_CR0_FIXED0                     0x486
#define IA32_VMX_CR0_FIXED1                     0x487
#define IA32_VMX_CR4_FIXED0                     0x488
#define IA32_VMX_CR4_FIXED1                     0x489
#define	IA32_FS_BASE    						0xc0000100
#define	IA32_GS_BASE							0xc0000101
#define IA32_VMX_PROCBASED_CTLS2				0x0000048b

#define MSR_IA32_VMX_BASIC                      0x480
#define MSR_IA32_VMX_PINBASED_CTLS              0x481
#define MSR_IA32_VMX_PROCBASED_CTLS             0x482
#define MSR_IA32_VMX_EXIT_CTLS                  0x483
#define MSR_IA32_VMX_ENTRY_CTLS                 0x484
#define MSR_IA32_VMX_MISC                       0x485
#define MSR_IA32_VMX_CR0_FIXED0                 0x486
#define MSR_IA32_VMX_CR0_FIXED1                 0x487
#define MSR_IA32_VMX_CR4_FIXED0                 0x488
#define MSR_IA32_VMX_CR4_FIXED1                 0x489
#define MSR_IA32_VMX_VMCS_ENUM                  0x48a
#define MSR_IA32_VMX_PROCBASED_CTLS2            0x48b
#define MSR_IA32_VMX_EPT_VPID_CAP               0x48c
#define MSR_IA32_VMX_TRUE_PINBASED_CTLS         0x48d
#define MSR_IA32_VMX_TRUE_PROCBASED_CTLS        0x48e
#define MSR_IA32_VMX_TRUE_EXIT_CTLS             0x48f
#define MSR_IA32_VMX_TRUE_ENTRY_CTLS            0x490

#define MSR_IA32_MTRRCAP				0xfe
#define MSR_IA32_MTRR_DEF_TYPE			0x2ff
#define MSR_IA32_MTRR_PHYSBASE(n)		(0x200 + 2*(n))
#define MSR_IA32_MTRR_PHYSMASK(n)		(0x200 + 2*(n) + 1)
#define MSR_IA32_MTRR_FIX64K_00000		0x250
#define MSR_IA32_MTRR_FIX16K_80000		0x258
#define MSR_IA32_MTRR_FIX16K_A0000		0x259
#define MSR_IA32_MTRR_FIX4K_C0000		0x268
#define MSR_IA32_MTRR_FIX4K_C8000		0x269
#define MSR_IA32_MTRR_FIX4K_D0000		0x26a
#define MSR_IA32_MTRR_FIX4K_D8000		0x26b
#define MSR_IA32_MTRR_FIX4K_E0000		0x26c
#define MSR_IA32_MTRR_FIX4K_E8000		0x26d
#define MSR_IA32_MTRR_FIX4K_F0000		0x26e
#define MSR_IA32_MTRR_FIX4K_F8000		0x26f
#define MSR_GS_BASE						0xC0000101
#define MSR_IA32_EFER					0xC0000080
#define MSR_IA32_STAR					0xC0000081
#define MSR_LSTAR						0xC0000082
#define MSR_IA32_FMASK					0xC0000084
#define MSR_IA32_VMX_VMFUNC             0x491
#define MSR_IA32_DEBUGCTL               0x1D9
#define MSR_IA32_FEATURE_CONTROL        0x03A

#define MTRR_TYPE_UC            0
#define MTRR_TYPE_USWC          1
#define MTRR_TYPE_WT            4
#define MTRR_TYPE_WP            5
#define MTRR_TYPE_WB            6
#define MTRR_TYPE_MAX           7

#define MTRR_MSR_CAPABILITIES   0x0fe
#define MTRR_MSR_DEFAULT        0x2ff
#define MTRR_MSR_VARIABLE_BASE  0x200
#define MTRR_MSR_VARIABLE_MASK  (MTRR_MSR_VARIABLE_BASE+1)
#define MTRR_PAGE_SIZE          4096
#define MTRR_PAGE_MASK          (~(MTRR_PAGE_SIZE-1))

/**
 * @brief Memory Types
 *
 */
#define MEMORY_TYPE_UNCACHEABLE     0x00000000
#define MEMORY_TYPE_WRITE_COMBINING 0x00000001
#define MEMORY_TYPE_WRITE_THROUGH   0x00000004
#define MEMORY_TYPE_WRITE_PROTECTED 0x00000005
#define MEMORY_TYPE_WRITE_BACK      0x00000006
#define MEMORY_TYPE_INVALID         0x000000FF

 /**
  * @brief Index of the 1st paging structure (4096 byte)
  *
  */
#define ADDRMASK_EPT_PML1_INDEX(_VAR_) ((_VAR_ & 0x1FF000ULL) >> 12)

  /**
   * @brief Index of the 2nd paging structure (2MB)
   *
   */
#define ADDRMASK_EPT_PML2_INDEX(_VAR_) ((_VAR_ & 0x3FE00000ULL) >> 21)

   /**
	* @brief Index of the 3rd paging structure (1GB)
	*
	*/
#define ADDRMASK_EPT_PML3_INDEX(_VAR_) ((_VAR_ & 0x7FC0000000ULL) >> 30)

	/**
	 * @brief Index of the 4th paging structure (512GB)
	 *
	 */
#define ADDRMASK_EPT_PML4_INDEX(_VAR_) ((_VAR_ & 0xFF8000000000ULL) >> 39)