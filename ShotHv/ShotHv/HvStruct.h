#pragma once

#pragma pack(push,1)
typedef struct _vCpuId
{
	ULONG32 eax;
	ULONG32 ebx;
	ULONG32 ecx;
	ULONG32 edx;
}CpuId, * pCpuId;

typedef struct _InvpCid
{
	ULONG64 scale : 2;
	ULONG64 und : 5;
	ULONG64 addrssSize : 3;
	ULONG64 rev1 : 1;
	ULONG64 und2 : 4;
	ULONG64 segement : 3;
	ULONG64 index : 4;
	ULONG64 indexInvaild : 1;
	ULONG64 base : 4;
	ULONG64 baseInvaild : 1;
	ULONG64 regOpt : 4;
	ULONG64 un3 : 32;
}InvpCid, * pInvpCid;

// See: Feature Information Returned in the ECX Register (白皮书 3-212)
// CPUID: RAX 为 1 时, RCX 的定义
typedef union _CpuidFeatureByEcx
{
	ULONG32 all;
	struct
	{
		ULONG32 sse3 : 1;	    // [0 bit] Streaming SIMD Extensions 3 (SSE3). 值1表示处理器支持该技术。
		ULONG32 pclmulqdq : 1;	// [1 bit] PCLMULQDQ. 值1表示处理器支持PCLMULQDQ指令。
		ULONG32 dtes64 : 1;		// [2 bit] 64-bit DS Area. 值1表示处理器使用64位布局支持DS区域。
		ULONG32 monitor : 1;	// [3 bit] MONITOR/MWAIT. 值1表示处理器支持此功能。
		ULONG32 ds_cpl : 1;		// [4 bit] CPL Qualified Debug Store. 值1表示处理器支持DebugStore特性的扩展，以允许CPL限定的分支消息存储。
		ULONG32 vmx : 1;	    // [5 bit] Virtual Machine Extensions(虚拟机扩展位). 值1表示处理器支持该技术。
		ULONG32 smx : 1;	    // [6 bit] Safer Mode Extensions. 值1表示处理器支持该技术。
		ULONG32 eist : 1;		// [7 bit] Enhanced Intel SpeedStep® technology(Intel SpeedStep 动态节能技术).值1表示处理器支持该技术。
		ULONG32 tm2 : 1;		// [8 bit] Thermal Monitor 2. 值1表示处理器是否支持该技术。
		ULONG32 ssse3 : 1;		// [9 bit] 值1表示存在补充流SIMD扩展3(SSSE3)。 值为0表示处理器中不存在指令扩展。
		ULONG32 cnxt_id : 1;	// [10 bit] L1 Context ID. 值1表示L1数据缓存模式可以设置为自适应模式或共享模式。 值为0表示不支持此功能
		ULONG32 sdbg : 1;		// [11 bit] 值1表示处理器支持用于硅调试的IA32_DEBUG_INTERFACE MSR。
		ULONG32 fma : 1;		// [12 bit] 值1表示处理器支持使用YMM状态的FMA扩展。
		ULONG32 cmpxchg16b : 1;	// [13 bit] CMPXCHG16B Available. 值1表示该特性可用。
		ULONG32 xtrrupdatecontrol : 1; // [14 bit] xTPR Update Control. 值1表示处理器支持更改IA32_MISC_ENABLE[bit 23]。
		ULONG32 pdcm : 1;		// [15 bit] Perfmon and Debug Capability: 值1表示处理器支持性能和调试功能指示MSR IA32_PERF_CAPABILITIES
		ULONG32 reserved : 1;	// [16 bit] 保留
		ULONG32 pcid : 1;		// [17 bit] Process-context identifiers. A value of 1 indicates that the processor supports PCIDs and that software may set CR4.PCIDE to 1.
		ULONG32 dca : 1;		// [18 bit] A value of 1 indicates the processor supports the ability to prefetch data from a memory mapped device.
		ULONG32 sse41 : 1;		// [19 bit] A value of 1 indicates that the processor supports SSE4.1.
		ULONG32 sse42 : 1;		// [20 bit] A value of 1 indicates that the processor supports SSE4.2.
		ULONG32 x2apic : 1;		// [21 bit] A value of 1 indicates that the processor supports x2APIC feature.
		ULONG32 movbe : 1;		// [22 bit] A value of 1 indicates that the processor supports MOVBE instruction.
		ULONG32 popcnt : 1;		// [23 bit] A value of 1 indicates that the processor supports the POPCNT instruction.
		ULONG32 tsc_deadline : 1; // [24 bit] 值1表示处理器的本地APIC定时器支持使用TSC截止日期值进行一次操作。
		ULONG32 aesni : 1;		// [25 bit] A value of 1 indicates that the processor supports the AESNI instruction extensions.
		ULONG32 xsave : 1;		// [26 bit] A value of 1 indicates that the processor supports the XSAVE/XRSTOR processor extended states feature, the XSETBV / XGETBV instructions, and XCR0.
		ULONG32 osxsave : 1;	// [27 bit] A value of 1 indicates that the OS has set CR4.OSXSAVE[bit 18] to enable XSETBV/XGETBV instructions to access XCR0 and to support processor extended state management using XSAVE / XRSTOR.
		ULONG32 avx : 1;		// [28 bit] A value of 1 indicates the processor supports the AVX instruction extensions.
		ULONG32 f16c : 1;		// [29 bit] 值1表示处理器支持16位浮点转换指令。
		ULONG32 rdrand : 1;		// [30 bit] A value of 1 indicates that processor supports RDRAND instruction.
		ULONG32 notused : 1;	// [31 bit] Always returns 0.
	}fields;
}CpuidFeatureByEcx, * pCpuidFeatureByEcx;

// See: ARCHITECTURAL MSRS (请看白皮书 2-4 Vol.4)
// IA32_FEATURE_CONTROL 寄存器结构定义 
typedef union _Ia32FeatureControlMsr
{
	ULONGLONG all;
	struct
	{
		ULONGLONG lock : 1;					 // [0 bit] 置锁位, 为0则VMXON不能调用, 为1那么WRMSR(写 MSR 寄存器指令)不能去写这个寄存器。该位在系统上电后便不能修改。
											 // BIOS 通过修改这个寄存器来设置是否支持虚拟化操作。在支持虚拟化的操作下，BIOS还要设置Bit1和Bit2	
		ULONGLONG enable_smx : 1;			 // [1 bit] 为 0, 则 VMXON 不能在SMX(安全扩展模式, 请参考intel白皮书5-34)操作系统中调用
		ULONGLONG enable_vmxon : 1;          // [2 bit] 为 0, 则 VMXON 不能在SMX操作系统外调用
		ULONGLONG reserved1 : 5;             //!< [3:7]
		ULONGLONG enable_local_senter : 7;   //!< [8:14]
		ULONGLONG enable_global_senter : 1;  //!< [15]
		ULONGLONG reserved2 : 16;            //!<
		ULONGLONG reserved3 : 32;            //!< [16:63]
	}fields;
}Ia32FeatureControlMsr, * pIa32FeatureControlMsr;

union Cr0Type {
	ULONG_PTR all;
	struct {
		unsigned pe : 1;          //!< [0] Protected Mode Enabled
		unsigned mp : 1;          //!< [1] Monitor Coprocessor FLAG
		unsigned em : 1;          //!< [2] Emulate FLAG
		unsigned ts : 1;          //!< [3] Task Switched FLAG
		unsigned et : 1;          //!< [4] Extension Type FLAG
		unsigned ne : 1;          //!< [5] Numeric Error
		unsigned reserved1 : 10;  //!< [6:15]
		unsigned wp : 1;          //!< [16] Write Protect
		unsigned reserved2 : 1;   //!< [17]
		unsigned am : 1;          //!< [18] Alignment Mask
		unsigned reserved3 : 10;  //!< [19:28]
		unsigned nw : 1;          //!< [29] Not Write-Through
		unsigned cd : 1;          //!< [30] Cache Disable
		unsigned pg : 1;          //!< [31] Paging Enabled
	} fields;
};

// See: CONTROL REGISTERS (白皮书 2-14 Vol.3A)
typedef union _Cr4Type
{
	ULONG_PTR all;
	struct
	{
		ULONG_PTR vme : 1;			// [0 bit] Virtual Mode Extensions
		ULONG_PTR pvi : 1;			// [1 bit] Virtual-8086 Mode Extensions
		ULONG_PTR tsd : 1;			// [2 bit] Time Stamp Disable
		ULONG_PTR de : 1;			// [3 bit] Debugging Extensions
		ULONG_PTR pse : 1;			// [4 bit] Page Size Extensions
		ULONG_PTR pae : 1;			// [5 bit] Physical Address Extension
		ULONG_PTR mce : 1;			// [6 bit] Machine-Check Enable
		ULONG_PTR pge : 1;			// [7 bit] Page Global Enable
		ULONG_PTR pce : 1;			// [8 bit] Performance-Monitoring Counter Enable
		ULONG_PTR osfxsr : 1;		// [9 bit] Operating System Support for FXSAVE and FXRSTOR instructions
		ULONG_PTR osxmmexcpt : 1;	// [10 bit] Operating System Support for Unmasked SIMD Floating-Point Exceptions
		ULONG_PTR umip : 1;			// [11 bit] User-Mode Instruction Prevention. (设置时，如果CPL>0：SGDT、SIDT、SLDT、SMSW和STR，则无法执行。 这种执行的尝试会导致一般保护异常(#GP))
		ULONG_PTR reserved1 : 1;	// [12 bit]
		ULONG_PTR vmxe : 1;			// [13 bit] VMX-Enable Bit. 设置时启用VMX操作。
		ULONG_PTR smxe : 1;			// [14 bit] SMX-Enable Bit. 
		ULONG_PTR reserved2 : 1;	// [15 bit]
		ULONG_PTR fsgsbase : 1;		// [16 bit] 启用指令RDFSBASE、RDGSBASE、WRFSBASE和WRGSBASE。
		ULONG_PTR pcide : 1;		// [17 bit] PCID-Enable Bit
		ULONG_PTR osxsave : 1;		// [18 bit] XSAVE and Processor Extended States-Enable Bit.
		ULONG_PTR reserved3 : 1;	// [19 bit]
		ULONG_PTR smep : 1;			// [20 bit] SMEP-Enable Bit
		ULONG_PTR smap : 1;			// [21 bit] SMAP-Enable Bit
		ULONG_PTR pke : 1;			// [22 bit] Protection-Key-Enable Bit (Enables 4-level paging ???)
	}fields;
}Cr4Type, * pCr4Type;

/* GDT */
typedef struct _GDT {
	USHORT uLimit;
	ULONG_PTR uBase;
} GDT, * PGDT;

/* IDT */
typedef struct _IDT {
	USHORT uLimit;
	ULONG_PTR uBase;
} IDT, * PIDT;

/* GUEST 环境结构体 */
typedef struct _GUEST_STATE {
	ULONG_PTR cs;
	ULONG_PTR ds;
	ULONG_PTR ss;
	ULONG_PTR es;
	ULONG_PTR fs;
	ULONG_PTR gs;
	GDT gdt;
	IDT idt;
	ULONG_PTR ldtr;
	ULONG_PTR tr;
	ULONG_PTR rsp;
	ULONG_PTR rip;
	ULONG_PTR rflags;
	ULONG_PTR cr0;
	ULONG_PTR cr4;
	ULONG_PTR cr3;
	ULONG_PTR dr7;
	ULONG_PTR msr_debugctl;
	ULONG_PTR msr_sysenter_cs;
	ULONG_PTR msr_sysenter_eip;
	ULONG_PTR msr_sysenter_esp;

	ULONG_PTR msr_perf_global_ctrl;
	ULONG_PTR msr_pat;
	ULONG_PTR msr_efer;
	ULONG_PTR msr_bndcfgs;

	ULONG_PTR cr0_mask;
	ULONG_PTR cr0_shadow;
	ULONG_PTR cr4_mask;
	ULONG_PTR cr4_shadow;
} GUEST_STATE, * PGUEST_STATE;

/* HOST 环境结构体 */
typedef struct _HOST_STATE {
	ULONG_PTR cr0;
	ULONG_PTR cr3;
	ULONG_PTR cr4;
	ULONG_PTR rsp;
	ULONG_PTR rip;
	ULONG_PTR cs;
	ULONG_PTR ds;
	ULONG_PTR ss;
	ULONG_PTR es;
	ULONG_PTR fs;
	ULONG_PTR gs;
	ULONG_PTR tr;
	ULONG_PTR fsbase;
	ULONG_PTR gsbase;
	ULONG_PTR trbase;
	GDT gdt;
	IDT idt;
	ULONG_PTR msr_sysenter_cs;
	ULONG_PTR msr_sysenter_esp;
	ULONG_PTR msr_sysenter_eip;
	ULONG_PTR msr_efer;
} HOST_STATE, * PHOST_STATE;

/* GDT 段描述符 */
typedef union _kGdtEntry64
{
	struct
	{
		UINT16 LimitLow;
		UINT16 BaseLow;
		union
		{
			struct
			{
				UINT8 BaseMiddle;
				UINT8 Flags1;
				UINT8 Flags2;
				UINT8 BaseHigh;
			} Bytes;

			struct
			{
				UINT32 BaseMiddle : 8;
				UINT32 Type : 5;
				UINT32 Dpl : 2;
				UINT32 Present : 1;
				UINT32 LimitHigh : 4;
				UINT32 System : 1;
				UINT32 LongMode : 1;
				UINT32 DefaultBig : 1;
				UINT32 Granularity : 1;
				UINT32 BaseHigh : 8;
			} Bits;
		};
		UINT32 BaseUpper;
		UINT32 MustBeZero;
	}u1;
	struct
	{
		INT64 DataLow;
		INT64 DataHigh;
	}u2;
}kGdtEntry64;

// SYSTEM FLAGS AND FIELDS IN THE EFLAGS REGISTER (白皮书 2-10 Vol. 3A)
// rflag 寄存器的定义
typedef union _FlagReg {
	ULONG_PTR all;
	struct {
		ULONG_PTR cf : 1;          //!< [0] Carry flag
		ULONG_PTR reserved1 : 1;   //!< [1] Always 1
		ULONG_PTR pf : 1;          //!< [2] Parity flag
		ULONG_PTR reserved2 : 1;   //!< [3] Always 0
		ULONG_PTR af : 1;          //!< [4] Borrow flag
		ULONG_PTR reserved3 : 1;   //!< [5] Always 0
		ULONG_PTR zf : 1;          //!< [6] Zero flag
		ULONG_PTR sf : 1;          //!< [7] Sign flag
		ULONG_PTR tf : 1;          //!< [8] Trap flag
		ULONG_PTR intf : 1;        //!< [9] Interrupt flag
		ULONG_PTR df : 1;          //!< [10] Direction flag
		ULONG_PTR of : 1;          //!< [11] Overflow flag
		ULONG_PTR iopl : 2;        //!< [12:13] I/O privilege level
		ULONG_PTR nt : 1;          //!< [14] Nested task flag
		ULONG_PTR reserved4 : 1;   //!< [15] Always 0
		ULONG_PTR rf : 1;          //!< [16] Resume flag
		ULONG_PTR vm : 1;          //!< [17] Virtual 8086 mode
		ULONG_PTR ac : 1;          //!< [18] Alignment check
		ULONG_PTR vif : 1;         //!< [19] Virtual interrupt flag
		ULONG_PTR vip : 1;         //!< [20] Virtual interrupt pending
		ULONG_PTR id : 1;          //!< [21] Identification flag
		ULONG_PTR reserved5 : 10;  //!< [22:31] Always 0
	} fields;
}FlagReg, * pFlagReg;

// See: BASIC VMX INFORMATION (请看白皮书 Vol. 3D A-1)
typedef union _Ia32VmxBasicMsr{
	unsigned __int64 all;
	struct {
		unsigned __int64 revision_identifier : 31;    //!< [0:30]
		unsigned __int64 reserved1 : 1;               //!< [31]    总为0
		unsigned __int64 region_size : 12;            //!< [32:43]
		unsigned __int64 region_clear : 1;            //!< [44]
		unsigned __int64 reserved2 : 3;               //!< [45:47]
		unsigned __int64 supported_ia64 : 1;          //!< [48]
		unsigned __int64 supported_dual_moniter : 1;  //!< [49]
		unsigned __int64 memory_type : 4;             //!< [50:53]
		unsigned __int64 vm_exit_report : 1;          //!< [54]
		unsigned __int64 vmx_capability_hint : 1;     //!< [55]
		unsigned __int64 reserved3 : 8;               //!< [56:63] 保留
	} fields;
}Ia32VmxBasicMsr, * pIa32VmxBasicMsr;

// See: Definitions of Pin-Based VM-Execution Controls (白皮书 Vol. 3C 24-9)
// 该字段用于管理处理器异常事件(如：中断等)
typedef union _VmxPinBasedControls
{
	unsigned int all;
	struct {
		unsigned int external_interrupt_exiting : 1;    //!< [0]    // 为1时, 发生外部中断则产生 VM-EXIT
		unsigned int reserved1 : 2;                     //!< [1:2]  // 保留, 固定为1
		unsigned int nmi_exiting : 1;                   //!< [3]    // 为1时, 发生NMI则产生 VM-EXIT
		unsigned int reserved2 : 1;                     //!< [4]	// 保留, 固定为1
		unsigned int virtual_nmis : 1;                  //!< [5]	// 为1时, 定义 virtual NMI
		unsigned int activate_vmx_peemption_timer : 1;  //!< [6]	// 为1时，启用 vmx-peemption 定时器
		unsigned int process_posted_interrupts : 1;     //!< [7]	// 为1时，启用 posted-interrupt processing 机制处理虚拟中断
	}fields;
}VmxPinBasedControls, * pVmxPinBasedControls;

// See: Definitions of Primary Processor-Based VM-Execution Controls (请看白皮书 24-10 Vol.3C)
// 处理器 VMX non-root operation 模式下的主要行为由这个字段控制
typedef union _VmxProcessorBasedControls {
	unsigned int all;
	struct
	{
		unsigned int reserved1 : 2;                   //!< [0:1] 保留，固定为0
		unsigned int interrupt_window_exiting : 1;    //!< [2]   为1时, 在IF=1斌且中断没被阻塞时, 产生 VM-EXIT
		unsigned int use_tsc_offseting : 1;           //!< [3]   为1时, 读取TSC值时, 返回的TSC值加上一个偏移值
		unsigned int reserved2 : 3;                   //!< [4:6] 保留，固定为1
		unsigned int hlt_exiting : 1;                 //!< [7]   为1时，执行HLT指令产生的 VM-EXIT
		unsigned int reserved3 : 1;                   //!< [8]	 保留，固定为1
		unsigned int invlpg_exiting : 1;              //!< [9]   为1时，执行INVLPG指令产生VM-EXIT
		unsigned int mwait_exiting : 1;               //!< [10]  为1时，执行MWAIT指令产生VM-EXIT
		unsigned int rdpmc_exiting : 1;               //!< [11]  为1时，执行RDPMC指令产生VM-EXIT
		unsigned int rdtsc_exiting : 1;               //!< [12]  为1时，执行RDTSC指令产生VM-EXIT
		unsigned int reserved4 : 2;                   //!< [13:14] 保留，固定为1
		unsigned int cr3_load_exiting : 1;            //!< [15]  为1时, 写CR3寄存器产生VM-EXIT
		unsigned int cr3_store_exiting : 1;           //!< [16]  为1时, 读CR3寄存器产生VM-EXIT
		unsigned int reserved5 : 2;                   //!< [17:18] 保留，固定为0
		unsigned int cr8_load_exiting : 1;            //!< [19]  为1时, 写CR8寄存器产生VM-EXIT
		unsigned int cr8_store_exiting : 1;           //!< [20]  为1时, 读CR8寄存器产生VM-EXIT
		unsigned int use_tpr_shadow : 1;              //!< [21]  为1时, 启用"virtual-APIC page"页面来虚拟化local APIC
		unsigned int nmi_window_exiting : 1;          //!< [22]  为1时, 开virtual-NMI window 时产生VM-EXIT
		unsigned int mov_dr_exiting : 1;              //!< [23]  为1时, 读写DR寄存器产生VM-EXIT
		unsigned int unconditional_io_exiting : 1;    //!< [24]  为1时, 执行IN/OUT或INS/OUTS类指令产生VM-EXIT
		unsigned int use_io_bitmaps : 1;              //!< [25]  为1时, 启用I/O bitmap
		unsigned int reserved6 : 1;                   //!< [26]  保留，固定为1
		unsigned int monitor_trap_flag : 1;           //!< [27]  为1时, 启用MTF调试功能
		unsigned int use_msr_bitmaps : 1;             //!< [28]  为1时, 启用MSR bitmap
		unsigned int monitor_exiting : 1;             //!< [29]  为1时, 执行MONITOR指令产生VM-EXIT
		unsigned int pause_exiting : 1;               //!< [30]  为1时, 执行PAUSE指令产生VM-EXIT
		unsigned int activate_secondary_control : 1;  //!< [31]  为1时, secondary processor-based VM-execution control 字段有效
	}fields;
}VmxProcessorBasedControls, * pVmxProcessorBasedControls;

// See: Definitions of Secondary Processor-Based VM-Execution Controls (请看白皮书 Vol.3C 24-11)
// 该字段用于提供 VMX 扩展的控制功能, 只在 VmxProcessorBasedControls.activate_secondary_control 为1时有效
typedef union _VmxSecondaryProcessorBasedControls
{
	unsigned int all;
	struct {
		unsigned int virtualize_apic_accesses : 1;            //!< [0] 为1时, 虚拟化访问 APIC-access page
		unsigned int enable_ept : 1;                          //!< [1] 为1时, 启用EPT
		unsigned int descriptor_table_exiting : 1;            //!< [2] 为1时, 访问GDTR/LDTR/IDTR或者TR产生VM-EXIT
		unsigned int enable_rdtscp : 1;                       //!< [3] 为0时, 执行RDTSCP产生#UD异常
		unsigned int virtualize_x2apic_mode : 1;              //!< [4] 为1时, 虚拟化访问x2APIC MSR
		unsigned int enable_vpid : 1;                         //!< [5] 为1时, 启用VPID机制
		unsigned int wbinvd_exiting : 1;                      //!< [6] 为1时, 执行WBINVD指令产生VM-EXIT
		unsigned int unrestricted_guest : 1;                  //!< [7] 为1时, Guest 可以使用非分页保护模式或实模式
		unsigned int apic_register_virtualization : 1;        //!< [8] 为1时, 支持访问virtual-APIC page 内的虚拟寄存器
		unsigned int virtual_interrupt_delivery : 1;          //!< [9] 为1时, 支持虚拟中断的delivery
		unsigned int pause_loop_exiting : 1;                  //!< [10] 为1时, 决定PASUE指令是否产生VM-EXIT
		unsigned int rdrand_exiting : 1;                      //!< [11] 为1时, 执行RDRAND指令产生VM-EXIT
		unsigned int enable_invpcid : 1;                      //!< [12] 为0时, 执行INVPCID指令产生#UD异常
		unsigned int enable_vm_functions : 1;                 //!< [13] 为1时, VMX non-root operation 内可以执行VMFUNC指令
		unsigned int vmcs_shadowing : 1;                      //!< [14] 为1时, VMX non-root operation 内可以执行VMREAD和VMWRITE指令
		unsigned int enable_encls_exiting : 1;                //!< [15] 为1时, 执行ENCLS指令产生VM-EXIT
		unsigned int rdseed_exiting : 1;                      //!< [16] 为1时, 执行RDSEED指令产生VM-EXIT
		unsigned int enable_pml : 1;                          //!< [17] 为1时, 执行RDSEED指令产生VM-EXIT
		unsigned int ept_violation_ve : 1;                    //!< [18] If this control is 1, an access to a guest-physical address that sets an EPT dirty bit first adds an entry to the page - modification log.
		unsigned int conceal_vmx_from_pt : 1;                 //!< [19] 
		unsigned int enable_xsaves_xstors : 1;                //!< [20] 如果此控件为0，则XSAVES或XRSTORS的任一执行都会导致#UD。
		unsigned int reserved1 : 1;                           //!< [21] 
		unsigned int mode_based_execute_control_for_ept : 1;  //!< [22] If this control is 1, EPT execute permissions are based on whether the linear address being accessed is supervisor mode or user mode.
		unsigned int sun_page_write_permissions_for_ept : 1;  //!< [23] If this control is 1, EPT write permissions may be specified at the granularity of 128 bytes.
		unsigned int reserved2 : 1;                           //!< [24]
		unsigned int use_tsc_scaling : 1;                     //!< [25]
		unsigned int reserved3 : 2;                           //!< [26:27]
		unsigned int enable_enclv_exiting : 1;				  //!< [28] 
	}fields;
}VmxSecondaryProcessorBasedControls, * pVmxSecondaryProcessorBasedControls;

// See: Definitions of VM-Entry Controls (白皮书 Vol. 3C 24-19、【处理器虚拟化技术】第3.6节)
// 该字段用于控制 VMX 的基本操作
typedef union _VmxVmentryControls
{
	unsigned int all;
	struct {
		unsigned reserved1 : 2;                          //!< [0:1] 
		unsigned load_debug_controls : 1;                //!< [2]	为1时, 从(guest-state)加载debug寄存器
		unsigned reserved2 : 6;                          //!< [3:8]
		unsigned ia32e_mode_guest : 1;                   //!< [9]	为1时, 进入IA-32e模式
		unsigned entry_to_smm : 1;                       //!< [10]	为1时, 进入SMM模式
		unsigned deactivate_dual_monitor_treatment : 1;  //!< [11]	为1时, 返回executive monitor, 关闭 SMM 双重监控处理
		unsigned reserved3 : 1;                          //!< [12]
		unsigned load_ia32_perf_global_ctrl : 1;         //!< [13]	为1时, 加载 ia32_perf_global_ctrl
		unsigned load_ia32_pat : 1;                      //!< [14]	为1时, 加载 ia32_pat
		unsigned load_ia32_efer : 1;                     //!< [15]	为1时, 加载 ia32_efer
		unsigned load_ia32_bndcfgs : 1;                  //!< [16]	为1时, 加载 ia32_bndcfgs
		unsigned conceal_vmentries_from_intel_pt : 1;    //!< [17]	
	}fields;
}VmxVmentryControls, * pVmxVmentryControls;

// See: Definitions of VM-Exit Controls (白皮书 24-18 Vol. 3C、【处理器虚拟化技术】第3.7.1节)
// 该字段用于控制发生 VM-EXIT 时的处理器行为
typedef union _VmxmexitControls
{
	unsigned int all;
	struct {
		unsigned reserved1 : 2;                        //!< [0:1]	
		unsigned save_debug_controls : 1;              //!< [2]		为1时, 保存debug寄存器
		unsigned reserved2 : 6;                        //!< [3:8]
		unsigned host_address_space_size : 1;          //!< [9]		为1时, 返回到IA-32e模式
		unsigned reserved3 : 2;                        //!< [10:11]
		unsigned load_ia32_perf_global_ctrl : 1;       //!< [12]	为1时, 加载 ia32_perf_global_ctrl
		unsigned reserved4 : 2;                        //!< [13:14]
		unsigned acknowledge_interrupt_on_exit : 1;    //!< [15]	为1时, VM-exit 时处理器响应中断寄存器, 读取中断向量号
		unsigned reserved5 : 2;                        //!< [16:17]
		unsigned save_ia32_pat : 1;                    //!< [18]	为1时, 保存 ia32_pat
		unsigned load_ia32_pat : 1;                    //!< [19]	为1时, 加载 ia32_pat
		unsigned save_ia32_efer : 1;                   //!< [20]	为1时, 保存 ia32_efer
		unsigned load_ia32_efer : 1;                   //!< [21]	为1时, 加载 ia32_efer
		unsigned save_vmx_preemption_timer_value : 1;  //!< [22]	为1时, VM-exit 时保存VMX定时器计数值
		unsigned clear_ia32_bndcfgs : 1;               //!< [23]	此控件确定IA32_BNDCFGS的MSR是否在VM退出时被清除。
		unsigned conceal_vmexits_from_intel_pt : 1;    //!< [24]
	}fields;
}VmxmexitControls, * pVmxmexitControls;

// See: Format of Exit Reason in Basic VM-Exit Information
// 定义 Exit reason 字段 (参考 【处理器虚拟化技术】(第3.10.1.1节))
typedef union _VmxExitInfo
{
	unsigned int all;
	struct
	{
		unsigned short reason;                     //!< [0:15]	保存VM退出原因值
		unsigned short reserved1 : 12;             //!< [16:27]
		unsigned short pending_mtf_vm_exit : 1;    //!< [28]	为1时，指示SMM VM-exit 时, 存在 pending MTF VM-exit 事件
		unsigned short vm_exit_from_vmx_root : 1;  //!< [29]	为1时，指示SMM VM-exit从VMX root-operation 
		unsigned short reserved2 : 1;              //!< [30]
		unsigned short vm_entry_failure : 1;       //!< [31]	为1时, 表明是在VM-entry过程中引发VM-exit
	}fields;
}VmxExitInfo, * pVmxExitInfo;

// @copydoc VmEntryInterruptionInformationField
// 参考 【处理器虚拟化技术】(第3.6.3.1节)
enum InterruptionType {
	kExternalInterrupt = 0,				// 外部硬件中断
	kReserved = 1,						// Not used for VM-Exit
	kNonMaskableInterrupt = 2,			// NMI 中断(不可屏蔽的外部中断)
	kHardwareException = 3,				// 硬件异常 (指 fault 或 abort 事件, 除#BP及#OF异常以外的所有异常, 包括BOUND与UD2指令产生的异常)(包括#DF,#TS,#NP,#SS,#GP,#PF,#AC)
	kSoftwareInterrupt = 4,             // 软件中断 (由 INT 指令产生的中断) (关于中断和异常可以参考【系统虚拟化：原理与实现】(第2.4节))
	kPrivilegedSoftwareException = 5,	// 特权级软件中断 Not used for VM-Exit
	kSoftwareException = 6,				// 软件异常 (指由 INT3 或 INT0指令产生的#BP与#OF异常, 它们属于trap事件)
	kOtherEvent = 7,					// 注入 MTF VM-exit 事件
};

enum InterruptionVector
{
	EXCEPTION_VECTOR_DIVIDE_ERROR,		   // DIV 和 IDIV 指令导致的异常 (#DE)
	EXCEPTION_VECTOR_DEBUG,				   // 任何代码或数据的错误引用或 INT 1 指令导致的异常 (#DB)
	EXCEPTION_VECTOR_NMI_INTERRUPT,		   // 不可屏蔽中断 (#DB)
	EXCEPTION_VECTOR_BREAKPOINT,		   // INT 3 指令导致的异常 (#BP)
	EXCEPTION_VECTOR_OVERFLOW,			   // INT 0 指令导致的异常 (#OF)
	EXCEPTION_VECTOR_BOUND_RANGE_EXCEEDED, // BOUND 指令导致的异常 (#BR)
	EXCEPTION_VECTOR_INVALID_OPCODE,       // 无效的操作码导致的异常 (#UD)
	EXCEPTION_VECTOR_NO_MATH_COPROCESSOR,  // 浮点或 WAIT/FWAIT指令导致的异常 (#NM)
	EXCEPTION_VECTOR_DOUBLE_FAULT,		   // 双重错误导致的异常 (#DF)		
	EXCEPTION_VECTOR_RESERVED0,            // 浮点指令导致的异常 (#MF)
	EXCEPTION_VECTOR_INVALID_TSS,		   // 任务切换或TSS访问导致的异常 (#TS)
	EXCEPTION_VECTOR_SEGMENT_NOT_PRESENT,  // 加载段寄存器或访问系统段导致的异常 (#NP)
	EXCEPTION_VECTOR_STACK_SEGMENT_FAULT,  // 堆栈操作或SS寄存器加载导致的异常 (#SS)
	EXCEPTION_VECTOR_GENERAL_PROTECTION,   // 任何内存引用和其他保护检查导致的异常 (#GP)
	EXCEPTION_VECTOR_PAGE_FAULT,		   // 页面访问异常导致的异常 (#PF)	
	EXCEPTION_VECTOR_RESERVED1,			   // 保留(?)
	EXCEPTION_VECTOR_MATH_FAULT,           // 浮点或WAIT/FWAIT指令导致的异常 (#MF)
	EXCEPTION_VECTOR_ALIGNMENT_CHECK,      // 对齐检测导致的异常 (#AC)
	EXCEPTION_VECTOR_SIMD_FLOATING_POINT_NUMERIC_ERROR, // SIMD浮点指令致的异常 (#VE)
	EXCEPTION_VECTOR_VIRTUAL_EXCEPTION,    // EPT异常导致的异常 (#VE)

	// 21 ~ 31 Reserved

	// Maskable Interrupts

	//
	// NT (Windows) specific exception vectors.
	//
	APC_INTERRUPT = 31,
	DPC_INTERRUPT = 47,
	CLOCK_INTERRUPT = 209,
	IPI_INTERRUPT = 225,
	PMI_INTERRUPT = 254,
};

enum VmcsField {
	VIRTUAL_PROCESSOR_ID = 0x00000000,
	POSTED_INTR_NOTIFICATION_VECTOR = 0x00000002,
	EPTP_INDEX = 0x00000004,
	GUEST_ES_SELECTOR = 0x00000800,
	GUEST_CS_SELECTOR = 0x00000802,
	GUEST_SS_SELECTOR = 0x00000804,
	GUEST_DS_SELECTOR = 0x00000806,
	GUEST_FS_SELECTOR = 0x00000808,
	GUEST_GS_SELECTOR = 0x0000080a,
	GUEST_LDTR_SELECTOR = 0x0000080c,
	GUEST_TR_SELECTOR = 0x0000080e,
	GUEST_INTR_STATUS = 0x00000810,
	GUEST_PML_INDEX = 0x00000812,
	HOST_ES_SELECTOR = 0x00000c00,
	HOST_CS_SELECTOR = 0x00000c02,
	HOST_SS_SELECTOR = 0x00000c04,
	HOST_DS_SELECTOR = 0x00000c06,
	HOST_FS_SELECTOR = 0x00000c08,
	HOST_GS_SELECTOR = 0x00000c0a,
	HOST_TR_SELECTOR = 0x00000c0c,
	IO_BITMAP_A = 0x00002000,
	IO_BITMAP_B = 0x00002002,
	MSR_BITMAP = 0x00002004,
	VM_EXIT_MSR_STORE_ADDR = 0x00002006,
	VM_EXIT_MSR_LOAD_ADDR = 0x00002008,
	VM_ENTRY_MSR_LOAD_ADDR = 0x0000200a,
	PML_ADDRESS = 0x0000200e,
	TSC_OFFSET = 0x00002010,
	VIRTUAL_APIC_PAGE_ADDR = 0x00002012,
	APIC_ACCESS_ADDR = 0x00002014,
	PI_DESC_ADDR = 0x00002016,
	VM_FUNCTION_CONTROL = 0x00002018,
	EPT_POINTER = 0x0000201a,
	EOI_EXIT_BITMAP0 = 0x0000201c,
	EPTP_LIST_ADDR = 0x00002024,
	VMREAD_BITMAP = 0x00002026,
	VMWRITE_BITMAP = 0x00002028,
	VIRT_EXCEPTION_INFO = 0x0000202a,
	XSS_EXIT_BITMAP = 0x0000202c,
	TSC_MULTIPLIER = 0x00002032,
	GUEST_PHYSICAL_ADDRESS = 0x00002400,
	GUEST_PHYSICAL_ADDRESS_HIGH = 0x00002401,
	VMCS_LINK_POINTER = 0x00002800,
	GUEST_IA32_DEBUGCTL = 0x00002802,
	GUEST_PAT = 0x00002804,
	GUEST_EFER = 0x00002806,
	GUEST_PERF_GLOBAL_CTRL = 0x00002808,
	GUEST_PDPTE0 = 0x0000280a,
	GUEST_BNDCFGS = 0x00002812,
	HOST_PAT = 0x00002c00,
	HOST_EFER = 0x00002c02,
	HOST_PERF_GLOBAL_CTRL = 0x00002c04,
	PIN_BASED_VM_EXEC_CONTROL = 0x00004000, // 基于处理器的主vm执行控制信息域
	CPU_BASED_VM_EXEC_CONTROL = 0x00004002,
	EXCEPTION_BITMAP = 0x00004004,			// 异常 BitMap
	PAGE_FAULT_ERROR_CODE_MASK = 0x00004006,
	PAGE_FAULT_ERROR_CODE_MATCH = 0x00004008,
	CR3_TARGET_COUNT = 0x0000400a,
	VM_EXIT_CONTROLS = 0x0000400c,
	VM_EXIT_MSR_STORE_COUNT = 0x0000400e,
	VM_EXIT_MSR_LOAD_COUNT = 0x00004010,
	VM_ENTRY_CONTROLS = 0x00004012,
	VM_ENTRY_MSR_LOAD_COUNT = 0x00004014,
	VM_ENTRY_INTR_INFO = 0x00004016,
	VM_ENTRY_EXCEPTION_ERROR_CODE = 0x00004018,
	VM_ENTRY_INSTRUCTION_LEN = 0x0000401a,
	TPR_THRESHOLD = 0x0000401c,
	SECONDARY_VM_EXEC_CONTROL = 0x0000401e, // 基于处理器的辅助vm执行控制信息域的扩展字段 【Secondary Processor-Based VM-Execution Controls】
	PLE_GAP = 0x00004020,
	PLE_WINDOW = 0x00004022,
	VM_INSTRUCTION_ERROR = 0x00004400,
	VM_EXIT_REASON = 0x00004402,
	VM_EXIT_INTR_INFO = 0x00004404,
	VM_EXIT_INTR_ERROR_CODE = 0x00004406,   // See: VM-Instruction Error Numbers
	IDT_VECTORING_INFO = 0x00004408,
	IDT_VECTORING_ERROR_CODE = 0x0000440a,
	VM_EXIT_INSTRUCTION_LEN = 0x0000440c,
	VMX_INSTRUCTION_INFO = 0x0000440e,
	GUEST_ES_LIMIT = 0x00004800,
	GUEST_CS_LIMIT = 0x00004802,
	GUEST_SS_LIMIT = 0x00004804,
	GUEST_DS_LIMIT = 0x00004806,
	GUEST_FS_LIMIT = 0x00004808,
	GUEST_GS_LIMIT = 0x0000480a,
	GUEST_LDTR_LIMIT = 0x0000480c,
	GUEST_TR_LIMIT = 0x0000480e,
	GUEST_GDTR_LIMIT = 0x00004810,
	GUEST_IDTR_LIMIT = 0x00004812,
	GUEST_ES_AR_BYTES = 0x00004814,
	GUEST_CS_AR_BYTES = 0x00004816,
	GUEST_SS_AR_BYTES = 0x00004818,
	GUEST_DS_AR_BYTES = 0x0000481a,
	GUEST_FS_AR_BYTES = 0x0000481c,
	GUEST_GS_AR_BYTES = 0x0000481e,
	GUEST_LDTR_AR_BYTES = 0x00004820,
	GUEST_TR_AR_BYTES = 0x00004822,
	GUEST_INTERRUPTIBILITY_INFO = 0x00004824,
	GUEST_ACTIVITY_STATE = 0x00004826,
	GUEST_SMBASE = 0x00004828,
	GUEST_SYSENTER_CS = 0x0000482a,
	GUEST_PREEMPTION_TIMER = 0x0000482e,
	HOST_SYSENTER_CS = 0x00004c00,
	CR0_GUEST_HOST_MASK = 0x00006000,
	CR4_GUEST_HOST_MASK = 0x00006002,
	CR0_READ_SHADOW = 0x00006004,
	CR4_READ_SHADOW = 0x00006006,
	CR3_TARGET_VALUE0 = 0x00006008,
	EXIT_QUALIFICATION = 0x00006400, // (哪些指令该字段有效，请参考【处理器虚拟化技术】(第3.10.1.3节))
	GUEST_LINEAR_ADDRESS = 0x0000640a,
	GUEST_CR0 = 0x00006800,
	GUEST_CR3 = 0x00006802,
	GUEST_CR4 = 0x00006804,
	GUEST_ES_BASE = 0x00006806,
	GUEST_CS_BASE = 0x00006808,
	GUEST_SS_BASE = 0x0000680a,
	GUEST_DS_BASE = 0x0000680c,
	GUEST_FS_BASE = 0x0000680e,
	GUEST_GS_BASE = 0x00006810,
	GUEST_LDTR_BASE = 0x00006812,
	GUEST_TR_BASE = 0x00006814,
	GUEST_GDTR_BASE = 0x00006816,
	GUEST_IDTR_BASE = 0x00006818,
	GUEST_DR7 = 0x0000681a,
	GUEST_RSP = 0x0000681c,
	GUEST_RIP = 0x0000681e,
	GUEST_RFLAGS = 0x00006820,
	GUEST_PENDING_DBG_EXCEPTIONS = 0x00006822,
	GUEST_SYSENTER_ESP = 0x00006824,
	GUEST_SYSENTER_EIP = 0x00006826,
	HOST_CR0 = 0x00006c00,
	HOST_CR3 = 0x00006c02,
	HOST_CR4 = 0x00006c04,
	HOST_FS_BASE = 0x00006c06,
	HOST_GS_BASE = 0x00006c08,
	HOST_TR_BASE = 0x00006c0a,
	HOST_GDTR_BASE = 0x00006c0c,
	HOST_IDTR_BASE = 0x00006c0e,
	HOST_SYSENTER_ESP = 0x00006c10,
	HOST_SYSENTER_EIP = 0x00006c12,
	HOST_RSP = 0x00006c14,
	HOST_RIP = 0x00006c16,
};

// See: VMX BASIC EXIT REASONS
// VM-exit 异常信息定义 (参考 【处理器虚拟化技术】(第3.10.1.2节))
enum VmxExitReason
{
	//软件异常导致的,要求异常位图中设置;出现了不可屏蔽中断Nmi并且要求vm执行域的NmiExit置1
	ExitExceptionOrNmi = 0,
	//An external interrupt arrived and the “external-interrupt exiting” VM-execution control was 1.
	ExitExternalInterrupt = 1,
	//3重异常,对它的处理直接蓝屏;The logical processor encountered an exception while attempting to call the double-fault handler and that exception did not itself cause a VM exit due to the exception bitmap
	ExitTripleFault = 2,


	//这几个没有控制域来进行关闭,但很少发生
	//An INIT signal arrived
	ExitInit = 3,
	//A SIPI arrived while the logical processor was in the “wait-for-SIPI” state.
	ExitSipi = 4,
	//An SMI arrived immediately after retirement of an I/O instruction and caused an SMM VM exit
	ExitIoSmi = 5,
	//An SMI arrived and caused an SMM VM exit (see Section 34.15.2) but not immediately after retirement of an I/O instruction
	ExitOtherSmi = 6,


	//At the beginning of an instruction, RFLAGS.IF was 1; events were not blocked by STI or by MOV SS; and the “interrupt-window exiting” VM-execution control was 1.
	ExitPendingInterrupt = 7,
	//At the beginning of an instruction, there was no virtual-NMI blocking; events were not blocked by MOV SS; and the “NMI-window exiting” VM-execution control was 1.
	ExitNmiWindow = 8,

	//必须处理 由指令引发的无条件vmexit,也无法在控制域中关闭
	// Guest software attempted a task switch.
	ExitTaskSwitch = 9,
	ExitCpuid = 10,
	ExitGetSec = 11,

	//Guest software attempted to execute HLT and the “HLT exiting” VM-execution control was 1.
	ExitHlt = 12,


	//必须处理  Guest software attempted to execute INVD.无法在控制域中关闭
	ExitInvd = 13,

	//Guest software attempted to execute INVLPG and the “INVLPG exiting” VM-execution control was 1.
	ExitInvlpg = 14,
	//Guest software attempted to execute RDPMC and the “RDPMC exiting” VM-execution control was 1.
	ExitRdpmc = 15,
	//Guest software attempted to execute RDTSC and the “RDTSC exiting” VM-execution control was 1.
	ExitRdtsc = 16,


	//Guest software attempted to execute RSM in SMM.直接忽略
	ExitRsm = 17,

	//必须处理 
	ExitVmcall = 18,
	ExitVmclear = 19,
	ExitVmlaunch = 20,
	ExitVmptrld = 21,
	ExitVmptrst = 22,
	ExitVmread = 23,
	ExitVmresume = 24,
	ExitVmwrite = 25,
	ExitVmoff = 26,
	ExitVmon = 27,

	//Guest software attempted to access CR0, CR3, CR4, or CR8 using CLTS, LMSW, or MOV CR and the VM-execution control fields 
	//indicate that a VM exit should occur (see Section 25.1 for details). This basic exit reason is not used for trap-like VM exits 
	//following executions of the MOV to CR8 instruction when the “use TPR shadow” VM-execution control is 1.
	//Such VM exits instead use basic exit reason 43.
	ExitCrAccess = 28,
	//Guest software attempted a MOV to or from a debug register and the “MOV-DR exiting” VM-execution control was 1.
	ExitDrAccess = 29,

	//io指令和msr访问都可以进行禁用.这里需要将use I/O bitmaps域置0,并且unconditional I/O exiting置0
	//IN, INS/INSB/INSW/INSD, OUT, OUTS/OUTSB/OUTSW/OUTSD
	//Guest software attempted to execute an I/O instruction and either: 1: The “use I/O bitmaps” VM-execution control was 0 
	//and the “unconditional I/O exiting” VM-execution control was 1. 2: The “use I/O bitmaps” VM-execution control was 1 
	//and a bit in the I/O bitmap associated with one of the ports accessed by the I/O instruction was 1.
	ExitIoInstruction = 30,

	//同理,禁用方式如上
	//Guest software attempted to execute RDMSR and either: 1: The “use MSR bitmaps” VM-execution control was 0. 
	//2: The value of RCX is neither in the range 00000000H – 00001FFFH nor in the range C0000000H – C0001FFFH. 越界意味着#GP异常
	//3: The value of RCX was in the range 00000000H – 00001FFFH and the nth bit in read bitmap for low MSRs is 1, where n was the value of RCX.
	//4: The value of RCX is in the range C0000000H – C0001FFFH and the nth bit in read bitmap for high MSRs is 1, where n is the value of RCX & 00001FFFH.
	ExitMsrRead = 31,
	ExitMsrWrite = 32,

	//致命错误 A VM entry failed one of the checks identified in Section 26.3.1.
	ExitInvalidGuestState = 33,  // See: BASIC VM-ENTRY CHECKS
	//A VM entry failed in an attempt to load MSRs. 
	ExitMsrLoading = 34,
	ExitUndefined35 = 35,
	//Guest software attempted to execute MWAIT and the “MWAIT exiting” VM-execution control was 1.
	ExitMwaitInstruction = 36,
	//A VM entry occurred due to the 1-setting of the “monitor trap flag” VM-execution control and injection of an MTF VM exit as part of VM entry.
	ExitMonitorTrapFlag = 37,
	ExitUndefined38 = 38,
	//Guest software attempted to execute MONITOR and the “MONITOR exiting” VM-execution control was 1.
	ExitMonitorInstruction = 39,
	//Either guest software attempted to execute PAUSE and the “PAUSE exiting” VM-execution control was 1 or 
	//the “PAUSE-loop exiting” VM-execution control was 1 and guest software executed a PAUSE loop with execution time exceeding PLE_Window
	ExitPauseInstruction = 40,
	//致命错误A machine-check event occurred during VM entry
	ExitMachineCheck = 41,
	ExitUndefined42 = 42,
	//The logical processor determined that the value of bits 7:4 of the byte at offset 080H on the virtual-APIC page 
	//was below that of the TPR threshold VM-execution control field while the “use TPR shadow” VMexecution control was 1 either as part of TPR virtualization (Section 29.1.2) or VM entry 
	ExitTprBelowThreshold = 43,
	//Guest software attempted to access memory at a physical address on the APIC-access page 
	//and the “virtualize APIC accesses” VM-execution control was 1
	ExitApicAccess = 44,
	//EOI virtualization was performed for a virtual interrupt whose vector indexed a bit set in the EOIexit bitmap
	ExitVirtualizedEoi = 45,
	//Guest software attempted to execute LGDT, LIDT, SGDT, or SIDT and the “descriptor-table exiting” VM-execution control was 1.
	ExitGdtrOrIdtrAccess = 46,
	//Guest software attempted to execute LLDT, LTR, SLDT, or STR and the “descriptor-table exiting” VM-execution control was 1
	ExitLdtrOrTrAccess = 47,
	//An attempt to access memory with a guest-physical address was disallowed by the configuration of the EPT paging structures.
	ExitEptViolation = 48,
	//致命错误An attempt to access memory with a guest-physical address encountered a misconfigured EPT paging-structure entry.
	ExitEptMisconfig = 49,
	//必须处理 Guest software attempted to execute INVEPT.
	ExitInvept = 50,
	//Guest software attempted to execute RDTSCP and the “enable RDTSCP” and “RDTSC exiting” VM-execution controls were both 1.
	ExitRdtscp = 51,
	//The preemption timer counted down to zero.
	ExitVmxPreemptionTime = 52,
	//必须处理 Guest software attempted to execute INVVPID.
	ExitInvvpid = 53,
	//Guest software attempted to execute WBINVD and the “WBINVD exiting” VM-execution control was 1.
	ExitWbinvd = 54,
	//必须处理 Guest software attempted to execute XSETBV.
	ExitXsetbv = 55,
	//Guest software completed a write to the virtual-APIC page that must be virtualized by VMM software
	ExitApicWrite = 56,
	//Guest software attempted to execute RDRAND and the “RDRAND exiting” VM-execution control was 1.
	ExitRdrand = 57,
	//Guest software attempted to execute INVPCID and the “enable INVPCID” and “INVLPG exiting” VM-execution controls were both 1.
	ExitInvpcid = 58,
	//可以关闭 Guest software invoked a VM function with the VMFUNC instruction and the VM function 
	//either was not enabled or generated a function-specific condition causing a VM exit.
	ExitVmfunc = 59,
	//可以关闭 Guest software attempted to execute ENCLS and “enable ENCLS exiting” VM-execution control was 1 and either (1) EAX < 63 
	//and the corresponding bit in the ENCLS-exiting bitmap is 1; or (2) EAX ≥ 63 and bit 63 in the ENCLS-exiting bitmap is 1
	ExitUndefined60 = 60,
	//可以关闭 Guest software attempted to execute RDSEED and the “RDSEED exiting” VM-execution control was 1.
	ExitRdseed = 61,
	//The processor attempted to create a page-modification log entry and the value of the PML index was not in the range 0–511.
	ExitUndefined62 = 62,
	//可以关闭 Guest software attempted to execute XSAVES, the “enable XSAVES/XRSTORS” was 1, 
	//and a bit was set in the logical-AND of the following three values: EDX:EAX, the IA32_XSS MSR, and the XSS-exiting bitmap.
	ExitXsaves = 63,
	//可以关闭 Guest software attempted to execute XRSTORS, the “enable XSAVES/XRSTORS” was 1, 
	//and a bit was set in the logical-AND of the following three values: EDX:EAX, the IA32_XSS MSR, and the XSS-exiting bitmap.
	ExitXrstors = 64,
};

// See: Format of the VM-Exit Interruption-Information Field
// (直接向量事件类含义, 请参考【处理器虚拟化技术】(第3.10.2节、3.10.3.1节))
// 定义 instruction 字段结构体 (参考白皮书 Vol. 3C 24-23,【处理器虚拟化技术】(第3.10.2.1节))
typedef union _VmxExitInterruptInfo
{
	ULONG32 all;
	struct {
		ULONG32 vector : 8;             //!< [0:7]		记录异常或中断的向量号
		ULONG32 interruption_type : 3;  //!< [8:10]		中断类型 (0-外部中断; 1-保留; 2-NMI; 3-硬件异常; 4-保留; 5-保留; 6-软件异常; 7-保留)
		ULONG32 error_code_valid : 1;   //!< [11]		为 1 时，有错误码 (外部中断、NMI及软件异常并不存在错误码)
		ULONG32 nmi_unblocking : 1;     //!< [12]		为 1 时, 表示"blocaking by NMI"被解除
		ULONG32 reserved : 18;          //!< [13:30]	为 0
		ULONG32 valid : 1;              //!< [31]		为 1 时， VM-Exit Interruption-Information 字段有效
	}fields;
}VmxExitInterruptInfo, * pVmxExitInterruptInfo;

union PageFaultErrorCode {
	ULONG32 all;
	struct {
		ULONG32 present : 1;		//!< [0] 0 - 该错误是由于访问不存在页面导致的; 1 - 该错误是由于页面级别保护导致的
		ULONG32 read_write : 1;		//!< [1] 0 - 导致故障的访问是读取; 1 - 导致故障的访问是写入
		ULONG32 user : 1;			//!< [2] 0 - 该错误发生在非 UserMode 下; 1 - 该错误发生在 UserMode 下
		ULONG32 reserved1 : 1;		//!< [3]
		ULONG32 fetch : 1;			//!< [4] 0 - #PF 发生在fetch data时；1 - #PF 发生在fetch instruction
		ULONG32 protection_key : 1;	//!< [5] Protection Key induced fault.
		ULONG32 reserved2 : 9;		//!< [6:14]
		ULONG32 sgx_error : 1;		//!< [15]
	}fields;
};

enum MovCrAccessType {
	kMoveToCr = 0, // MOV crx, reg
	KMobeFromCr,   // MOV reg, crx
	kClts,
	kLmsw
};

typedef union _CrxVmExitQualification
{
	ULONG_PTR all;
	struct
	{
		ULONG_PTR crn : 4;				  //!< [0:3]	记录访问的控制寄存器
		ULONG_PTR access_type : 2;		  //!< [4:5]	访问类型 (MovCrAccessType)
		ULONG_PTR lmsw_operand_type : 1;  //!< [6]		LMSW指令的操作数类型
		ULONG_PTR reserved1 : 1;          //!< [7]		
		ULONG_PTR gp_register : 4;        //!< [8:11]	记录使用的通用寄存器
		ULONG_PTR reserved2 : 4;          //!< [12:15]	
		ULONG_PTR lmsw_source_data : 16;  //!< [16:31]	LMSW指令的源操作数
		ULONG_PTR reserved3 : 32;         //!< [32:63]
	}Bits;
}CrxVmExitQualification, * pCrxVmExitQualification;

// See: VPID AND EPT CAPABILITIES (请看白皮书 Vol. 3D A-7, 【处理器虚拟化技术】(157页))
typedef union _Ia32VmxEptVpidCapMsr
{
	unsigned __int64 all;
	struct {
		unsigned __int64 support_execute_only_pages : 1;                        //!< [0]    为1时, 允许 execeute-only
		unsigned __int64 reserved1 : 5;                                         //!< [1:5]  
		unsigned __int64 support_page_walk_length4 : 1;                         //!< [6]	支持4级页表
		unsigned __int64 reserved2 : 1;                                         //!< [7]	
		unsigned __int64 support_uncacheble_memory_type : 1;                    //!< [8]	EPT 允许使用 UC 类型(0),请参考【处理器虚拟化技术】(第4.4.1.3节)
		unsigned __int64 reserved3 : 5;                                         //!< [9:13] 
		unsigned __int64 support_write_back_memory_type : 1;                    //!< [14]	EPT 允许使用 WB 类型(6)
		unsigned __int64 reserved4 : 1;                                         //!< [15]
		unsigned __int64 support_pde_2mb_pages : 1;                             //!< [16]	EPT 支持2MB页面
		unsigned __int64 support_pdpte_1_gb_pages : 1;                          //!< [17]	EPT 支持1GB页面
		unsigned __int64 reserved5 : 2;                                         //!< [18:19]
		unsigned __int64 support_invept : 1;                                    //!< [20]	为1时, 支持 invept 指令
		unsigned __int64 support_accessed_and_dirty_flag : 1;                   //!< [21]	为1时, 支持 dirty 标志位
		unsigned __int64 reserved6 : 3;                                         //!< [22:24]
		unsigned __int64 support_single_context_invept : 1;                     //!< [25]	为1时, 支持 single-context invept
		unsigned __int64 support_all_context_invept : 1;                        //!< [26]	为1时, 支持 all-context invept
		unsigned __int64 reserved7 : 5;                                         //!< [27:31]
		unsigned __int64 support_invvpid : 1;                                   //!< [32]	为1时, 支持 invvpid 指令
		unsigned __int64 reserved8 : 7;                                         //!< [33:39]
		unsigned __int64 support_individual_address_invvpid : 1;                //!< [40]	为1时, 支持 individual-address invvpid 指令
		unsigned __int64 support_single_context_invvpid : 1;                    //!< [41]	为1时, 支持 single-context invvpid 指令
		unsigned __int64 support_all_context_invvpid : 1;                       //!< [42]	为1时, 支持 all-context invvpid 指令
		unsigned __int64 support_single_context_retaining_globals_invvpid : 1;  //!< [43]	为1时, 支持 single-context-retaining-globals invvpid
		unsigned __int64 reserved9 : 20;                                        //!< [44:63]
	}fields;
}Ia32VmxEptVpidCapMsr, * pIa32VmxEptVpidCapMsr;

typedef union _Ia32MtrrDefTypeRegister
{
	struct
	{
		UINT64 DefaultMemoryType : 3;
		UINT64 Reserved1 : 7;
		UINT64 FixedRangeMtrrEnable : 1;
		UINT64 MtrrEnable : 1;
		UINT64 Reserved2 : 52;
	};

	UINT64 Flags;
} Ia32MtrrDefTypeRegister, * pIa32MtrrDefTypeRegister;

typedef struct _SHV_MTRR_RANGE
{
	UINT32 Enabled;
	UINT32 Type;
	UINT64 PhysicalAddressMin;
	UINT64 PhysicalAddressMax;
} SHV_MTRR_RANGE, * PSHV_MTRR_RANGE;

typedef struct _MTRR_CAPABILITIES
{
	union
	{
		struct
		{
			UINT64 VarCnt : 8;
			UINT64 FixedSupported : 1;
			UINT64 Reserved : 1;
			UINT64 WcSupported : 1;
			UINT64 SmrrSupported : 1;
			UINT64 Reserved_2 : 52;
		} u;
		UINT64 AsUlonglong;
	};
} MTRR_CAPABILITIES, * PMTRR_CAPABILITIES;

typedef struct _MTRR_VARIABLE_BASE
{
	union
	{
		struct
		{
			UINT64 Type : 8;
			UINT64 Reserved : 4;
			UINT64 PhysBase : 36;
			UINT64 Reserved2 : 16;
		} u;
		UINT64 AsUlonglong;
	};
} MTRR_VARIABLE_BASE, * PMTRR_VARIABLE_BASE;

typedef struct _MTRR_VARIABLE_MASK
{
	union
	{
		struct
		{
			UINT64 Reserved : 11;
			UINT64 Enabled : 1;
			UINT64 PhysMask : 36;
			UINT64 Reserved2 : 16;
		} u;
		UINT64 AsUlonglong;
	};
} MTRR_VARIABLE_MASK, * PMTRR_VARIABLE_MASK;

typedef union _EPML4E
{
	struct
	{
		/**
		 * @brief [Bit 0] Read access; indicates whether reads are allowed from the 512-GByte region controlled by this entry.
		 */
		UINT64 ReadAccess : 1;

		/**
		 * @brief [Bit 1] Write access; indicates whether writes are allowed from the 512-GByte region controlled by this entry.
		 */
		UINT64 WriteAccess : 1;

		/**
		 * @brief [Bit 2] If the "mode-based execute control for EPT" VM-execution control is 0, execute access; indicates whether
		 * instruction fetches are allowed from the 512-GByte region controlled by this entry.
		 * If that control is 1, execute access for supervisor-mode linear addresses; indicates whether instruction fetches are
		 * allowed from supervisor-mode linear addresses in the 512-GByte region controlled by this entry.
		 */
		UINT64 ExecuteAccess : 1;
		UINT64 Reserved1 : 5;

		/**
		 * @brief [Bit 8] If bit 6 of EPTP is 1, accessed flag for EPT; indicates whether software has accessed the 512-GByte region
		 * controlled by this entry. Ignored if bit 6 of EPTP is 0.
		 *
		 * @see Vol3C[28.2.4(Accessed and Dirty Flags for EPT)]
		 */
		UINT64 Accessed : 1;
		UINT64 Reserved2 : 1;

		/**
		 * @brief [Bit 10] Execute access for user-mode linear addresses. If the "mode-based execute control for EPT" VM-execution control
		 * is 1, indicates whether instruction fetches are allowed from user-mode linear addresses in the 512-GByte region
		 * controlled by this entry. If that control is 0, this bit is ignored.
		 */
		UINT64 UserModeExecute : 1;
		UINT64 Reserved3 : 1;

		/**
		 * @brief [Bits 47:12] Physical address of 4-KByte aligned EPT page-directory-pointer table referenced by this entry.
		 */
		UINT64 PageFrameNumber : 36;
		UINT64 Reserved4 : 16;
	};

	UINT64 Flags;
} EPML4E, * PEPML4E;

typedef union _EPDPTE_1GB
{
	struct
	{
		/**
		 * @brief [Bit 0] Read access; indicates whether reads are allowed from the 1-GByte page referenced by this entry.
		 */
		UINT64 ReadAccess : 1;

		/**
		 * @brief [Bit 1] Write access; indicates whether writes are allowed from the 1-GByte page referenced by this entry.
		 */
		UINT64 WriteAccess : 1;

		/**
		 * @brief [Bit 2] If the "mode-based execute control for EPT" VM-execution control is 0, execute access; indicates whether
		 * instruction fetches are allowed from the 1-GByte page controlled by this entry.
		 * If that control is 1, execute access for supervisor-mode linear addresses; indicates whether instruction fetches are
		 * allowed from supervisor-mode linear addresses in the 1-GByte page controlled by this entry.
		 */
		UINT64 ExecuteAccess : 1;

		/**
		 * @brief [Bits 5:3] EPT memory type for this 1-GByte page.
		 *
		 * @see Vol3C[28.2.6(EPT and memory Typing)]
		 */
		UINT64 MemoryType : 3;

		/**
		 * @brief [Bit 6] Ignore PAT memory type for this 1-GByte page.
		 *
		 * @see Vol3C[28.2.6(EPT and memory Typing)]
		 */
		UINT64 IgnorePat : 1;

		/**
		 * @brief [Bit 7] Must be 1 (otherwise, this entry references an EPT page directory).
		 */
		UINT64 LargePage : 1;

		/**
		 * @brief [Bit 8] If bit 6 of EPTP is 1, accessed flag for EPT; indicates whether software has accessed the 1-GByte page
		 * referenced by this entry. Ignored if bit 6 of EPTP is 0.
		 *
		 * @see Vol3C[28.2.4(Accessed and Dirty Flags for EPT)]
		 */
		UINT64 Accessed : 1;

		/**
		 * @brief [Bit 9] If bit 6 of EPTP is 1, dirty flag for EPT; indicates whether software has written to the 1-GByte page referenced
		 * by this entry. Ignored if bit 6 of EPTP is 0.
		 *
		 * @see Vol3C[28.2.4(Accessed and Dirty Flags for EPT)]
		 */
		UINT64 Dirty : 1;

		/**
		 * @brief [Bit 10] Execute access for user-mode linear addresses. If the "mode-based execute control for EPT" VM-execution control
		 * is 1, indicates whether instruction fetches are allowed from user-mode linear addresses in the 1-GByte page controlled
		 * by this entry. If that control is 0, this bit is ignored.
		 */
		UINT64 UserModeExecute : 1;
		UINT64 Reserved1 : 19;

		/**
		 * @brief [Bits 47:30] Physical address of 4-KByte aligned EPT page-directory-pointer table referenced by this entry.
		 */
		UINT64 PageFrameNumber : 18;
		UINT64 Reserved2 : 15;

		/**
		 * @brief [Bit 63] Suppress \#VE. If the "EPT-violation \#VE" VM-execution control is 1, EPT violations caused by accesses to this
		 * page are convertible to virtualization exceptions only if this bit is 0. If "EPT-violation \#VE" VMexecution control is
		 * 0, this bit is ignored.
		 *
		 * @see Vol3C[25.5.6.1(Convertible EPT Violations)]
		 */
		UINT64 SuppressVe : 1;
	};

	UINT64 Flags;
} EPDPTE_1GB, * PEPDPTE_1GB;

typedef union _EPDPTE
{
	struct
	{
		/**
		 * @brief [Bit 0] Read access; indicates whether reads are allowed from the 1-GByte region controlled by this entry.
		 */
		UINT64 ReadAccess : 1;

		/**
		 * @brief [Bit 1] Write access; indicates whether writes are allowed from the 1-GByte region controlled by this entry.
		 */
		UINT64 WriteAccess : 1;

		/**
		 * @brief [Bit 2] If the "mode-based execute control for EPT" VM-execution control is 0, execute access; indicates whether
		 * instruction fetches are allowed from the 1-GByte region controlled by this entry.
		 * If that control is 1, execute access for supervisor-mode linear addresses; indicates whether instruction fetches are
		 * allowed from supervisor-mode linear addresses in the 1-GByte region controlled by this entry.
		 */
		UINT64 ExecuteAccess : 1;
		UINT64 Reserved1 : 5;

		/**
		 * @brief [Bit 8] If bit 6 of EPTP is 1, accessed flag for EPT; indicates whether software has accessed the 1-GByte region
		 * controlled by this entry. Ignored if bit 6 of EPTP is 0.
		 *
		 * @see Vol3C[28.2.4(Accessed and Dirty Flags for EPT)]
		 */
		UINT64 Accessed : 1;
		UINT64 Reserved2 : 1;

		/**
		 * @brief [Bit 10] Execute access for user-mode linear addresses. If the "mode-based execute control for EPT" VM-execution control
		 * is 1, indicates whether instruction fetches are allowed from user-mode linear addresses in the 1-GByte region controlled
		 * by this entry. If that control is 0, this bit is ignored.
		 */
		UINT64 UserModeExecute : 1;
		UINT64 Reserved3 : 1;

		/**
		 * @brief [Bits 47:12] Physical address of 4-KByte aligned EPT page-directory-pointer table referenced by this entry.
		 */
		UINT64 PageFrameNumber : 36;
		UINT64 Reserved4 : 16;
	};

	UINT64 Flags;
} EPDPTE, * PEPDPTE;

typedef union _EPDE_2MB
{
	struct
	{
		/**
		 * @brief [Bit 0] Read access; indicates whether reads are allowed from the 2-MByte page referenced by this entry.
		 */
		UINT64 ReadAccess : 1;

		/**
		 * @brief [Bit 1] Write access; indicates whether writes are allowed from the 2-MByte page referenced by this entry.
		 */
		UINT64 WriteAccess : 1;

		/**
		 * @brief [Bit 2] If the "mode-based execute control for EPT" VM-execution control is 0, execute access; indicates whether
		 * instruction fetches are allowed from the 2-MByte page controlled by this entry.
		 * If that control is 1, execute access for supervisor-mode linear addresses; indicates whether instruction fetches are
		 * allowed from supervisor-mode linear addresses in the 2-MByte page controlled by this entry.
		 */
		UINT64 ExecuteAccess : 1;

		/**
		 * @brief [Bits 5:3] EPT memory type for this 2-MByte page.
		 *
		 * @see Vol3C[28.2.6(EPT and memory Typing)]
		 */
		UINT64 MemoryType : 3;

		/**
		 * @brief [Bit 6] Ignore PAT memory type for this 2-MByte page.
		 *
		 * @see Vol3C[28.2.6(EPT and memory Typing)]
		 */
		UINT64 IgnorePat : 1;

		/**
		 * @brief [Bit 7] Must be 1 (otherwise, this entry references an EPT page table).
		 */
		UINT64 LargePage : 1;

		/**
		 * @brief [Bit 8] If bit 6 of EPTP is 1, accessed flag for EPT; indicates whether software has accessed the 2-MByte page
		 * referenced by this entry. Ignored if bit 6 of EPTP is 0.
		 *
		 * @see Vol3C[28.2.4(Accessed and Dirty Flags for EPT)]
		 */
		UINT64 Accessed : 1;

		/**
		 * @brief [Bit 9] If bit 6 of EPTP is 1, dirty flag for EPT; indicates whether software has written to the 2-MByte page referenced
		 * by this entry. Ignored if bit 6 of EPTP is 0.
		 *
		 * @see Vol3C[28.2.4(Accessed and Dirty Flags for EPT)]
		 */
		UINT64 Dirty : 1;

		/**
		 * @brief [Bit 10] Execute access for user-mode linear addresses. If the "mode-based execute control for EPT" VM-execution control
		 * is 1, indicates whether instruction fetches are allowed from user-mode linear addresses in the 2-MByte page controlled
		 * by this entry. If that control is 0, this bit is ignored.
		 */
		UINT64 UserModeExecute : 1;
		UINT64 Reserved1 : 10;

		/**
		 * @brief [Bits 47:21] Physical address of 4-KByte aligned EPT page-directory-pointer table referenced by this entry.
		 */
		UINT64 PageFrameNumber : 27;
		UINT64 Reserved2 : 15;

		/**
		 * @brief [Bit 63] Suppress \#VE. If the "EPT-violation \#VE" VM-execution control is 1, EPT violations caused by accesses to this
		 * page are convertible to virtualization exceptions only if this bit is 0. If "EPT-violation \#VE" VMexecution control is
		 * 0, this bit is ignored.
		 *
		 * @see Vol3C[25.5.6.1(Convertible EPT Violations)]
		 */
		UINT64 SuppressVe : 1;
	};

	UINT64 Flags;
} EPDE_2MB, * PEPDE_2MB;

typedef union _EPDE
{
	struct
	{
		/**
		 * @brief [Bit 0] Read access; indicates whether reads are allowed from the 2-MByte region controlled by this entry.
		 */
		UINT64 ReadAccess : 1;

		/**
		 * @brief [Bit 1] Write access; indicates whether writes are allowed from the 2-MByte region controlled by this entry.
		 */
		UINT64 WriteAccess : 1;

		/**
		 * @brief [Bit 2] If the "mode-based execute control for EPT" VM-execution control is 0, execute access; indicates whether
		 * instruction fetches are allowed from the 2-MByte region controlled by this entry.
		 * If that control is 1, execute access for supervisor-mode linear addresses; indicates whether instruction fetches are
		 * allowed from supervisor-mode linear addresses in the 2-MByte region controlled by this entry.
		 */
		UINT64 ExecuteAccess : 1;
		UINT64 Reserved1 : 5;

		/**
		 * @brief [Bit 8] If bit 6 of EPTP is 1, accessed flag for EPT; indicates whether software has accessed the 2-MByte region
		 * controlled by this entry. Ignored if bit 6 of EPTP is 0.
		 *
		 * @see Vol3C[28.2.4(Accessed and Dirty Flags for EPT)]
		 */
		UINT64 Accessed : 1;
		UINT64 Reserved2 : 1;

		/**
		 * @brief [Bit 10] Execute access for user-mode linear addresses. If the "mode-based execute control for EPT" VM-execution control
		 * is 1, indicates whether instruction fetches are allowed from user-mode linear addresses in the 2-MByte region controlled
		 * by this entry. If that control is 0, this bit is ignored.
		 */
		UINT64 UserModeExecute : 1;
		UINT64 Reserved3 : 1;

		/**
		 * @brief [Bits 47:12] Physical address of 4-KByte aligned EPT page table referenced by this entry.
		 */
		UINT64 PageFrameNumber : 36;
		UINT64 Reserved4 : 16;
	};

	UINT64 Flags;
} EPDE, * PEPDE;

typedef union _EPTE
{
	struct
	{
		/**
		 * @brief [Bit 0] Read access; indicates whether reads are allowed from the 4-KByte page referenced by this entry.
		 */
		UINT64 ReadAccess : 1;

		/**
		 * @brief [Bit 1] Write access; indicates whether writes are allowed from the 4-KByte page referenced by this entry.
		 */
		UINT64 WriteAccess : 1;

		/**
		 * @brief [Bit 2] If the "mode-based execute control for EPT" VM-execution control is 0, execute access; indicates whether
		 * instruction fetches are allowed from the 4-KByte page controlled by this entry.
		 * If that control is 1, execute access for supervisor-mode linear addresses; indicates whether instruction fetches are
		 * allowed from supervisor-mode linear addresses in the 4-KByte page controlled by this entry.
		 */
		UINT64 ExecuteAccess : 1;

		/**
		 * @brief [Bits 5:3] EPT memory type for this 4-KByte page.
		 *
		 * @see Vol3C[28.2.6(EPT and memory Typing)]
		 */
		UINT64 MemoryType : 3;

		/**
		 * @brief [Bit 6] Ignore PAT memory type for this 4-KByte page.
		 *
		 * @see Vol3C[28.2.6(EPT and memory Typing)]
		 */
		UINT64 IgnorePat : 1;
		UINT64 Reserved1 : 1;

		/**
		 * @brief [Bit 8] If bit 6 of EPTP is 1, accessed flag for EPT; indicates whether software has accessed the 4-KByte page
		 * referenced by this entry. Ignored if bit 6 of EPTP is 0.
		 *
		 * @see Vol3C[28.2.4(Accessed and Dirty Flags for EPT)]
		 */
		UINT64 Accessed : 1;

		/**
		 * @brief [Bit 9] If bit 6 of EPTP is 1, dirty flag for EPT; indicates whether software has written to the 4-KByte page referenced
		 * by this entry. Ignored if bit 6 of EPTP is 0.
		 *
		 * @see Vol3C[28.2.4(Accessed and Dirty Flags for EPT)]
		 */
		UINT64 Dirty : 1;

		/**
		 * @brief [Bit 10] Execute access for user-mode linear addresses. If the "mode-based execute control for EPT" VM-execution control
		 * is 1, indicates whether instruction fetches are allowed from user-mode linear addresses in the 4-KByte page controlled
		 * by this entry. If that control is 0, this bit is ignored.
		 */
		UINT64 UserModeExecute : 1;
		UINT64 Reserved2 : 1;

		/**
		 * @brief [Bits 47:12] Physical address of the 4-KByte page referenced by this entry.
		 */
		UINT64 PageFrameNumber : 36;
		UINT64 Reserved3 : 15;

		/**
		 * @brief [Bit 63] Suppress \#VE. If the "EPT-violation \#VE" VM-execution control is 1, EPT violations caused by accesses to this
		 * page are convertible to virtualization exceptions only if this bit is 0. If "EPT-violation \#VE" VMexecution control is
		 * 0, this bit is ignored.
		 *
		 * @see Vol3C[25.5.6.1(Convertible EPT Violations)]
		 */
		UINT64 SuppressVe : 1;
	};

	UINT64 Flags;
} EPTE, * PEPTE;

typedef union _HvEptp
{
	struct
	{
		/**
		 * @brief [Bits 2:0] EPT paging-structure memory type:
		 * - 0 = Uncacheable (UC)
		 * - 6 = Write-back (WB)
		 * Other values are reserved.
		 *
		 * @see Vol3C[28.2.6(EPT and memory Typing)]
		 */
		UINT64 MemoryType : 3;

		/**
		 * @brief [Bits 5:3] This value is 1 less than the EPT page-walk length.
		 *
		 * @see Vol3C[28.2.6(EPT and memory Typing)]
		 */
		UINT64 PageWalkLength : 3;

		/**
		 * @brief [Bit 6] Setting this control to 1 enables accessed and dirty flags for EPT.
		 *
		 * @see Vol3C[28.2.4(Accessed and Dirty Flags for EPT)]
		 */
		UINT64 EnableAccessAndDirtyFlags : 1;
		UINT64 Reserved1 : 5;

		/**
		 * @brief [Bits 47:12] Bits N-1:12 of the physical address of the 4-KByte aligned EPT PML4 table.
		 */
		UINT64 PageFrameNumber : 36;
		UINT64 Reserved2 : 16;
	};

	UINT64 Flags;
} HvEptp, * pHvEptp;

typedef union _EptAttributePae {

	struct
	{
		ULONGLONG Read : 1;      //0读
		ULONGLONG Write : 1;     //1写
		ULONGLONG Execute : 1;  //2执行
		ULONGLONG ReadAble : 1; //3为1时表表示GPA可读
		ULONGLONG WriteAble : 1;   //4为1时表表示GPA可写
		ULONGLONG ExecuteAble : 1;//5为1时表表示GPA可执行
		ULONGLONG reserved : 1;//// 6保留
		ULONGLONG Valid : 1;//为1时 7表明存在一个线性地址
		ULONGLONG TranSlation : 1;////8为1时表面EPT VIOLATION发生在GPA转HPA 为0表明发生在对guest paging-stucture表现访问环节
		ULONGLONG reserved2 : 1;//9保留 为0
		ULONGLONG NMIunblocking : 1;//10为1表明执行啦IRET指令，并且NMI阻塞已经解除
		ULONGLONG reserved3 : 1;//11
		ULONGLONG reserved4 : 13;//23:11
		ULONGLONG GET_PTE : 1;//24
		ULONGLONG GET_PAGE_FRAME : 1;//25
		ULONGLONG FIX_ACCESS : 1;//26为1时 进行access ringht修复工作
		ULONGLONG FIX_MISCONF : 1;//27为1时 进行misconfiguration修复工作
		ULONGLONG FIX_FIXING : 1;//28为1时 修复 为0映射
		ULONGLONG EPT_FORCE : 1;//29为1时 强制进行映射
		ULONGLONG reserved5 : 1;
	};

	ULONGLONG Flag;
} EptAttributePae, * pEptAttributePae;

// Split 2MB granularity to 4 KB granularity
typedef struct _EPT_DYNAMIC_SPLIT
{
	DECLSPEC_ALIGN(PAGE_SIZE)
		EPTE PTT[PTE_ENTRY_COUNT];

	union
	{
		PEPDE_2MB		Entry;
		PEPDE			Pointer;
	};

	BOOLEAN IsUse;
} EPT_DYNAMIC_SPLIT, * PEPT_DYNAMIC_SPLIT;

#pragma pack(pop)

typedef struct _GuestReg
{
	ULONG64 Rax;
	ULONG64 Rcx;
	ULONG64 Rdx;
	ULONG64 Rbx;
	ULONG64 Rsp;
	ULONG64 Rbp;
	ULONG64 Rsi;
	ULONG64 Rdi;
	ULONG64 R8;
	ULONG64 R9;
	ULONG64 R10;
	ULONG64 R11;
	ULONG64 R12;
	ULONG64 R13;
	ULONG64 R14;
	ULONG64 R15;
	ULONG64 RMax;
}GuestReg, * pGuestReg;

typedef struct _HvEptEntry
{
	DECLSPEC_ALIGN(PAGE_SIZE) EPML4E	PML4T[PML4E_ENTRY_COUNT];
	DECLSPEC_ALIGN(PAGE_SIZE) EPDPTE	PDPT[PDPTE_ENTRY_COUNT];
	DECLSPEC_ALIGN(PAGE_SIZE) EPDE_2MB  PDT[PDPTE_ENTRY_COUNT][PDE_ENTRY_COUNT];
}HvEptEntry, * pHvEptEntry;

/* VMX  环境结构体 */
typedef struct _HvContextEntry
{
	ULONG		VmxCpuNumber;						// 当前 CPU 编号
	BOOLEAN		VmxOnOFF;							// Vmx 是否启动成功
	PVOID		VmxOnRegionLinerAddress;			// Vmx-On 区域虚拟地址
	PVOID		VmxCsRegionLinerAddress;			// Vmx-Cs 区域虚拟地址
	PVOID		VmxMsrBitMapRegionLinerAddress;		// Vmx-BitMap 区域虚拟地址
	PVOID		VmxStackRootRegionLinerAddress;		// Vmx-Stack 堆栈区域虚拟地址
	ULONG64		VmxOnRegionPhyAddress;				// Vmx-On 区域物理地址
	ULONG64		VmxCsRegionPhyAddress;				// Vmx-Cs 区域物理地址
	ULONG64		VmxMsrBitMapRegionPhyAddress;		// Vmx-BitMap 区域物理地址

	ULONG64		VmxGuestRsp;						// Guest 初始 Rsp
	ULONG64		VmxGuestRip;						// Guest 初始 Rip

	GUEST_STATE VmxGuestState;						// Vmx Guest 环境块
	HOST_STATE	VmxHostState;						// Vmx Host 环境块

	pHvEptEntry    VmxEpt;							// 存储EPT内存相关信息
	HvEptp		   VmxEptp;							// 存储EPTP相关信息

	EPT_DYNAMIC_SPLIT* DynSplits;					// EPT_DYNAMIC_SPLIT 结构体数组
	ULONG DynSplitCount;							// 已使用的EPT_DYNAMIC_SPLIT个数
}HvContextEntry, * pHvContextEntry;

typedef enum _PAGE_HOOK_STATE
{
	Ready    = 0,		// 就绪
	Activiti = 1,		// 激活
	Stop     = 2,		// 停止
} PAGE_HOOK_STATE;

typedef struct _PAGE_HOOK_CONTEXT
{
	LIST_ENTRY List;		// PAGE_HOOK_CONTEXT 链表

	BOOLEAN Hook;			// HOOK

	BOOLEAN NewPage;		// 是否为新页面
	PAGE_HOOK_STATE State;  // 状态

	ULONG64 DataPagePFN;    // Physical data page PFN
	ULONG64 CodePagePFN;    // Physical code page PFN

	ULONG64 DataPageBase;	// DATA PAGE 起始地址
	ULONG64 CodePageBase;	// CODE PAGE 起始地址
		
	ULONG64 HookAddress;	// HOOK 地址
	ULONG64 DetourAddress;	// 代理函数地址

	ULONG32 HookSize;		// HOOK 所需要的字节数

	ULONG64 OriFunc;		// 原函数流程

	ULONG64 Cr3;			// 拥有者Cr3
}PAGE_HOOK_CONTEXT, * PPAGE_HOOK_CONTEXT;

typedef enum _PAGE_TYPE
{
	DATA_PAGE = 0,
	CODE_PAGE = 1,
} PAGE_TYPE;

#pragma pack(push, 1)
typedef struct _HOOK_SHELLCODE1
{
	UCHAR PushOp;           // 0x68
	ULONG AddressLow;       // 
	ULONG MovOp;            // 0x042444C7
	ULONG AddressHigh;      // 
	UCHAR RetOp;            // 0xC3
} HOOK_SHELLCODE1, * PHOOK_SHELLCODE1;
#pragma pack(pop)

typedef enum _EPT_ACCESS
{
	EPT_ACCESS_NONE = 0,
	EPT_ACCESS_READ = 1,
	EPT_ACCESS_WRITE = 2,
	EPT_ACCESS_EXEC = 4,
	EPT_ACCESS_RW = EPT_ACCESS_READ | EPT_ACCESS_WRITE,
	EPT_ACCESS_ALL = EPT_ACCESS_READ | EPT_ACCESS_WRITE | EPT_ACCESS_EXEC
} EPT_ACCESS;

typedef enum _INV_TYPE
{
	INV_INDIV_ADDR = 0,						// Invalidate a specific page
	INV_SINGLE_CONTEXT = 1,					// Invalidate one context (specific VPID)
	INV_ALL_CONTEXTS = 2,					// Invalidate all contexts (all VPIDs)
	INV_SINGLE_CONTEXT_RETAIN_GLOBALS = 3   // Invalidate a single VPID context retaining global mappings
} IVVPID_TYPE, INVEPT_TYPE;

typedef enum _SYSTEM_INFORMATION_CLASS
{
	SystemBasicInformation = 0x0,
	SystemProcessorInformation = 0x1,
	SystemPerformanceInformation = 0x2,
	SystemTimeOfDayInformation = 0x3,
	SystemPathInformation = 0x4,
	SystemProcessInformation = 0x5,
	SystemCallCountInformation = 0x6,
	SystemDeviceInformation = 0x7,
	SystemProcessorPerformanceInformation = 0x8,
	SystemFlagsInformation = 0x9,
	SystemCallTimeInformation = 0xa,
	SystemModuleInformation = 0xb,
	SystemLocksInformation = 0xc,
	SystemStackTraceInformation = 0xd,
	SystemPagedPoolInformation = 0xe,
	SystemNonPagedPoolInformation = 0xf,
	SystemHandleInformation = 0x10,
	SystemObjectInformation = 0x11,
	SystemPageFileInformation = 0x12,
	SystemVdmInstemulInformation = 0x13,
	SystemVdmBopInformation = 0x14,
	SystemFileCacheInformation = 0x15,
	SystemPoolTagInformation = 0x16,
	SystemInterruptInformation = 0x17,
	SystemDpcBehaviorInformation = 0x18,
	SystemFullMemoryInformation = 0x19,
	SystemLoadGdiDriverInformation = 0x1a,
	SystemUnloadGdiDriverInformation = 0x1b,
	SystemTimeAdjustmentInformation = 0x1c,
	SystemSummaryMemoryInformation = 0x1d,
	SystemMirrorMemoryInformation = 0x1e,
	SystemPerformanceTraceInformation = 0x1f,
	SystemObsolete0 = 0x20,
	SystemExceptionInformation = 0x21,
	SystemCrashDumpStateInformation = 0x22,
	SystemKernelDebuggerInformation = 0x23,
	SystemContextSwitchInformation = 0x24,
	SystemRegistryQuotaInformation = 0x25,
	SystemExtendServiceTableInformation = 0x26,
	SystemPrioritySeperation = 0x27,
	SystemVerifierAddDriverInformation = 0x28,
	SystemVerifierRemoveDriverInformation = 0x29,
	SystemProcessorIdleInformation = 0x2a,
	SystemLegacyDriverInformation = 0x2b,
	SystemCurrentTimeZoneInformation = 0x2c,
	SystemLookasideInformation = 0x2d,
	SystemTimeSlipNotification = 0x2e,
	SystemSessionCreate = 0x2f,
	SystemSessionDetach = 0x30,
	SystemSessionInformation = 0x31,
	SystemRangeStartInformation = 0x32,
	SystemVerifierInformation = 0x33,
	SystemVerifierThunkExtend = 0x34,
	SystemSessionProcessInformation = 0x35,
	SystemLoadGdiDriverInSystemSpace = 0x36,
	SystemNumaProcessorMap = 0x37,
	SystemPrefetcherInformation = 0x38,
	SystemExtendedProcessInformation = 0x39,
	SystemRecommendedSharedDataAlignment = 0x3a,
	SystemComPlusPackage = 0x3b,
	SystemNumaAvailableMemory = 0x3c,
	SystemProcessorPowerInformation = 0x3d,
	SystemEmulationBasicInformation = 0x3e,
	SystemEmulationProcessorInformation = 0x3f,
	SystemExtendedHandleInformation = 0x40,
	SystemLostDelayedWriteInformation = 0x41,
	SystemBigPoolInformation = 0x42,
	SystemSessionPoolTagInformation = 0x43,
	SystemSessionMappedViewInformation = 0x44,
	SystemHotpatchInformation = 0x45,
	SystemObjectSecurityMode = 0x46,
	SystemWatchdogTimerHandler = 0x47,
	SystemWatchdogTimerInformation = 0x48,
	SystemLogicalProcessorInformation = 0x49,
	SystemWow64SharedInformationObsolete = 0x4a,
	SystemRegisterFirmwareTableInformationHandler = 0x4b,
	SystemFirmwareTableInformation = 0x4c,
	SystemModuleInformationEx = 0x4d,
	SystemVerifierTriageInformation = 0x4e,
	SystemSuperfetchInformation = 0x4f,
	SystemMemoryListInformation = 0x50,
	SystemFileCacheInformationEx = 0x51,
	SystemThreadPriorityClientIdInformation = 0x52,
	SystemProcessorIdleCycleTimeInformation = 0x53,
	SystemVerifierCancellationInformation = 0x54,
	SystemProcessorPowerInformationEx = 0x55,
	SystemRefTraceInformation = 0x56,
	SystemSpecialPoolInformation = 0x57,
	SystemProcessIdInformation = 0x58,
	SystemErrorPortInformation = 0x59,
	SystemBootEnvironmentInformation = 0x5a,
	SystemHypervisorInformation = 0x5b,
	SystemVerifierInformationEx = 0x5c,
	SystemTimeZoneInformation = 0x5d,
	SystemImageFileExecutionOptionsInformation = 0x5e,
	SystemCoverageInformation = 0x5f,
	SystemPrefetchPatchInformation = 0x60,
	SystemVerifierFaultsInformation = 0x61,
	SystemSystemPartitionInformation = 0x62,
	SystemSystemDiskInformation = 0x63,
	SystemProcessorPerformanceDistribution = 0x64,
	SystemNumaProximityNodeInformation = 0x65,
	SystemDynamicTimeZoneInformation = 0x66,
	SystemCodeIntegrityInformation = 0x67,
	SystemProcessorMicrocodeUpdateInformation = 0x68,
	SystemProcessorBrandString = 0x69,
	SystemVirtualAddressInformation = 0x6a,
	SystemLogicalProcessorAndGroupInformation = 0x6b,
	SystemProcessorCycleTimeInformation = 0x6c,
	SystemStoreInformation = 0x6d,
	SystemRegistryAppendString = 0x6e,
	SystemAitSamplingValue = 0x6f,
	SystemVhdBootInformation = 0x70,
	SystemCpuQuotaInformation = 0x71,
	SystemNativeBasicInformation = 0x72,
	SystemErrorPortTimeouts = 0x73,
	SystemLowPriorityIoInformation = 0x74,
	SystemBootEntropyInformation = 0x75,
	SystemVerifierCountersInformation = 0x76,
	SystemPagedPoolInformationEx = 0x77,
	SystemSystemPtesInformationEx = 0x78,
	SystemNodeDistanceInformation = 0x79,
	SystemAcpiAuditInformation = 0x7a,
	SystemBasicPerformanceInformation = 0x7b,
	SystemQueryPerformanceCounterInformation = 0x7c,
	SystemSessionBigPoolInformation = 0x7d,
	SystemBootGraphicsInformation = 0x7e,
	SystemScrubPhysicalMemoryInformation = 0x7f,
	SystemBadPageInformation = 0x80,
	SystemProcessorProfileControlArea = 0x81,
	SystemCombinePhysicalMemoryInformation = 0x82,
	SystemEntropyInterruptTimingInformation = 0x83,
	SystemConsoleInformation = 0x84,
	SystemPlatformBinaryInformation = 0x85,
	SystemThrottleNotificationInformation = 0x86,
	SystemHypervisorProcessorCountInformation = 0x87,
	SystemDeviceDataInformation = 0x88,
	SystemDeviceDataEnumerationInformation = 0x89,
	SystemMemoryTopologyInformation = 0x8a,
	SystemMemoryChannelInformation = 0x8b,
	SystemBootLogoInformation = 0x8c,
	SystemProcessorPerformanceInformationEx = 0x8d,
	SystemSpare0 = 0x8e,
	SystemSecureBootPolicyInformation = 0x8f,
	SystemPageFileInformationEx = 0x90,
	SystemSecureBootInformation = 0x91,
	SystemEntropyInterruptTimingRawInformation = 0x92,
	SystemPortableWorkspaceEfiLauncherInformation = 0x93,
	SystemFullProcessInformation = 0x94,
	SystemKernelDebuggerInformationEx = 0x95,
	SystemBootMetadataInformation = 0x96,
	SystemSoftRebootInformation = 0x97,
	SystemElamCertificateInformation = 0x98,
	SystemOfflineDumpConfigInformation = 0x99,
	SystemProcessorFeaturesInformation = 0x9a,
	SystemRegistryReconciliationInformation = 0x9b,
	SystemSupportedProcessArchitectures = 0xb5,
} SYSTEM_INFORMATION_CLASS, * PSYSTEM_INFORMATION_CLASS;
typedef struct _RTL_PROCESS_MODULE_INFORMATION {
	HANDLE Section;                 // Not filled in
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	CHAR  FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;
typedef struct _RTL_PROCESS_MODULES {
	ULONG_PTR NumberOfModules;
	RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;

typedef enum _PML
{
	PT = 0, // Page Table
	PD,     // Page Directory
	PDPT,   // Page Directory Pointer Table
	PML4    // Page Map Level 4
} PML;
typedef struct _PAGE_ENTRY
{
	union
	{
		UINT64 Flags;

		//
		// Common fields.
		//

		struct
		{
			UINT64 Present : 1;
			UINT64 Write : 1;
			UINT64 Supervisor : 1;
			UINT64 PageLevelWriteThrough : 1;
			UINT64 PageLevelCacheDisable : 1;
			UINT64 Accessed : 1;
			UINT64 Dirty : 1;
			UINT64 LargePage : 1;
			UINT64 Global : 1;
			UINT64 Ignored1 : 3;
			UINT64 PageFrameNumber : 36;
			UINT64 Reserved1 : 4;
			UINT64 Ignored2 : 7;
			UINT64 ProtectionKey : 4;
			UINT64 ExecuteDisable : 1;
		};
	};
} PAGE_ENTRY, * PPAGE_ENTRY;

/* 64bit 系统版本定义 */
enum SYSTEM_VERSION
{
	WINDOWS_7 = 7600,
	WINDOWS_7_SP1 = 7601,
	WINDOWS_10_1803 = 17134,
	WINDOWS_10_1809 = 17763,
	WINDOWS_10_1903 = 18362,
	WINDOWS_10_1909 = 18363,
	WINDOWS_10_2004 = 19041,
	WINDOWS_10_20H2 = 19042,
	WINDOWS_10_21H1 = 19043,
	WINDOWS_11 = 22200,
};