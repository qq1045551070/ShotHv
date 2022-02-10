#include "HvPch.h"

extern "C"
{
	void VmxExitHandler(_In_ GuestReg* Registers)
	{
		VmxExitInfo dwExitReason = { 0 };
		FlagReg GuestRflag = { 0 };

		dwExitReason.all = (ULONG32)VmxCsRead(VM_EXIT_REASON); // 获取 VM-exit 原因

		switch (dwExitReason.fields.reason)
		{
		case ExitExceptionOrNmi:	// 拦截 Nmi 中断(不可屏蔽)
			NmiExceptionVtExitHandler(Registers);
			break;
		case ExitExternalInterrupt: // 拦截外部中断(可屏蔽)
			break;
		case ExitCpuid:			// 拦截 cpuid
			CpuidVmExitHandler(Registers);
			break;
		case ExitRdtsc:			// 拦截 Rdtsc
			RdtscVtExitHandler(Registers);
			break;
		case ExitRdtscp:		// 拦截 Rdtscp
			RdtscpVtExitHandler(Registers);
			break;
		case ExitVmcall:		// 拦截 vmcall
			VmCallVmExitHandler(Registers);
			break;
		case ExitCrAccess:		// 拦截访问 CrX 寄存器
			CrAccessVtExitHandler(Registers);
			break;
		case ExitMsrRead:		// 拦截msr寄存器访问,必须设置,不然任何访msr的操作都会导致vmexit		
			MsrReadVtExitHandler(Registers);
			break;
		case ExitMsrWrite:		// 拦截msr寄存器 写入	
			MsrWriteVtExitHandler(Registers);
			break;
		case ExitMonitorTrapFlag: // MTF 异常
			MonitorTrapFlagVtExitHandler(Registers);
			break;
		case ExitGdtrOrIdtrAccess:	// 拦截 LGDT、LIDT、SGDT or SIDT 指令
			break;
		case ExitLdtrOrTrAccess:	// 拦截 LLDT, LTR, SLDT, or STR 指令
			break;
		case ExitEptViolation:		// EPT Violation 导致的 VM-EXIT
			EptViolationVtExitHandler(Registers);
			break;
		case ExitEptMisconfig:		// Ept 配置错误
			DBG_PRINT("ExitEptMisconfig!\r\n");
			DbgBreakPoint();
			break;
		case ExitTripleFault:		// 3重异常,对它的处理直接蓝屏;
			DBG_PRINT("ExitTripleFault 0x%llx!\r\n", VmxCsRead(GUEST_RIP));
			DbgBreakPoint();
			break;
		case ExitXsetbv:			// Win10 必须处理高速缓存
			_xsetbv((ULONG32)Registers->Rcx, MAKEQWORD(Registers->Rax, Registers->Rdx));
			break;
		case ExitInvd:
			__wbinvd();
			break;
		case ExitInvpcid:			// 服务器可能会用到
			ExitInvpcidVtExitHandler(Registers);
			break;
		case ExitVmclear:			// 不实现VT指令, 拒绝 VT 嵌套
		case ExitVmptrld:
		case ExitVmptrst:
		case ExitVmread:
		case ExitVmwrite:
		case ExitVmresume:
		case ExitVmoff:
		case ExitVmon:
		case ExitVmlaunch:
		case ExitVmfunc:
		case ExitInvept:
		case ExitInvvpid:
		{
			// 设置 Rflags 的 cf 位, 置为1(表明失败)
			GuestRflag.all = VmxCsRead(GUEST_RFLAGS);
			GuestRflag.fields.cf = 1;
			VmxCsWrite(GUEST_RFLAGS, GuestRflag.all);
			// 走默认流程
			DefaultVmExitHandler(Registers);
		}
		break;
		default:		// 默认例程
			DefaultVmExitHandler(Registers);
			DBG_PRINT("未知的 VM_EIXT 原因:0x%x\n", dwExitReason.all);
			break;
		}
		return;
	}

	void CpuidVmExitHandler(_In_ GuestReg* Registers)
	{
		CpuId dwCpuidRegisters = { 0 };

		switch (Registers->Rax)
		{
		case 0x1:
		{
			CpuidFeatureByEcx CpuidEcx = { 0 };
			__cpuidex((int*)&dwCpuidRegisters, (int)Registers->Rax, (int)Registers->Rcx);
			CpuidEcx.all = (ULONG_PTR)dwCpuidRegisters.ecx;
			CpuidEcx.fields.vmx = false; // 不支持虚拟化
			dwCpuidRegisters.ecx = CpuidEcx.all;
			Registers->Rax = (ULONG_PTR)dwCpuidRegisters.eax;
			Registers->Rbx = (ULONG_PTR)dwCpuidRegisters.ebx;
			Registers->Rcx = (ULONG_PTR)dwCpuidRegisters.ecx;
			Registers->Rdx = (ULONG_PTR)dwCpuidRegisters.edx;
		}
		break;
		case CupidHvCheck:
		{
			// 返回验证代码
			Registers->Rax = 'SBTX';
		}
		break;
		default:
		{
			// 默认正常流程
			__cpuidex((int*)&dwCpuidRegisters, (int)Registers->Rax, (int)Registers->Rcx);
			Registers->Rax = (ULONG_PTR)dwCpuidRegisters.eax;
			Registers->Rbx = (ULONG_PTR)dwCpuidRegisters.ebx;
			Registers->Rcx = (ULONG_PTR)dwCpuidRegisters.ecx;
			Registers->Rdx = (ULONG_PTR)dwCpuidRegisters.edx;
		}
		break;
		}

		// 走默认流程
		DefaultVmExitHandler(Registers);
	}

	void MsrReadVtExitHandler(_In_ GuestReg* Registers)
	{
		ULONGLONG MsrValue = __readmsr((ULONG)Registers->Rcx);
		switch (Registers->Rcx)
		{
		case MSR_LSTAR: // 读取 MSR RIP
		{
		}
		break;
		case MSR_IA32_EFER:
		{
			// EFER HOOK 注意 Hypervisor Guard
		}
		break;
		case MSR_IA32_FEATURE_CONTROL:
		{
			// 伪装MSR让系统认为BIOS并没有开启VT-x
			Ia32FeatureControlMsr FeatureControlMsr = { 0 };
			FeatureControlMsr.all = MsrValue;
			FeatureControlMsr.fields.lock = false;
			FeatureControlMsr.fields.enable_vmxon = false;
			MsrValue = FeatureControlMsr.all;
		}
		break;
		default:
			// 默认MSR正常流程
			break;
		}

		Registers->Rax = LODWORD(MsrValue);
		Registers->Rdx = HIDWORD(MsrValue);

		// 走默认流程
		DefaultVmExitHandler(Registers);

		return VOID();
	}

	void MsrWriteVtExitHandler(_In_ GuestReg* Registers)
	{
		ULONGLONG MsrValue = MAKEQWORD(Registers->Rax, Registers->Rdx);

		switch (Registers->Rcx)
		{
		case IA32_SYSENTER_EIP: // 写入 MSR 0x176
		case IA32_SYSENTER_ESP: // 写入 MSR 0x175
		case IA32_SYSENTER_CS:	// 写入 MSR 0x174
		default:
		{
			// 默认正常流程
			__writemsr((ULONG)Registers->Rcx, MsrValue);
		}
		break;
		}

		// 走默认流程
		DefaultVmExitHandler(Registers);

		return VOID();
	}

	void VmCallVmExitHandler(_In_ GuestReg* Registers)
	{
		ULONG_PTR jmpRip = 0;
		ULONG_PTR GuestRIP = 0, GuestRSP = 0;
		ULONG_PTR ExitInstructionLength = 0;
		HvContextEntry* VmxEntry = NULL;

		GuestRIP = VmxCsRead(GUEST_RIP);
		GuestRSP = VmxCsRead(GUEST_RSP);
		ExitInstructionLength = VmxCsRead(VM_EXIT_INSTRUCTION_LEN);
		VmxEntry = GetHvContextEntry();

		switch (Registers->Rax)
		{
		case CallHookPage:		// R0 HOOK
		{
			auto pHvContext = GetHvContextEntry();
			EptUpdateTable(
				pHvContext->VmxEpt,
				EPT_ACCESS_EXEC,
				MmGetPhysicalAddress((PVOID)Registers->Rdx).QuadPart,
				Registers->R8
			);
			__invept(INV_ALL_CONTEXTS, &pHvContext->VmxEptp.Flags);
		}
		break;
		case CallUnHookPage:	// R0 UNHOOK
		{
			auto pHvContext = GetHvContextEntry();
			EptUpdateTable(
				pHvContext->VmxEpt,
				EPT_ACCESS_ALL,
				MmGetPhysicalAddress((PVOID)Registers->Rdx).QuadPart,
				Registers->R8
			);
			__invept(INV_ALL_CONTEXTS, &pHvContext->VmxEptp.Flags);
		}
		break;
		case CallExitVt: // 退出当前虚拟化
		{
			DBG_PRINT("退出Intel VT!\r\n");
			
			// 复原寄存器
			HvRestoreRegisters();

			// 将 VMCS 的状态清除为非活动状态
			if (__vmx_vmclear(&VmxEntry->VmxCsRegionPhyAddress)) {
				__vmx_off();
			}

			// 退出当前虚拟化
			__vmx_off();

			VmxEntry->VmxOnOFF = FALSE;

			jmpRip = GuestRIP + ExitInstructionLength; // 越过产生 VM-EXIT 的指令

			// CR4.VMXE 置为 0
			__writecr4(__readcr4() & (~X86_CR4_VMXE));

			// 修改 Rsp\Rip 返回到 Guest 中
			AsmUpdateRspAndRip(GuestRSP, jmpRip);
		}
		break;
		default:
			break;
		}

		DefaultVmExitHandler(Registers);
	}

	void NmiExceptionVtExitHandler(_In_ GuestReg* Registers)
	{
		UNREFERENCED_PARAMETER(Registers);

		VmxExitInterruptInfo exception = { 0 }; // 定义直接向量事件
		InterruptionType interruption_type = InterruptionType::kExternalInterrupt; // 默认初始化
		InterruptionVector vector = InterruptionVector::EXCEPTION_VECTOR_DIVIDE_ERROR;
		ULONG32 error_code_valid = 0;

		/*
			"直接向量事件" 是指直接引发 VM-exit 的向量事件。包括以下三种：
			(1). 硬件异常：由于异常的向量号在 exception bitmap 对应的位为1而直接导致 VM-exit.
			(2). 软件异常(#BP与#OF)：由于异常的向量号在 exception bitmap 对应的位为1而直接导致 VM-exit.
			(3). 外部中断：发生外部中断请求时, 由于"exception-interrupt exiting"为1而直接导致 VM-exit.
			(4). NMI：发生NMI请求时, 由于"NMI exiting"为1而直接导致 VM-exit.
		*/

		// 处理中断时, 获取 VM-Exit Interruption-Information 字段
		exception.all = static_cast<ULONG32>(VmxCsRead(VM_EXIT_INTR_INFO));

		interruption_type = static_cast<InterruptionType>(exception.fields.interruption_type); // 获取中断类型
		vector = static_cast<InterruptionVector>(exception.fields.vector); // 获取中断向量号
		error_code_valid = exception.fields.error_code_valid; // 是否有错误码

		if (interruption_type == InterruptionType::kHardwareException)
		{
			// 如果是硬件异常, 处理其关于内存的异常
			if (vector == InterruptionVector::EXCEPTION_VECTOR_PAGE_FAULT)
			{

				// 如果为 #PF 异常
				// exit qualification 字段存储的是 #PF 异常的线性地址值 (参考【处理器虚拟化技术】(第3.10.1.6节))
				auto fault_address = VmxCsRead(EXIT_QUALIFICATION);

				// VM-exit interruption error code 字段指向的是 Page-Fault Error Code (参考【处理器虚拟化技术】(第3.10.2节))
				PageFaultErrorCode fault_code = { 0 };
				fault_code.all = static_cast<ULONG32>(VmxCsRead(VM_EXIT_INTR_ERROR_CODE));

				// 判断异常是否与Hook相关
				//auto ntStatus = intException::PfExceptionHandler(fault_address, fault_code);

				//if (!NT_SUCCESS(ntStatus))
				{
					// 默认不修改，重新注入回去
					InjectInterruption(interruption_type, vector, true, fault_code.all);

					// 注意同步 cr2 寄存器
					__writecr2(fault_address);

					VmxCsWrite(VM_ENTRY_INTR_INFO, exception.all);

					if (error_code_valid) {
						VmxCsWrite(VM_ENTRY_EXCEPTION_ERROR_CODE, VmxCsRead(VM_EXIT_INTR_ERROR_CODE));
					}
				}
			}
			else if (vector == InterruptionVector::EXCEPTION_VECTOR_GENERAL_PROTECTION) {
				// 如果为 #GP 异常

				auto error_code = VmxCsRead(VM_EXIT_INTR_ERROR_CODE);

				// 默认不修改，重新注入回去
				InjectInterruption(interruption_type, vector, true, (ULONG32)error_code);

			}
			else if (vector == InterruptionVector::EXCEPTION_VECTOR_INVALID_OPCODE) {
				// 如果是 #UD 异常

				// 默认注入 #UD		
				InjectInterruption(interruption_type, vector, false, 0);

			}
		}
		else if (interruption_type == InterruptionType::kSoftwareException) {
			// 如果是 软件异常
			if (vector == InterruptionVector::EXCEPTION_VECTOR_BREAKPOINT)
			{
				// #BP
				// int3 触发的软件异常, 注意此指令有长度

				// 默认不修改，重新注入回去
				InjectInterruption(interruption_type, vector, false, 0);
				auto exit_inst_length = VmxCsRead(VM_EXIT_INSTRUCTION_LEN); // 获取导致 VM-exit 的指令长度
				VmxCsWrite(VM_ENTRY_INSTRUCTION_LEN, exit_inst_length);
			}
		}
		else {
			VmxCsWrite(VM_ENTRY_INTR_INFO, exception.all);

			if (error_code_valid) {
				VmxCsWrite(VM_ENTRY_EXCEPTION_ERROR_CODE, VmxCsRead(VM_EXIT_INTR_ERROR_CODE));
			}
		}
	}

	void MonitorTrapFlagVtExitHandler(_In_ GuestReg* Registers)
	{
		UNREFERENCED_PARAMETER(Registers);

		DisableMTF();
	}

	void EptViolationVtExitHandler(_In_ GuestReg* Registers)
	{
		UNREFERENCED_PARAMETER(Registers);

		EptViolationHandler(Registers);
	}

	void RdtscVtExitHandler(_In_ GuestReg* Registers)
	{
		ULARGE_INTEGER tsc = { 0 };
		tsc.QuadPart = __rdtsc();
		Registers->Rdx = tsc.HighPart;
		Registers->Rax = tsc.LowPart;

		DefaultVmExitHandler(Registers);
	}

	void RdtscpVtExitHandler(_In_ GuestReg* Registers)
	{
		unsigned int tscAux = 0;
		ULARGE_INTEGER tsc = { 0 };
		tsc.QuadPart = __rdtscp(&tscAux);
		Registers->Rdx = tsc.HighPart;
		Registers->Rax = tsc.LowPart;
		Registers->Rcx = tscAux;

		DefaultVmExitHandler(Registers);
	}

	void CrAccessVtExitHandler(_In_ GuestReg* Registers)
	{
		CrxVmExitQualification CrxQualification = { 0 };
		CrxQualification.all = VmxCsRead(EXIT_QUALIFICATION); // 获取字段信息
		ULONG_PTR* pRegisters = (PULONG_PTR)Registers;

		switch (CrxQualification.Bits.access_type) {
		case MovCrAccessType::kMoveToCr: {
			switch (CrxQualification.Bits.crn) {
			case 0:
			{
				const Cr0Type cr0_fixed0 = { VmxCsRead(IA32_VMX_CR0_FIXED0) };
				const Cr0Type cr0_fixed1 = { VmxCsRead(IA32_VMX_CR0_FIXED1) };
				Cr0Type cr0 = { pRegisters[CrxQualification.Bits.gp_register] };
				cr0.all &= cr0_fixed1.all;
				cr0.all |= cr0_fixed0.all;
				VmxCsWrite(GUEST_CR0, cr0.all);
				VmxCsWrite(CR0_READ_SHADOW, cr0.all);
				break;
			}
			case 4: {
				const Cr4Type cr4_fixed0 = { VmxCsRead(IA32_VMX_CR4_FIXED0) };
				const Cr4Type cr4_fixed1 = { VmxCsRead(IA32_VMX_CR4_FIXED1) };
				Cr4Type cr4 = { pRegisters[CrxQualification.Bits.gp_register] };
				cr4.all &= cr4_fixed1.all;
				cr4.all |= cr4_fixed0.all;
				VmxCsWrite(GUEST_CR4, cr4.all);
				VmxCsWrite(CR4_READ_SHADOW, cr4.all);
				break;
			}
			}
			break;
		}
		}

		// 走默认流程
		DefaultVmExitHandler(Registers);
	}

	void ExitInvpcidVtExitHandler(_In_ GuestReg* Registers)
	{
		ULONG64 mrsp = 0;
		ULONG64 instinfo = 0;
		ULONG64 qualification = 0;
		__vmx_vmread(VMX_INSTRUCTION_INFO, &instinfo); //指令详细信息
		__vmx_vmread(EXIT_QUALIFICATION, &qualification); //偏移量
		__vmx_vmread(GUEST_RSP, &mrsp);

		pInvpCid pinfo = (pInvpCid)&instinfo;

		ULONG64 base = 0;
		ULONG64 index = 0;
		ULONG64 scale = pinfo->scale ? 2 ^ pinfo->scale : 0;
		ULONG64 addr = 0;
		ULONG64 regopt = ((PULONG64)Registers)[pinfo->regOpt];;

		if (!pinfo->baseInvaild)
		{
			if (pinfo->base == 4)
			{
				base = mrsp;
			}
			else
			{
				base = ((PULONG64)Registers)[pinfo->base];
			}
		}

		if (!pinfo->indexInvaild)
		{
			if (pinfo->index == 4)
			{
				index = mrsp;
			}
			else
			{
				index = ((PULONG64)Registers)[pinfo->index];
			}
		}

		if (pinfo->addrssSize == 0)
		{
			addr = *(PSHORT)(base + index * scale + qualification);
		}
		else if (pinfo->addrssSize == 1)
		{
			addr = *(PULONG)(base + index * scale + qualification);
		}
		else
		{
			addr = *(PULONG64)(base + index * scale + qualification);
		}

		_invpcid((UINT)regopt, &addr);
		
		DefaultVmExitHandler(Registers);
	}

	void DefaultVmExitHandler(_In_ GuestReg* Registers)
	{
		ULONG_PTR GuestRip = VmxCsRead(GUEST_RIP);
		ULONG_PTR GuestRsp = VmxCsRead(GUEST_RSP);
		ULONG_PTR ExitInstructionLength = VmxCsRead(VM_EXIT_INSTRUCTION_LEN); // 退出的指令长度

		UNREFERENCED_PARAMETER(Registers);

		VmxCsWrite(GUEST_RIP, GuestRip + ExitInstructionLength);
		VmxCsWrite(GUEST_RSP, GuestRsp);
	}
}
