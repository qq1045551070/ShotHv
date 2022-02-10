#pragma once

extern "C"
{
	void VmxExitHandler(_In_ GuestReg* Registers);					// 中央处理器
	void DefaultVmExitHandler(_In_ GuestReg* Registers);			// 默认处理器
	void CpuidVmExitHandler(_In_ GuestReg* Registers);				// CPUID 处理器
	void MsrWriteVtExitHandler(_In_ GuestReg* Registers);			// Msr Write 处理器
	void MsrReadVtExitHandler(_In_ GuestReg* Registers);			// Msr Read  处理器
	void VmCallVmExitHandler(_In_ GuestReg* Registers);				// Vmcall 异常处理器
	void NmiExceptionVtExitHandler(_In_ GuestReg* Registers);		// Nmi 处理器
	void MonitorTrapFlagVtExitHandler(_In_ GuestReg* Registers);	// MTF 处理器
	void EptViolationVtExitHandler(_In_ GuestReg* Registers);		// EPT 处理器
	void RdtscVtExitHandler(_In_ GuestReg* Registers);				// Rdtsc 处理器
	void RdtscpVtExitHandler(_In_ GuestReg* Registers);				// Rdtsc 处理器
	void CrAccessVtExitHandler(_In_ GuestReg* Registers);			// Crx 处理器
	void ExitInvpcidVtExitHandler(_In_ GuestReg* Registers);		// ExitInvpcid 处理器
}

