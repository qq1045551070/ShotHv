#include "HvPch.h"

void InjectInterruption(
	_In_ InterruptionType interruption_type,
	_In_ InterruptionVector vector,
	_In_ BOOLEAN deliver_error_code,
	_In_ ULONG32 error_code
)
{
	VmxExitInterruptInfo inject_event = { 0 };
	inject_event.fields.valid = true;
	inject_event.fields.interruption_type = static_cast<ULONG32>(interruption_type);
	inject_event.fields.vector = static_cast<ULONG32>(vector);
	inject_event.fields.error_code_valid = deliver_error_code;
	VmxCsWrite(VmcsField::VM_ENTRY_INTR_INFO, inject_event.all);

	if (deliver_error_code)
	{
		// Èç¹ûÓÐ´íÎóÂë
		VmxCsWrite(VmcsField::VM_ENTRY_EXCEPTION_ERROR_CODE, error_code);
	}
}

void EnableMTF()
{
	ULONG64 uCPUBase;
	uCPUBase = VmxCsRead(CPU_BASED_VM_EXEC_CONTROL);
	uCPUBase |= CPU_BASED_MTF_TRAP_EXITING;
	VmxCsWrite(CPU_BASED_VM_EXEC_CONTROL, uCPUBase);
}

void DisableMTF()
{
	ULONG64 uCPUBase;
	uCPUBase = VmxCsRead(CPU_BASED_VM_EXEC_CONTROL);
	uCPUBase &= ~CPU_BASED_MTF_TRAP_EXITING;
	VmxCsWrite(CPU_BASED_VM_EXEC_CONTROL, uCPUBase);
}

void EnableTF()
{
	ULONG64 uTemp64;
	FlagReg* Rflags;
	uTemp64 = VmxCsRead(GUEST_RFLAGS);
	Rflags = (FlagReg*)&uTemp64;

	Rflags->fields.tf = 1;
	VmxCsWrite(GUEST_RFLAGS, uTemp64);
}

void DisableTF()
{
	ULONG64 uTemp64;
	FlagReg* Rflags;
	uTemp64 = VmxCsRead(GUEST_RFLAGS);
	Rflags = (FlagReg*)&uTemp64;

	Rflags->fields.tf = 0;
	VmxCsWrite(GUEST_RFLAGS, uTemp64);
}
