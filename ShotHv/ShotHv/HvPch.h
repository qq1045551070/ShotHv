#pragma once
#pragma warning(disable:4996)
#pragma warning(disable:4201)
#pragma warning(disable:4311)
#pragma warning(disable:4302)
#pragma warning(disable:4366)

#include <ntdef.h>
#include <ntifs.h>
#include <ntddk.h>
#include <windef.h>
#include <ntstrsafe.h>
#include <ntimage.h>
#include <wdm.h>
#pragma comment(lib, "ntoskrnl.lib")
#include <intrin.h>
#include <basetsd.h>

#include "Lde.h"
#include "Ssdt.h"

#include "HvDefine.h"
#include "HvStruct.h"
#include "HvNative.h"

#include "HvUtil.h"
#include "HvMemory.h"
#include "HvCallback.h"
#include "HvInjectException.h"
#include "HvExitHandle.h"
#include "HvEpt.h"
#include "PageHook.h"
#include "CoreHv.h"

#include "HvComm.h"