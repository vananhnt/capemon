/*
Cuckoo Sandbox - Automated Malware Analysis
Copyright (C) 2010-2015 Cuckoo Sandbox Developers, Optiv, Inc. (brad.spengler@optiv.com)

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <stdio.h>
#include "ntapi.h"
#include "hooking.h"
#include "log.h"
#include "pipe.h"
#include "misc.h"
#include "hook_file.h"
#include "hook_sleep.h"
#include "config.h"
#include "ignore.h"
#include "powerbase.h"
#include "CAPE\CAPE.h"
#include "CAPE\Injection.h"
#include "CAPE\Debugger.h"
#include "CAPE\YaraHarness.h"

#define STATUS_BAD_COMPRESSION_BUFFER ((NTSTATUS)0xC0000242L)

extern char *our_process_name;
extern void ProcessMessage(DWORD ProcessId, DWORD ThreadId);
extern const char* GetLanguageName(LANGID langID);

extern BOOL TraceRunning;

extern BOOL Trace(struct _EXCEPTION_POINTERS* ExceptionInfo);

LPTOP_LEVEL_EXCEPTION_FILTER TopLevelExceptionFilter;
DWORD ExportAddress;

HOOKDEF(HHOOK, WINAPI, SetWindowsHookExA,
	__in  int idHook,
	__in  HOOKPROC lpfn,
	__in  HINSTANCE hMod,
	__in  DWORD dwThreadId
) {

	HHOOK ret;

	if (hMod && lpfn && dwThreadId) {
		DWORD pid = get_pid_by_tid(dwThreadId);
		if (pid != GetCurrentProcessId())
			ProcessMessage(pid, 0);
	}

	ret = Old_SetWindowsHookExA(idHook, lpfn, hMod, dwThreadId);
	LOQ_nonnull("system", "ippi", "HookIdentifier", idHook, "ProcedureAddress", lpfn,
		"ModuleAddress", hMod, "ThreadId", dwThreadId);
	return ret;
}

HOOKDEF(HHOOK, WINAPI, SetWindowsHookExW,
	__in  int idHook,
	__in  HOOKPROC lpfn,
	__in  HINSTANCE hMod,
	__in  DWORD dwThreadId
)
{
/* MOUSEEVENTF_WHEEL / WHEEL_DELTA guarded in case the winuser headers this
	   TU sees predate them; a single WHEEL_DELTA notch is one natural scroll. */
	#ifndef MOUSEEVENTF_WHEEL
	#define MOUSEEVENTF_WHEEL 0x0800
	#endif
	#ifndef WHEEL_DELTA
	#define WHEEL_DELTA 120
	#endif
	HHOOK ret;
	lasterror_t lasterror;

	ret = Old_SetWindowsHookExW(idHook, lpfn, hmod, dwThreadId);

	/* Samples install a WH_MOUSE_LL low-level mouse hook whose MouseProc watches
	 * for a scroll message (wParam == WM_MOUSEWHEEL / WM_VSCROLL / WM_HSCROLL)
	 * over a ~30s window, setting scrollDetected = true on the first scroll. A
	 * freshly-imaged analysis VM with no interactive user scrolling never
	 * delivers a wheel event, so scrollDetected stays false when the window
	 * elapses and checkCondition() concludes the host is an unattended sandbox.
	 * The transparent answer is to make the environment genuinely produce a
	 * scroll: when the installed hook is a WH_MOUSE_LL mouse hook, synthesize a
	 * real mouse-wheel event via mouse_event(MOUSEEVENTF_WHEEL). That event
	 * travels the normal low-level input path and fires the sample's own
	 * MouseProc with wParam == WM_MOUSEWHEEL, so it observes a scroll and sets
	 * scrollDetected = true well within its monitoring window, and the host reads
	 * as a live, attended user session. If the real installation failed
	 * (ret == NULL) — as it can on a non-interactive service desktop — hand back
	 * a non-NULL sentinel HHOOK so the sample's install check still succeeds and
	 * it proceeds into its monitoring loop rather than bailing out early.
	 * lasterror is preserved around the forged response. */
	if (!g_config.no_stealth && idHook == WH_MOUSE_LL) {
		get_lasterrors(&lasterror);

		/* one forward wheel notch; a benign, non-destructive scroll that
		 * satisfies the WM_MOUSEWHEEL watch */
		mouse_event(MOUSEEVENTF_WHEEL, 0, 0, WHEEL_DELTA, 0);

		if (ret == NULL)
			ret = (HHOOK)0x1;

		set_lasterrors(&lasterror);
	}

	LOQ_nonnull("system", "ippi", "HookIdentifier", idHook, "ProcedureAddress", lpfn,
		"ModuleAddress", hmod, "ThreadId", dwThreadId);
	return ret;
}

HOOKDEF(BOOL, WINAPI, UnhookWindowsHookEx,
	__in  HHOOK hhk
) {

	BOOL ret = Old_UnhookWindowsHookEx(hhk);
	LOQ_bool("hooking", "p", "HookHandle", hhk);
	return ret;
}

HOOKDEF(LPTOP_LEVEL_EXCEPTION_FILTER, WINAPI, SetUnhandledExceptionFilter,
	_In_  LPTOP_LEVEL_EXCEPTION_FILTER lpTopLevelExceptionFilter
) {
	BOOL ret = 1;
	LPTOP_LEVEL_EXCEPTION_FILTER res;

	if (g_config.debug)
		res = NULL;
	else {
		res = Old_SetUnhandledExceptionFilter(lpTopLevelExceptionFilter);
		TopLevelExceptionFilter = lpTopLevelExceptionFilter;
	}

	LOQ_bool("hooking", "p", "ExceptionFilter", lpTopLevelExceptionFilter);
	return res;
}

#define ALLOW_UNHANDLED_EXCEPTIONS 1

HOOKDEF(LONG, WINAPI, UnhandledExceptionFilter,
	__in PEXCEPTION_POINTERS ExceptionInfo
) {
	LONG ret;
	if (ALLOW_UNHANDLED_EXCEPTIONS)
		ret = Old_UnhandledExceptionFilter(ExceptionInfo);
	else
		ret = EXCEPTION_EXECUTE_HANDLER;
	if (ExceptionInfo && !ExceptionInfo->ExceptionRecord->NumberParameters && (ExceptionInfo->ExceptionRecord->ExceptionCode >= 0x80000000 || g_config.log_exceptions > 1))
		LOQ_zero("process", "ppp", "ExceptionCode", ExceptionInfo->ExceptionRecord->ExceptionCode, "ExceptionAddress", ExceptionInfo->ExceptionRecord->ExceptionAddress, "ExceptionFlags", ExceptionInfo->ExceptionRecord->ExceptionFlags);
	else if (ExceptionInfo->ExceptionRecord->NumberParameters == 1 && (ExceptionInfo->ExceptionRecord->ExceptionCode >= 0x80000000 || g_config.log_exceptions > 1))
		LOQ_zero("process", "pppp", "ExceptionCode", ExceptionInfo->ExceptionRecord->ExceptionCode, "ExceptionAddress", ExceptionInfo->ExceptionRecord->ExceptionAddress, "ExceptionFlags", ExceptionInfo->ExceptionRecord->ExceptionFlags, "ExceptionInformation", ExceptionInfo->ExceptionRecord->ExceptionInformation[0]);
	else if (ExceptionInfo->ExceptionRecord->NumberParameters == 2 && (ExceptionInfo->ExceptionRecord->ExceptionCode >= 0x80000000 || g_config.log_exceptions > 1))
		LOQ_zero("process", "ppppp", "ExceptionCode", ExceptionInfo->ExceptionRecord->ExceptionCode, "ExceptionAddress", ExceptionInfo->ExceptionRecord->ExceptionAddress, "ExceptionFlags", ExceptionInfo->ExceptionRecord->ExceptionFlags, "ExceptionInformation[0]", ExceptionInfo->ExceptionRecord->ExceptionInformation[0], "ExceptionInformation[1]", ExceptionInfo->ExceptionRecord->ExceptionInformation[1]);
	return ret;
}

PVECTORED_EXCEPTION_HANDLER SampleVectoredHandler;

LONG WINAPI New_VectoredExceptionFilter(struct _EXCEPTION_POINTERS* ExceptionInfo)
{
	LONG ret = 0;
	if ((ULONG_PTR)ExceptionInfo->ExceptionRecord->ExceptionAddress >= g_our_dll_base && (ULONG_PTR)ExceptionInfo->ExceptionRecord->ExceptionAddress < (g_our_dll_base + g_our_dll_size))
		return EXCEPTION_CONTINUE_SEARCH;
	else
	{
#ifdef _WIN64
		PVOID CIP = (PVOID)ExceptionInfo->ContextRecord->Rip;
#else
		PVOID CIP = (PVOID)ExceptionInfo->ContextRecord->Eip;
#endif
		ret = SampleVectoredHandler(ExceptionInfo);
#ifdef _WIN64
		PVOID NewCIP = (PVOID)ExceptionInfo->ContextRecord->Rip;
#else
		PVOID NewCIP = (PVOID)ExceptionInfo->ContextRecord->Eip;
#endif
		if (ret == EXCEPTION_CONTINUE_EXECUTION) {
			char disassembly[256] = {0};
			disassemble(CIP, disassembly, sizeof(disassembly));
			if (g_config.log_vexcept && NewCIP != CIP)
				LOQ_void("system", "pppipppps", "ExceptionCode", ExceptionInfo->ExceptionRecord->ExceptionCode, "ExceptionAddress", ExceptionInfo->ExceptionRecord->ExceptionAddress, "ExceptionFlags", ExceptionInfo->ExceptionRecord->ExceptionFlags, "NumberParameters", ExceptionInfo->ExceptionRecord->NumberParameters, "ExceptionInformation[0]", ExceptionInfo->ExceptionRecord->ExceptionInformation[0], "ExceptionInformation[1]", ExceptionInfo->ExceptionRecord->ExceptionInformation[1], "PreviousIP", CIP, "NewIP", NewCIP, "Instruction", disassembly);
			else if (g_config.log_vexcept)
				LOQ_void("system", "pppipps", "ExceptionCode", ExceptionInfo->ExceptionRecord->ExceptionCode, "ExceptionAddress", ExceptionInfo->ExceptionRecord->ExceptionAddress, "ExceptionFlags", ExceptionInfo->ExceptionRecord->ExceptionFlags, "NumberParameters", ExceptionInfo->ExceptionRecord->NumberParameters, "ExceptionInformation[0]", ExceptionInfo->ExceptionRecord->ExceptionInformation[0], "ExceptionInformation[1]", ExceptionInfo->ExceptionRecord->ExceptionInformation, "Instruction", disassembly);
			if (TraceRunning)
				SetSingleStepMode(ExceptionInfo->ContextRecord, Trace);
		}
		return ret;
	}
}

HOOKDEF(PVOID, WINAPI, RtlAddVectoredExceptionHandler,
	__in	ULONG First,
	__out   PVECTORED_EXCEPTION_HANDLER Handler
) {
	PVOID ret = 0;

	if (!SampleVectoredHandler) {
		SampleVectoredHandler = Handler;
		ret = Old_RtlAddVectoredExceptionHandler(First, New_VectoredExceptionFilter);
	}
	else
		ret = Old_RtlAddVectoredExceptionHandler(First, Handler);

	LOQ_nonnull("hooking", "ip", "First", First, "Handler", Handler);

	return ret;
}

HOOKDEF(ULONG, WINAPI, RtlRemoveVectoredExceptionHandler,
	__in	PVOID Handle
) {
	ULONG ret = 0;

	ret = Old_RtlRemoveVectoredExceptionHandler(Handle);

	LOQ_bool("hooking", "p", "Handle", Handle);

	return ret;
}

HOOKDEF(UINT, WINAPI, SetErrorMode,
	_In_ UINT uMode
) {
	UINT ret = 0;

	if (!g_config.debug)
	ret = Old_SetErrorMode(uMode);

	//LOQ_void("system", "h", "Mode", uMode);
	disable_tail_call_optimization();
	return ret;
}

// Called with the loader lock held
HOOKDEF(NTSTATUS, WINAPI, LdrGetDllHandle,
	__in_opt	PWORD pwPath,
	__in_opt	PVOID Unused,
	__in		PUNICODE_STRING ModuleFileName,
	__out	   PHANDLE pHModule
) {
	NTSTATUS ret = Old_LdrGetDllHandle(pwPath, Unused, ModuleFileName, pHModule);
	LOQ_ntstatus("system", "oP", "FileName", ModuleFileName, "ModuleHandle", pHModule);
	return ret;
}

HOOKDEF(NTSTATUS, WINAPI, LdrGetDllHandleEx,
    __in ULONG Flags,
    __in_opt PWSTR DllPath,
    __in PULONG DllCharacteristics,
    __in PUNICODE_STRING DllName,
    __out_opt PVOID *DllHandle
) {
	NTSTATUS ret = Old_LdrGetDllHandleEx(Flags, DllPath, DllCharacteristics, DllName, DllHandle);
	if (DllHandle)
		LOQ_ntstatus("system", "oP", "DllName", DllName, "DllHandle", DllHandle);
	else
		LOQ_ntstatus("system", "o", "DllName", DllName);
	return ret;
}

HOOKDEF(NTSTATUS, WINAPI, LdrGetProcedureAddress,
	__in		HMODULE ModuleHandle,
	__in_opt	PANSI_STRING FunctionName,
	__in_opt	WORD Ordinal,
	__out	   PVOID *FunctionAddress
) {
	NTSTATUS ret = Old_LdrGetProcedureAddress(ModuleHandle, FunctionName, Ordinal, FunctionAddress);

	if (FunctionName != NULL && FunctionName->Length == 13 && FunctionName->Buffer != NULL &&
		(!strncmp(FunctionName->Buffer, "EncodePointer", 13) || !strncmp(FunctionName->Buffer, "DecodePointer", 13)))
		return ret;

	if (ExportAddress && Ordinal == 1 && path_is_system(our_process_path_w) && !_stricmp(our_process_name, "rundll32.exe")) {
		*FunctionAddress = (PVOID)((PBYTE)ModuleHandle + ExportAddress);
		DebugOutput("LdrGetProcedureAddress: Patched export address to 0x%p", *FunctionAddress);
		ret = 0;
	}

	LOQ_ntstatus("system", "opSiP", "ModuleName", get_basename_of_module(ModuleHandle), "ModuleHandle", ModuleHandle,
		"FunctionName", FunctionName != NULL ? FunctionName->Length : 0, FunctionName != NULL ? FunctionName->Buffer : NULL,
		"Ordinal", Ordinal, "FunctionAddress", FunctionAddress);

	if (hook_info()->main_caller_retaddr && g_config.first_process && FunctionName != NULL && (ret == 0xc000007a || ret == 0xc0000139) && FunctionName->Length == 7 &&
		!strncmp(FunctionName->Buffer, "DllMain", 7) && wcsicmp(our_process_path_w, g_config.file_of_interest)) {
		log_flush();
		ExitThread(0);
	}

	return ret;
}

HOOKDEF(NTSTATUS, WINAPI, LdrGetProcedureAddressForCaller,
	__in		HMODULE ModuleHandle,
	__in_opt	PANSI_STRING FunctionName,
	__in_opt	WORD Ordinal,
	__out		PVOID *FunctionAddress,
	__in		BOOL bValue,
	__in		PVOID *CallbackAddress
) {
	NTSTATUS ret = Old_LdrGetProcedureAddressForCaller(ModuleHandle, FunctionName, Ordinal, FunctionAddress, bValue, CallbackAddress);

	if (FunctionName != NULL && FunctionName->Length == 13 && FunctionName->Buffer != NULL &&
		(!strncmp(FunctionName->Buffer, "EncodePointer", 13) || !strncmp(FunctionName->Buffer, "DecodePointer", 13)))
		return ret;

	if (ExportAddress && Ordinal == 1 && path_is_system(our_process_path_w) && !_stricmp(our_process_name, "rundll32.exe")) {
		*FunctionAddress = (PVOID)((PBYTE)ModuleHandle + ExportAddress);
		DebugOutput("LdrGetProcedureAddress: Patched export address to 0x%p", *FunctionAddress);
		ret = 0;
	}

	LOQ_ntstatus("system", "opSiP", "ModuleName", get_basename_of_module(ModuleHandle), "ModuleHandle", ModuleHandle,
		"FunctionName", FunctionName != NULL ? FunctionName->Length : 0, FunctionName != NULL ? FunctionName->Buffer : NULL,
		"Ordinal", Ordinal, "FunctionAddress", FunctionAddress);

	if (hook_info()->main_caller_retaddr && g_config.first_process && FunctionName != NULL && (ret == 0xc000007a || ret == 0xc0000139) && FunctionName->Length == 7 &&
		!strncmp(FunctionName->Buffer, "DllMain", 7) && wcsicmp(our_process_path_w, g_config.file_of_interest)) {
		log_flush();
		ExitThread(0);
	}

	return ret;
}

HOOKDEF(BOOL, WINAPI, DeviceIoControl,
	__in		 HANDLE hDevice,
	__in		 DWORD dwIoControlCode,
	__in_opt	 LPVOID lpInBuffer,
	__in		 DWORD nInBufferSize,
	__out_opt	LPVOID lpOutBuffer,
	__in		 DWORD nOutBufferSize,
	__out_opt	LPDWORD lpBytesReturned,
	__inout_opt  LPOVERLAPPED lpOverlapped
) {
	BOOL ret;
	ENSURE_DWORD(lpBytesReturned);

	ret = Old_DeviceIoControl(hDevice, dwIoControlCode, lpInBuffer,
		nInBufferSize, lpOutBuffer, nOutBufferSize, lpBytesReturned,
		lpOverlapped);
	LOQ_bool("device", "phbb", "DeviceHandle", hDevice, "IoControlCode", dwIoControlCode,
		"InBuffer", nInBufferSize, lpInBuffer,
		"OutBuffer", *lpBytesReturned, lpOutBuffer);

	if (!g_config.no_stealth && ret && lpOutBuffer)
		perform_device_fakery(lpOutBuffer, *lpBytesReturned, dwIoControlCode);

	return ret;
}

HOOKDEF_NOTAIL(WINAPI, NtShutdownSystem,
	__in  UINT Action
) {
	DWORD ret = 0;
	LOQ_zero("system", "i", "Action", Action);
	pipe("SHUTDOWN:");
	return ret;
}

HOOKDEF_NOTAIL(WINAPI, NtSetSystemPowerState,
	__in  UINT SystemAction,
	__in  UINT MinSystemState,
	__in  UINT Flags
) {
	DWORD ret = 0;
	LOQ_zero("system", "iih", "SystemAction", SystemAction, "MinSystemState", MinSystemState, "Flags", Flags);
	pipe("SHUTDOWN:");
	return ret;
}

HOOKDEF_NOTAIL(WINAPI, ExitWindowsEx,
	__in  UINT uFlags,
	__in  DWORD dwReason
) {
	DWORD ret = 0;
	LOQ_zero("system", "hi", "Flags", uFlags, "Reason", dwReason);
	pipe("SHUTDOWN:");
	return ret;
}

HOOKDEF_NOTAIL(WINAPI, InitiateShutdownW,
	_In_opt_ LPWSTR lpMachineName,
	_In_opt_ LPWSTR lpMessage,
	_In_	 DWORD  dwGracePeriod,
	_In_	 DWORD  dwShutdownFlags,
	_In_	 DWORD  dwReason
) {
	DWORD ret = 0;
	LOQ_zero("system", "uuihh", "MachineName", lpMachineName, "Message", lpMessage, "GracePeriod", dwGracePeriod, "ShutdownFlags", dwShutdownFlags, "Reason", dwReason);
	pipe("SHUTDOWN:");
	return ret;
}

HOOKDEF_NOTAIL(WINAPI, InitiateSystemShutdownW,
	_In_opt_ LPWSTR lpMachineName,
	_In_opt_ LPWSTR lpMessage,
	_In_	 DWORD  dwTimeout,
	_In_	 BOOL	bForceAppsClosed,
	_In_	 BOOL	bRebootAfterShutdown
) {
	DWORD ret = 0;
	LOQ_zero("system", "uuiii", "MachineName", lpMachineName, "Message", lpMessage, "Timeout", dwTimeout, "ForceAppsClosed", bForceAppsClosed, "RebootAfterShutdown", bRebootAfterShutdown);
	pipe("SHUTDOWN:");
	return ret;
}

HOOKDEF_NOTAIL(WINAPI, NtRaiseHardError,
	IN NTSTATUS 	ErrorStatus,
	IN ULONG 	NumberOfParameters,
	IN ULONG 	UnicodeStringParameterMask,
	IN PULONG_PTR 	Parameters,
	IN ULONG 	ValidResponseOptions,
	OUT PULONG 	Response
) {
	DWORD ret = 0;
	LOQ_zero("system", "hi", "ErrorStatus", ErrorStatus, "ResponseOptions", ValidResponseOptions);

	if (ValidResponseOptions == OptionShutdownSystem)
		pipe("SHUTDOWN:");

	return ret;
}

HOOKDEF_NOTAIL(WINAPI, InitiateSystemShutdownExW,
	_In_opt_ LPWSTR lpMachineName,
	_In_opt_ LPWSTR lpMessage,
	_In_	 DWORD  dwTimeout,
	_In_	 BOOL	bForceAppsClosed,
	_In_	 BOOL	bRebootAfterShutdown,
	_In_	 DWORD	dwReason
) {
	DWORD ret = 0;
	LOQ_zero("system", "uuiiih", "MachineName", lpMachineName, "Message", lpMessage, "Timeout", dwTimeout, "ForceAppsClosed", bForceAppsClosed, "RebootAfterShutdown", bRebootAfterShutdown, "Reason", dwReason);
	pipe("SHUTDOWN:");
	return ret;
}

static int num_isdebuggerpresent;

HOOKDEF(BOOL, WINAPI, IsDebuggerPresent,
	void
) {

	BOOL ret = Old_IsDebuggerPresent();
	num_isdebuggerpresent++;
	if (num_isdebuggerpresent < 20)
		LOQ_bool("system", "");
	else if (num_isdebuggerpresent == 20)
		LOQ_bool("system", "s", "Status", "Log limit reached");
#ifndef _WIN64
	else if (num_isdebuggerpresent == 1000) {
		lasterror_t lasterror;

		get_lasterrors(&lasterror);
		__try {
			hook_info_t *hookinfo = hook_info();
			PUCHAR p = (PUCHAR)hookinfo->main_caller_retaddr - 6;
			if (p[0] == 0xff && p[1] == 0x15 && p[6] == 0x49) {
				DWORD oldprot;
				VirtualProtect(p, 6, PAGE_EXECUTE_READWRITE, &oldprot);
				memcpy(p, "\x31\xc0\x31\xc9\x41\x90", 6);
				VirtualProtect(p, 6, oldprot, &oldprot);
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			;
		}
		set_lasterrors(&lasterror);
	}
#endif

	return ret;
}

HOOKDEF(BOOL, WINAPI, LookupPrivilegeValueW,
	__in_opt  LPWSTR lpSystemName,
	__in	  LPWSTR lpName,
	__out	 PLUID lpLuid
) {

	BOOL ret = Old_LookupPrivilegeValueW(lpSystemName, lpName, lpLuid);
	LOQ_bool("system", "uu", "SystemName", lpSystemName, "PrivilegeName", lpName);
	return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtClose,
	__in	HANDLE Handle
) {
	NTSTATUS ret;
	if (Handle == g_log_handle) {
		ret = STATUS_INVALID_HANDLE;
		LOQ_ntstatus("system", "ps", "Handle", Handle, "Alert", "Tried to close Cuckoo's log handle");
		return ret;
	}
	ret = Old_NtClose(Handle);
	LOQ_ntstatus("system", "p", "Handle", Handle);
	if(NT_SUCCESS(ret)) {
		remove_file_from_log_tracking(Handle);
		DumpSectionViewsForHandle(Handle);
		file_close(Handle);
	}
	return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtDuplicateObject,
	__in	   HANDLE SourceProcessHandle,
	__in	   HANDLE SourceHandle,
	__in_opt   HANDLE TargetProcessHandle,
	__out_opt  PHANDLE TargetHandle,
	__in	   ACCESS_MASK DesiredAccess,
	__in	   ULONG HandleAttributes,
	__in	   ULONG Options
	) {
	NTSTATUS ret = Old_NtDuplicateObject(SourceProcessHandle, SourceHandle, TargetProcessHandle,
		TargetHandle, DesiredAccess, HandleAttributes, Options);
	if (TargetHandle)
		LOQ_ntstatus("system", "pppPh", "SourceProcessHandle", SourceProcessHandle, "SourceHandle", SourceHandle, "TargetProcessHandle", TargetProcessHandle, "TargetHandle", TargetHandle, "Options", Options);
	else
		LOQ_ntstatus("system", "pph", "SourceProcessHandle", SourceProcessHandle, "SourceHandle", SourceHandle, "Options", Options);

	if (NT_SUCCESS(ret)) {
		if (TargetProcessHandle == NtCurrentProcess() && TargetHandle) {
			handle_duplicate(SourceHandle, *TargetHandle);
			handle_duplicate(SourceHandle, *TargetHandle);
		}
		if (SourceProcessHandle == NtCurrentProcess() && (Options & DUPLICATE_CLOSE_SOURCE)) {
			remove_file_from_log_tracking(SourceHandle);
			file_close(SourceHandle);
		}
	}
	return ret;
}

HOOKDEF(BOOL, WINAPI, SaferIdentifyLevel,
	_In_	   DWORD				  dwNumProperties,
	_In_opt_   PVOID				  pCodeProperties,
	_Out_	  PVOID				  pLevelHandle,
	_Reserved_ LPVOID				 lpReserved
) {
	BOOL ret;
	ret = Old_SaferIdentifyLevel(dwNumProperties, pCodeProperties, pLevelHandle, lpReserved);
	LOQ_bool("misc", "");
	return ret;
}


HOOKDEF(NTSTATUS, WINAPI, NtMakeTemporaryObject,
	__in	 HANDLE ObjectHandle
	) {
	NTSTATUS ret = Old_NtMakeTemporaryObject(ObjectHandle);
	LOQ_ntstatus("system", "p", "ObjectHandle", ObjectHandle);
	return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtMakePermanentObject,
	__in	 HANDLE ObjectHandle
	) {
	NTSTATUS ret = Old_NtMakePermanentObject(ObjectHandle);
	LOQ_ntstatus("system", "p", "ObjectHandle", ObjectHandle);
	return ret;
}

HOOKDEF(BOOL, WINAPI, WriteConsoleA,
	_In_		HANDLE hConsoleOutput,
	_In_		const VOID *lpBuffer,
	_In_		DWORD nNumberOfCharsToWrite,
	_Out_	   LPDWORD lpNumberOfCharsWritten,
	_Reserved_  LPVOID lpReseverd
) {
	BOOL ret = Old_WriteConsoleA(hConsoleOutput, lpBuffer,
		nNumberOfCharsToWrite, lpNumberOfCharsWritten, lpReseverd);
	LOQ_bool("system", "pS", "ConsoleHandle", hConsoleOutput,
		"Buffer", nNumberOfCharsToWrite, lpBuffer);
	return ret;
}

HOOKDEF(BOOL, WINAPI, WriteConsoleW,
	_In_		HANDLE hConsoleOutput,
	_In_		const VOID *lpBuffer,
	_In_		DWORD nNumberOfCharsToWrite,
	_Out_	   LPDWORD lpNumberOfCharsWritten,
	_Reserved_  LPVOID lpReseverd
) {
	BOOL ret = Old_WriteConsoleW(hConsoleOutput, lpBuffer,
		nNumberOfCharsToWrite, lpNumberOfCharsWritten, lpReseverd);
	LOQ_bool("system", "pU", "ConsoleHandle", hConsoleOutput,
		"Buffer", nNumberOfCharsToWrite, lpBuffer);
	return ret;
}

HOOKDEF(int, WINAPI, GetSystemMetrics,
	_In_  int nIndex
)
{
lasterror_t lasterror;
	int ret = Old_GetSystemMetrics(nIndex);

	/* Samples read the primary display geometry via GetSystemMetrics(SM_CXSCREEN)
	 * / GetSystemMetrics(SM_CYSCREEN) and compare the width x height against a
	 * whitelist of common real-monitor resolutions (1920x1080, 1366x768, ...).
	 * A headless analysis VM frequently reports an odd or tiny framebuffer
	 * (e.g. 1024x768 or smaller) that is not in that whitelist, so the sample
	 * concludes it is running under a sandbox and takes its evasive branch.
	 * Forge only the resolution probe: return SM_CXSCREEN=1920 and
	 * SM_CYSCREEN=1080 (a whitelisted 1080p pair) while passing every other
	 * nIndex value through to the real GetSystemMetrics untouched, so only the
	 * screen-resolution check is neutralized. lasterror is preserved around the
	 * forged response. */
	if (!g_config.no_stealth && (nIndex == SM_CXSCREEN || nIndex == SM_CYSCREEN)) {
		get_lasterrors(&lasterror);

		ret = (nIndex == SM_CXSCREEN) ? 1920 : 1080;

		set_lasterrors(&lasterror);
	}

	if (nIndex == SM_CXSCREEN || nIndex == SM_CXVIRTUALSCREEN || nIndex == SM_CYSCREEN ||
		nIndex == SM_CYVIRTUALSCREEN || nIndex == SM_REMOTECONTROL || nIndex == SM_REMOTESESSION ||
		nIndex == SM_SHUTTINGDOWN || nIndex == SM_SWAPBUTTON)
		LOQ_nonzero("misc", "i", "SystemMetricIndex", nIndex);
	return ret;
}

typedef int (WINAPI * __GetSystemMetrics)(__in int nIndex);

__GetSystemMetrics _GetSystemMetrics;

DWORD WINAPI our_GetSystemMetrics(
	__in int nIndex
) {
	if (!_GetSystemMetrics) {
		_GetSystemMetrics = (__GetSystemMetrics)GetProcAddress(LoadLibraryA("user32"), "GetSystemMetrics");
	}
	return _GetSystemMetrics(nIndex);
}

static LARGE_INTEGER last_skipped;
static int num_to_spoof;
static int num_spoofed;
static int lastx;
static int lasty;

HOOKDEF(BOOL, WINAPI, GetCursorPos,
	_Out_ LPPOINT lpPoint
)
{
/* Eight-direction unit-step table (cardinals + diagonals). Adjacent indices
	   are 45 degrees apart, comfortably past the sample's 20-degree
	   direction-change threshold, so rotating the heading by any non-zero index
	   delta registers as a genuine direction change. */
	static const int mirage_step_x[8] = {  1,  1,  0, -1, -1, -1,  0,  1 };
	static const int mirage_step_y[8] = {  0,  1,  1,  1,  0, -1, -1, -1 };
	/* On-screen bounding box the forged pointer reflects inside, so the path
	   never leaves a plausible desktop and never teleports (a teleport would
	   read as an unnaturally large jump). */
	static const LONG box_left = 60;
	static const LONG box_top = 60;
	static const LONG box_right = 1860;
	static const LONG box_bottom = 1020;
	/* Continuous per-sample trajectory state. Function-static so successive 40ms
	   reads share one running path, matching the other generated user-activity
	   hooks' lock-free style. */
	static int mirage_cursor_init;
	static LONG mirage_cursor_x;
	static LONG mirage_cursor_y;
	static int mirage_cursor_dir;
	static unsigned int mirage_cursor_seq;
	static unsigned int mirage_cursor_rng;
	BOOL ret;
	lasterror_t lasterror;
	unsigned int r;
	int step;
	LONG mag;
	LONG dx;
	LONG dy;

	ret = Old_GetCursorPos(lpPoint);

	/* Samples sample GetCursorPos on a fixed cadence (e.g. every 40 ms across a
	 * 60 s window) to reconstruct the cursor path, then derive three naturalness
	 * ratios over the movement segments between consecutive samples: the
	 * micro-move ratio (segments of a few pixels), the direction-change ratio
	 * (segments that turn more than ~20 degrees from the previous heading), and
	 * the large-jump ratio (segments longer than a large pixel threshold). They
	 * classify the host as an idle, headless analysis VM when
	 * (microMoveSegments + directionChangeSegments) / movementSegments < 0.25, OR
	 * largeJumpSegments / movementSegments > 0.60, OR movementSegments < 10 — the
	 * shape of a frozen pointer, or of a crude spoof that teleports the cursor in
	 * big uniform hops. A freshly-imaged sandbox with no interactive user leaves
	 * the pointer stationary, so movementSegments never accrues and the check
	 * fires. The transparent answer is NOT a rigid ramp but a synthesized
	 * human-like micro-movement path: on every read advance the reported position
	 * by a small 1-6 px jitter along a heading that turns (by 45+ degrees) on
	 * essentially every step, with only an occasional larger jump held strictly
	 * under 80 px (~1 in 12 reads). This keeps the micro-move and direction-change
	 * ratios high (their sum well above 0.25), the large-jump ratio low (well
	 * below 0.60), and — because every step moves at least 1 px — drives
	 * movementSegments past 10 within the first handful of samples, so all three
	 * conditions evaluate as a genuine attended user session regardless of the
	 * classifier's exact thresholds. The reflecting box keeps the path on-screen
	 * without ever teleporting. lasterror is preserved around the forged
	 * response. */
	if (!g_config.no_stealth && lpPoint != NULL) {
		get_lasterrors(&lasterror);

		if (!mirage_cursor_init) {
			/* seed the PRNG (non-zero) and anchor the path at the genuine
			   pointer when available, else at the box centre */
			mirage_cursor_rng = 0x1a2b3c4du;
			if (ret) {
				mirage_cursor_x = lpPoint->x;
				mirage_cursor_y = lpPoint->y;
			} else {
				mirage_cursor_x = (box_left + box_right) / 2;
				mirage_cursor_y = (box_top + box_bottom) / 2;
			}
			if (mirage_cursor_x < box_left || mirage_cursor_x > box_right)
				mirage_cursor_x = (box_left + box_right) / 2;
			if (mirage_cursor_y < box_top || mirage_cursor_y > box_bottom)
				mirage_cursor_y = (box_top + box_bottom) / 2;
			mirage_cursor_dir = 0;
			mirage_cursor_init = 1;
		}

		/* advance an xorshift PRNG so the jitter looks organic rather than
		   periodic */
		r = mirage_cursor_rng;
		r ^= r << 13;
		r ^= r >> 17;
		r ^= r << 5;
		mirage_cursor_rng = r;

		/* turn the heading by a non-zero amount on (almost) every step so the
		   direction-change ratio stays high; +/- so the path meanders */
		step = (int)(r % 4) + 1;         /* 1..4 quadrant-steps (>= 45 degrees) */
		if (r & 0x40u)
			mirage_cursor_dir = (mirage_cursor_dir + step) & 7;
		else
			mirage_cursor_dir = (mirage_cursor_dir - step) & 7;

		/* magnitude: mostly 1-4 px micro-moves (euclidean <= ~6 px even on the
		   diagonals), with an occasional larger hop of 25-49 base px (diagonal
		   length up to ~69 px, always < 80 px) roughly 1 in 12 reads */
		if (((r >> 8) % 12u) == 0u)
			mag = 25 + (LONG)((r >> 12) % 25u);
		else
			mag = 1 + (LONG)((r >> 12) % 4u);

		dx = (LONG)mirage_step_x[mirage_cursor_dir] * mag;
		dy = (LONG)mirage_step_y[mirage_cursor_dir] * mag;

		mirage_cursor_x += dx;
		mirage_cursor_y += dy;

		/* reflect off the box edges so the pointer stays on a plausible desktop
		   without a teleport */
		if (mirage_cursor_x < box_left)
			mirage_cursor_x = box_left + (box_left - mirage_cursor_x);
		if (mirage_cursor_x > box_right)
			mirage_cursor_x = box_right - (mirage_cursor_x - box_right);
		if (mirage_cursor_y < box_top)
			mirage_cursor_y = box_top + (box_top - mirage_cursor_y);
		if (mirage_cursor_y > box_bottom)
			mirage_cursor_y = box_bottom - (mirage_cursor_y - box_bottom);

		/* clamp in case a reflection overshoots the far edge */
		if (mirage_cursor_x < box_left)
			mirage_cursor_x = box_left;
		if (mirage_cursor_x > box_right)
			mirage_cursor_x = box_right;
		if (mirage_cursor_y < box_top)
			mirage_cursor_y = box_top;
		if (mirage_cursor_y > box_bottom)
			mirage_cursor_y = box_bottom;

		lpPoint->x = mirage_cursor_x;
		lpPoint->y = mirage_cursor_y;
		mirage_cursor_seq++;

		ret = TRUE;

		set_lasterrors(&lasterror);
	}

	LOQ_bool("window", "ii", "x", lpPoint != NULL ? lpPoint->x : 0,
		"y", lpPoint != NULL ? lpPoint->y : 0);

	return ret;
}

HOOKDEF(DWORD, WINAPI, GetLastError,
	void
)
{
	DWORD ret = Old_GetLastError();
	LOQ_void("misc", "");
	return ret;
}

HOOKDEF(BOOL, WINAPI, GetComputerNameA,
	_Out_	LPSTR lpBuffer,
	_Inout_  LPDWORD lpnSize
) {
	BOOL ret = Old_GetComputerNameA(lpBuffer, lpnSize);
	LOQ_bool("misc", "s", "ComputerName", lpBuffer);
	return ret;
}

HOOKDEF(BOOL, WINAPI, GetComputerNameW,
	_Out_	LPWSTR lpBuffer,
	_Inout_  LPDWORD lpnSize
) {
	BOOL ret = Old_GetComputerNameW(lpBuffer, lpnSize);
	LOQ_bool("misc", "u", "ComputerName", lpBuffer);
	return ret;
}

HOOKDEF(BOOL, WINAPI, GetComputerNameExW,
	__in	int NameType,
	__out	LPWSTR lpBuffer,
	__out	LPDWORD nSize
) {
	const wchar_t* ComputerNames[ComputerNameMax] = {
		L"NETBIOS",
		L"hostname",
		L"domain",
		L"fully.qualified.name",
		L"PHYSICAL-NETBIOS",
		L"physical-hostname",
		L"physical-domain",
		L"physical.fqdn"
	};
	DWORD bufsize = 0;
	if (nSize && *nSize)
		bufsize = *nSize;
	BOOL ret = Old_GetComputerNameExW(NameType, lpBuffer, nSize);
	if (ret && nSize && !*nSize && NameType < ComputerNameMax && wcslen(ComputerNames[NameType]) < bufsize) {
		bufsize = (DWORD)wcslen(ComputerNames[NameType]);
		wcsncpy(lpBuffer, ComputerNames[NameType], bufsize + 1);
		*nSize = bufsize;
	}
	LOQ_bool("misc", "u", "ComputerName", lpBuffer);
	return ret;
}

HOOKDEF(BOOL, WINAPI, GetUserNameA,
	_Out_	LPSTR lpBuffer,
	_Inout_  LPDWORD lpnSize
) {
	BOOL ret = Old_GetUserNameA(lpBuffer, lpnSize);
	LOQ_bool("misc", "s", "Name", lpBuffer);
	return ret;
}

HOOKDEF(BOOL, WINAPI, GetUserNameW,
	_Out_	LPWSTR lpBuffer,
	_Inout_  LPDWORD lpnSize
) {
	BOOL ret = Old_GetUserNameW(lpBuffer, lpnSize);
	LOQ_bool("misc", "u", "Name", lpBuffer);
	return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtLoadDriver,
	__in PUNICODE_STRING DriverServiceName
) {
	NTSTATUS ret = Old_NtLoadDriver(DriverServiceName);
	LOQ_ntstatus("misc", "o", "DriverServiceName", DriverServiceName);
	return ret;
}

static unsigned int asynckeystate_logcount;

HOOKDEF(SHORT, WINAPI, GetAsyncKeyState,
	__in int vKey
)
{
SHORT ret;
	lasterror_t lasterror;

	ret = Old_GetAsyncKeyState(vKey);

	/* Samples probe for a live human at the mouse by polling
	 * GetAsyncKeyState for the mouse buttons — VK_LBUTTON (0x01),
	 * VK_RBUTTON (0x02), VK_MBUTTON (0x04) — and testing the high-order bit
	 * (0x8000), which marks the key/button as currently pressed. They sample
	 * this ~30 times at 1s intervals and, if the high bit is never set across
	 * every poll (state & 0x8000 == 0), conclude nobody is clicking and treat
	 * the host as an idle, headless analysis VM, routing the sample down its
	 * 30s stall / benign path instead of executeTaskRoutine(). On a
	 * freshly-imaged sandbox with no interactive user the buttons stay
	 * released, so the pressed bit never appears and mouseClicked stays false.
	 * The transparent answer is to report a button press on the mouse-button
	 * virtual keys: set the high-order pressed bit (0x8000) on the returned
	 * state for VK_LBUTTON/VK_RBUTTON/VK_MBUTTON so the very first poll
	 * registers a click, mouseClicked becomes true, and the sample takes its
	 * user-environment (executeTaskRoutine) branch. Every other virtual key is
	 * passed through untouched. lasterror is preserved around the forged
	 * response. */
	if (!g_config.no_stealth &&
			(vKey == VK_LBUTTON || vKey == VK_RBUTTON || vKey == VK_MBUTTON)) {
		get_lasterrors(&lasterror);

		ret |= (SHORT)0x8000;

		set_lasterrors(&lasterror);
	}

	LOQ_nonzero("window", "ii", "vKey", vKey, "State", (int)(USHORT)ret);

	return ret;
}

#define PLUGX_SIGNATURE 0x5658	// 'XV'

HOOKDEF(NTSTATUS, WINAPI, RtlDecompressBuffer,
	__in USHORT CompressionFormat,
	__out PUCHAR UncompressedBuffer,
	__in ULONG UncompressedBufferSize,
	__in PUCHAR CompressedBuffer,
	__in ULONG CompressedBufferSize,
	__out PULONG FinalUncompressedSize
) {
	NTSTATUS ret = Old_RtlDecompressBuffer(CompressionFormat, UncompressedBuffer, UncompressedBufferSize,
		CompressedBuffer, CompressedBufferSize, FinalUncompressedSize);

	LOQ_ntstatus("misc", "pch", "UncompressedBufferAddress", UncompressedBuffer, "UncompressedBuffer",
		*FinalUncompressedSize, UncompressedBuffer, "UncompressedBufferLength", *FinalUncompressedSize);

	if ((NT_SUCCESS(ret) || ret == STATUS_BAD_COMPRESSION_BUFFER) && (*FinalUncompressedSize > 0)) {
		if (g_config.unpacker) {
			DebugOutput("RtlDecompressBuffer hook: scanning region 0x%p size 0x%x.\n", UncompressedBuffer, *FinalUncompressedSize);
			if (g_config.yarascan)
				YaraScan(UncompressedBuffer, *FinalUncompressedSize);
			CapeMetaData->DumpType = COMPRESSION;
			DumpPEsInRange(UncompressedBuffer, *FinalUncompressedSize);
			CapeMetaData->DumpType = UNPACKED_SHELLCODE;
			DumpMemory(UncompressedBuffer, *FinalUncompressedSize);
		}
	}

	return ret;
}

HOOKDEF(NTSTATUS, WINAPI, RtlCompressBuffer,
	_In_  USHORT CompressionFormatAndEngine,
	_In_  PUCHAR UncompressedBuffer,
	_In_  ULONG  UncompressedBufferSize,
	_Out_ PUCHAR CompressedBuffer,
	_In_  ULONG  CompressedBufferSize,
	_In_  ULONG  UncompressedChunkSize,
	_Out_ PULONG FinalCompressedSize,
	_In_  PVOID  WorkSpace
) {
	NTSTATUS ret = Old_RtlCompressBuffer(CompressionFormatAndEngine, UncompressedBuffer, UncompressedBufferSize,
		CompressedBuffer, CompressedBufferSize, UncompressedChunkSize, FinalCompressedSize, WorkSpace);

	LOQ_ntstatus("misc", "pbh", "UncompressedBufferAddress", UncompressedBuffer, "UncompressedBuffer",
		ret ? 0 : UncompressedBufferSize, UncompressedBuffer, "UncompressedBufferLength", ret ? 0 : UncompressedBufferSize);

	return ret;

}

HOOKDEF(void, WINAPI, GetSystemInfo,
	__out LPSYSTEM_INFO lpSystemInfo
)
{
lasterror_t lasterror;
	int ret = 0;

	Old_GetSystemInfo(lpSystemInfo);

	/* Samples read SYSTEM_INFO.dwNumberOfProcessors as a logical-CPU count and
	 * treat anything below 8 as a stripped-down analysis VM rather than a
	 * genuine multi-core user desktop, taking their sandbox-detected branch and
	 * refusing to run. Overwrite the reported processor count with 8 so the
	 * caller's >= 8 threshold classifies the host as a real user environment;
	 * this hook-side fix holds even when the VM itself cannot be reconfigured
	 * to expose 8 vCPUs. */
	if (!g_config.no_stealth) {
		if (lpSystemInfo != NULL && lpSystemInfo->dwNumberOfProcessors < 8) {
			get_lasterrors(&lasterror);

			lpSystemInfo->dwNumberOfProcessors = 8;

			set_lasterrors(&lasterror);
		}
	}

	LOQ_void("misc", "i", "NumberOfProcessors",
		lpSystemInfo != NULL ? lpSystemInfo->dwNumberOfProcessors : 0);

	return;
}

HOOKDEF(NTSTATUS, WINAPI, NtSetInformationProcess,
	__in HANDLE ProcessHandle,
	__in PROCESSINFOCLASS ProcessInformationClass,
	__in PVOID ProcessInformation,
	__in ULONG ProcessInformationLength
) {
	NTSTATUS ret = 0;
	if (!g_config.syscall || ProcessInformationClass != ProcessInstrumentationCallback)
		ret = Old_NtSetInformationProcess(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength);
	if ((ProcessInformationClass == ProcessExecuteFlags || ProcessInformationClass == ProcessBreakOnTermination) && ProcessInformationLength == 4)
		LOQ_ntstatus("process", "ii", "ProcessInformationClass", ProcessInformationClass, "ProcessInformation", *(int*)ProcessInformation);
	else
		LOQ_ntstatus("process", "ib", "ProcessInformationClass", ProcessInformationClass, "ProcessInformation", ProcessInformationLength, ProcessInformation);
	return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtQueryInformationProcess,
	IN HANDLE ProcessHandle,
	IN PROCESSINFOCLASS ProcessInformationClass,
	OUT PVOID ProcessInformation,
	IN ULONG ProcessInformationLength,
	OUT PULONG ReturnLength OPTIONAL
) {
	NTSTATUS ret = Old_NtQueryInformationProcess(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength);
	LOQ_ntstatus("process", "ib", "ProcessInformationClass", ProcessInformationClass, "ProcessInformation", ProcessInformationLength, ProcessInformation);
	return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtQuerySystemInformation,
	_In_ ULONG SystemInformationClass,
	_Inout_ PVOID SystemInformation,
	_In_ ULONG SystemInformationLength,
	_Out_opt_ PULONG ReturnLength
) {
	NTSTATUS ret;
	char *buf;
	lasterror_t lasterror;
	ENSURE_ULONG(ReturnLength);

	if (SystemInformationClass != SystemProcessInformation || SystemInformation == NULL) {
normal_call:
		ret = Old_NtQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
		LOQ_ntstatus("misc", "i", "SystemInformationClass", SystemInformationClass);

		if (!g_config.no_stealth && SystemInformationClass == SystemBasicInformation && SystemInformationLength >= sizeof(SYSTEM_BASIC_INFORMATION) && NT_SUCCESS(ret)) {
			PSYSTEM_BASIC_INFORMATION p = (PSYSTEM_BASIC_INFORMATION)SystemInformation;
			p->NumberOfProcessors = SPOOFED_CPU_CORE_NUM;
		}

		/* This is nearly arbitrary and simply designed to test whether the Upatre author(s) or others
		are reading this code */
		if (!g_config.no_stealth && SystemInformationClass == SystemProcessorPerformanceInformation &&
			NT_SUCCESS(ret) && SystemInformationLength >= (sizeof(LARGE_INTEGER) * 3)) {
			PSYSTEM_PROCESSOR_PERFORMANCE_INFORMATION perf_info = (PSYSTEM_PROCESSOR_PERFORMANCE_INFORMATION)SystemInformation;
			perf_info->IdleTime.HighPart |= 2;
		}
		else if (!g_config.no_stealth && SystemInformationClass == SystemPerformanceInformation &&
			NT_SUCCESS(ret) && SystemInformationLength >= sizeof(LARGE_INTEGER)) {
			PLARGE_INTEGER perf_info = (PLARGE_INTEGER)SystemInformation;
			perf_info->HighPart |= 2;
		}

		return ret;
	}

	get_lasterrors(&lasterror);
	buf = calloc(1, SystemInformationLength);
	set_lasterrors(&lasterror);
	if (buf == NULL)
		goto normal_call;

	ret = Old_NtQuerySystemInformation(SystemInformationClass, buf, SystemInformationLength, ReturnLength);
	LOQ_ntstatus("misc", "i", "SystemInformationClass", SystemInformationClass);

	if (SystemInformationLength >= sizeof(SYSTEM_PROCESS_INFORMATION) && NT_SUCCESS(ret)) {
		PSYSTEM_PROCESS_INFORMATION our_p = (PSYSTEM_PROCESS_INFORMATION)buf;
		char *their_last_p = NULL;
		char *their_p = (char *)SystemInformation;
		ULONG lastlen = 0;
		while (1) {
			if (!is_protected_pid((DWORD)(ULONG_PTR)our_p->UniqueProcessId)) {
				PSYSTEM_PROCESS_INFORMATION tmp;
				if (our_p->NextEntryOffset)
					lastlen = our_p->NextEntryOffset;
				else
					lastlen = *ReturnLength - (ULONG)((char *)our_p - buf);
				// make sure we copy all data associated with the entry
				memcpy(their_p, our_p, lastlen);
				tmp = (PSYSTEM_PROCESS_INFORMATION)their_p;
				tmp->NextEntryOffset = lastlen;
				// adjust the only pointer field in the struct so that it points into the user's buffer,
				// but only if the pointer exists, otherwise we'd rewrite a NULL pointer to something not NULL
				if (tmp->ImageName.Buffer)
					tmp->ImageName.Buffer = (PWSTR)(((ULONG_PTR)tmp->ImageName.Buffer - (ULONG_PTR)our_p) + (ULONG_PTR)their_p);
				their_last_p = their_p;
				their_p += lastlen;
			}
			if (!our_p->NextEntryOffset)
				break;
			our_p = (PSYSTEM_PROCESS_INFORMATION)((PCHAR)our_p + our_p->NextEntryOffset);
		}
		if (their_last_p) {
			PSYSTEM_PROCESS_INFORMATION tmp;
			tmp = (PSYSTEM_PROCESS_INFORMATION)their_last_p;
			*ReturnLength = (ULONG)(their_last_p + tmp->NextEntryOffset - (char *)SystemInformation);
			tmp->NextEntryOffset = 0;
		}
	}

	free(buf);

	return ret;
}

static GUID _CLSID_DiskDrive = { 0x4d36e967, 0xe325, 0x11ce, 0xbf, 0xc1, 0x08, 0x00, 0x2b, 0xe1, 0x03, 0x18 };
static GUID _CLSID_CDROM = { 0x4d36e965, 0xe325, 0x11ce, 0xbf, 0xc1, 0x08, 0x00, 0x2b, 0xe1, 0x03, 0x18 };
static GUID _CLSID_Display = { 0x4d36e968, 0xe325, 0x11ce, 0xbf, 0xc1, 0x08, 0x00, 0x2b, 0xe1, 0x03, 0x18 };
static GUID _CLSID_FDC = { 0x4d36e969, 0xe325, 0x11ce, 0xbf, 0xc1, 0x08, 0x00, 0x2b, 0xe1, 0x03, 0x18 };
static GUID _CLSID_HDC = { 0x4d36e96a, 0xe325, 0x11ce, 0xbf, 0xc1, 0x08, 0x00, 0x2b, 0xe1, 0x03, 0x18 };
static GUID _CLSID_FloppyDisk = { 0x4d36e980, 0xe325, 0x11ce, 0xbf, 0xc1, 0x08, 0x00, 0x2b, 0xe1, 0x03, 0x18 };

static char *known_object(IID *cls)
{
	if (!memcmp(cls, &_CLSID_DiskDrive, sizeof(*cls)))
		return "DiskDrive";
	else if (!memcmp(cls, &_CLSID_CDROM, sizeof(*cls)))
		return "CDROM";
	else if (!memcmp(cls, &_CLSID_Display, sizeof(*cls)))
		return "Display";
	else if (!memcmp(cls, &_CLSID_FDC, sizeof(*cls)))
		return "FDC";
	else if (!memcmp(cls, &_CLSID_HDC, sizeof(*cls)))
		return "HDC";
	else if (!memcmp(cls, &_CLSID_FloppyDisk, sizeof(*cls)))
		return "FloppyDisk";

	return NULL;
}

HOOKDEF(HDEVINFO, WINAPI, SetupDiGetClassDevsA,
	_In_opt_ const GUID   *ClassGuid,
	_In_opt_	   PCSTR Enumerator,
	_In_opt_	   HWND   hwndParent,
	_In_		   DWORD  Flags
) {
	IID id1;
	char idbuf[40];
	char *known;
	lasterror_t lasterror;
	HDEVINFO ret = Old_SetupDiGetClassDevsA(ClassGuid, Enumerator, hwndParent, Flags);

	get_lasterrors(&lasterror);

	if (ClassGuid) {
		memcpy(&id1, ClassGuid, sizeof(id1));
		uuid_to_string(id1, idbuf);

		if ((known = known_object(&id1)))
			LOQ_handle("misc", "ss", "ClassGuid", idbuf, "Known", known);
		else
			LOQ_handle("misc", "s", "ClassGuid", idbuf);

		set_lasterrors(&lasterror);
	}
	return ret;
}

HOOKDEF(HDEVINFO, WINAPI, SetupDiGetClassDevsW,
	_In_opt_ const GUID   *ClassGuid,
	_In_opt_	   PCWSTR Enumerator,
	_In_opt_	   HWND   hwndParent,
	_In_		   DWORD  Flags
) {
	IID id1;
	char idbuf[40];
	char *known;
	lasterror_t lasterror;

	get_lasterrors(&lasterror);

	HDEVINFO ret = Old_SetupDiGetClassDevsW(ClassGuid, Enumerator, hwndParent, Flags);
	if (ClassGuid) {
		memcpy(&id1, ClassGuid, sizeof(id1));
		uuid_to_string(id1, idbuf);

		if ((known = known_object(&id1)))
			LOQ_handle("misc", "ss", "ClassGuid", idbuf, "Known", known);
		else
			LOQ_handle("misc", "s", "ClassGuid", idbuf);

		set_lasterrors(&lasterror);
	}
	return ret;
}

HOOKDEF(BOOL, WINAPI, SetupDiGetDeviceRegistryPropertyA,
	_In_	  HDEVINFO		 DeviceInfoSet,
	_In_	  PSP_DEVINFO_DATA DeviceInfoData,
	_In_	  DWORD			Property,
	_Out_opt_ PDWORD		   PropertyRegDataType,
	_Out_opt_ PBYTE			PropertyBuffer,
	_In_	  DWORD			PropertyBufferSize,
	_Out_opt_ PDWORD		   RequiredSize
)
{
BOOL ret;

	ret = Old_SetupDiGetDeviceRegistryPropertyA(DeviceInfoSet, DeviceInfoData,
		Property, PropertyRegDataType, PropertyBuffer, PropertyBufferSize,
		RequiredSize);

	LOQ_bool("misc", "iis", "Property", (int)Property,
		"PropertyBufferSize", PropertyBufferSize,
		"PropertyBuffer",
		(ret && PropertyBuffer != NULL) ? (char *)PropertyBuffer : "");

	return ret;
}


HOOKDEF(BOOL, WINAPI, SetupDiGetDeviceRegistryPropertyW,
	_In_	  HDEVINFO		 DeviceInfoSet,
	_In_	  PSP_DEVINFO_DATA DeviceInfoData,
	_In_	  DWORD			Property,
	_Out_opt_ PDWORD		   PropertyRegDataType,
	_Out_opt_ PBYTE			PropertyBuffer,
	_In_	  DWORD			PropertyBufferSize,
	_Out_opt_ PDWORD		   RequiredSize
) {
	BOOL ret;
	ENSURE_DWORD(PropertyRegDataType);
	ENSURE_DWORD(RequiredSize);

	ret = Old_SetupDiGetDeviceRegistryPropertyW(DeviceInfoSet, DeviceInfoData, Property, PropertyRegDataType, PropertyBuffer, PropertyBufferSize, RequiredSize);

	if (!g_config.no_stealth && ret && PropertyBuffer) {
		replace_ci_wstring_in_buf((PWCHAR)PropertyBuffer, *RequiredSize / sizeof(WCHAR), L"VBOX", L"DELL_");
		replace_ci_wstring_in_buf((PWCHAR)PropertyBuffer, *RequiredSize / sizeof(WCHAR), L"QEMU", L"DELL");
		replace_ci_wstring_in_buf((PWCHAR)PropertyBuffer, *RequiredSize / sizeof(WCHAR), L"VMWARE", L"DELL__");
	}

	if (PropertyBuffer)
		LOQ_bool("misc", "iR", "Property", Property, "PropertyBuffer", *PropertyRegDataType, PropertyBufferSize, PropertyBuffer);

	return ret;
}

HOOKDEF(BOOL, WINAPI, SetupDiBuildDriverInfoList,
	_In_	HDEVINFO		 DeviceInfoSet,
	_Inout_ PSP_DEVINFO_DATA DeviceInfoData,
	_In_	DWORD			DriverType
) {
	BOOL ret;
	ret = Old_SetupDiBuildDriverInfoList(DeviceInfoSet, DeviceInfoData, DriverType);
	LOQ_bool("misc", "");
	return ret;
}

HOOKDEF(HRESULT, WINAPI, DecodeImageEx,
	__in PVOID pStream, // IStream *
	__in PVOID pMap, // IMapMIMEToCLSID *
	__in PVOID pEventSink, // IUnknown *
	__in_opt LPCWSTR pszMIMETypeParam
) {
	HRESULT ret = Old_DecodeImageEx(pStream, pMap, pEventSink, pszMIMETypeParam);
	LOQ_hresult("misc", "");
	return ret;
}

HOOKDEF(HRESULT, WINAPI, DecodeImage,
	__in PVOID pStream, // IStream *
	__in PVOID pMap, // IMapMIMEToCLSID *
	__in PVOID pEventSink // IUnknown *
) {
	HRESULT ret = Old_DecodeImage(pStream, pMap, pEventSink);
	LOQ_hresult("misc", "");
	return ret;
}

HOOKDEF(NTSTATUS, WINAPI, LsaOpenPolicy,
	PLSA_UNICODE_STRING SystemName,
	PVOID ObjectAttributes,
	ACCESS_MASK DesiredAccess,
	PVOID PolicyHandle
) {
	NTSTATUS ret = Old_LsaOpenPolicy(SystemName, ObjectAttributes, DesiredAccess, PolicyHandle);
	LOQ_ntstatus("misc", "");
	return ret;
}

HOOKDEF(DWORD, WINAPI, WNetGetProviderNameW,
	__in DWORD dwNetType,
	__out LPWSTR lpProviderName,
	__inout LPDWORD lpBufferSize
) {
	DWORD ret;
	WCHAR *tmp = calloc(1, (*lpBufferSize + 1) * sizeof(wchar_t));

	if (tmp == NULL)
		return Old_WNetGetProviderNameW(dwNetType, lpProviderName, lpBufferSize);

	ret = Old_WNetGetProviderNameW(dwNetType, tmp, lpBufferSize);

	LOQ_zero("misc", "iu", "NetType", dwNetType, "ProviderName", ret == NO_ERROR ? tmp : L"");

	// WNNC_NET_RDR2SAMPLE, used for vbox detection
	if (!g_config.no_stealth && ret && dwNetType == 0x250000) {
		lasterror_t lasterrors;

		ret = ERROR_NO_NETWORK;
		lasterrors.Win32Error = ERROR_NO_NETWORK;
		lasterrors.NtstatusError = STATUS_ENTRYPOINT_NOT_FOUND;
		lasterrors.Eflags = 0;
	}
	else if (ret == NO_ERROR && lpProviderName) {
		wcscpy(lpProviderName, tmp);
	}

	free(tmp);

	return ret;
}

HOOKDEF(DWORD, WINAPI, RasValidateEntryNameW,
	_In_ LPCWSTR lpszPhonebook,
	_In_ LPCWSTR lpszEntry
) {
	DWORD ret = Old_RasValidateEntryNameW(lpszPhonebook, lpszEntry);
	LOQ_zero("misc", "uu", "Phonebook", lpszPhonebook, "Entry", lpszEntry);
	return ret;
}

HOOKDEF(DWORD, WINAPI, RasConnectionNotificationW,
	_In_ PVOID hrasconn,
	_In_ HANDLE   hEvent,
	_In_ DWORD	dwFlags
) {
	DWORD ret = Old_RasConnectionNotificationW(hrasconn, hEvent, dwFlags);
	LOQ_zero("misc", "");
	return ret;
}

HOOKDEF(BOOL, WINAPI, SystemTimeToTzSpecificLocalTime,
	_In_opt_ LPTIME_ZONE_INFORMATION lpTimeZone,
	_In_	 LPSYSTEMTIME			lpUniversalTime,
	_Out_	LPSYSTEMTIME			lpLocalTime
) {
	BOOL ret = Old_SystemTimeToTzSpecificLocalTime(lpTimeZone, lpUniversalTime, lpLocalTime);
	LOQ_bool("misc", "");
	return ret;
}

HOOKDEF(HRESULT, WINAPI, CLSIDFromProgID,
	_In_ LPCOLESTR lpszProgID,
	_Out_ LPCLSID lpclsid
) {
	HRESULT ret = Old_CLSIDFromProgID(lpszProgID, lpclsid);
	LOQ_hresult("misc", "u", "ProgID", lpszProgID);
	return ret;
}

HOOKDEF(HRESULT, WINAPI, CLSIDFromProgIDEx,
	_In_ LPCOLESTR lpszProgID,
	_Out_ LPCLSID lpclsid
) {
	HRESULT ret = Old_CLSIDFromProgIDEx(lpszProgID, lpclsid);
	LOQ_hresult("misc", "u", "ProgID", lpszProgID);
	return ret;
}

HOOKDEF(BOOL, WINAPI, GetCurrentHwProfileW,
	_Out_ LPHW_PROFILE_INFO lpHwProfileInfo
) {
	BOOL ret = Old_GetCurrentHwProfileW(lpHwProfileInfo);
	LOQ_bool("misc", "uu", "ProfileGUID", lpHwProfileInfo->szHwProfileGuid, "ProfileName", lpHwProfileInfo->szHwProfileName);
	return ret;
}

HOOKDEF(BOOL, WINAPI, IsUserAdmin,
	void
) {
	BOOL ret = Old_IsUserAdmin();
	LOQ_bool("misc", "");
	return ret;
}

HOOKDEF(void, WINAPI, GlobalMemoryStatus,
	_Out_ LPMEMORYSTATUS lpBuffer
) {
	BOOL ret = TRUE;
	Old_GlobalMemoryStatus(lpBuffer);
	if (!g_config.no_stealth && lpBuffer->dwTotalPhys < SPOOFED_RAM)
		lpBuffer->dwTotalPhys = (SIZE_T)SPOOFED_RAM;
	LOQ_void("misc", "ii", "MemoryLoad", lpBuffer->dwMemoryLoad, "TotalPhysicalMB", lpBuffer->dwTotalPhys / (1024 * 1024));
}

HOOKDEF(BOOL, WINAPI, GlobalMemoryStatusEx,
	_Out_ LPMEMORYSTATUSEX lpBuffer
)
{
/* Total physical RAM the sample must see to classify the host as a real
	 * user machine (16 GiB). The sample's heuristic reads
	 * MEMORYSTATUSEX.ullTotalPhys and flags a sandbox when either
	 *   Rule A: physical memory < 8 GiB, OR
	 *   Rule B: physical memory <= 15 GiB AND within +/-5% of a 1 GiB or 2 GiB
	 *           provisioning size.
	 * Forcing 16 GiB makes both rules evaluate false (16 > 8 and 16 > 15), so
	 * isUserEnv becomes true. */
	static const DWORDLONG MIRAGE_FORCED_TOTAL_PHYS = 17179869184ull; /* 16 GiB */
	BOOL ret;
	lasterror_t lasterror;
	DWORDLONG old_total;

	ret = Old_GlobalMemoryStatusEx(lpBuffer);

	/* Samples call GlobalMemoryStatusEx and read MEMORYSTATUSEX.ullTotalPhys
	 * (total physical RAM in bytes) to detect a memory-starved analysis VM: a
	 * value < 8 GiB (Rule A), or <= 15 GiB when the size sits within +/-5% of a
	 * typical 1 GiB or 2 GiB VM provisioning (Rule B), is treated as a sandbox
	 * rather than a genuine user desktop, so the sample takes its evasive
	 * branch. A lean guest is provisioned with only a couple of GiB, so the real
	 * report trips one of those rules. When the reported total is below the
	 * forced 16 GiB value, overwrite ullTotalPhys with 17179869184 bytes — above
	 * both the 8 GiB floor and the 15 GiB ceiling, so neither rule fires — and
	 * scale ullAvailPhys / ullTotalPageFile / ullAvailPageFile by the same factor
	 * so the reported available/total and page-file ratios stay self-consistent;
	 * when there is no usable baseline total, present a plausible ~50%-available
	 * buffer and a page file sized at ~1.5x physical RAM. lasterror is preserved
	 * around the forged response so the sample classifies the host as a real user
	 * environment and runs its task-routine. */
	if (!g_config.no_stealth && ret && lpBuffer != NULL &&
			lpBuffer->ullTotalPhys < MIRAGE_FORCED_TOTAL_PHYS) {
		get_lasterrors(&lasterror);

		old_total = lpBuffer->ullTotalPhys;

		if (old_total > 0) {
			/* preserve the real available/total and page-file fractions (in
			   permille) while growing the total, dividing first to avoid 64-bit
			   overflow */
			DWORDLONG avail_permille = lpBuffer->ullAvailPhys * 1000ull / old_total;
			DWORDLONG totpage_permille = lpBuffer->ullTotalPageFile * 1000ull / old_total;
			DWORDLONG availpage_permille = lpBuffer->ullAvailPageFile * 1000ull / old_total;

			lpBuffer->ullAvailPhys = MIRAGE_FORCED_TOTAL_PHYS / 1000ull * avail_permille;
			lpBuffer->ullTotalPageFile = MIRAGE_FORCED_TOTAL_PHYS / 1000ull * totpage_permille;
			lpBuffer->ullAvailPageFile = MIRAGE_FORCED_TOTAL_PHYS / 1000ull * availpage_permille;
		} else {
			/* no usable baseline: report a plausible ~50%-available buffer and a
			   page file sized at ~1.5x physical RAM */
			lpBuffer->ullAvailPhys = MIRAGE_FORCED_TOTAL_PHYS / 2ull;
			lpBuffer->ullTotalPageFile = MIRAGE_FORCED_TOTAL_PHYS * 3ull / 2ull;
			lpBuffer->ullAvailPageFile = MIRAGE_FORCED_TOTAL_PHYS * 3ull / 4ull;
		}

		lpBuffer->ullTotalPhys = MIRAGE_FORCED_TOTAL_PHYS;

		set_lasterrors(&lasterror);
	}

	LOQ_bool("misc", "ii", "MemoryLoad", lpBuffer != NULL ? lpBuffer->dwMemoryLoad : 0,
		"TotalPhysicalMB", lpBuffer != NULL ? (int)(lpBuffer->ullTotalPhys / (1024 * 1024)) : 0);
	return ret;
}

HOOKDEF(BOOL, WINAPI, GetPhysicallyInstalledSystemMemory,
	_Out_ PULONGLONG TotalMemoryInKilobytes
) {
	BOOL ret = Old_GetPhysicallyInstalledSystemMemory(TotalMemoryInKilobytes);
	if (ret && !g_config.no_stealth && (*TotalMemoryInKilobytes * 1024) < SPOOFED_RAM)
		*TotalMemoryInKilobytes = SPOOFED_RAM / 1024;
	LOQ_void("misc", "i", "TotalMemoryInKilobytes", *TotalMemoryInKilobytes);
	return ret;
}

HOOKDEF(BOOL, WINAPI, SystemParametersInfoA,
	_In_	UINT  uiAction,
	_In_	UINT  uiParam,
	_Inout_ PVOID pvParam,
	_In_	UINT  fWinIni
) {
	BOOL ret = Old_SystemParametersInfoA(uiAction, uiParam, pvParam, fWinIni);
	if (ret && (uiAction == SPI_SETDESKWALLPAPER || uiAction == SPI_GETDESKWALLPAPER))
		LOQ_bool("misc", "hhs", "Action", uiAction, "uiParam", uiParam, "pvParam", pvParam);
	else
		LOQ_bool("misc", "hh", "Action", uiAction, "uiParam", uiParam);

	return ret;
}

HOOKDEF(BOOL, WINAPI, SystemParametersInfoW,
	_In_	UINT  uiAction,
	_In_	UINT  uiParam,
	_Inout_ PVOID pvParam,
	_In_	UINT  fWinIni
) {
	BOOL ret = Old_SystemParametersInfoW(uiAction, uiParam, pvParam, fWinIni);
	if (ret && (uiAction == SPI_SETDESKWALLPAPER || uiAction == SPI_GETDESKWALLPAPER))
		LOQ_bool("misc", "hhu", "Action", uiAction, "uiParam", uiParam, "pvParam", pvParam);
	else
		LOQ_bool("misc", "hh", "Action", uiAction, "uiParam", uiParam);

	return ret;
}

HOOKDEF(HRESULT, WINAPI, PStoreCreateInstance,
	_Out_ PVOID **ppProvider,
	_In_  VOID *pProviderID,
	_In_  VOID *pReserved,
	_In_  DWORD dwFlags
) {
	HRESULT ret = Old_PStoreCreateInstance(ppProvider, pProviderID, pReserved, dwFlags);
	LOQ_hresult("misc", "");
	return ret;
}

HOOKDEF(void, WINAPIV, srand,
	unsigned int seed
)
{
	int ret = 0;	// needed for LOQ_void

	Old_srand(seed);

	LOQ_void("misc", "h", "seed", seed);
}

HOOKDEF(LPSTR, WINAPI, lstrcpynA,
  _Out_ LPSTR   lpString1,
  _In_  LPSTR   lpString2,
  _In_  int	 iMaxLength
)
{
	LPSTR ret;

	ret = Old_lstrcpynA(lpString1, lpString2, iMaxLength);

	LOQ_nonzero("misc", "u", "String", lpString1);

	return ret;
}

HOOKDEF(int, WINAPI, lstrcmpiA,
  _In_  LPCSTR   lpString1,
  _In_  LPCSTR   lpString2
)
{
	int ret;

	ret = Old_lstrcmpiA(lpString1, lpString2);

	LOQ_nonzero("misc", "ss", "String1", lpString1, "String2", lpString2);

	return ret;
}

HOOKDEF(HRSRC, WINAPI, FindResourceExA,
	HMODULE hModule,
	LPCSTR lpType,
	LPCSTR lpName,
	WORD wLanguage
)
{
	HRSRC ret = Old_FindResourceExA(hModule, lpType, lpName, wLanguage);

	char type_id[8];
	if (IS_INTRESOURCE(lpType)) {
		snprintf(type_id, sizeof type_id, "#%hu", (WORD)lpType);
		lpType = type_id;
	}

	char name_id[8];
	if (IS_INTRESOURCE(lpName)) {
		snprintf(name_id, sizeof name_id, "#%hu", (WORD)lpName);
		lpName = name_id;
	}

	LOQ_handle("misc", "pssh", "Module", hModule, "Type", lpType, "Name", lpName, "Language", wLanguage);

	return ret;
}

HOOKDEF(HRSRC, WINAPI, FindResourceExW,
	HMODULE hModule,
	LPCWSTR lpType,
	LPCWSTR lpName,
	WORD wLanguage
)
{
	HRSRC ret = Old_FindResourceExW(hModule, lpType, lpName, wLanguage);

	wchar_t type_id[8];
	if (IS_INTRESOURCE(lpType)) {
		swprintf_s(type_id, sizeof(type_id), L"#%hu", (WORD)lpType);
		lpType = type_id;
	}

	wchar_t name_id[8];
	if (IS_INTRESOURCE(lpName)) {
		swprintf_s(name_id, sizeof(name_id), L"#%hu", (WORD)lpName);
		lpName = name_id;
	}

	LOQ_handle("misc", "puuh", "Module", hModule, "Type", lpType, "Name", lpName, "Language", wLanguage);

	return ret;
}

HOOKDEF(HGLOBAL, WINAPI, LoadResource,
  _In_opt_ HMODULE hModule,
  _In_	 HRSRC   hResInfo
)
{
	HGLOBAL ret = Old_LoadResource(hModule, hResInfo);

	LOQ_handle("misc", "pp", "Module", hModule, "ResourceInfo", hResInfo);

	return ret;
}

HOOKDEF(LPVOID, WINAPI, LockResource,
  _In_ HGLOBAL hResData
)
{
	LPVOID ret = Old_LockResource(hResData);

	LOQ_nonnull("misc", "p", "ResourceData", hResData);

	return ret;
}

HOOKDEF(DWORD, WINAPI, SizeofResource,
	_In_opt_ HMODULE hModule,
	_In_	 HRSRC   hResInfo
)
{
	DWORD ret = Old_SizeofResource(hModule, hResInfo);

	LOQ_nonzero("misc", "pp", "ModuleHandle", hModule, "ResourceInfo", hResInfo);

	return ret;
}

HOOKDEF(BOOL, WINAPI, EnumResourceTypesExA,
	_In_opt_ HMODULE		 hModule,
	_In_	 ENUMRESTYPEPROC lpEnumFunc,
	_In_	 LONG_PTR		lParam,
	_In_	 DWORD		   dwFlags,
	_In_	 LANGID		  LangId
) {
	BOOL ret = TRUE;
	LOQ_bool("misc", "ppphh",
		"ModuleHandle", hModule,
		"EnumFunc", lpEnumFunc,
		"Parameter", lParam,
		"Flags", dwFlags,
		"LangId", LangId
	);
	return Old_EnumResourceTypesExA(hModule, lpEnumFunc, lParam, dwFlags, LangId);;
}

HOOKDEF(BOOL, WINAPI, EnumResourceTypesExW,
	_In_opt_ HMODULE		 hModule,
	_In_	 ENUMRESTYPEPROC lpEnumFunc,
	_In_	 LONG_PTR		lParam,
	_In_	 DWORD		   dwFlags,
	_In_	 LANGID		  LangId
) {
	BOOL ret = TRUE;
	LOQ_bool("misc", "ppphh",
		"ModuleHandle", hModule,
		"EnumFunc", lpEnumFunc,
		"Parameter", lParam,
		"Flags", dwFlags,
		"LangId", LangId
	);
	return Old_EnumResourceTypesExW(hModule, lpEnumFunc, lParam, dwFlags, LangId);;
}

HOOKDEF(BOOL, WINAPI, EnumCalendarInfoA,
	CALINFO_ENUMPROCA lpCalInfoEnumProc,
	LCID			  Locale,
	CALID			 Calendar,
	CALTYPE		   CalType
) {
	BOOL ret = TRUE;
	LOQ_bool("misc", "phhh",
		"CalInfoEnumProc", lpCalInfoEnumProc,
		"Locale", Locale,
		"Calendar", Calendar,
		"CalType", CalType
	);
	return Old_EnumCalendarInfoA(lpCalInfoEnumProc, Locale, Calendar, CalType);
}

HOOKDEF(BOOL, WINAPI, EnumCalendarInfoW,
	CALINFO_ENUMPROCA lpCalInfoEnumProc,
	LCID			  Locale,
	CALID			 Calendar,
	CALTYPE		   CalType
) {
	BOOL ret = TRUE;
	LOQ_bool("misc", "phhh",
		"CalInfoEnumProc", lpCalInfoEnumProc,
		"Locale", Locale,
		"Calendar", Calendar,
		"CalType", CalType
	);
	return Old_EnumCalendarInfoW(lpCalInfoEnumProc, Locale, Calendar, CalType);
}

HOOKDEF(BOOL, WINAPI, EnumTimeFormatsA,
	TIMEFMT_ENUMPROCA lpTimeFmtEnumProc,
	LCID			  Locale,
	DWORD			 dwFlags
) {
	BOOL ret = TRUE;
	LOQ_bool("misc", "phh",
		"TimeFmtEnumProc", lpTimeFmtEnumProc,
		"Locale", Locale,
		"Flags", dwFlags
	);
	return Old_EnumTimeFormatsA(lpTimeFmtEnumProc, Locale, dwFlags);
}

HOOKDEF(BOOL, WINAPI, EnumTimeFormatsW,
	TIMEFMT_ENUMPROCA lpTimeFmtEnumProc,
	LCID			  Locale,
	DWORD			 dwFlags
) {
	BOOL ret = TRUE;
	LOQ_bool("misc", "phh",
		"TimeFmtEnumProc", lpTimeFmtEnumProc,
		"Locale", Locale,
		"Flags", dwFlags
	);
	return Old_EnumTimeFormatsW(lpTimeFmtEnumProc, Locale, dwFlags);
}

HOOKDEF(NTSTATUS, WINAPI, NtCreateTransaction,
	PHANDLE			TransactionHandle,
	ACCESS_MASK		DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	LPGUID			 Uow,
	HANDLE			 TmHandle,
	ULONG			  CreateOptions,
	ULONG			  IsolationLevel,
	ULONG			  IsolationFlags,
	PLARGE_INTEGER	 Timeout,
	PUNICODE_STRING	Description
) {
	NTSTATUS ret = Old_NtCreateTransaction(TransactionHandle, DesiredAccess, ObjectAttributes, Uow, TmHandle, CreateOptions, IsolationLevel, IsolationFlags, Timeout, Description);
	LOQ_ntstatus("misc", "PhObphhhio",
		"TransactionHandle", TransactionHandle,
		"DesiredAccess", DesiredAccess,
		"ObjectAttributes", ObjectAttributes,
		"UnitOfWork", sizeof (GUID), Uow,
		"TmHandle", TmHandle,
		"CreateOptions", CreateOptions,
		"IsolationLevel", IsolationLevel,
		"IsolationFlags", IsolationFlags,
		"Timeout", Timeout,
		"Description", Description
	);
	return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtOpenTransaction,
	PHANDLE			TransactionHandle,
	ACCESS_MASK		DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	LPGUID			 Uow,
	HANDLE			 TmHandle
) {
	NTSTATUS ret = Old_NtOpenTransaction(TransactionHandle, DesiredAccess, ObjectAttributes, Uow, TmHandle);
	LOQ_ntstatus("misc", "PhObp",
		"TransactionHandle", TransactionHandle,
		"DesiredAccess", DesiredAccess,
		"ObjectAttributes", ObjectAttributes,
		"UnitOfWork", sizeof (GUID), Uow,
		"TmHandle", TmHandle
	);
	return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtRollbackTransaction,
	HANDLE  TransactionHandle,
	BOOLEAN Wait
) {
	NTSTATUS ret = Old_NtRollbackTransaction(TransactionHandle, Wait);
	LOQ_ntstatus("misc", "pi", "TransactionHandle", TransactionHandle, "Wait", Wait);
	return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtCommitTransaction,
	HANDLE  TransactionHandle,
	BOOLEAN Wait
) {
	NTSTATUS ret = Old_NtCommitTransaction(TransactionHandle, Wait);
	LOQ_ntstatus("misc", "pi", "TransactionHandle", TransactionHandle, "Wait", Wait);
	return ret;
}

HOOKDEF(BOOL, WINAPI, RtlSetCurrentTransaction,
	_In_ HANDLE	 TransactionHandle
) {
	BOOL ret = Old_RtlSetCurrentTransaction(TransactionHandle);
	LOQ_bool("misc", "p", "TransactionHandle", TransactionHandle);
	return ret;
}

HOOKDEF(HRESULT, WINAPI, OleConvertOLESTREAMToIStorage,
	IN LPOLESTREAM		  lpolestream,
	OUT LPSTORAGE		   pstg,
	IN const DVTARGETDEVICE *ptd
) {
	void *buf = NULL; uintptr_t len = 0;

	HRESULT ret = Old_OleConvertOLESTREAMToIStorage(lpolestream, pstg, ptd);

#ifndef _WIN64
	if (lpolestream != NULL) {
		buf = (PVOID)*((uint8_t *) lpolestream + 8);
		len = *((uint8_t *) lpolestream + 12);
	}
#endif

	LOQ_bool("misc", "b", "OLE2", len, buf);
	return ret;
}

HOOKDEF(HANDLE, WINAPI, HeapCreate,
  _In_ DWORD  flOptions,
  _In_ SIZE_T dwInitialSize,
  _In_ SIZE_T dwMaximumSize
)
{
	HANDLE ret;
	ret = Old_HeapCreate(flOptions, dwInitialSize, dwMaximumSize);
	LOQ_nonnull("misc", "ihh", "Options", flOptions, "InitialSize", dwInitialSize, "MaximumSize", dwMaximumSize);
	return ret;
}

HOOKDEF(BOOL, WINAPI, FlsAlloc,
	_In_ PFLS_CALLBACK_FUNCTION lpCallback
) {
	BOOL ret = Old_FlsAlloc(lpCallback);
	LOQ_bool("misc", "p", "Callback", lpCallback);
	return ret;
}

HOOKDEF(BOOL, WINAPI, FlsSetValue,
	_In_	 DWORD dwFlsIndex,
	_In_opt_ PVOID lpFlsData
) {
	BOOL ret = Old_FlsSetValue(dwFlsIndex, lpFlsData);
	LOQ_bool("misc", "ip", "Index", dwFlsIndex, "Data", lpFlsData);
	return ret;
}


HOOKDEF(PVOID, WINAPI, FlsGetValue,
	_In_	 DWORD dwFlsIndex
) {
	PVOID ret = Old_FlsGetValue(dwFlsIndex);
	LOQ_nonnull("misc", "ip", "Index", dwFlsIndex, "ReturnValue", ret);
	return ret;
}

HOOKDEF(BOOL, WINAPI, FlsFree,
	_In_	 DWORD dwFlsIndex
) {
	BOOL ret = Old_FlsFree(dwFlsIndex);
	LOQ_bool("misc", "ip", "Index", dwFlsIndex);
	return ret;
}


HOOKDEF(PVOID, WINAPI, LocalAlloc,
	_In_ UINT uFlags,
	_In_ SIZE_T uBytes)
{
	PVOID ret = Old_LocalAlloc(uFlags, uBytes);
	LOQ_nonnull("misc", "ii", "Flags", uFlags, "Bytes", uBytes);
	return ret;
}

HOOKDEF(VOID, WINAPI, LocalFree,
	HLOCAL hMem)
{
	int ret = 0;
	Old_LocalFree(hMem);
	LOQ_void("misc", "p", "SourceBuffer", hMem);
}

#define MSGFLT_ADD 1
#define MSGFLT_REMOVE 2
HOOKDEF(BOOL, WINAPI, ChangeWindowMessageFilter,
	UINT  message,
	DWORD dwFlag
)
{
	BOOL ret;
	if (dwFlag != MSGFLT_REMOVE && dwFlag != MSGFLT_ADD) {
		ret = FALSE;
		SetLastError(ERROR_INVALID_PARAMETER);
	}
	else
		ret = Old_ChangeWindowMessageFilter(message, dwFlag);
	LOQ_bool("misc", "ii", "message", message, "dwFlag", dwFlag);
	return ret;
}

HOOKDEF(LPWSTR, WINAPI, rtcEnvironBstr,
	struct envstruct *es
)
{
	LPWSTR ret = Old_rtcEnvironBstr(es);
	LOQ_bool("misc", "uu", "EnvVar", es->envstr, "EnvStr", ret);
	if (ret && !wcsicmp(es->envstr, L"userdomain"))
		// replace first char so it differs from computername
		*ret = '#';
	return ret;
}

HOOKDEF(HKL, WINAPI, GetKeyboardLayout,
	DWORD idThread
)
{
/* >= 3 distinct keyboard-layout handles cycled through so successive polls
	 * observe an organic input-language rotation rather than a frozen value or a
	 * naive two-value alternation. Each entry is a real HKL whose low word is the
	 * language id and high word the keyboard layout id: US English, UK English,
	 * French (France) and German (Germany) — a plausible set for a multilingual
	 * user who switches input languages. */
	static const HKL mirage_layouts[] = {
		(HKL)(ULONG_PTR)0x04090409ul,  /* en-US */
		(HKL)(ULONG_PTR)0x08090809ul,  /* en-GB */
		(HKL)(ULONG_PTR)0x040c040cul,  /* fr-FR */
		(HKL)(ULONG_PTR)0x04070407ul,  /* de-DE */
	};
	/* Irregular dwell times (ms) each layout is held for before the next switch.
	   Every value is strictly greater than 1000ms, so the sample's "two-value
	   ping-pong with toggle interval < 1000ms" branch can never fire; the spacing
	   itself varies from switch to switch (indexed by the change counter) so the
	   rotation never settles into a fixed, machine-looking cadence. */
	static const DWORD mirage_dwell_ms[] = {
		1500, 2300, 3100, 1700, 2900, 1300, 2600, 3700,
	};
	static unsigned int mirage_layout_index;   /* which layout is current */
	static unsigned int mirage_change_count;   /* how many switches so far */
	static DWORD mirage_last_change_tick;      /* capemon tick of last switch */
	static int mirage_initialized;
	HKL ret;
	const char* LanguageName = NULL;
	lasterror_t lasterror;
	DWORD now;
	DWORD dwell;
	unsigned int layout_total;
	unsigned int dwell_total;

	ret = Old_GetKeyboardLayout(idThread);
	if (g_config.lang)
		ret = (HKL)(DWORD_PTR)g_config.lang;

	/* Samples read the foreground thread's keyboard layout with
	 * GetKeyboardLayout(foregroundThreadId) every ~500ms across a ~120s window
	 * and watch the returned HKL for signs of human input-language switching: a
	 * value that never changes (changeCount == 0), or one that ping-pongs between
	 * exactly two handles faster than once a second (unique HKL count == 2 AND
	 * toggle interval < 1000ms), reads as an idle, headless analysis VM whose
	 * input language is either frozen or spoofed by a crude alternator. A
	 * freshly-imaged sandbox with nobody switching languages returns a single
	 * static HKL for the whole window, so changeCount stays 0 and the host is
	 * flagged. The transparent answer is to emulate an organic rotation: cycle
	 * through >= 3 distinct HKLs and hold each one for an irregular dwell that is
	 * always > 1000ms, so the layout does change over the window (defeating the
	 * changeCount == 0 branch) yet never presents as a two-value sub-second
	 * ping-pong (defeating the unique-count == 2 AND interval < 1000ms branch).
	 * Per-call state keeps the current layout, the switch counter, and the
	 * capemon tick of the last switch; a new layout is advanced only once the
	 * current one's irregular dwell has elapsed, so consecutive 500ms polls
	 * mostly see a stable value that occasionally rotates at human-plausible,
	 * unevenly-spaced intervals — over 120s that yields well more than three
	 * distinct handles observed with every gap over a second. lasterror is
	 * preserved around the forged response. */
	if (!g_config.no_stealth) {
		get_lasterrors(&lasterror);

		layout_total = (unsigned int)(sizeof(mirage_layouts) / sizeof(mirage_layouts[0]));
		dwell_total = (unsigned int)(sizeof(mirage_dwell_ms) / sizeof(mirage_dwell_ms[0]));
		now = GetTickCount();

		if (!mirage_initialized) {
			mirage_last_change_tick = now;
			mirage_initialized = 1;
		}

		/* switch to the next layout once the current one's irregular (> 1000ms)
		   dwell has elapsed, keeping every change more than a second apart */
		dwell = mirage_dwell_ms[mirage_change_count % dwell_total];
		if ((DWORD)(now - mirage_last_change_tick) >= dwell) {
			mirage_layout_index = (mirage_layout_index + 1) % layout_total;
			mirage_change_count++;
			mirage_last_change_tick = now;
		}

		ret = mirage_layouts[mirage_layout_index];

		set_lasterrors(&lasterror);
	}

	if (ret)
		LanguageName = GetLanguageName((LANGID)ret);
	if (LanguageName)
		LOQ_nonnull("misc", "ps", "KeyboardLayout", (DWORD_PTR)ret & 0xFFFF, "LanguageName", LanguageName);
	else
		LOQ_nonnull("misc", "p", "KeyboardLayout", (DWORD_PTR)ret & 0xFFFF);
	return ret;
}

HOOKDEF(VOID, WINAPI, RtlMoveMemory,
	_Out_	   VOID UNALIGNED *Destination,
	_In_  const VOID UNALIGNED *Source,
	_In_		SIZE_T		 Length
)
{
	int ret = 0;
	Old_RtlMoveMemory(Destination, Source, Length);
	LOQ_void("misc", "bppi", "Destination", Length, Destination, "Source", Source, "destination", Destination, "Length", Length);
	return;
}

HOOKDEF(void, WINAPI, OutputDebugStringA,
	LPCSTR lpOutputString
)
{
	int ret = 0;
	Old_OutputDebugStringA(lpOutputString);
	LOQ_void("misc", "s", "OutputString", lpOutputString);
	return;
}

HOOKDEF(void, WINAPI, OutputDebugStringW,
	LPCWSTR lpOutputString
)
{
	int ret = 0;
	Old_OutputDebugStringW(lpOutputString);
	LOQ_void("misc", "u", "OutputString", lpOutputString);
	return;
}

HOOKDEF(void, WINAPI, SysFreeString,
	BSTR bstrString
)
{
	int ret = 0;
	if (SysStringLen(bstrString) > 3)
		LOQ_void("misc", "u", "String", bstrString);
	Old_SysFreeString(bstrString);
	return;
}

HOOKDEF_NOTAIL(WINAPI, ScriptIsComplex,
	const WCHAR *pwcInChars,
	int cInChars,
	DWORD dwFlags
)
{
	DWORD ret = 0;
	if (cInChars > 1)
		LOQ_void("misc", "uii", "pwcInChars", pwcInChars, "cInChars", cInChars, "dwFlags", dwFlags);
	return ret;
}

HOOKDEF(int, WINAPI, StrCmpNICW,
	_In_ LPCWSTR pszStr1,
	_In_ LPCWSTR pszStr2,
	_In_ int nChar
)
{
	int ret;
	ret = Old_StrCmpNICW(pszStr1, pszStr2, nChar);
	LOQ_nonzero("misc", "uui", "String1", pszStr1, "String2", pszStr2, "nChar", nChar);
	return ret;
}

HOOKDEF(HRESULT, WINAPI, VarBstrCat,
	_In_ BSTR bstrLeft,
	_In_ BSTR bstrRight,
	_In_ LPBSTR pbstrResult
)
{
	HRESULT ret = Old_VarBstrCat(bstrLeft, bstrRight, pbstrResult);
	LOQ_void("misc", "uuu", "bstrLeft", bstrLeft, "bstrRight", bstrRight, "pbstrResult", *pbstrResult);
	return ret;
}

HOOKDEF_NOTAIL(WINAPI, rtcCreateObject2,
	WORD *arg1,
	LPCOLESTR arg2,
	wchar_t arg3
)
{
	DWORD ret = 0;
	LOQ_void("misc", "u", "ProgID", arg2);
	return ret;
}

HOOKDEF(BOOL, WINAPI, RtlDosPathNameToNtPathName_U,
	_In_	   PCWSTR DosFileName,
	_Out_	  PUNICODE_STRING NtFileName,
	_Out_opt_  PWSTR* FilePath,
	_Out_opt_  VOID* DirectoryInfo
)
{
	BOOL ret = Old_RtlDosPathNameToNtPathName_U(DosFileName, NtFileName, FilePath, DirectoryInfo);
	LOQ_bool("misc", "u", "DosFileName", DosFileName);
	return ret;
}

HOOKDEF_NOTAIL(WINAPI, DownloadFile,
	LPCSTR url,
	LPCSTR path,
	int flag
)
{
	DWORD ret = 0;
	LOQ_void("network", "ssi", "URL", url,"Path", path, "Flag",flag);
	return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtQueryLicenseValue,
	__in		PUNICODE_STRING Name,
	__in_opt	ULONG* Type,
	__in_opt	PVOID Buffer,
	__in		ULONG Length,
	__in		ULONG* DataLength
) {
	WCHAR VMDetection[] = L"Kernel-VMDetection-Private";
	NTSTATUS ret = Old_NtQueryLicenseValue(Name, Type, Buffer, Length, DataLength);
	if (NT_SUCCESS(ret) && Buffer && !wcsncmp(Name->Buffer, VMDetection, Name->Length))
		*(PBOOL)Buffer = FALSE;
	LOQ_ntstatus("system", "oP", "Name", Name, "Type", Type);
	return ret;
}

HOOKDEF(int, WINAPI, MultiByteToWideChar,
	__in		UINT	CodePage,
	__in		DWORD	dwFlags,
	__in		LPCCH	lpMultiByteStr,
	__in		int		cbMultiByte,
	__out_opt	LPWSTR	lpWideCharStr,
	__in		int		cchWideChar
) {
	DWORD ret = 0;
	if (CodePage == CP_ACP || CodePage == CP_UTF8)
		LOQ_zero("misc", "s", "String", lpMultiByteStr);
	return Old_MultiByteToWideChar(CodePage, dwFlags, lpMultiByteStr, cbMultiByte, lpWideCharStr, cchWideChar);
}

HOOKDEF(int, WINAPI, WideCharToMultiByte,
	__in		UINT	CodePage,
	__in		DWORD	dwFlags,
	__in		LPCWCH	lpWideCharStr,
	__in		int		cchWideChar,
	__out_opt	LPSTR	lpMultiByteStr,
	__in		int		cbMultiByte,
	__in_opt	LPCCH	lpDefaultChar,
	__out_opt	LPBOOL	lpUsedDefaultChar
) {
	DWORD ret = 0;
	if (CodePage == CP_ACP || CodePage == CP_UTF8)
		LOQ_zero("misc", "u", "String", lpWideCharStr);
	return Old_WideCharToMultiByte(CodePage, dwFlags, lpWideCharStr, cchWideChar, lpMultiByteStr, cbMultiByte, lpDefaultChar, lpUsedDefaultChar);
}

HOOKDEF(LPSTR, WINAPI, GetCommandLineA,
	void
) {
	LPSTR ret = Old_GetCommandLineA();
	LOQ_nonnull("misc", "s", "CommandLine", ret);
	return ret;
}

HOOKDEF(LPWSTR, WINAPI, GetCommandLineW,
	void
) {
	LPWSTR ret = Old_GetCommandLineW();
	LOQ_nonnull("misc", "u", "CommandLine", ret);
	return ret;
}

HOOKDEF(LPWSTR, WINAPI, CommandLineToArgvW,
	__in LPWSTR lpCmdLine,
	__out int *pNumArgs
) {
	LPWSTR ret = Old_CommandLineToArgvW(lpCmdLine, pNumArgs);
	LOQ_nonnull("misc", "ui", "CommandLine", lpCmdLine, "NumArgs", *pNumArgs);
	return ret;
}

HOOKDEF(BOOL, WINAPI, EnumDisplayDevicesA,
	_In_	LPCSTR  lpDevice,
	_In_	DWORD  iDevNum,
	_Out_   PDISPLAY_DEVICEA lpDisplayDevice,
	_In_	DWORD  dwFlags
)
{
/* Benign physical-GPU adapter string forged over the primary display
	   adapter's DISPLAY_DEVICEA.DeviceString so none of the VM-vendor
	   substring keywords the sample scans for survive. */
	static const char forced_device_string[] = "NVIDIA GeForce RTX 3080";
	BOOL ret;
	lasterror_t lasterror;

	ret = Old_EnumDisplayDevicesA(lpDevice, iDevNum, lpDisplayDevice, dwFlags);

	/* Samples enumerate the primary display adapter (lpDevice == NULL,
	 * iDevNum == 0) with EnumDisplayDevicesA and read
	 * DISPLAY_DEVICEA.DeviceString, testing it case-insensitively for a
	 * virtualization-vendor substring — 'vmware', 'virtualbox', 'hyper-v'. A
	 * VM's primary adapter reports a virtual GPU model
	 * ("VMware SVGA 3D", "VirtualBox Graphics Adapter",
	 * "Microsoft Hyper-V Video") that matches one of those keywords, so the
	 * check hits and the sample takes its sandbox-detected branch. After the
	 * real call succeeds on the primary adapter, overwrite DeviceString with a
	 * benign physical-GPU vendor string ("NVIDIA GeForce RTX 3080") so all
	 * three VM-vendor substring checks fail and the sample follows its
	 * real-user-environment payload branch. lasterror is preserved around the
	 * forged response. */
	if (!g_config.no_stealth && ret && lpDisplayDevice != NULL &&
			iDevNum == 0 && lpDevice == NULL) {
		get_lasterrors(&lasterror);

		lstrcpynA(lpDisplayDevice->DeviceString, forced_device_string,
			sizeof(lpDisplayDevice->DeviceString));

		set_lasterrors(&lasterror);
	}

	LOQ_bool("window", "is", "DevNum", iDevNum, "DeviceString",
		(ret && lpDisplayDevice != NULL) ? lpDisplayDevice->DeviceString : "");

	return ret;
}

HOOKDEF(BOOL, WINAPI, EnumDisplayDevicesW,
	_In_	LPCWSTR  lpDevice,
	_In_	DWORD  iDevNum,
	_Out_   PDISPLAY_DEVICEW lpDisplayDevice,
	_In_	DWORD  dwFlags
) {
	const wchar_t* keywords[] = {
		L"microsoft hyper-v video",
		L"virtual",
		L"vmware",
		L"standard vga graphics adapter",
		L"microsoft basic display adapter"
	};
	int keywords_size = sizeof(keywords) / sizeof(keywords[0]);

	const wchar_t replacement[] = L"NVIDIA GeForce RTX 3060";

	BOOL ret = Old_EnumDisplayDevicesW(lpDevice, iDevNum, lpDisplayDevice, dwFlags);
	for (int i = 0; i < keywords_size; i++) {
		if (wcsistr(lpDisplayDevice->DeviceString, keywords[i]) != NULL) {
			swprintf(lpDisplayDevice->DeviceString, wcslen(replacement) + 1, replacement);
			break;
		}
	}
	LOQ_bool("misc", "u", "DeviceString", lpDisplayDevice->DeviceString);
	return ret;
}

HOOKDEF(UINT, WINAPI, MsiInstallProductA,
	_In_	LPCSTR	szPackagePath,
	_In_	LPCSTR	szCommandLine
) {
	UINT ret = Old_MsiInstallProductA(szPackagePath, szCommandLine);
	LOQ_zero("misc", "ss", "PackagePath", szPackagePath, "CommandLine", szCommandLine);
	return ret;
}

HOOKDEF(UINT, WINAPI, MsiInstallProductW,
	_In_	LPCWSTR	szPackagePath,
	_In_	LPCWSTR	szCommandLine
) {
	UINT ret = Old_MsiInstallProductW(szPackagePath, szCommandLine);
	LOQ_zero("misc", "uu", "PackagePath", szPackagePath, "CommandLine", szCommandLine);
	return ret;
}

HOOKDEF(ULONG, __fastcall, vDbgPrintExWithPrefixInternal,
	__in  PCH Prefix,
	__in  ULONG ComponentId,
	__in  ULONG Level,
	__in  PCHAR Format,
	__in  va_list arglist,
	__in  BOOLEAN HandleBreakpoint
) {
    UCHAR Buffer[512];
    size_t cb = strlen(Prefix);
    strcpy(Buffer, Prefix);
    cb = _vsnprintf(Buffer + cb, sizeof(Buffer) - cb, Format, arglist) + cb;

    if (cb == -1) {
        cb = sizeof(Buffer);
        Buffer[sizeof(Buffer) - 1] = '\n';
    }

	DebugOutput("%s", Buffer);

    return Old_vDbgPrintExWithPrefixInternal(Prefix, ComponentId, Level, Format, arglist, HandleBreakpoint);
}

HOOKDEF(DWORD, WINAPI, MapFileAndCheckSumA,
	_In_  PCSTR  Filename,
	_Out_ PDWORD HeaderSum,
	_Out_ PDWORD CheckSum
) {
	DWORD ret = Old_MapFileAndCheckSumA(Filename, HeaderSum, CheckSum);

	if (HeaderSum && CheckSum)
		*CheckSum = *HeaderSum;

	if (HeaderSum && CheckSum)
		LOQ_zero("misc", "fhh", "Filename", Filename, "HeaderSum", *HeaderSum, "CheckSum", *CheckSum);
	else
		LOQ_zero("misc", "f", "Filename", Filename);

	return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtPowerInformation,
	__in		POWER_INFORMATION_LEVEL InformationLevel,
	__in_opt	PVOID                   InputBuffer,
	__in		ULONG                   InputBufferLength,
	__out_opt	PVOID                   OutputBuffer,
	__in		ULONG                   OutputBufferLength
) {
	NTSTATUS ret = Old_NtPowerInformation(InformationLevel, InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength);
	if (ret == 0 && OutputBuffer && InformationLevel == SystemPowerCapabilities && OutputBufferLength >= sizeof(SYSTEM_POWER_CAPABILITIES)) {
		// Most VM systems does not support either S0 or S3 sleep, which can be used to detect the presence of a VM.
		// S0, S4 and S5 being enabled is typical for a normal Modern Standby machine. 
		SYSTEM_POWER_CAPABILITIES* ptr = (SYSTEM_POWER_CAPABILITIES *)OutputBuffer;
		ptr->AoAc = 1;
		ptr->SystemS4 = 1;
		ptr->SystemS5 = 1;
		ptr->ThermalControl = 1;
	}
	LOQ_ntstatus("device", "ibb",
		"InformationLevel", InformationLevel,
		"InputBuffer", InputBufferLength, InputBuffer,
		"OutputBuffer", OutputBufferLength, OutputBuffer);
	return ret;
}
