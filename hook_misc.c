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
) {

	HHOOK ret;

	if (hMod && lpfn && dwThreadId) {
		DWORD pid = get_pid_by_tid(dwThreadId);
		if (pid != GetCurrentProcessId())
			ProcessMessage(pid, 0);
	}

	ret = Old_SetWindowsHookExW(idHook, lpfn, hMod, dwThreadId);
	LOQ_nonnull("system", "ippi", "HookIdentifier", idHook, "ProcedureAddress", lpfn,
		"ModuleAddress", hMod, "ThreadId", dwThreadId);
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
) {
	int ret = Old_GetSystemMetrics(nIndex);

	if (!g_config.no_stealth) {
		if (nIndex == SM_CXSCREEN || nIndex == SM_CXVIRTUALSCREEN)
			ret = 1920;
		else if (nIndex == SM_CYSCREEN || nIndex == SM_CYVIRTUALSCREEN)
			ret = 1080;
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
) {
	ENSURE_STRUCT(lpPoint, POINT);
	BOOL ret = Old_GetCursorPos(lpPoint);

	/* work around the fact that skipping sleeps prevents the human module from making the system look active */
	if (ret && time_skipped.QuadPart != last_skipped.QuadPart) {
		int xres, yres;
		xres = our_GetSystemMetrics(0);
		yres = our_GetSystemMetrics(1);
		if (!num_to_spoof)
			num_to_spoof = (random() % 20) + 10;
		if (num_spoofed < num_to_spoof) {
			lpPoint->x = random() % xres;
			lpPoint->y = random() % yres;
			num_spoofed++;
		}
		else {
			lpPoint->x = lastx;
			lpPoint->y = lasty;
			lastx = lpPoint->x;
			lasty = lpPoint->y;
		}
		last_skipped.QuadPart = time_skipped.QuadPart;
	}
	else if (last_skipped.QuadPart == 0) {
		last_skipped.QuadPart = time_skipped.QuadPart;
	}

	if (ret){
			LOQ_bool("misc", "ii", "x", lpPoint != NULL ? lpPoint->x : 0,
				 "y", lpPoint != NULL ? lpPoint->y : 0);
	}
	else{
		LOQ_bool("misc", "ii", "x", 0, "y", 0);
	}
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
) {
	SHORT ret = Old_GetAsyncKeyState(vKey);
	if (asynckeystate_logcount < 50 && ((vKey >= 0x30 && vKey <= 0x39) || (vKey >= 0x41 && vKey <= 0x5a))) {
		asynckeystate_logcount++;
		LOQ_nonzero("windows", "i", "KeyCode", vKey);
	}
	else if (asynckeystate_logcount == 50) {
		asynckeystate_logcount++;
		LOQ_nonzero("windows", "is", "KeyCode", vKey, "Status", "Log limit reached");
	}
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
) {
	int ret = 0;

	Old_GetSystemInfo(lpSystemInfo);

	if (!g_config.no_stealth && lpSystemInfo->dwNumberOfProcessors < g_config.spoofed_cpu_count)
		lpSystemInfo->dwNumberOfProcessors = g_config.spoofed_cpu_count;

	LOQ_void("misc", "");

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

		if (!g_config.no_stealth && SystemInformationClass == SystemHypervisorDetailInformation) {
			if (SystemInformation && SystemInformationLength > 0) {
				memset(SystemInformation, 0, SystemInformationLength);
			}
			if (ReturnLength) {
				*ReturnLength = 0;
			}
			return 0xC0000003L; // STATUS_INVALID_INFO_CLASS
		}

		if (!g_config.no_stealth && SystemInformationClass == SystemBasicInformation && SystemInformationLength >= sizeof(SYSTEM_BASIC_INFORMATION) && NT_SUCCESS(ret)) {
			PSYSTEM_BASIC_INFORMATION p = (PSYSTEM_BASIC_INFORMATION)SystemInformation;
			p->NumberOfProcessors = g_config.spoofed_cpu_count;
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
) {
	BOOL ret;
	ENSURE_DWORD(PropertyRegDataType);
	ENSURE_DWORD(RequiredSize);

	ret = Old_SetupDiGetDeviceRegistryPropertyA(DeviceInfoSet, DeviceInfoData, Property, PropertyRegDataType, PropertyBuffer, PropertyBufferSize, RequiredSize);

	if (!g_config.no_stealth && ret && PropertyBuffer) {
		replace_ci_string_in_buf(PropertyBuffer, *RequiredSize, "VBOX", "DELL_");
		replace_ci_string_in_buf(PropertyBuffer, *RequiredSize, "QEMU", "DELL");
		replace_ci_string_in_buf(PropertyBuffer, *RequiredSize, "VMWARE", "DELL__");
	}

	if (PropertyBuffer)
		LOQ_bool("misc", "ir", "Property", Property, "PropertyBuffer", *PropertyRegDataType, PropertyBufferSize, PropertyBuffer);

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
) {
	BOOL ret = Old_GlobalMemoryStatusEx(lpBuffer);
	if (ret && !g_config.no_stealth && lpBuffer->ullTotalPhys < SPOOFED_RAM)
		lpBuffer->ullTotalPhys = SPOOFED_RAM;
	LOQ_void("misc", "ii", "MemoryLoad", lpBuffer->dwMemoryLoad, "TotalPhysicalMB", lpBuffer->ullTotalPhys / (1024 * 1024));
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
	HKL ret = Old_GetKeyboardLayout(idThread);
	if (g_config.lang)
		ret = (HKL)(DWORD_PTR)g_config.lang;
	const char* LanguageName = NULL;
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
) {
	const char* keywords[] = {
		"microsoft hyper-v video",
		"virtual",
		"vmware",
		"standard vga graphics adapter",
		"microsoft basic display adapter"
	};
	int keywords_size = sizeof(keywords) / sizeof(keywords[0]);

	const char replacement[] = "NVIDIA GeForce RTX 3060";

	BOOL ret = Old_EnumDisplayDevicesA(lpDevice, iDevNum, lpDisplayDevice, dwFlags);
	for (int i = 0; i < keywords_size; i++) {
		if (stristr(lpDisplayDevice->DeviceString, keywords[i]) != NULL) {
			snprintf(lpDisplayDevice->DeviceString, strlen(replacement) + 1, replacement);
			break;
		}
	}
	LOQ_bool("misc", "s", "DeviceString", lpDisplayDevice->DeviceString);
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

/* ==== complete_hooks.py generated batch (all-free) ==== */

// -> hook_misc.c に追加 | category="misc" | winapi:Font and Text
// REVIEW: 戻り型 HFONT の成功判定が曖昧 -> LOQ_nonzero を仮採用。0=成功のAPIなら LOQ_zero 等へ変更
// REVIEW: 引数 lplf: 型 const LOGFONT* は自動解釈不可(構造体等)。アドレスのみ記録。内容が重要なら該当メンバを手動でログ
HOOKDEF(HFONT, WINAPI, CreateFontIndirectW, // 呼出規約は WINAPI 仮定(socket/native/CRT系は要確認)
	_In_ const LOGFONT* lplf
) {
	HFONT ret;
	ret = Old_CreateFontIndirectW(lplf);
	LOQ_nonzero("misc", "p", "Lf", lplf);
	return ret;
}

// -> hook_misc.c に追加 | category="misc" | winapi:Device Context
HOOKDEF(BOOL, WINAPI, DeleteDC, // 呼出規約は WINAPI 仮定(socket/native/CRT系は要確認)
	_In_ HDC hdc
) {
	BOOL ret;
	ret = Old_DeleteDC(hdc);
	LOQ_bool("misc", "p", "Dc", hdc);
	return ret;
}

// -> hook_misc.c に追加 | category="misc" | winapi:Device Context
HOOKDEF(BOOL, WINAPI, DeleteObject, // 呼出規約は WINAPI 仮定(socket/native/CRT系は要確認)
	_In_ HGDIOBJ hObject
) {
	BOOL ret;
	ret = Old_DeleteObject(hObject);
	LOQ_bool("misc", "p", "Object", hObject);
	return ret;
}

// -> hook_misc.c に追加 | category="misc" | winapi:Font and Text
// REVIEW: 戻り型 int の成功判定が曖昧 -> LOQ_nonzero を仮採用。0=成功のAPIなら LOQ_zero 等へ変更
// REVIEW: 引数 lpDTParams: 型 LPDRAWTEXTPARAMS は自動解釈不可(構造体等)。アドレスのみ記録。内容が重要なら該当メンバを手動でログ
HOOKDEF(int, WINAPI, DrawTextExW, // 呼出規約は WINAPI 仮定(socket/native/CRT系は要確認)
	_In_ HDC hdc,
	_Inout_ LPWSTR lpchText,
	_In_ int cchText,
	_Inout_ LPRECT lprc,
	_In_ UINT dwDTFormat,
	_In_ LPDRAWTEXTPARAMS lpDTParams
) {
	int ret;
	ret = Old_DrawTextExW(hdc, lpchText, cchText, lprc, dwDTFormat, lpDTParams);
	LOQ_nonzero("misc", "puiPip", "Dc", hdc, "ChText", lpchText, "Text", cchText, "Rc", lprc, "DTFormat", dwDTFormat, "DTParams", lpDTParams);
	return ret;
}

// -> hook_misc.c に追加 | category="misc" | winapi:Device Context
HOOKDEF(BOOL, WINAPI, EnumDisplaySettingsW, // 呼出規約は WINAPI 仮定(socket/native/CRT系は要確認)
	_In_ LPCWSTR lpszDeviceName,
	_In_ DWORD iModeNum,
	_Out_ DEVMODE* lpDevMode
) {
	BOOL ret;
	ret = Old_EnumDisplaySettingsW(lpszDeviceName, iModeNum, lpDevMode);
	LOQ_bool("misc", "uiP", "SzDeviceName", lpszDeviceName, "IModeNum", iModeNum, "DevMode", lpDevMode);
	return ret;
}

// -> hook_misc.c に追加 | category="misc" | winapi:System Information Functions
// REVIEW: 戻り型 UINT の成功判定が曖昧 -> LOQ_nonzero を仮採用。0=成功のAPIなら LOQ_zero 等へ変更
// REVIEW: 引数 pFirmwareTableBuffer: 生バッファ(void*)。アドレスのみ記録。長さ引数と対にして 'b'(size_t,buf)/'S'(int,buf) 指定にすれば内容を人間可読で記録できる
HOOKDEF(UINT, WINAPI, EnumSystemFirmwareTables, // 呼出規約は WINAPI 仮定(socket/native/CRT系は要確認)
	_In_ DWORD FirmwareTableProviderSignature,
	_Out_ PVOID pFirmwareTableBuffer,
	_In_ DWORD BufferSize
) {
	UINT ret;
	ret = Old_EnumSystemFirmwareTables(FirmwareTableProviderSignature, pFirmwareTableBuffer, BufferSize);
	LOQ_nonzero("misc", "ipi", "FirmwareTableProviderSignature", FirmwareTableProviderSignature, "FirmwareTableBuffer", pFirmwareTableBuffer, "BufferSize", BufferSize);
	return ret;
}

// -> hook_misc.c に追加 | category="misc" | winapi:System Information Functions
// REVIEW: 戻り型 DWORD の成功判定が曖昧 -> LOQ_nonzero を仮採用。0=成功のAPIなら LOQ_zero 等へ変更
HOOKDEF(DWORD, WINAPI, ExpandEnvironmentStringsA, // 呼出規約は WINAPI 仮定(socket/native/CRT系は要確認)
	_In_ LPCSTR lpSrc,
	_Out_opt_ LPSTR lpDst,
	_In_ DWORD nSize
) {
	DWORD ret;
	ret = Old_ExpandEnvironmentStringsA(lpSrc, lpDst, nSize);
	LOQ_nonzero("misc", "ssi", "Src", lpSrc, "Dst", lpDst, "Size", nSize);
	return ret;
}

// -> hook_misc.c に追加 | category="misc" | winapi:Device Context
HOOKDEF(HGDIOBJ, WINAPI, GetCurrentObject, // 呼出規約は WINAPI 仮定(socket/native/CRT系は要確認)
	_In_ HDC hdc,
	_In_ UINT uObjectType
) {
	HGDIOBJ ret;
	ret = Old_GetCurrentObject(hdc, uObjectType);
	LOQ_nonnull("misc", "pi", "Dc", hdc, "UObjectType", uObjectType);
	return ret;
}

// -> hook_misc.c に追加 | category="misc" | winapi:Device Context
HOOKDEF(HDC, WINAPI, GetDC, // 呼出規約は WINAPI 仮定(socket/native/CRT系は要確認)
	_In_ HWND hWnd
) {
	HDC ret;
	ret = Old_GetDC(hWnd);
	LOQ_nonnull("misc", "p", "Wnd", hWnd);
	return ret;
}

// -> hook_misc.c に追加 | category="misc" | winapi:Device Context
// REVIEW: 引数 hrgnClip: 型 HRGN は自動解釈不可(構造体等)。アドレスのみ記録。内容が重要なら該当メンバを手動でログ
HOOKDEF(HDC, WINAPI, GetDCEx, // 呼出規約は WINAPI 仮定(socket/native/CRT系は要確認)
	_In_ HWND hWnd,
	_In_ HRGN hrgnClip,
	_In_ DWORD flags
) {
	HDC ret;
	ret = Old_GetDCEx(hWnd, hrgnClip, flags);
	LOQ_nonnull("misc", "ppi", "Wnd", hWnd, "RgnClip", hrgnClip, "Lags", flags);
	return ret;
}

// -> hook_misc.c に追加 | category="misc" | winapi:Device Context
// REVIEW: 戻り型 int の成功判定が曖昧 -> LOQ_nonzero を仮採用。0=成功のAPIなら LOQ_zero 等へ変更
HOOKDEF(int, WINAPI, GetDeviceCaps, // 呼出規約は WINAPI 仮定(socket/native/CRT系は要確認)
	_In_ HDC hdc,
	_In_ int nIndex
) {
	int ret;
	ret = Old_GetDeviceCaps(hdc, nIndex);
	LOQ_nonzero("misc", "pi", "Dc", hdc, "Index", nIndex);
	return ret;
}

// -> hook_misc.c に追加 | category="misc" | winapi:System Information Functions
// REVIEW: 戻り型 DWORD の成功判定が曖昧 -> LOQ_nonzero を仮採用。0=成功のAPIなら LOQ_zero 等へ変更
HOOKDEF(DWORD, WINAPI, GetEnvironmentVariableA, // 呼出規約は WINAPI 仮定(socket/native/CRT系は要確認)
	_In_opt_ LPCSTR lpName,
	_Out_opt_ LPSTR lpBuffer,
	_In_ DWORD nSize
) {
	DWORD ret;
	ret = Old_GetEnvironmentVariableA(lpName, lpBuffer, nSize);
	LOQ_nonzero("misc", "ssi", "Name", lpName, "Buffer", lpBuffer, "Size", nSize);
	return ret;
}

// -> hook_misc.c に追加 | category="misc" | winapi:Multiple Display Monitors
// REVIEW: 引数 hMonitor: 型 HMONITOR は自動解釈不可(構造体等)。アドレスのみ記録。内容が重要なら該当メンバを手動でログ
HOOKDEF(BOOL, WINAPI, GetMonitorInfoW, // 呼出規約は WINAPI 仮定(socket/native/CRT系は要確認)
	_In_ HMONITOR hMonitor,
	_Out_ LPMONITORINFO lpmi
) {
	BOOL ret;
	ret = Old_GetMonitorInfoW(hMonitor, lpmi);
	LOQ_bool("misc", "pP", "Monitor", hMonitor, "Mi", lpmi);
	return ret;
}

// -> hook_misc.c に追加 | category="misc" | winapi:Device Context
// REVIEW: 戻り型 int の成功判定が曖昧 -> LOQ_nonzero を仮採用。0=成功のAPIなら LOQ_zero 等へ変更
// REVIEW: 引数 lpvObject: 生バッファ(void*)。アドレスのみ記録。長さ引数と対にして 'b'(size_t,buf)/'S'(int,buf) 指定にすれば内容を人間可読で記録できる
HOOKDEF(int, WINAPI, GetObjectW, // 呼出規約は WINAPI 仮定(socket/native/CRT系は要確認)
	_In_ HGDIOBJ hgdiobj,
	_In_ int cbBuffer,
	_Out_ LPVOID lpvObject
) {
	int ret;
	ret = Old_GetObjectW(hgdiobj, cbBuffer, lpvObject);
	LOQ_nonzero("misc", "pip", "Gdiobj", hgdiobj, "Buffer", cbBuffer, "VObject", lpvObject);
	return ret;
}

// -> hook_misc.c に追加 | category="misc" | winapi:Device Context
HOOKDEF(HGDIOBJ, WINAPI, GetStockObject, // 呼出規約は WINAPI 仮定(socket/native/CRT系は要確認)
	_In_ int fnObject
) {
	HGDIOBJ ret;
	ret = Old_GetStockObject(fnObject);
	LOQ_nonnull("misc", "i", "NObject", fnObject);
	return ret;
}

// -> hook_misc.c に追加 | category="misc" | winapi:System Information Functions
// REVIEW: 戻り型 UINT の成功判定が曖昧 -> LOQ_nonzero を仮採用。0=成功のAPIなら LOQ_zero 等へ変更
// REVIEW: 引数 pFirmwareTableBuffer: 生バッファ(void*)。アドレスのみ記録。長さ引数と対にして 'b'(size_t,buf)/'S'(int,buf) 指定にすれば内容を人間可読で記録できる
HOOKDEF(UINT, WINAPI, GetSystemFirmwareTable, // 呼出規約は WINAPI 仮定(socket/native/CRT系は要確認)
	_In_ DWORD FirmwareTableProviderSignature,
	_In_ DWORD FirmwareTableID,
	_Out_ PVOID pFirmwareTableBuffer,
	_In_ DWORD BufferSize
) {
	UINT ret;
	ret = Old_GetSystemFirmwareTable(FirmwareTableProviderSignature, FirmwareTableID, pFirmwareTableBuffer, BufferSize);
	LOQ_nonzero("misc", "iipi", "FirmwareTableProviderSignature", FirmwareTableProviderSignature, "FirmwareTableID", FirmwareTableID, "FirmwareTableBuffer", pFirmwareTableBuffer, "BufferSize", BufferSize);
	return ret;
}

// -> hook_misc.c に追加 | category="misc" | winapi:Painting and Drawing
// REVIEW: 引数 lpRect: 型 const RECT* は自動解釈不可(構造体等)。アドレスのみ記録。内容が重要なら該当メンバを手動でログ
HOOKDEF(BOOL, WINAPI, InvalidateRect, // 呼出規約は WINAPI 仮定(socket/native/CRT系は要確認)
	_In_ HWND hWnd,
	_In_ const RECT* lpRect,
	_In_ BOOL bErase
) {
	BOOL ret;
	ret = Old_InvalidateRect(hWnd, lpRect, bErase);
	LOQ_bool("misc", "ppi", "Wnd", hWnd, "Rect", lpRect, "Erase", bErase);
	return ret;
}

// -> hook_misc.c に追加 | category="misc" | winapi:Large Integer
// REVIEW: 戻り型 int の成功判定が曖昧 -> LOQ_nonzero を仮採用。0=成功のAPIなら LOQ_zero 等へ変更
HOOKDEF(int, WINAPI, MulDiv, // 呼出規約は WINAPI 仮定(socket/native/CRT系は要確認)
	_In_ int nNumber,
	_In_ int nNumerator,
	_In_ int nDenominator
) {
	int ret;
	ret = Old_MulDiv(nNumber, nNumerator, nDenominator);
	LOQ_nonzero("misc", "iii", "Number", nNumber, "Numerator", nNumerator, "Denominator", nDenominator);
	return ret;
}

// -> hook_misc.c に追加 | category="misc" | winapi:Authentication
// REVIEW: 戻り型 DWORD の成功判定が曖昧 -> LOQ_nonzero を仮採用。0=成功のAPIなら LOQ_zero 等へ変更
// REVIEW: 引数 lpNetResource: 型 LPNETRESOURCE は自動解釈不可(構造体等)。アドレスのみ記録。内容が重要なら該当メンバを手動でログ
// REVIEW: 引数 lpPassword: 型 LPTSTR は自動解釈不可(構造体等)。アドレスのみ記録。内容が重要なら該当メンバを手動でログ
// REVIEW: 引数 lpUserName: 型 LPTSTR は自動解釈不可(構造体等)。アドレスのみ記録。内容が重要なら該当メンバを手動でログ
HOOKDEF(DWORD, WINAPI, NPAddConnection, // 呼出規約は WINAPI 仮定(socket/native/CRT系は要確認)
	_In_ LPNETRESOURCE lpNetResource,
	_In_ LPTSTR lpPassword,
	_In_ LPTSTR lpUserName
) {
	DWORD ret;
	ret = Old_NPAddConnection(lpNetResource, lpPassword, lpUserName);
	LOQ_nonzero("misc", "ppp", "NetResource", lpNetResource, "Password", lpPassword, "UserName", lpUserName);
	return ret;
}

// -> hook_misc.c に追加 | category="misc" | winapi:Authentication
// REVIEW: 戻り型 DWORD の成功判定が曖昧 -> LOQ_nonzero を仮採用。0=成功のAPIなら LOQ_zero 等へ変更
// REVIEW: 引数 lpNetResource: 型 LPNETRESOURCE は自動解釈不可(構造体等)。アドレスのみ記録。内容が重要なら該当メンバを手動でログ
// REVIEW: 引数 lpPassword: 型 LPTSTR は自動解釈不可(構造体等)。アドレスのみ記録。内容が重要なら該当メンバを手動でログ
// REVIEW: 引数 lpUserName: 型 LPTSTR は自動解釈不可(構造体等)。アドレスのみ記録。内容が重要なら該当メンバを手動でログ
HOOKDEF(DWORD, WINAPI, NPAddConnection3, // 呼出規約は WINAPI 仮定(socket/native/CRT系は要確認)
	_In_ HWND hwndOwner,
	_In_ LPNETRESOURCE lpNetResource,
	_In_ LPTSTR lpPassword,
	_In_ LPTSTR lpUserName,
	_In_ DWORD dwFlags
) {
	DWORD ret;
	ret = Old_NPAddConnection3(hwndOwner, lpNetResource, lpPassword, lpUserName, dwFlags);
	LOQ_nonzero("misc", "ppppi", "WndOwner", hwndOwner, "NetResource", lpNetResource, "Password", lpPassword, "UserName", lpUserName, "Flags", dwFlags);
	return ret;
}

// -> hook_misc.c に追加 | category="misc" | winapi:Authentication
// REVIEW: 戻り型 DWORD の成功判定が曖昧 -> LOQ_nonzero を仮採用。0=成功のAPIなら LOQ_zero 等へ変更
// REVIEW: 引数 lpName: 型 LPTSTR は自動解釈不可(構造体等)。アドレスのみ記録。内容が重要なら該当メンバを手動でログ
HOOKDEF(DWORD, WINAPI, NPCancelConnection, // 呼出規約は WINAPI 仮定(socket/native/CRT系は要確認)
	_In_ LPTSTR lpName,
	_In_ BOOL fForce
) {
	DWORD ret;
	ret = Old_NPCancelConnection(lpName, fForce);
	LOQ_nonzero("misc", "pi", "Name", lpName, "Force", fForce);
	return ret;
}

// -> hook_misc.c に追加 | category="misc" | winapi:Authentication
// REVIEW: 戻り型 DWORD の成功判定が曖昧 -> LOQ_nonzero を仮採用。0=成功のAPIなら LOQ_zero 等へ変更
HOOKDEF(DWORD, WINAPI, NPCloseEnum, // 呼出規約は WINAPI 仮定(socket/native/CRT系は要確認)
	_In_ HANDLE hEnum
) {
	DWORD ret;
	ret = Old_NPCloseEnum(hEnum);
	LOQ_nonzero("misc", "p", "Enum", hEnum);
	return ret;
}

// -> hook_misc.c に追加 | category="misc" | winapi:Authentication
// REVIEW: 戻り型 DWORD の成功判定が曖昧 -> LOQ_nonzero を仮採用。0=成功のAPIなら LOQ_zero 等へ変更
// REVIEW: 引数 lpBuffer: 生バッファ(void*)。アドレスのみ記録。長さ引数と対にして 'b'(size_t,buf)/'S'(int,buf) 指定にすれば内容を人間可読で記録できる
HOOKDEF(DWORD, WINAPI, NPEnumResource, // 呼出規約は WINAPI 仮定(socket/native/CRT系は要確認)
	_In_ HANDLE hEnum,
	_Inout_ LPDWORD lpcCount,
	_Out_ LPVOID lpBuffer,
	_Inout_ LPDWORD lpBufferSize
) {
	DWORD ret;
	ret = Old_NPEnumResource(hEnum, lpcCount, lpBuffer, lpBufferSize);
	LOQ_nonzero("misc", "pIpI", "Enum", hEnum, "CCount", lpcCount, "Buffer", lpBuffer, "BufferSize", lpBufferSize);
	return ret;
}

// -> hook_misc.c に追加 | category="misc" | winapi:Authentication
// REVIEW: 戻り型 DWORD の成功判定が曖昧 -> LOQ_nonzero を仮採用。0=成功のAPIなら LOQ_zero 等へ変更
HOOKDEF(DWORD, WINAPI, NPGetCaps, // 呼出規約は WINAPI 仮定(socket/native/CRT系は要確認)
	_In_ DWORD nIndex
) {
	DWORD ret;
	ret = Old_NPGetCaps(nIndex);
	LOQ_nonzero("misc", "i", "Index", nIndex);
	return ret;
}

// -> hook_misc.c に追加 | category="misc" | winapi:Authentication
// REVIEW: 戻り型 DWORD の成功判定が曖昧 -> LOQ_nonzero を仮採用。0=成功のAPIなら LOQ_zero 等へ変更
// REVIEW: 引数 lpLocalName: 型 LPTSTR は自動解釈不可(構造体等)。アドレスのみ記録。内容が重要なら該当メンバを手動でログ
HOOKDEF(DWORD, WINAPI, NPGetConnection, // 呼出規約は WINAPI 仮定(socket/native/CRT系は要確認)
	_In_ LPTSTR lpLocalName,
	_Out_ LPTSTR lpRemoteName,
	_Inout_ LPDWORD lpBufferSize
) {
	DWORD ret;
	ret = Old_NPGetConnection(lpLocalName, lpRemoteName, lpBufferSize);
	LOQ_nonzero("misc", "pPI", "LocalName", lpLocalName, "RemoteName", lpRemoteName, "BufferSize", lpBufferSize);
	return ret;
}

// -> hook_misc.c に追加 | category="misc" | winapi:Authentication
// REVIEW: 戻り型 DWORD の成功判定が曖昧 -> LOQ_nonzero を仮採用。0=成功のAPIなら LOQ_zero 等へ変更
// REVIEW: 引数 lpBuffer: 生バッファ(void*)。アドレスのみ記録。長さ引数と対にして 'b'(size_t,buf)/'S'(int,buf) 指定にすれば内容を人間可読で記録できる
HOOKDEF(DWORD, WINAPI, NPGetConnection3, // 呼出規約は WINAPI 仮定(socket/native/CRT系は要確認)
	_In_ LPCWSTR lpLocalName,
	_In_ DWORD dwLevel,
	_Out_ LPVOID lpBuffer,
	_Inout_ LPDWORD lpBufferSize
) {
	DWORD ret;
	ret = Old_NPGetConnection3(lpLocalName, dwLevel, lpBuffer, lpBufferSize);
	LOQ_nonzero("misc", "uipI", "LocalName", lpLocalName, "Level", dwLevel, "Buffer", lpBuffer, "BufferSize", lpBufferSize);
	return ret;
}

// -> hook_misc.c に追加 | category="misc" | winapi:Authentication
// REVIEW: 戻り型 DWORD の成功判定が曖昧 -> LOQ_nonzero を仮採用。0=成功のAPIなら LOQ_zero 等へ変更
// REVIEW: 引数 lpRemoteName: 型 LPTSTR は自動解釈不可(構造体等)。アドレスのみ記録。内容が重要なら該当メンバを手動でログ
HOOKDEF(DWORD, WINAPI, NPGetConnectionPerformance, // 呼出規約は WINAPI 仮定(socket/native/CRT系は要確認)
	_In_ LPTSTR lpRemoteName,
	_Out_ LPNETCONNECTINFOSTRUCT lpNetConnectInfo
) {
	DWORD ret;
	ret = Old_NPGetConnectionPerformance(lpRemoteName, lpNetConnectInfo);
	LOQ_nonzero("misc", "pP", "RemoteName", lpRemoteName, "NetConnectInfo", lpNetConnectInfo);
	return ret;
}

// -> hook_misc.c に追加 | category="misc" | winapi:Authentication
// REVIEW: 戻り型 DWORD の成功判定が曖昧 -> LOQ_nonzero を仮採用。0=成功のAPIなら LOQ_zero 等へ変更
// REVIEW: 引数 lpNetResource: 型 LPNETRESOURCE は自動解釈不可(構造体等)。アドレスのみ記録。内容が重要なら該当メンバを手動でログ
// REVIEW: 引数 lpBuffer: 生バッファ(void*)。アドレスのみ記録。長さ引数と対にして 'b'(size_t,buf)/'S'(int,buf) 指定にすれば内容を人間可読で記録できる
HOOKDEF(DWORD, WINAPI, NPGetResourceInformation, // 呼出規約は WINAPI 仮定(socket/native/CRT系は要確認)
	_In_ LPNETRESOURCE lpNetResource,
	_Out_ LPVOID lpBuffer,
	_Inout_ LPDWORD lpcbBuffer,
	_Out_ LPTSTR* lplpSystem
) {
	DWORD ret;
	ret = Old_NPGetResourceInformation(lpNetResource, lpBuffer, lpcbBuffer, lplpSystem);
	LOQ_nonzero("misc", "ppIP", "NetResource", lpNetResource, "Buffer", lpBuffer, "CbBuffer", lpcbBuffer, "LpSystem", lplpSystem);
	return ret;
}

// -> hook_misc.c に追加 | category="misc" | winapi:Authentication
// REVIEW: 戻り型 DWORD の成功判定が曖昧 -> LOQ_nonzero を仮採用。0=成功のAPIなら LOQ_zero 等へ変更
// REVIEW: 引数 lpNetResource: 型 LPNETRESOURCE は自動解釈不可(構造体等)。アドレスのみ記録。内容が重要なら該当メンバを手動でログ
// REVIEW: 引数 lpBuffer: 生バッファ(void*)。アドレスのみ記録。長さ引数と対にして 'b'(size_t,buf)/'S'(int,buf) 指定にすれば内容を人間可読で記録できる
HOOKDEF(DWORD, WINAPI, NPGetResourceParent, // 呼出規約は WINAPI 仮定(socket/native/CRT系は要確認)
	_In_ LPNETRESOURCE lpNetResource,
	_Out_ LPVOID lpBuffer,
	_Inout_ LPDWORD lpcbBuffer
) {
	DWORD ret;
	ret = Old_NPGetResourceParent(lpNetResource, lpBuffer, lpcbBuffer);
	LOQ_nonzero("misc", "ppI", "NetResource", lpNetResource, "Buffer", lpBuffer, "CbBuffer", lpcbBuffer);
	return ret;
}

// -> hook_misc.c に追加 | category="misc" | winapi:Authentication
// REVIEW: 戻り型 DWORD の成功判定が曖昧 -> LOQ_nonzero を仮採用。0=成功のAPIなら LOQ_zero 等へ変更
// REVIEW: 引数 lpLocalPath: 型 LPCTSTR は自動解釈不可(構造体等)。アドレスのみ記録。内容が重要なら該当メンバを手動でログ
// REVIEW: 引数 lpBuffer: 生バッファ(void*)。アドレスのみ記録。長さ引数と対にして 'b'(size_t,buf)/'S'(int,buf) 指定にすれば内容を人間可読で記録できる
HOOKDEF(DWORD, WINAPI, NPGetUniversalName, // 呼出規約は WINAPI 仮定(socket/native/CRT系は要確認)
	_In_ LPCTSTR lpLocalPath,
	_In_ DWORD dwInfoLevel,
	_Out_ LPVOID lpBuffer,
	_Inout_ LPDWORD lpBufferSize
) {
	DWORD ret;
	ret = Old_NPGetUniversalName(lpLocalPath, dwInfoLevel, lpBuffer, lpBufferSize);
	LOQ_nonzero("misc", "pipI", "LocalPath", lpLocalPath, "InfoLevel", dwInfoLevel, "Buffer", lpBuffer, "BufferSize", lpBufferSize);
	return ret;
}

// -> hook_misc.c に追加 | category="misc" | winapi:Authentication
// REVIEW: 戻り型 DWORD の成功判定が曖昧 -> LOQ_nonzero を仮採用。0=成功のAPIなら LOQ_zero 等へ変更
// REVIEW: 引数 lpName: 型 LPTSTR は自動解釈不可(構造体等)。アドレスのみ記録。内容が重要なら該当メンバを手動でログ
HOOKDEF(DWORD, WINAPI, NPGetUser, // 呼出規約は WINAPI 仮定(socket/native/CRT系は要確認)
	_In_ LPTSTR lpName,
	_Out_ LPTSTR lpUserName,
	_Inout_ LPDWORD lpBufferSize
) {
	DWORD ret;
	ret = Old_NPGetUser(lpName, lpUserName, lpBufferSize);
	LOQ_nonzero("misc", "pPI", "Name", lpName, "UserName", lpUserName, "BufferSize", lpBufferSize);
	return ret;
}

// -> hook_misc.c に追加 | category="misc" | winapi:Authentication
// REVIEW: 戻り型 DWORD の成功判定が曖昧 -> LOQ_nonzero を仮採用。0=成功のAPIなら LOQ_zero 等へ変更
// REVIEW: 引数 lpNetResource: 型 LPNETRESOURCE は自動解釈不可(構造体等)。アドレスのみ記録。内容が重要なら該当メンバを手動でログ
HOOKDEF(DWORD, WINAPI, NPOpenEnum, // 呼出規約は WINAPI 仮定(socket/native/CRT系は要確認)
	_In_ DWORD dwScope,
	_In_ DWORD dwType,
	_In_ DWORD dwUsage,
	_In_ LPNETRESOURCE lpNetResource,
	_Out_ LPHANDLE lphEnum
) {
	DWORD ret;
	ret = Old_NPOpenEnum(dwScope, dwType, dwUsage, lpNetResource, lphEnum);
	LOQ_nonzero("misc", "iiipP", "Scope", dwScope, "Type", dwType, "Usage", dwUsage, "NetResource", lpNetResource, "HEnum", lphEnum);
	return ret;
}

// -> hook_misc.c に追加 | category="misc" | winapi:Structured Exception Handling
HOOKDEF(void, WINAPI, RaiseException, // 呼出規約は WINAPI 仮定(socket/native/CRT系は要確認)
	_In_ DWORD dwExceptionCode,
	_In_ DWORD dwExceptionFlags,
	_In_ DWORD nNumberOfArguments,
	_In_ const ULONG_PTR* lpArguments
) {
	ULONG_PTR ret = 0; (void)ret;  // void 関数: LOQ 用ダミー
	Old_RaiseException(dwExceptionCode, dwExceptionFlags, nNumberOfArguments, lpArguments);
	LOQ_void("misc", "iiiI", "ExceptionCode", dwExceptionCode, "ExceptionFlags", dwExceptionFlags, "NumberOfArguments", nNumberOfArguments, "Arguments", lpArguments);
}

// -> hook_misc.c に追加 | category="misc" | winapi:Device Context
// REVIEW: 戻り型 int の成功判定が曖昧 -> LOQ_nonzero を仮採用。0=成功のAPIなら LOQ_zero 等へ変更
HOOKDEF(int, WINAPI, ReleaseDC, // 呼出規約は WINAPI 仮定(socket/native/CRT系は要確認)
	_In_ HWND hWnd,
	_In_ HDC hDC
) {
	int ret;
	ret = Old_ReleaseDC(hWnd, hDC);
	LOQ_nonzero("misc", "pp", "Wnd", hWnd, "DC", hDC);
	return ret;
}

// -> hook_misc.c に追加 | category="misc" | winapi:Conversion and Manipulation
// REVIEW: 引数 psa: 型 SAFEARRAY* は自動解釈不可(構造体等)。アドレスのみ記録。内容が重要なら該当メンバを手動でログ
HOOKDEF(HRESULT, WINAPI, SafeArrayGetElement, // 呼出規約は WINAPI 仮定(socket/native/CRT系は要確認)
	_In_ SAFEARRAY* psa,
	_In_ LONG* rgIndices,
	_Out_ void* pv
) {
	HRESULT ret;
	ret = Old_SafeArrayGetElement(psa, rgIndices, pv);
	LOQ_hresult("misc", "pIP", "Sa", psa, "RgIndices", rgIndices, "V", pv);
	return ret;
}

// -> hook_misc.c に追加 | category="misc" | winapi:Conversion and Manipulation
// REVIEW: 引数 psa: 型 SAFEARRAY* は自動解釈不可(構造体等)。アドレスのみ記録。内容が重要なら該当メンバを手動でログ
HOOKDEF(HRESULT, WINAPI, SafeArrayGetLBound, // 呼出規約は WINAPI 仮定(socket/native/CRT系は要確認)
	_In_ SAFEARRAY* psa,
	_In_ UINT nDim,
	_Out_ LONG* plLbound
) {
	HRESULT ret;
	ret = Old_SafeArrayGetLBound(psa, nDim, plLbound);
	LOQ_hresult("misc", "piI", "Sa", psa, "Dim", nDim, "LLbound", plLbound);
	return ret;
}

// -> hook_misc.c に追加 | category="misc" | winapi:Conversion and Manipulation
// REVIEW: 引数 psa: 型 SAFEARRAY* は自動解釈不可(構造体等)。アドレスのみ記録。内容が重要なら該当メンバを手動でログ
HOOKDEF(HRESULT, WINAPI, SafeArrayGetUBound, // 呼出規約は WINAPI 仮定(socket/native/CRT系は要確認)
	_In_ SAFEARRAY* psa,
	_In_ UINT nDim,
	_Out_ LONG* plUbound
) {
	HRESULT ret;
	ret = Old_SafeArrayGetUBound(psa, nDim, plUbound);
	LOQ_hresult("misc", "piI", "Sa", psa, "Dim", nDim, "LUbound", plUbound);
	return ret;
}

// -> hook_misc.c に追加 | category="misc" | winapi:Device Context
HOOKDEF(HGDIOBJ, WINAPI, SelectObject, // 呼出規約は WINAPI 仮定(socket/native/CRT系は要確認)
	_In_ HDC hdc,
	_In_ HGDIOBJ hgdiobj
) {
	HGDIOBJ ret;
	ret = Old_SelectObject(hdc, hgdiobj);
	LOQ_nonnull("misc", "pp", "Dc", hdc, "Gdiobj", hgdiobj);
	return ret;
}

// -> hook_misc.c に追加 | category="misc" | winapi:Painting and Drawing
// REVIEW: 戻り型 int の成功判定が曖昧 -> LOQ_nonzero を仮採用。0=成功のAPIなら LOQ_zero 等へ変更
HOOKDEF(int, WINAPI, SetBkMode, // 呼出規約は WINAPI 仮定(socket/native/CRT系は要確認)
	_In_ HDC hdc,
	_In_ int iBkMode
) {
	int ret;
	ret = Old_SetBkMode(hdc, iBkMode);
	LOQ_nonzero("misc", "pi", "Dc", hdc, "IBkMode", iBkMode);
	return ret;
}

// -> hook_misc.c に追加 | category="misc" | winapi:Font and Text
// REVIEW: 戻り型 COLORREF の成功判定が曖昧 -> LOQ_nonzero を仮採用。0=成功のAPIなら LOQ_zero 等へ変更
// REVIEW: 引数 crColor: 型 COLORREF を i(int32)で仮記録。要確認
HOOKDEF(COLORREF, WINAPI, SetTextColor, // 呼出規約は WINAPI 仮定(socket/native/CRT系は要確認)
	_In_ HDC hdc,
	_In_ COLORREF crColor
) {
	COLORREF ret;
	ret = Old_SetTextColor(hdc, crColor);
	LOQ_nonzero("misc", "pi", "Dc", hdc, "CrColor", crColor);
	return ret;
}
