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


HOOKDEF(NTSTATUS, WINAPI, NtCreateMutant,
	__out	   PHANDLE MutantHandle,
	__in		ACCESS_MASK DesiredAccess,
	__in_opt	POBJECT_ATTRIBUTES ObjectAttributes,
	__in		BOOLEAN InitialOwner
) {
	NTSTATUS ret = Old_NtCreateMutant(MutantHandle, DesiredAccess,
		ObjectAttributes, InitialOwner);
	LOQ_ntstatus("synchronization", "Poi", "Handle", MutantHandle,
		"MutexName", unistr_from_objattr(ObjectAttributes),
		"InitialOwner", InitialOwner);
	return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtOpenMutant,
	__out	   PHANDLE MutantHandle,
	__in		ACCESS_MASK DesiredAccess,
	__in		POBJECT_ATTRIBUTES ObjectAttributes
) {
	NTSTATUS ret = Old_NtOpenMutant(MutantHandle, DesiredAccess,
		ObjectAttributes);
	LOQ_ntstatus("synchronization", "Po", "Handle", MutantHandle,
		"MutexName", unistr_from_objattr(ObjectAttributes));
	return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtReleaseMutant,
	__in		HANDLE MutantHandle,
	__out_opt   PLONG PreviousCount
) {
	NTSTATUS ret = Old_NtReleaseMutant(MutantHandle, PreviousCount);
	LOQ_ntstatus("synchronization", "h", "Handle", MutantHandle);
	return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtCreateEvent,
	__out		PHANDLE EventHandle,
	__in		ACCESS_MASK DesiredAccess,
	__in_opt	POBJECT_ATTRIBUTES ObjectAttributes,
	__in		DWORD EventType,
	__in		BOOLEAN InitialState
) {
	NTSTATUS ret = Old_NtCreateEvent(EventHandle, DesiredAccess,
		ObjectAttributes, EventType, InitialState);
	UNICODE_STRING *eventname = unistr_from_objattr(ObjectAttributes);
	if (eventname && eventname->Length) {
		LOQ_ntstatus("synchronization", "Poii", "Handle", EventHandle,
			"EventName", eventname, "EventType", EventType, "InitialState", InitialState);
	}
	return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtOpenEvent,
	__out		PHANDLE EventHandle,
	__in		ACCESS_MASK DesiredAccess,
	__in		POBJECT_ATTRIBUTES ObjectAttributes
) {
	NTSTATUS ret = Old_NtOpenEvent(EventHandle, DesiredAccess,
		ObjectAttributes);
	LOQ_ntstatus("synchronization", "Po", "Handle", EventHandle,
		"EventName", unistr_from_objattr(ObjectAttributes));
	return ret;

}

HOOKDEF(NTSTATUS, WINAPI, NtCreateNamedPipeFile,
	OUT		PHANDLE NamedPipeFileHandle,
	IN		ACCESS_MASK DesiredAccess,
	IN		POBJECT_ATTRIBUTES ObjectAttributes,
	OUT		PIO_STATUS_BLOCK IoStatusBlock,
	IN		ULONG ShareAccess,
	IN		ULONG CreateDisposition,
	IN		ULONG CreateOptions,
	IN		ULONG NamedPipeType,
	IN		ULONG ReadMode,
	IN		ULONG CompletionMode,
	IN		ULONG MaxInstances,
	IN		ULONG InBufferSize,
	IN		ULONG OutBufferSize,
	IN		PLARGE_INTEGER DefaultTimeOut
) {
	NTSTATUS ret = Old_NtCreateNamedPipeFile(NamedPipeFileHandle,
		DesiredAccess, ObjectAttributes, IoStatusBlock, ShareAccess,
		CreateDisposition, CreateOptions, NamedPipeType, ReadMode,
		CompletionMode, MaxInstances, InBufferSize, OutBufferSize,
		DefaultTimeOut);
	LOQ_ntstatus("synchronization", "PhOi", "NamedPipeHandle", NamedPipeFileHandle,
		"DesiredAccess", DesiredAccess, "PipeName", ObjectAttributes,
		"ShareAccess", ShareAccess);
	return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtAddAtom,
	IN	PWCHAR AtomName,
	IN	ULONG	AtomNameLength,
	OUT PRTL_ATOM Atom
) {
	NTSTATUS ret = Old_NtAddAtom(AtomName, AtomNameLength, Atom);
	LOQ_ntstatus("synchronization", "uh", "AtomName", AtomName, "Atom", *Atom);
	return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtDeleteAtom,
	IN RTL_ATOM Atom
) {
	NTSTATUS ret = Old_NtDeleteAtom(Atom);
	LOQ_ntstatus("synchronization", "h", "Atom", Atom);
	return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtFindAtom,
	IN	PWCHAR AtomName,
	IN	ULONG AtomNameLength,
	OUT PRTL_ATOM Atom OPTIONAL
) {
	ENSURE_RTL_ATOM(Atom);
	NTSTATUS ret = Old_NtFindAtom(AtomName, AtomNameLength, Atom);
	LOQ_ntstatus("synchronization", "uh", "AtomName", AtomName, "Atom", *Atom);
	return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtAddAtomEx,
	IN	PWCHAR AtomName,
	IN	ULONG	AtomNameLength,
	OUT PRTL_ATOM Atom,
	IN	PVOID	Unknown
) {
	NTSTATUS ret = Old_NtAddAtomEx(AtomName, AtomNameLength, Atom, Unknown);
	LOQ_ntstatus("synchronization", "uh", "AtomName", AtomName, "Atom", *Atom);
	return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtQueryInformationAtom,
	IN	RTL_ATOM Atom,
	IN	ATOM_INFORMATION_CLASS AtomInformationClass,
	OUT PVOID AtomInformation,
	IN  ULONG AtomInformationLength,
	OUT PULONG ReturnLength OPTIONAL
) {
	WCHAR* AtomName;
	ULONG AtomNameLength;
	
	NTSTATUS ret = Old_NtQueryInformationAtom(Atom, AtomInformationClass, AtomInformation, AtomInformationLength, ReturnLength);
	
	if (NT_SUCCESS(ret) && AtomInformationClass == AtomBasicInformation)
	{
		AtomNameLength = (ULONG)((PATOM_BASIC_INFORMATION)AtomInformation)->NameLength;
		AtomName = ((PATOM_BASIC_INFORMATION)AtomInformation)->Name;
		LOQ_ntstatus("synchronization", "bih", "AtomName", AtomNameLength, AtomName, "Size", AtomNameLength, "Atom", Atom);
	}
	else
		LOQ_ntstatus("synchronization", "h", "Atom", Atom);
	
	return ret;
}


// ---- all unhooked-classified hooks (auto-generated, sanitized types) ----

HOOKDEF(BOOL, WINAPI, CancelWaitableTimer,
	HANDLE hTimer
) {
	BOOL ret;
	ret = Old_CancelWaitableTimer(hTimer);
	LOQ_bool("synchronisation", "p", "hTimer", hTimer);
	return ret;
}

HOOKDEF(BOOL, WINAPI, CloseEventLog,
	HANDLE hEventLog
) {
	BOOL ret;
	ret = Old_CloseEventLog(hEventLog);
	LOQ_bool("synchronisation", "p", "hEventLog", hEventLog);
	return ret;
}

HOOKDEF(void, WINAPI, CloseThreadpoolTimer,
	PVOID pti
) {
	int ret = 0;
	Old_CloseThreadpoolTimer(pti);
	LOQ_void("synchronisation", "p", "pti", pti);
	return;
}

HOOKDEF(void, WINAPI, CloseThreadpoolWait,
	PVOID pwa
) {
	int ret = 0;
	Old_CloseThreadpoolWait(pwa);
	LOQ_void("synchronisation", "p", "pwa", pwa);
	return;
}

HOOKDEF(HANDLE, WINAPI, CreateIoCompletionPort,
	HANDLE FileHandle,
	HANDLE ExistingCompletionPort,
	ULONG_PTR CompletionKey,
	DWORD NumberOfConcurrentThreads
) {
	HANDLE ret;
	ret = Old_CreateIoCompletionPort(FileHandle, ExistingCompletionPort, CompletionKey, NumberOfConcurrentThreads);
	LOQ_handle("synchronisation", "pphh", "FileHandle", FileHandle, "ExistingCompletionPort", ExistingCompletionPort, "CompletionKey", CompletionKey, "NumberOfConcurrentThreads", NumberOfConcurrentThreads);
	return ret;
}

HOOKDEF(HANDLE, WINAPI, CreateSemaphoreA,
	PVOID lpSemaphoreAttributes,
	LONG lInitialCount,
	LONG lMaximumCount,
	LPCSTR lpName
) {
	HANDLE ret;
	ret = Old_CreateSemaphoreA(lpSemaphoreAttributes, lInitialCount, lMaximumCount, lpName);
	LOQ_handle("synchronisation", "piis", "lpSemaphoreAttributes", lpSemaphoreAttributes, "lInitialCount", lInitialCount, "lMaximumCount", lMaximumCount, "lpName", lpName);
	return ret;
}

HOOKDEF(PVOID, WINAPI, CreateThreadpoolTimer,
	PVOID pfnti,
	PVOID pv,
	PVOID pcbe
) {
	PVOID ret;
	ret = Old_CreateThreadpoolTimer(pfnti, pv, pcbe);
	LOQ_nonnull("synchronisation", "ppp", "pfnti", pfnti, "pv", pv, "pcbe", pcbe);
	return ret;
}

HOOKDEF(PVOID, WINAPI, CreateThreadpoolWait,
	PVOID pfnwa,
	PVOID pv,
	PVOID pcbe
) {
	PVOID ret;
	ret = Old_CreateThreadpoolWait(pfnwa, pv, pcbe);
	LOQ_nonnull("synchronisation", "ppp", "pfnwa", pfnwa, "pv", pv, "pcbe", pcbe);
	return ret;
}

HOOKDEF(HANDLE, WINAPI, CreateTimerQueue,
	void
) {
	HANDLE ret;
	ret = Old_CreateTimerQueue();
	LOQ_handle("synchronisation", "");
	return ret;
}

HOOKDEF(HANDLE, WINAPI, CreateWaitableTimer,
	PVOID lpTimerAttributes,
	BOOL bManualReset,
	LPCTSTR lpTimerName
) {
	HANDLE ret;
	ret = Old_CreateWaitableTimer(lpTimerAttributes, bManualReset, lpTimerName);
	LOQ_handle("synchronisation", "pis", "lpTimerAttributes", lpTimerAttributes, "bManualReset", bManualReset, "lpTimerName", lpTimerName);
	return ret;
}

HOOKDEF(HANDLE, WINAPI, CreateWaitableTimerA,
	PVOID lpTimerAttributes,
	BOOL bManualReset,
	LPCSTR lpTimerName
) {
	HANDLE ret;
	ret = Old_CreateWaitableTimerA(lpTimerAttributes, bManualReset, lpTimerName);
	LOQ_handle("synchronisation", "pis", "lpTimerAttributes", lpTimerAttributes, "bManualReset", bManualReset, "lpTimerName", lpTimerName);
	return ret;
}

HOOKDEF(HANDLE, WINAPI, CreateWaitableTimerExW,
	PVOID lpTimerAttributes,
	LPCWSTR lpTimerName,
	DWORD dwFlags,
	DWORD dwDesiredAccess
) {
	HANDLE ret;
	ret = Old_CreateWaitableTimerExW(lpTimerAttributes, lpTimerName, dwFlags, dwDesiredAccess);
	LOQ_handle("synchronisation", "puhh", "lpTimerAttributes", lpTimerAttributes, "lpTimerName", lpTimerName, "dwFlags", dwFlags, "dwDesiredAccess", dwDesiredAccess);
	return ret;
}

HOOKDEF(HANDLE, WINAPI, CreateWaitableTimerW,
	PVOID lpTimerAttributes,
	BOOL bManualReset,
	LPCWSTR lpTimerName
) {
	HANDLE ret;
	ret = Old_CreateWaitableTimerW(lpTimerAttributes, bManualReset, lpTimerName);
	LOQ_handle("synchronisation", "piu", "lpTimerAttributes", lpTimerAttributes, "bManualReset", bManualReset, "lpTimerName", lpTimerName);
	return ret;
}

HOOKDEF(void, WINAPI, DeleteCriticalSection,
	PVOID lpCriticalSection
) {
	int ret = 0;
	Old_DeleteCriticalSection(lpCriticalSection);
	LOQ_void("synchronisation", "p", "lpCriticalSection", lpCriticalSection);
	return;
}

HOOKDEF(BOOL, WINAPI, DeleteTimerQueue,
	HANDLE TimerQueue
) {
	BOOL ret;
	ret = Old_DeleteTimerQueue(TimerQueue);
	LOQ_bool("synchronisation", "p", "TimerQueue", TimerQueue);
	return ret;
}

HOOKDEF(BOOL, WINAPI, DeleteTimerQueueEx,
	HANDLE TimerQueue,
	HANDLE CompletionEvent
) {
	BOOL ret;
	ret = Old_DeleteTimerQueueEx(TimerQueue, CompletionEvent);
	LOQ_bool("synchronisation", "pp", "TimerQueue", TimerQueue, "CompletionEvent", CompletionEvent);
	return ret;
}

HOOKDEF(BOOL, WINAPI, DeleteTimerQueueTimer,
	HANDLE TimerQueue,
	HANDLE Timer,
	HANDLE CompletionEvent
) {
	BOOL ret;
	ret = Old_DeleteTimerQueueTimer(TimerQueue, Timer, CompletionEvent);
	LOQ_bool("synchronisation", "ppp", "TimerQueue", TimerQueue, "Timer", Timer, "CompletionEvent", CompletionEvent);
	return ret;
}

HOOKDEF(BOOL, WINAPI, GenerateConsoleCtrlEvent,
	DWORD dwCtrlEvent,
	DWORD dwProcessGroupId
) {
	BOOL ret;
	ret = Old_GenerateConsoleCtrlEvent(dwCtrlEvent, dwProcessGroupId);
	LOQ_bool("synchronisation", "hh", "dwCtrlEvent", dwCtrlEvent, "dwProcessGroupId", dwProcessGroupId);
	return ret;
}

HOOKDEF(BOOL, WINAPI, GetNumberOfConsoleInputEvents,
	HANDLE hConsoleInput,
	LPDWORD lpNumberOfEvents
) {
	BOOL ret;
	ret = Old_GetNumberOfConsoleInputEvents(hConsoleInput, lpNumberOfEvents);
	LOQ_bool("synchronisation", "ph", "hConsoleInput", hConsoleInput, "lpNumberOfEvents", lpNumberOfEvents);
	return ret;
}

HOOKDEF(BOOL, WINAPI, GetNumberOfEventLogRecords,
	HANDLE hEventLog,
	PDWORD NumberOfRecords
) {
	BOOL ret;
	ret = Old_GetNumberOfEventLogRecords(hEventLog, NumberOfRecords);
	LOQ_bool("synchronisation", "ph", "hEventLog", hEventLog, "NumberOfRecords", NumberOfRecords);
	return ret;
}

HOOKDEF(BOOL, WINAPI, GetOldestEventLogRecord,
	HANDLE hEventLog,
	PDWORD OldestRecord
) {
	BOOL ret;
	ret = Old_GetOldestEventLogRecord(hEventLog, OldestRecord);
	LOQ_bool("synchronisation", "ph", "hEventLog", hEventLog, "OldestRecord", OldestRecord);
	return ret;
}

HOOKDEF(void, WINAPI, InitializeConditionVariable,
	PVOID ConditionVariable
) {
	int ret = 0;
	Old_InitializeConditionVariable(ConditionVariable);
	LOQ_void("synchronisation", "p", "ConditionVariable", ConditionVariable);
	return;
}

HOOKDEF(DWORD, WINAPI, MsgWaitForMultipleObjects,
	DWORD nCount,
	PVOID pHandles,
	BOOL fWaitAll,
	DWORD dwMilliseconds,
	DWORD dwWakeMask
) {
	DWORD ret;
	ret = Old_MsgWaitForMultipleObjects(nCount, pHandles, fWaitAll, dwMilliseconds, dwWakeMask);
	LOQ_nonzero("synchronisation", "hpihh", "nCount", nCount, "pHandles", pHandles, "fWaitAll", fWaitAll, "dwMilliseconds", dwMilliseconds, "dwWakeMask", dwWakeMask);
	return ret;
}

HOOKDEF(HANDLE, WINAPI, OpenEventLog,
	LPCTSTR lpUNCServerName,
	LPCTSTR lpSourceName
) {
	HANDLE ret;
	ret = Old_OpenEventLog(lpUNCServerName, lpSourceName);
	LOQ_handle("synchronisation", "ss", "lpUNCServerName", lpUNCServerName, "lpSourceName", lpSourceName);
	return ret;
}

HOOKDEF(HANDLE, WINAPI, OpenEventLogA,
	LPCSTR lpUNCServerName,
	LPCSTR lpSourceName
) {
	HANDLE ret;
	ret = Old_OpenEventLogA(lpUNCServerName, lpSourceName);
	LOQ_handle("synchronisation", "ss", "lpUNCServerName", lpUNCServerName, "lpSourceName", lpSourceName);
	return ret;
}

HOOKDEF(HANDLE, WINAPI, OpenEventLogW,
	LPCWSTR lpUNCServerName,
	LPCWSTR lpSourceName
) {
	HANDLE ret;
	ret = Old_OpenEventLogW(lpUNCServerName, lpSourceName);
	LOQ_handle("synchronisation", "uu", "lpUNCServerName", lpUNCServerName, "lpSourceName", lpSourceName);
	return ret;
}

HOOKDEF(BOOL, WINAPI, QueueUserWorkItem,
	PVOID Function,
	PVOID Context,
	ULONG Flags
) {
	BOOL ret;
	ret = Old_QueueUserWorkItem(Function, Context, Flags);
	LOQ_bool("synchronisation", "pph", "Function", Function, "Context", Context, "Flags", Flags);
	return ret;
}

HOOKDEF(BOOL, WINAPI, ReadEventLog,
	HANDLE hEventLog,
	DWORD dwReadFlags,
	DWORD dwRecordOffset,
	LPVOID lpBuffer,
	DWORD nNumberOfBytesToRead,
	PVOID pnBytesRead,
	PVOID pnMinNumberOfBytesNeeded
) {
	BOOL ret;
	ret = Old_ReadEventLog(hEventLog, dwReadFlags, dwRecordOffset, lpBuffer, nNumberOfBytesToRead, pnBytesRead, pnMinNumberOfBytesNeeded);
	LOQ_bool("synchronisation", "phhphpp", "hEventLog", hEventLog, "dwReadFlags", dwReadFlags, "dwRecordOffset", dwRecordOffset, "lpBuffer", lpBuffer, "nNumberOfBytesToRead", nNumberOfBytesToRead, "pnBytesRead", pnBytesRead, "pnMinNumberOfBytesNeeded", pnMinNumberOfBytesNeeded);
	return ret;
}

HOOKDEF(BOOL, WINAPI, RegisterWaitForSingleObject,
	PHANDLE phNewWaitObject,
	HANDLE hObject,
	PVOID Callback,
	PVOID Context,
	ULONG dwMilliseconds,
	ULONG dwFlags
) {
	BOOL ret;
	ret = Old_RegisterWaitForSingleObject(phNewWaitObject, hObject, Callback, Context, dwMilliseconds, dwFlags);
	LOQ_bool("synchronisation", "hppphh", "phNewWaitObject", phNewWaitObject, "hObject", hObject, "Callback", Callback, "Context", Context, "dwMilliseconds", dwMilliseconds, "dwFlags", dwFlags);
	return ret;
}

HOOKDEF(BOOL, WINAPI, ReleaseSemaphore,
	HANDLE hSemaphore,
	LONG lReleaseCount,
	LPLONG lpPreviousCount
) {
	BOOL ret;
	ret = Old_ReleaseSemaphore(hSemaphore, lReleaseCount, lpPreviousCount);
	LOQ_bool("synchronisation", "pih", "hSemaphore", hSemaphore, "lReleaseCount", lReleaseCount, "lpPreviousCount", lpPreviousCount);
	return ret;
}

HOOKDEF(void, WINAPI, SetThreadpoolTimer,
	PVOID pti,
	PFILETIME pftDueTime,
	DWORD msPeriod,
	DWORD msWindowLength
) {
	int ret = 0;
	Old_SetThreadpoolTimer(pti, pftDueTime, msPeriod, msWindowLength);
	LOQ_void("synchronisation", "phhh", "pti", pti, "pftDueTime", pftDueTime, "msPeriod", msPeriod, "msWindowLength", msWindowLength);
	return;
}

HOOKDEF(void, WINAPI, SetThreadpoolWait,
	PVOID pwa,
	HANDLE h,
	PFILETIME pftTimeout
) {
	int ret = 0;
	Old_SetThreadpoolWait(pwa, h, pftTimeout);
	LOQ_void("synchronisation", "pph", "pwa", pwa, "h", h, "pftTimeout", pftTimeout);
	return;
}

HOOKDEF(BOOL, WINAPI, SetWaitableTimer,
	HANDLE hTimer,
	PVOID lpDueTime,
	LONG lPeriod,
	PVOID pfnCompletionRoutine,
	LPVOID lpArgToCompletionRoutine,
	BOOL fResume
) {
	BOOL ret;
	ret = Old_SetWaitableTimer(hTimer, lpDueTime, lPeriod, pfnCompletionRoutine, lpArgToCompletionRoutine, fResume);
	LOQ_bool("synchronisation", "ppippi", "hTimer", hTimer, "lpDueTime", lpDueTime, "lPeriod", lPeriod, "pfnCompletionRoutine", pfnCompletionRoutine, "lpArgToCompletionRoutine", lpArgToCompletionRoutine, "fResume", fResume);
	return ret;
}

HOOKDEF(BOOL, WINAPI, SleepConditionVariableCS,
	PVOID ConditionVariable,
	PVOID CriticalSection,
	DWORD dwMilliseconds
) {
	BOOL ret;
	ret = Old_SleepConditionVariableCS(ConditionVariable, CriticalSection, dwMilliseconds);
	LOQ_bool("synchronisation", "pph", "ConditionVariable", ConditionVariable, "CriticalSection", CriticalSection, "dwMilliseconds", dwMilliseconds);
	return ret;
}

HOOKDEF(BOOL, WINAPI, UnregisterWait,
	HANDLE WaitHandle
) {
	BOOL ret;
	ret = Old_UnregisterWait(WaitHandle);
	LOQ_bool("synchronisation", "p", "WaitHandle", WaitHandle);
	return ret;
}

HOOKDEF(BOOL, WINAPI, UnregisterWaitEx,
	HANDLE WaitHandle,
	HANDLE CompletionEvent
) {
	BOOL ret;
	ret = Old_UnregisterWaitEx(WaitHandle, CompletionEvent);
	LOQ_bool("synchronisation", "pp", "WaitHandle", WaitHandle, "CompletionEvent", CompletionEvent);
	return ret;
}

HOOKDEF(DWORD, WINAPI, WaitForMultipleObjects,
	DWORD nCount,
	PVOID lpHandles,
	BOOL bWaitAll,
	DWORD dwMilliseconds
) {
	DWORD ret;
	ret = Old_WaitForMultipleObjects(nCount, lpHandles, bWaitAll, dwMilliseconds);
	LOQ_nonzero("synchronisation", "hpih", "nCount", nCount, "lpHandles", lpHandles, "bWaitAll", bWaitAll, "dwMilliseconds", dwMilliseconds);
	return ret;
}

HOOKDEF(DWORD, WINAPI, WaitForMultipleObjectsEx,
	DWORD nCount,
	PVOID lpHandles,
	BOOL bWaitAll,
	DWORD dwMilliseconds,
	BOOL bAlertable
) {
	DWORD ret;
	ret = Old_WaitForMultipleObjectsEx(nCount, lpHandles, bWaitAll, dwMilliseconds, bAlertable);
	LOQ_nonzero("synchronisation", "hpihi", "nCount", nCount, "lpHandles", lpHandles, "bWaitAll", bWaitAll, "dwMilliseconds", dwMilliseconds, "bAlertable", bAlertable);
	return ret;
}

HOOKDEF(void, WINAPI, WaitForThreadpoolTimerCallbacks,
	PVOID pti,
	BOOL fCancelPendingCallbacks
) {
	int ret = 0;
	Old_WaitForThreadpoolTimerCallbacks(pti, fCancelPendingCallbacks);
	LOQ_void("synchronisation", "pi", "pti", pti, "fCancelPendingCallbacks", fCancelPendingCallbacks);
	return;
}

HOOKDEF(BOOL, WINAPI, WaitOnAddress,
	PVOID Address,
	PVOID CompareAddress,
	SIZE_T AddressSize,
	DWORD dwMilliseconds
) {
	BOOL ret;
	ret = Old_WaitOnAddress(Address, CompareAddress, AddressSize, dwMilliseconds);
	LOQ_bool("synchronisation", "pphh", "Address", Address, "CompareAddress", CompareAddress, "AddressSize", AddressSize, "dwMilliseconds", dwMilliseconds);
	return ret;
}

HOOKDEF(UINT, WINAPI, timeKillEvent,
	UINT uTimerID
) {
	UINT ret;
	ret = Old_timeKillEvent(uTimerID);
	LOQ_nonzero("synchronisation", "h", "uTimerID", uTimerID);
	return ret;
}
