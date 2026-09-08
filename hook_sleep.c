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
#include "hooks.h"
#include "log.h"
#include "pipe.h"
#include "config.h"
#include "misc.h"
#include "CAPE\CAPE.h"
#include "CAPE\Debugger.h"

// only skip Sleep()s the first five seconds
#define MAX_SLEEP_SKIP_DIFF 5000

extern void DebugOutput(_In_ LPCTSTR lpOutputString, ...);
extern void ErrorOutput(_In_ LPCTSTR lpOutputString, ...);

// skipping sleep calls is done while this variable is set to true
static int sleep_skip_active = 1;

// the amount of time skipped, in 100-nanosecond
LARGE_INTEGER time_skipped;
static LARGE_INTEGER time_start;

static int num_skipped = 0;
static int num_small = 0;
static int num_msg_small = 0;
static int num_wait_skipped = 0;
static int num_wait_small = 0;

void disable_sleep_skip()
{
	if (sleep_skip_active && g_config.force_sleepskip < 1) {
		DebugOutput("Disabling sleep skipping.");
		sleep_skip_active = 0;
	}
}

HOOKDEF(NTSTATUS, WINAPI, NtWaitForSingleObject,
	__in	HANDLE Handle,
	__in	BOOLEAN Alertable,
	__in_opt	PLARGE_INTEGER Timeout
) {
	NTSTATUS ret = 0;
	LONGLONG interval;
	LARGE_INTEGER newint;
	LARGE_INTEGER li;
	unsigned long milli;
	FILETIME ft;
	lasterror_t lasterror;

	get_lasterrors(&lasterror);

	// handle INFINITE wait
	if (Timeout == NULL || Timeout->QuadPart == 0x8000000000000000ULL) {
		// only log potentially interesting cases
		if (hook_info()->main_caller_retaddr)
			LOQ_ntstatus("system", "pis", "Handle", Handle, "Milliseconds", -1, "Status", "Infinite");
		set_lasterrors(&lasterror);
		return Old_NtWaitForSingleObject(Handle, Alertable, Timeout);
	}

	newint.QuadPart = Timeout->QuadPart;

	if (sleep_skip_active && newint.QuadPart > 0LL) {
		/* convert absolute time to relative time */
		GetSystemTimeAsFileTime(&ft);

		newint.HighPart = ft.dwHighDateTime;
		newint.LowPart = ft.dwLowDateTime;
		newint.QuadPart += time_skipped.QuadPart;
		newint.QuadPart -= Timeout->QuadPart;
		if (newint.QuadPart > 0LL)
			newint.QuadPart = 0LL;
	}
	interval = -newint.QuadPart;
	milli = (unsigned long)(interval / 10000);

	GetSystemTimeAsFileTime(&ft);
	li.HighPart = ft.dwHighDateTime;
	li.LowPart = ft.dwLowDateTime;

	/* clamp sleeps between 30 seconds and 1 hour down to 10 seconds  as long as we didn't force off sleep skipping */
	if (sleep_skip_active && milli >= 30000 && milli <= 3600000 && g_config.force_sleepskip != 0) {
		newint.QuadPart = -(10000 * 10000);
		time_skipped.QuadPart += interval - (10000 * 10000);
		LOQ_ntstatus("system", "pis", "Handle", Handle, "Milliseconds", milli, "Status", "Skipped");
		goto docall;
	}
	else if (sleep_skip_active && g_config.force_sleepskip > 0) {
		time_skipped.QuadPart += interval;
		LOQ_ntstatus("system", "pis", "Handle", Handle, "Milliseconds", milli, "Status", "Skipped");
		newint.QuadPart = 0;
		goto docall;
	}
	else {
		disable_sleep_skip();
	}
	if (sleep_skip_active && milli <= 10) {
		if (num_wait_small < 20) {
			LOQ_ntstatus("system", "pi", "Handle", Handle, "Milliseconds", milli);
			num_wait_small++;
		}
		else if (num_wait_small == 20) {
			LOQ_ntstatus("system", "s", "Status", "Small log limit reached");
			num_wait_small++;
		}
		else {
			// likely using a bunch of tiny sleeps to delay execution, so let's suddenly mimic high load and give our
			// fake passage of time the impression of longer delays to return from sleep
			time_skipped.QuadPart += (randint(500, 1000) * 10000);
		}
	}
	else {
		LOQ_ntstatus("system", "pi", "Handle", Handle, "Milliseconds", milli);
	}

docall:
	set_lasterrors(&lasterror);
	return Old_NtWaitForSingleObject(Handle, Alertable, &newint);
}

HOOKDEF(NTSTATUS, WINAPI, NtDelayExecution,
	__in	BOOLEAN Alertable,
	__in	PLARGE_INTEGER DelayInterval
)
{
NTSTATUS ret;
	LONGLONG skip_100ns;
	LARGE_INTEGER newint;
	unsigned long milli = 0;
	lasterror_t lasterror;

	get_lasterrors(&lasterror);

	if (DelayInterval == NULL) {
		ret = Old_NtDelayExecution(Alertable, DelayInterval);
		set_lasterrors(&lasterror);
		return ret;
	}

	newint.QuadPart = DelayInterval->QuadPart;

	/* SAGE sandbox-transparency response: NtDelayExecution is the native syscall the
	 * Win32 Sleep() family resolves to, so a sample that issues it directly (to sidestep
	 * a Sleep() hook) parks here with a relative DelayInterval of, e.g., ~-50000000
	 * (5000ms in NT 100ns units; a negative interval is relative, a positive one is an
	 * absolute deadline). Force the real syscall to return immediately by handing
	 * Old_NtDelayExecution a zeroed interval, but advance capemon's shared faked-time
	 * accumulator (time_skipped, NT 100ns units, which the tick/perf-counter hooks divide
	 * back to milliseconds) by the originally requested relative interval so a tick sample
	 * taken before and after still shows the expected elapsed delta. Only relative
	 * (negative) intervals are shortened; an absolute deadline falls through unchanged. The
	 * zeroed interval is passed via the local newint so the caller's DelayInterval buffer
	 * is left untouched, and lasterror is preserved across the shortened wait. */
	if (!g_config.no_stealth && newint.QuadPart < 0LL) {
		skip_100ns = -newint.QuadPart;
		time_skipped.QuadPart += skip_100ns;
		milli = (unsigned long)(skip_100ns / 10000);
		newint.QuadPart = 0;
		LOQ_ntstatus("system", "is", "Milliseconds", milli, "Status", "Skipped");
	}
	else {
		LOQ_ntstatus("system", "i", "Milliseconds", milli);
	}

	ret = Old_NtDelayExecution(Alertable, &newint);
	set_lasterrors(&lasterror);
	return ret;
}

HOOKDEF(DWORD, WINAPI, MsgWaitForMultipleObjectsEx,
	_In_	   DWORD  nCount,
	_In_ const HANDLE *pHandles,
	_In_	   DWORD  dwMilliseconds,
	_In_	   DWORD  dwWakeMask,
	_In_	   DWORD  dwFlags
) {
	DWORD ret = 0;

	if (dwMilliseconds == INFINITE || nCount)
		goto docall;

	/* clamp sleeps between 30 seconds and 1 hour down to 10 seconds  as long as we didn't force off sleep skipping */
	else if (sleep_skip_active && dwMilliseconds >= 30000 && dwMilliseconds <= 3600000 && g_config.force_sleepskip != 0) {
		time_skipped.QuadPart += (dwMilliseconds - 10000) * 10000;
		LOQ_msgwait("system", "is", "Milliseconds", dwMilliseconds, "Status", "Skipped");
		dwMilliseconds = 10000;
		goto docall;
	}
	else if (sleep_skip_active && g_config.force_sleepskip > 0) {
		LOQ_msgwait("system", "is", "Milliseconds", dwMilliseconds, "Status", "Skipped");
		dwMilliseconds = 0;
		goto docall;
	}
	else {
		disable_sleep_skip();
	}

	if (sleep_skip_active && dwMilliseconds <= 10) {
		if (num_msg_small < 20) {
			LOQ_msgwait("system", "i", "Milliseconds", dwMilliseconds);
			num_msg_small++;
		}
		else if (num_msg_small == 20) {
			LOQ_msgwait("system", "s", "Status", "Small log limit reached");
			num_msg_small++;
		}
		else {
			// likely using a bunch of tiny sleeps to delay execution, so let's suddenly mimic high load and give our
			// fake passage of time the impression of longer delays to return from sleep
			time_skipped.QuadPart += (randint(500, 1000) * 10000);
		}
	}
	else {
		LOQ_msgwait("system", "i", "Milliseconds", dwMilliseconds);
	}

docall:
	ret = Old_MsgWaitForMultipleObjectsEx(nCount, pHandles, dwMilliseconds, dwWakeMask, dwFlags);

	disable_tail_call_optimization();

	return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtSetTimer,
	IN HANDLE			   TimerHandle,
	IN PLARGE_INTEGER	   DueTime,
	IN PVOID				TimerApcRoutine OPTIONAL,
	IN PVOID				TimerContext OPTIONAL,
	IN BOOLEAN			  ResumeTimer,
	IN LONG				 Period OPTIONAL,
	OUT PBOOLEAN			PreviousState OPTIONAL
) {
	NTSTATUS ret = 0;
	LONGLONG interval;
	FILETIME ft;
	LARGE_INTEGER newint;
	unsigned long milli;
	lasterror_t lasterror;

	get_lasterrors(&lasterror);

	newint.QuadPart = DueTime->QuadPart;
	// handle INFINITE sleep
	if (newint.QuadPart == 0x8000000000000000ULL) {
		LOQ_ntstatus("system", "is", "Milliseconds", -1, "Status", "Infinite");
		goto docall;
	}

	if (sleep_skip_active && newint.QuadPart > 0LL) {
		/* convert absolute time to relative time */
		GetSystemTimeAsFileTime(&ft);

		newint.HighPart = ft.dwHighDateTime;
		newint.LowPart = ft.dwLowDateTime;
		newint.QuadPart += time_skipped.QuadPart;
		newint.QuadPart -= DueTime->QuadPart;
		if (newint.QuadPart > 0LL)
			newint.QuadPart = 0LL;
	}
	interval = -newint.QuadPart;
	milli = (unsigned long)(interval / 10000);

	/* clamp sleeps between 30 seconds and 1 hour down to 10 seconds  as long as we didn't force off sleep skipping */
	if (sleep_skip_active && milli >= 30000 && milli <= 3600000 && g_config.force_sleepskip != 0) {
		newint.QuadPart = -(10000 * 10000);
		time_skipped.QuadPart += interval - (10000 * 10000);
		LOQ_ntstatus("system", "is", "Milliseconds", milli, "Status", "Skipped");
		goto docall;
	}
	else if (sleep_skip_active && g_config.force_sleepskip > 0) {
		time_skipped.QuadPart += interval;
		LOQ_ntstatus("system", "is", "Milliseconds", milli, "Status", "Skipped");
		newint.QuadPart = 0;
		goto docall;
	}

docall:
	set_lasterrors(&lasterror);

	ret = Old_NtSetTimer(TimerHandle, &newint, TimerApcRoutine, TimerContext, ResumeTimer, Period, PreviousState);

	return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtSetTimerEx,
	IN HANDLE TimerHandle,
	IN int TimerSetInformationClass,
	__inout PVOID TimerSetInformation,
	IN ULONG TimerSetInformationLength
) {
	NTSTATUS ret = 0;
	LONGLONG interval;
	FILETIME ft;
	LARGE_INTEGER newint;
	LARGE_INTEGER origdue;
	unsigned long milli;
	lasterror_t lasterror;
	BOOL modified_delay = FALSE;
	PTIMER_SET_COALESCABLE_TIMER_INFO timerinfo;

	get_lasterrors(&lasterror);

	if (TimerSetInformationClass)
		goto docall;

	timerinfo = (PTIMER_SET_COALESCABLE_TIMER_INFO)TimerSetInformation;
	origdue = timerinfo->DueTime;

	newint.QuadPart = origdue.QuadPart;
	// handle INFINITE sleep
	if (newint.QuadPart == 0x8000000000000000ULL) {
		LOQ_ntstatus("system", "is", "Milliseconds", -1, "Status", "Infinite");
		goto docall;
	}

	if (sleep_skip_active && newint.QuadPart > 0LL) {
		/* convert absolute time to relative time */
		GetSystemTimeAsFileTime(&ft);

		newint.HighPart = ft.dwHighDateTime;
		newint.LowPart = ft.dwLowDateTime;
		newint.QuadPart += time_skipped.QuadPart;
		newint.QuadPart -= origdue.QuadPart;
		if (newint.QuadPart > 0LL)
			newint.QuadPart = 0LL;
		timerinfo->DueTime.QuadPart = newint.QuadPart;
		modified_delay = TRUE;
	}
	interval = -newint.QuadPart;
	milli = (unsigned long)(interval / 10000);

	/* clamp sleeps between 30 seconds and 1 hour down to 10 seconds  as long as we didn't force off sleep skipping */
	if (sleep_skip_active && milli >= 30000 && milli <= 3600000 && g_config.force_sleepskip != 0) {
		timerinfo->DueTime.QuadPart = -(10000 * 10000);
		time_skipped.QuadPart += interval - (10000 * 10000);
		LOQ_ntstatus("system", "is", "Milliseconds", milli, "Status", "Skipped");
		modified_delay = TRUE;
		goto docall;
	}
	else if (sleep_skip_active && g_config.force_sleepskip > 0) {
		time_skipped.QuadPart += interval;
		LOQ_ntstatus("system", "is", "Milliseconds", milli, "Status", "Skipped");
		timerinfo->DueTime.QuadPart = 0;
		modified_delay = TRUE;
		goto docall;
	}

docall:
	set_lasterrors(&lasterror);
	ret = Old_NtSetTimerEx(TimerHandle, TimerSetInformationClass, TimerSetInformation, TimerSetInformationLength);

	if (modified_delay) {
		timerinfo->DueTime = origdue;
	}

	return ret;
}

static LARGE_INTEGER perf_multiplier;

HOOKDEF(NTSTATUS, WINAPI, NtQueryPerformanceCounter,
	_Out_	 PLARGE_INTEGER PerformanceCounter,
	_Out_opt_ PLARGE_INTEGER PerformanceFrequency
) {
	NTSTATUS ret;
	ENSURE_LARGE_INTEGER(PerformanceFrequency);

	ret = Old_NtQueryPerformanceCounter(PerformanceCounter, PerformanceFrequency);

	if (NT_SUCCESS(ret) && sleep_skip_active) {
		if (!perf_multiplier.QuadPart)
			perf_multiplier.QuadPart = PerformanceFrequency->QuadPart / 1000;
		PerformanceCounter->QuadPart += (time_skipped.QuadPart / 10000) * perf_multiplier.QuadPart;
	}

	return ret;
}


HOOKDEF(void, WINAPI, GetLocalTime,
	__out  LPSYSTEMTIME lpSystemTime
) {
	lasterror_t lasterror;
	LARGE_INTEGER li; FILETIME ft;
	DWORD ret = 0;

	Old_GetLocalTime(lpSystemTime);

	get_lasterrors(&lasterror);

	if (sleep_skip_active) {
		SystemTimeToFileTime(lpSystemTime, &ft);
		li.HighPart = ft.dwHighDateTime;
		li.LowPart = ft.dwLowDateTime;
		li.QuadPart += time_skipped.QuadPart;
		ft.dwHighDateTime = li.HighPart;
		ft.dwLowDateTime = li.LowPart;
		FileTimeToSystemTime(&ft, lpSystemTime);
	}

	LOQ_void("system", "");

	set_lasterrors(&lasterror);
}

HOOKDEF(void, WINAPI, GetSystemTime,
	__out  LPSYSTEMTIME lpSystemTime
) {
	lasterror_t lasterror;
	LARGE_INTEGER li; FILETIME ft;
	DWORD ret = 0;

	Old_GetSystemTime(lpSystemTime);

	get_lasterrors(&lasterror);

	if (sleep_skip_active) {
		SystemTimeToFileTime(lpSystemTime, &ft);
		li.HighPart = ft.dwHighDateTime;
		li.LowPart = ft.dwLowDateTime;
		li.QuadPart += time_skipped.QuadPart;
		ft.dwHighDateTime = li.HighPart;
		ft.dwLowDateTime = li.LowPart;
		FileTimeToSystemTime(&ft, lpSystemTime);
	}

	LOQ_void("system", "");

	set_lasterrors(&lasterror);
}

DWORD raw_gettickcount(void)
{
	if (g_osverinfo.dwMajorVersion >= 6)
		return (DWORD)((*(ULONGLONG *)0x7ffe0320 * *(DWORD *)0x7ffe0004) >> 24);
	else
		return (DWORD)(((ULONGLONG)*(DWORD *)0x7ffe0000 * *(DWORD *)0x7ffe0004) >> 24);
}

ULONGLONG raw_gettickcount64(void)
{
	ULARGE_INTEGER tickcount64;
	DWORD multiplier = *(DWORD *)0x7ffe0004;
	tickcount64.LowPart = *(DWORD *)0x7ffe0320;
	tickcount64.HighPart = *(DWORD *)0x7ffe0324;

	return (((ULONGLONG)tickcount64.LowPart  * multiplier) >> 24) +
		   (((ULONGLONG)tickcount64.HighPart * multiplier) <<  8);
}

HOOKDEF(DWORD, WINAPI, GetTickCount,
	void
) {
	DWORD ret;

	FORCE_FRAME_PTR_USE();

	ret = raw_gettickcount();

	// add the time we've skipped
	if (sleep_skip_active)
		ret += (DWORD)(time_skipped.QuadPart / 10000);

	return ret;
}

HOOKDEF(ULONGLONG, WINAPI, GetTickCount64,
	void
) {
	ULONGLONG ret;

	FORCE_FRAME_PTR_USE();

	ret = raw_gettickcount64();

	// add the time we've skipped
	if (sleep_skip_active)
		ret += (time_skipped.QuadPart / 10000);

	return ret;
}


HOOKDEF(NTSTATUS, WINAPI, NtQuerySystemTime,
	_Out_  PLARGE_INTEGER SystemTime
) {
	NTSTATUS ret = Old_NtQuerySystemTime(SystemTime);
	LOQ_ntstatus("system", "");
	if (NT_SUCCESS(ret) && sleep_skip_active) {
		SystemTime->QuadPart += time_skipped.QuadPart;
	}
	return 0;
}

HOOKDEF(DWORD, WINAPI, timeGetTime,
	void
) {
	DWORD ret;

	FORCE_FRAME_PTR_USE();

	ret = Old_timeGetTime();

	// add the time we've skipped
	if (sleep_skip_active)
		ret += (DWORD)(time_skipped.QuadPart / 10000);

	return ret;
}

HOOKDEF(void, WINAPI, GetSystemTimeAsFileTime,
	_Out_ LPFILETIME lpSystemTimeAsFileTime
) {
	LARGE_INTEGER li;
	FILETIME ft;
	DWORD ret = 0;

	Old_GetSystemTimeAsFileTime(&ft);

	if (sleep_skip_active) {
		li.HighPart = ft.dwHighDateTime;
		li.LowPart = ft.dwLowDateTime;
		li.QuadPart += time_skipped.QuadPart;
		ft.dwHighDateTime = li.HighPart;
		ft.dwLowDateTime = li.LowPart;
	}

	memcpy(lpSystemTimeAsFileTime, &ft, sizeof(ft));

	LOQ_void("system", "");

	return;
}

HOOKDEF(DWORD, WINAPI, timeSetEvent,
   UINT           uDelay,
   UINT           uResolution,
   LPTIMECALLBACK lpTimeProc,
   DWORD_PTR      dwUser,
   UINT           fuEvent
) {
	DWORD ret = Old_timeSetEvent(uDelay, uResolution, lpTimeProc, dwUser, fuEvent);
	LOQ_bool("system", "ip", "Delay", uDelay, "TimeProc", lpTimeProc);
	return ret;
}

HOOKDEF(BOOL, WINAPI, CreateTimerQueueTimer,
  _Out_		PHANDLE				phNewTimer,
  _In_opt_	HANDLE				TimerQueue,
  _In_		WAITORTIMERCALLBACK	Callback,
  _In_opt_	PVOID				Parameter,
  _In_		DWORD				DueTime,
  _In_		DWORD				Period,
  _In_		ULONG				Flags
) {
	BOOL ret = Old_CreateTimerQueueTimer(phNewTimer, TimerQueue, Callback, Parameter, DueTime, Period, Flags);
	LOQ_bool("system", "Pphhiii", "phNewTimer", phNewTimer, "TimerQueue", TimerQueue, "Callback", Callback, "Parameter", Parameter, "DueTime", DueTime, "Period", Period, "Flags", Flags);
	return ret;
}

static int lastinput_called;

HOOKDEF(BOOL, WINAPI, GetLastInputInfo,
	_Out_ PLASTINPUTINFO plii
)
{
BOOL ret;
	lasterror_t lasterror;

	ret = Old_GetLastInputInfo(plii);

	LOQ_bool("system", "");

	/* Samples call GetLastInputInfo to read LASTINPUTINFO.dwTime (the tick count
	 * of the last keyboard/mouse input event) and compute the idle interval as
	 * idle = GetTickCount() - plii->dwTime, treating idle > 6000ms (no user input
	 * for several seconds) as proof that no real user is present — a headless,
	 * unattended analysis VM where nothing moves the mouse or types. On such a
	 * sandbox dwTime stays at its boot value while the tick count climbs, so the
	 * computed idle time quickly exceeds the threshold and the sample takes the
	 * evasive branch. After the real call succeeds, overwrite plii->dwTime with
	 * GetTickCount() - 100 so the sample computes a ~100ms idle time, well under
	 * the 6000ms floor, and concludes a genuine user is actively interacting with
	 * the machine. Lasterror is preserved around the buffer edit so the forced
	 * value leaves no other trace. */
	if (!g_config.no_stealth && ret != FALSE && plii != NULL) {
		get_lasterrors(&lasterror);

		plii->dwTime = GetTickCount() - 100;

		set_lasterrors(&lasterror);
	}

	return ret;
}

void init_sleep_skip(int first_process)
{
	FILETIME ft;
	GetSystemTimeAsFileTime(&ft);
	time_start.HighPart = ft.dwHighDateTime;
	time_start.LowPart = ft.dwLowDateTime;

	// we don't want to skip sleep calls in child processes
	if (first_process == 0) {
		disable_sleep_skip();
	}
}

void init_startup_time(unsigned int startup_time)
{
	time_skipped.QuadPart += (unsigned __int64) startup_time * 10000;
}
