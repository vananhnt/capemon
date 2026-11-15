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

/*
 * Shared skip+credit helpers for timer/wait primitives that measure elapsed
 * time with a clock delta (GetTickCount64/QPC before vs. after a timed wait).
 * A sample that schedules a long timer/IOCP/queue wait and compares the
 * measured delta against the requested interval cannot be defeated by simply
 * returning the wait early -- that makes the delta too SMALL, which is itself
 * the sandbox tell. Instead we shrink the real wait so analysis stays fast and
 * credit `time_skipped` the requested interval, so every subsequent clock read
 * (GetTickCount/GetTickCount64/QPC/NtQuerySystemTime) advances to match. These
 * expose the file-local skip state to hook_mirage.c without leaking the static.
 */

// only reduce timer/wait intervals at or above this (ms); leave genuine short
// timers untouched so we don't perturb normal program behaviour.
#define MIRAGE_TIMER_SKIP_MIN_MS 1000
// the small real interval we leave so a callback can actually fire (ms).
#define MIRAGE_TIMER_REAL_MS 10

int mirage_sleep_skip_active(void)
{
	return sleep_skip_active;
}

void mirage_credit_skipped_ms(unsigned int ms)
{
	if (sleep_skip_active)
		time_skipped.QuadPart += (LONGLONG)ms * 10000;
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
) {
	NTSTATUS ret = 0;
	LONGLONG interval;
	FILETIME ft;
	LARGE_INTEGER li;
	LARGE_INTEGER newint;
	unsigned long milli;
	lasterror_t lasterror;

	get_lasterrors(&lasterror);

	if (!IsAddressAccessible(DelayInterval))
		return STATUS_ACCESS_VIOLATION;

	if (!is_aligned(DelayInterval, 4))
		return STATUS_DATATYPE_MISALIGNMENT;

	newint.QuadPart = DelayInterval->QuadPart;
	// handle INFINITE sleep
	if (newint.QuadPart == 0x8000000000000000ULL) {
		LOQ_ntstatus("system", "is", "Milliseconds", -1, "Status", "Infinite");
		goto docall;
	}

	if (sleep_skip_active && newint.QuadPart > 0LL) {
		/* convert absolute time to relative time */
		if (Old_GetSystemTimeAsFileTime)
			Old_GetSystemTimeAsFileTime(&ft);
		else
			GetSystemTimeAsFileTime(&ft);

		newint.HighPart = ft.dwHighDateTime;
		newint.LowPart = ft.dwLowDateTime;
		newint.QuadPart += time_skipped.QuadPart;
		newint.QuadPart -= DelayInterval->QuadPart;
		if (newint.QuadPart > 0LL)
			newint.QuadPart = 0LL;
	}
	interval = -newint.QuadPart;
	milli = (unsigned long)(interval / 10000);

	if (Old_GetSystemTimeAsFileTime)
		Old_GetSystemTimeAsFileTime(&ft);
	else
		GetSystemTimeAsFileTime(&ft);
	li.HighPart = ft.dwHighDateTime;
	li.LowPart = ft.dwLowDateTime;

	// check if we're still within the hardcoded limit
	if (sleep_skip_active && (li.QuadPart < time_start.QuadPart + MAX_SLEEP_SKIP_DIFF * 10000)) {
		time_skipped.QuadPart += interval;

		if (num_skipped < 20) {
			// notify how much we've skipped
			LOQ_ntstatus("system", "is", "Milliseconds", milli, "Status", "Skipped");
			num_skipped++;
		}
		else if (num_skipped == 20) {
			LOQ_ntstatus("system", "s", "Status", "Skipped log limit reached");
			num_skipped++;
		}
		goto skipcall;
	}
	/* clamp sleeps between 30 seconds and 1 hour down to 10 seconds  as long as we didn't force off sleep skipping */
	else if (sleep_skip_active && milli >= 30000 && milli <= 3600000 && g_config.force_sleepskip != 0) {
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
	else {
		disable_sleep_skip();
	}
	if (sleep_skip_active && milli <= 10) {
		if (num_small < 20) {
			LOQ_ntstatus("system", "i", "Milliseconds", milli);
			num_small++;
		}
		else if (num_small == 20) {
			LOQ_ntstatus("system", "s", "Status", "Small log limit reached");
			num_small++;
		}
		else {
			// likely using a bunch of tiny sleeps to delay execution, so let's suddenly mimic high load and give our
			// fake passage of time the impression of longer delays to return from sleep
			time_skipped.QuadPart += (randint(500, 1000) * 10000);
		}
	}
	else {
		LOQ_ntstatus("system", "i", "Milliseconds", milli);
	}
docall:
	set_lasterrors(&lasterror);
	return Old_NtDelayExecution(Alertable, &newint);
skipcall:
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

	// MIRAGE_PROBE: trace credit delivery for the timer/wait cluster. Only fires
	// once a large credit is pending so it isolates the post-timeSetEvent reads
	// (incl. the callback thread) without flooding the log. Remove after triage.
	if (time_skipped.QuadPart / 10000 >= 1000)
		DebugOutput("MIRAGE_GTC32: raw=%u credited=%u skip_active=%d skipped_ms=%lld tid=%u\n",
			(unsigned int)raw_gettickcount(), (unsigned int)ret, sleep_skip_active,
			(LONGLONG)(time_skipped.QuadPart / 10000), (unsigned int)GetCurrentThreadId());

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

	// MIRAGE_PROBE: see GetTickCount above. caller = real (non-capemon) return
	// address so we can tell whether the SAMPLE .exe's own measurement reads reach
	// this hook; disabled flags whether the api-cap turned this hook off (would make
	// it return raw to the caller). tid separates main vs winmm-callback threads.
	if (time_skipped.QuadPart / 10000 >= 1000)
		DebugOutput("MIRAGE_GTC64: raw=%llu credited=%llu skip_active=%d skipped_ms=%lld tid=%u caller=0x%p disabled=%d\n",
			(unsigned long long)raw_gettickcount64(), (unsigned long long)ret, sleep_skip_active,
			(LONGLONG)(time_skipped.QuadPart / 10000), (unsigned int)GetCurrentThreadId(),
			(PVOID)hook_info()->main_caller_retaddr,
			hook_info()->current_hook ? hook_info()->current_hook->hook_disabled : -1);

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
	DWORD ret;
	UINT realdelay = uDelay;
	int skipped = 0;

	/*
	 * Multimedia-timer stall check: the sample records a tick, schedules a
	 * long one-shot timer, waits on the event the callback signals, then
	 * compares the tick delta to uDelay. Fire the callback almost
	 * immediately (so the event is signalled before the sample's wait, even
	 * when that wait is itself sleep-skipped) and credit the requested delay
	 * so the measured delta still reads ~uDelay.
	 */
	if (sleep_skip_active && uDelay >= MIRAGE_TIMER_SKIP_MIN_MS) {
		realdelay = MIRAGE_TIMER_REAL_MS;
		time_skipped.QuadPart += (LONGLONG)(uDelay - realdelay) * 10000;
		skipped = 1;
	}

	// MIRAGE_PROBE: confirm the credit landed and on which thread. Pairs with the
	// MIRAGE_GTC64 probes so we can diff the credit site vs the callback read.
	DebugOutput("MIRAGE_TSE: uDelay=%u realdelay=%u skip_active=%d skipped=%d skipped_ms=%lld tid=%u\n",
		(unsigned int)uDelay, (unsigned int)realdelay, sleep_skip_active, skipped,
		(LONGLONG)(time_skipped.QuadPart / 10000), (unsigned int)GetCurrentThreadId());

	ret = Old_timeSetEvent(realdelay, uResolution, lpTimeProc, dwUser, fuEvent);
	LOQ_bool("system", "ipis", "Delay", uDelay, "TimeProc", lpTimeProc, "RealDelay", realdelay,
		"Status", skipped ? "Skipped" : "Unmodified");
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
	BOOL ret;
	DWORD realdue = DueTime;

	/*
	 * Timer-queue skew check: same shape as the multimedia-timer stall --
	 * fire the one-shot callback promptly and credit the requested DueTime so
	 * the sample's tick delta across the wait still reads ~DueTime. Only the
	 * initial fire is shifted; a recurring Period is left untouched.
	 */
	if (sleep_skip_active && DueTime >= MIRAGE_TIMER_SKIP_MIN_MS) {
		realdue = MIRAGE_TIMER_REAL_MS;
		time_skipped.QuadPart += (LONGLONG)(DueTime - realdue) * 10000;
	}

	ret = Old_CreateTimerQueueTimer(phNewTimer, TimerQueue, Callback, Parameter, realdue, Period, Flags);
	LOQ_bool("system", "Pphhiii", "phNewTimer", phNewTimer, "TimerQueue", TimerQueue, "Callback", Callback, "Parameter", Parameter, "DueTime", DueTime, "Period", Period, "Flags", Flags);
	return ret;
}

HOOKDEF(void, WINAPI, SetThreadpoolTimer,
  _Inout_	PVOID		pti,
  _In_opt_	PFILETIME	pftDueTime,
  _In_		DWORD		msPeriod,
  _In_		DWORD		msWindowLength
) {
	FILETIME local;
	PFILETIME due = pftDueTime;
	unsigned long milli = 0;
	DWORD ret = 0;

	/*
	 * Thread-pool timer skew check: the sample sets a relative-due TP timer
	 * (negative FILETIME = 100ns from now), waits on the event its callback
	 * signals, and compares the tick delta to the requested due time. Shorten
	 * the real due time so the callback fires promptly (pre-signalling the
	 * wait) and credit the sleep-skip clock the requested interval. A NULL
	 * due time (cancel) or an absolute (positive) due time is passed through.
	 */
	if (sleep_skip_active && pftDueTime) {
		LARGE_INTEGER li;
		li.LowPart = pftDueTime->dwLowDateTime;
		li.HighPart = pftDueTime->dwHighDateTime;
		if (li.QuadPart < 0) {
			unsigned __int64 ms = (unsigned __int64)(-li.QuadPart) / 10000;
			if (ms >= MIRAGE_TIMER_SKIP_MIN_MS) {
				LARGE_INTEGER red;
				milli = (unsigned long)ms;
				red.QuadPart = -((LONGLONG)MIRAGE_TIMER_REAL_MS * 10000);
				local.dwLowDateTime = red.LowPart;
				local.dwHighDateTime = red.HighPart;
				due = &local;
				time_skipped.QuadPart += (LONGLONG)(ms - MIRAGE_TIMER_REAL_MS) * 10000;
			}
		}
	}

	Old_SetThreadpoolTimer(pti, due, msPeriod, msWindowLength);
	LOQ_void("system", "pis", "Timer", pti, "Milliseconds", milli, "Status", milli ? "Skipped" : "Unmodified");
}

static int lastinput_called;

HOOKDEF(BOOL, WINAPI, GetLastInputInfo,
	_Out_ PLASTINPUTINFO plii
) {
	BOOL ret = Old_GetLastInputInfo(plii);

	LOQ_bool("system", "");

	lastinput_called++;

	/* fake recent user activity */
	if (lastinput_called > 2 && plii && plii->cbSize == 8)
		plii->dwTime = raw_gettickcount() + (DWORD)(time_skipped.QuadPart / 10000);

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
