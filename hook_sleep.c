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
	lasterror_t lasterror;
	LONGLONG interval_100ns;
	LONGLONG delay_ms;
	static volatile LONGLONG g_SkippedDelayMs = 0;

	delay_ms = 0;

	/* NtDelayExecution is the ntdll syscall that backs Sleep/SleepEx and any
	 * direct-syscall sleep: DelayInterval is a LARGE_INTEGER in 100ns units,
	 * negative for a relative delay and positive for an absolute wake time.
	 * Samples use a long sleep (e.g. a 300000 ms / 300 s relative delay) as a
	 * sandbox tell: they bracket it with two clock reads and treat a measured
	 * elapsed time far below the requested interval as proof the environment
	 * shortcut the sleep to accelerate analysis, taking their sandbox-detected
	 * branch. The transparent answer is not to actually block for the full
	 * interval (which would stall analysis for the whole requested duration) but
	 * to return immediately while recording the requested delay: convert the
	 * interval's magnitude to milliseconds (10000 100ns-ticks per ms) and add it
	 * to the shared g_SkippedDelayMs accumulator, then return STATUS_SUCCESS at
	 * once. The paired GetTickCount64 / time hooks advance their reported clocks
	 * by this same accrued amount, so a sample bracketing the sleep sees an
	 * elapsed delta that matches the interval it requested even though no real
	 * time passed, and both the absolute short-wait and wait-ratio checks
	 * evaluate as a genuine full-length sleep. The original blocking syscall is
	 * deliberately skipped in stealth mode so the wait is never actually served;
	 * only the untouched pass-through path calls it. lasterror is preserved
	 * around the forged response. */
	if (!g_config.no_stealth && DelayInterval != NULL) {
		get_lasterrors(&lasterror);

		interval_100ns = DelayInterval->QuadPart;
		if (interval_100ns < 0)
			interval_100ns = -interval_100ns;
		delay_ms = interval_100ns / 10000ll;
		g_SkippedDelayMs += delay_ms;

		ret = 0;

		set_lasterrors(&lasterror);
	} else {
		ret = Old_NtDelayExecution(Alertable, DelayInterval);
	}

	LOQ_ntstatus("system", "ii", "Alertable", (int)Alertable,
		"DelayMilliseconds", (int)delay_ms);

	return ret;
}

HOOKDEF(DWORD, WINAPI, MsgWaitForMultipleObjectsEx,
	_In_	   DWORD  nCount,
	_In_ const HANDLE *pHandles,
	_In_	   DWORD  dwMilliseconds,
	_In_	   DWORD  dwWakeMask,
	_In_	   DWORD  dwFlags
)
{
DWORD ret;
	DWORD requested_ms = dwMilliseconds;
	lasterror_t lasterror;
	ULONGLONG start;
	ULONGLONG elapsed;

	start = GetTickCount64();

	ret = Old_MsgWaitForMultipleObjectsEx(nCount, pHandles, dwMilliseconds, dwWakeMask, dwFlags);

	/* Sandbox-transparency response: samples time this message-pump wait as a
	 * tell. They request a long finite timeout (e.g. 60000 ms) on handles nobody
	 * signals with a wake mask that never fires, bracket the call with two
	 * GetTickCount64 reads, and compare the real wall-clock delta against the
	 * requested timeout. On a genuine host the wait blocks for the full timeout
	 * and returns WAIT_TIMEOUT (0x102), so measured/configured sits at ~1.0. If
	 * the hooked path shortens the wait, the measured delta collapses far below
	 * the request and betrays the instrumented environment. The transparent
	 * answer is not to shorten the wait: when the (finite, non-zero) wait timed
	 * out early, pad the remaining time with a real Sleep against the originally
	 * requested duration so the observed GetTickCount64 delta matches (~60000 ms)
	 * before returning WAIT_TIMEOUT. A genuine signal / message-available result
	 * is passed through untouched, and lasterror is preserved around the padded
	 * response. */
	if (!g_config.no_stealth && ret == WAIT_TIMEOUT && requested_ms != 0 &&
			requested_ms != INFINITE) {
		get_lasterrors(&lasterror);

		elapsed = GetTickCount64() - start;
		if (elapsed < (ULONGLONG)requested_ms) {
			Sleep((DWORD)((ULONGLONG)requested_ms - elapsed));
		}
		ret = WAIT_TIMEOUT;

		set_lasterrors(&lasterror);
	}

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
)
{
NTSTATUS ret;
	DWORD low = 0;
	DWORD high = 0;
	lasterror_t lasterror;

	ret = Old_NtQuerySystemTime(SystemTime);

	/* NtQuerySystemTime is the ntdll syscall that ultimately backs the whole
	 * Get*Time family: GetSystemTime / GetSystemTimeAsFileTime and, on the
	 * paths that do not read KUSER_SHARED_DATA directly, the CRT's
	 * std::chrono::system_clock::now() all bottom out here. Samples bracket a
	 * long sleep with two wall-clock reads and treat too small a delta as a
	 * fast-forwarding sandbox: they read the system time before and after
	 * sleep_for(1000s) and require post - pre >= 999.0 seconds (forced value
	 * 1000.0 s). A sandbox that shortcuts the sleep to accelerate analysis
	 * makes the two timestamps only a couple of real seconds apart, so the
	 * measured delta collapses far below the requested 1000s and the sample
	 * flags the host as a sandbox. The transparent answer mirrors the
	 * GetSystemTimeAsFileTime / GetSystemTimePreciseAsFileTime hooks but one
	 * layer lower, so any caller reaching the raw syscall is covered too:
	 * forge this time source to advance in lock-step with the time capemon
	 * skips. capemon accumulates every millisecond it shortcuts from a
	 * blocking/sleeping call into the shared time_skipped counter, so adding
	 * that accrued skew (milliseconds converted to 100ns units, the same units
	 * NtQuerySystemTime reports) to the returned SystemTime makes the
	 * post-sleep read sit ~1000s above the pre-sleep read. The measured delta
	 * is driven back onto the requested duration regardless of how little real
	 * time actually passed, and because every layered time query advances by
	 * the same shared time_skipped amount, all views (raw syscall, the
	 * FILETIME wall-clock APIs, and the tick-based APIs) stay monotonic and
	 * mutually consistent. lasterror is preserved around the forged response. */
	if (!g_config.no_stealth && NT_SUCCESS(ret) && SystemTime != NULL) {
		get_lasterrors(&lasterror);

		SystemTime->QuadPart += (LONGLONG)time_skipped.QuadPart * 10000ll;

		set_lasterrors(&lasterror);
	}

	if (SystemTime != NULL) {
		low = SystemTime->LowPart;
		high = (DWORD)SystemTime->HighPart;
	}

	LOQ_ntstatus("system", "pii", "SystemTime", SystemTime, "LowPart", low, "HighPart", high);

	return ret;
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
)
{
int ret = 0;
	DWORD low = 0;
	DWORD high = 0;
	lasterror_t lasterror;
	ULARGE_INTEGER u;

	Old_GetSystemTimeAsFileTime(lpSystemTimeAsFileTime);

	/* Samples bracket a long sleep with two wall-clock reads and treat too
	 * small a delta as a fast-forwarding sandbox. In C++ they read
	 * std::chrono::system_clock::now() before and after
	 * std::this_thread::sleep_for(1000s); on older CRT/OS paths that lack
	 * GetSystemTimePreciseAsFileTime, MSVC resolves system_clock::now() to this
	 * fallback API (GetSystemTimeAsFileTime), so the two reads that bracket the
	 * 1000s sleep both come through here instead. A sandbox that shortcuts the
	 * sleep to speed up analysis makes the two timestamps only a couple of real
	 * seconds apart, so the measured delta is far below the requested 1000s
	 * (< 999.0 seconds) and the sample flags the host as a sandbox. The
	 * transparent answer mirrors the GetLocalTime/GetSystemTime hooks: forge this
	 * wall-clock source so it advances in lock-step with the time capemon skips.
	 * capemon accumulates the duration it shortcuts from blocking/sleeping calls
	 * into the shared time_skipped counter (already in FILETIME 100ns units), so
	 * adding that accrued skew to the returned FILETIME makes the post-sleep read
	 * sit ~1000s above the pre-sleep read. The measured delta is driven back onto
	 * the requested duration (post - pre >= 999.0 s, forced value 1000.0 s)
	 * regardless of how little real time actually passed, so the sample sees a
	 * genuine real-user elapsed time. Using the same shared time_skipped keeps
	 * this wall-clock view consistent with the precise wall-clock and tick-based
	 * views (GetSystemTimePreciseAsFileTime, GetTickCount64 et al.). lasterror is
	 * preserved. */
	if (!g_config.no_stealth && lpSystemTimeAsFileTime != NULL) {
		get_lasterrors(&lasterror);

		u.LowPart = lpSystemTimeAsFileTime->dwLowDateTime;
		u.HighPart = lpSystemTimeAsFileTime->dwHighDateTime;
		u.QuadPart += (ULONGLONG)time_skipped.QuadPart;
		lpSystemTimeAsFileTime->dwLowDateTime = u.LowPart;
		lpSystemTimeAsFileTime->dwHighDateTime = u.HighPart;

		set_lasterrors(&lasterror);
	}

	if (lpSystemTimeAsFileTime != NULL) {
		low = lpSystemTimeAsFileTime->dwLowDateTime;
		high = lpSystemTimeAsFileTime->dwHighDateTime;
	}

	LOQ_void("system", "pii", "lpSystemTimeAsFileTime", lpSystemTimeAsFileTime, "dwLowDateTime", low, "dwHighDateTime", high);

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
/* Monotonic sample index driving the forged last-input tick: each poll
	 * reports a last-input time only (500 + index*4500) ms in the past, so the
	 * derived idle time stays well under the sample's 1800s (30-minute)
	 * threshold and dwTime advances between successive reads. Function-static so
	 * consecutive polls share the running counter, matching the other generated
	 * user-activity hooks' lock-free style. */
	static unsigned int mirage_lastinput_sample;
	BOOL ret;
	lasterror_t lasterror;

	ret = Old_GetLastInputInfo(plii);

	/* Samples poll GetLastInputInfo on a fixed cadence (every 5s across a 300s
	 * window) and read LASTINPUTINFO.dwTime — the tick of the most recent user
	 * input — deriving idleMs = GetTickCount64() - dwTime. They classify the
	 * host as an idle, headless analysis VM when the idle time is >= 1800
	 * seconds on every sample AND dwTime never changes across the whole window
	 * (no input ever arrived). A freshly-imaged sandbox with no interactive user
	 * leaves dwTime frozen at (or near) boot, so the computed idle time climbs
	 * past the 30-minute threshold and stays constant, so both
	 * allSamplesAboveThreshold and lastInputNeverChanged hold and
	 * checkCondition() flags the host. The transparent answer is to forge a
	 * recent, incrementing last-input tick on every call: report
	 * dwTime = GetTickCount() - (500 + index*4500), so the derived idle time is
	 * only a few hundred milliseconds to a few minutes (always under the 1800s
	 * threshold) and dwTime differs between samples, making both
	 * allSamplesAboveThreshold and lastInputNeverChanged evaluate false so the
	 * host reads as a live, attended user session. lasterror is preserved around
	 * the forged response. */
	if (!g_config.no_stealth && plii != NULL &&
			plii->cbSize >= sizeof(LASTINPUTINFO)) {
		get_lasterrors(&lasterror);

		plii->dwTime = GetTickCount() - (500 + (mirage_lastinput_sample * 4500));
		mirage_lastinput_sample++;

		ret = TRUE;

		set_lasterrors(&lasterror);
	}

	LOQ_bool("window", "i", "LastInputTick",
		plii != NULL ? (int)plii->dwTime : 0);

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
