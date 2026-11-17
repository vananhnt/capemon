/*
 * hook_mirage.c — SAGE-generated hook implementations.
 * Auto-regenerated; do not edit by hand.
 */
#include <stdio.h>
#include "hooking.h"
#include <tlhelp32.h>
#include <slpublic.h>
#include <winspool.h>
#include "log.h"
#include "config.h"
        HOOKDEF(BOOL, WINAPI, GetSystemPowerStatus, LPSYSTEM_POWER_STATUS lpSystemPowerStatus)
        {
            BOOL ret;
	lasterror_t lasterror;
	/* Persisted battery level so successive calls drift rather than return a
	 * fixed value; this defeats variability-based fake-battery detection. */
	static LONG s_battery_level = 50;
	static volatile LONG s_rng = 0x1a2b3c4d;

	ret = Old_GetSystemPowerStatus(lpSystemPowerStatus);

	if (!g_config.no_stealth && lpSystemPowerStatus != NULL) {
		LONG rng, step;

		get_lasterrors(&lasterror);

		/* Simple xorshift random walk kept within 40..70 so the reported
		 * BatteryLifePercent moves a few points per call (discharging laptop)
		 * without ever hitting the 255/unavailable or static-level branches. */
		rng = s_rng;
		rng ^= rng << 13;
		rng ^= rng >> 17;
		rng ^= rng << 5;
		s_rng = rng;

		step = (rng & 3) - 1;		/* -1, 0, or +1 (or +2) */
		s_battery_level += step;
		if (s_battery_level < 40)
			s_battery_level = 40;
		if (s_battery_level > 70)
			s_battery_level = 70;

		lpSystemPowerStatus->ACLineStatus = 0;			/* offline / on battery */
		lpSystemPowerStatus->BatteryFlag = 1;			/* high, >66% not required */
		lpSystemPowerStatus->BatteryLifePercent = (BYTE)s_battery_level;
		lpSystemPowerStatus->SystemStatusFlag = 0;
		lpSystemPowerStatus->BatteryLifeTime = 3600;
		lpSystemPowerStatus->BatteryFullLifeTime = 7200;

		ret = TRUE;
		set_lasterrors(&lasterror);
	}

	LOQ_bool("misc", "i", "BatteryLifePercent",
		lpSystemPowerStatus != NULL ? lpSystemPowerStatus->BatteryLifePercent : -1);
	return ret;
        }

        HOOKDEF(BOOL, WINAPI, EnumPrintersW, DWORD Flags, LPWSTR Name, DWORD Level, LPBYTE pPrinterEnum, DWORD cbBuf, LPDWORD pcbNeeded, LPDWORD pcReturned)
        {
            BOOL ret;
	lasterror_t lasterror;
	int spoofed = 0;

	ret = Old_EnumPrintersW(Flags, Name, Level, pPrinterEnum, cbBuf,
		pcbNeeded, pcReturned);

	if (!g_config.no_stealth && Level == 2 && pcbNeeded != NULL) {
		const wchar_t *forced = L"HP LaserJet Pro M404n";
		DWORD namebytes = (DWORD)((wcslen(forced) + 1) * sizeof(wchar_t));
		DWORD needed = (DWORD)sizeof(PRINTER_INFO_2W) + namebytes;

		get_lasterrors(&lasterror);

		if (pPrinterEnum == NULL || cbBuf < needed) {
			/* Sizing pass: report the byte count one printer requires and
			 * signal the caller to retry with a larger buffer. */
			*pcbNeeded = needed;
			if (pcReturned != NULL)
				*pcReturned = 0;
			ret = FALSE;
			set_lasterrors(&lasterror);
			SetLastError(ERROR_INSUFFICIENT_BUFFER);
			spoofed = 1;
		}
		else {
			/* Real pass: emit exactly one populated PRINTER_INFO_2W, placing
			 * the printer-name string at the tail of the caller's buffer (the
			 * way the real API packs variable-length strings). */
			PRINTER_INFO_2W *pi = (PRINTER_INFO_2W *)pPrinterEnum;
			wchar_t *namedst = (wchar_t *)(pPrinterEnum + cbBuf - namebytes);

			memset(pi, 0, sizeof(PRINTER_INFO_2W));
			memcpy(namedst, forced, namebytes);
			pi->pPrinterName = namedst;
			pi->Attributes = PRINTER_ATTRIBUTE_LOCAL;

			*pcbNeeded = needed;
			if (pcReturned != NULL)
				*pcReturned = 1;
			ret = TRUE;
			spoofed = 1;
			set_lasterrors(&lasterror);
		}
	}

	LOQ_bool("misc", "iii", "Flags", Flags, "Level", Level, "Spoofed", spoofed);
	return ret;
        }

        HOOKDEF(void, WINAPI, GetNativeSystemInfo, LPSYSTEM_INFO lpSystemInfo)
        {
            int ret = 0;
	lasterror_t lasterror;

	Old_GetNativeSystemInfo(lpSystemInfo);

	if (!g_config.no_stealth && lpSystemInfo != NULL) {
		get_lasterrors(&lasterror);
		lpSystemInfo->wProcessorArchitecture = PROCESSOR_ARCHITECTURE_AMD64;
		lpSystemInfo->dwNumberOfProcessors = 8;
		set_lasterrors(&lasterror);
	}

	LOQ_void("misc", "i", "NumberOfProcessors",
		lpSystemInfo != NULL ? lpSystemInfo->dwNumberOfProcessors : 0);
	return;
        }

        HOOKDEF(BOOL, WINAPI, ProcessIdToSessionId, DWORD dwProcessId, DWORD *pSessionId)
        {
            BOOL ret;
	lasterror_t lasterror;
	int spoofed = 0;

	ret = Old_ProcessIdToSessionId(dwProcessId, pSessionId);

	if (!g_config.no_stealth && pSessionId != NULL) {
		DWORD console_session;

		get_lasterrors(&lasterror);
		console_session = WTSGetActiveConsoleSessionId();
		if (console_session != 0xFFFFFFFF) {
			*pSessionId = console_session;
			ret = TRUE;
			spoofed = 1;
		}
		set_lasterrors(&lasterror);
	}

	LOQ_bool("misc", "ii", "ProcessId", dwProcessId, "Spoofed", spoofed);
	return ret;
        }

        HOOKDEF(void, WINAPI, GetSystemTimePreciseAsFileTime, LPFILETIME lpSystemTimeAsFileTime)
        {
            int ret = 0;
	lasterror_t lasterror;

	Old_GetSystemTimePreciseAsFileTime(lpSystemTimeAsFileTime);

	if (!g_config.no_stealth && lpSystemTimeAsFileTime != NULL &&
		time_skipped.QuadPart > 0) {
		ULARGE_INTEGER u;

		get_lasterrors(&lasterror);
		u.LowPart = lpSystemTimeAsFileTime->dwLowDateTime;
		u.HighPart = lpSystemTimeAsFileTime->dwHighDateTime;
		u.QuadPart += (ULONGLONG)time_skipped.QuadPart;
		lpSystemTimeAsFileTime->dwLowDateTime = u.LowPart;
		lpSystemTimeAsFileTime->dwHighDateTime = u.HighPart;
		set_lasterrors(&lasterror);
	}

	LOQ_void("misc", "");
	return;
        }

        HOOKDEF(BOOL, WINAPI, GetGUIThreadInfo, DWORD idThread, LPGUITHREADINFO lpgui)
        {
            static volatile LONG s_call_count = 0;
	static LONG s_caret_x = 100;
	static LONG s_caret_y = 120;
	BOOL ret;
	lasterror_t lasterror;
	int caret_present = 0;

	ret = Old_GetGUIThreadInfo(idThread, lpgui);

	if (!g_config.no_stealth && lpgui != NULL &&
		lpgui->cbSize == sizeof(GUITHREADINFO)) {
		LONG idx;
		HWND hwnd;

		get_lasterrors(&lasterror);

		idx = InterlockedIncrement(&s_call_count);

		/* A valid foreground-window handle to report as the caret owner. */
		hwnd = GetForegroundWindow();
		if (hwnd == NULL)
			hwnd = GetDesktopWindow();

		/* Rotating ~75% subset carries a blinking caret so the caretPresent
		 * ratio clears the >= 0.10 / 15% floor; on each such sample advance
		 * rcCaret a few pixels so successive reads show caret movement. */
		if ((idx & 3) != 0) {
			s_caret_x += 2;
			s_caret_y += 1;
			if (s_caret_x > 400)
				s_caret_x = 100;
			if (s_caret_y > 400)
				s_caret_y = 120;

			lpgui->hwndCaret = hwnd;
			lpgui->rcCaret.left = s_caret_x;
			lpgui->rcCaret.top = s_caret_y;
			lpgui->rcCaret.right = s_caret_x + 2;
			lpgui->rcCaret.bottom = s_caret_y + 16;
			lpgui->flags |= GUI_CARETBLINKING;
			caret_present = 1;
		}

		/* Keep a plausible interactive foreground/active window so the caret
		 * owner is consistent across samples. */
		if (lpgui->hwndActive == NULL)
			lpgui->hwndActive = hwnd;
		if (lpgui->hwndFocus == NULL)
			lpgui->hwndFocus = hwnd;

		ret = TRUE;
		set_lasterrors(&lasterror);
	}

	LOQ_bool("windows", "ii", "idThread", idThread, "CaretPresent", caret_present);
	return ret;
        }

        HOOKDEF(DWORD, WINAPI, GetClipboardSequenceNumber, VOID)
        {
            static volatile LONG s_seq = 0;
	DWORD ret;
	lasterror_t lasterror;

	ret = Old_GetClipboardSequenceNumber();

	if (!g_config.no_stealth) {
		LONG seq;

		get_lasterrors(&lasterror);

		/* Seed once from the tick count so the forced sequence starts at a
		 * plausible non-zero value, then advance a few units per call so every
		 * poll sees a strictly larger (ever-increasing) sequence number. */
		seq = s_seq;
		if (seq == 0)
			seq = (LONG)(GetTickCount() | 1);
		seq += 3;
		s_seq = seq;
		ret = (DWORD)seq;

		set_lasterrors(&lasterror);
	}

	LOQ_nonzero("windows", "i", "SequenceNumber", ret);
	return ret;
        }

        HOOKDEF(SHORT, WINAPI, GetKeyState, int nVirtKey)
        {
            static volatile LONG s_caps_counter = 0;
	static volatile LONG s_num_counter = 0;
	SHORT ret;
	lasterror_t lasterror;
	int spoofed = 0;

	ret = Old_GetKeyState(nVirtKey);

	if (!g_config.no_stealth &&
		(nVirtKey == VK_CAPITAL || nVirtKey == VK_NUMLOCK)) {
		LONG idx;

		get_lasterrors(&lasterror);

		/* Alternate the low toggle bit per key so each LowLevelKeyboardProc
		 * invocation registers a new transition (0x0001 then 0x0000). */
		idx = (nVirtKey == VK_CAPITAL)
			? InterlockedIncrement(&s_caps_counter)
			: InterlockedIncrement(&s_num_counter);

		/* Preserve the high-order key-down bit; force only the toggle bit. */
		ret = (SHORT)(ret & (SHORT)0xFF00);
		if (idx & 1)
			ret |= (SHORT)0x0001;
		spoofed = 1;

		set_lasterrors(&lasterror);
	}

	LOQ_nonzero("windows", "ii", "nVirtKey", nVirtKey, "Spoofed", spoofed);
	return ret;
        }
