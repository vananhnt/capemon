/*
 * hook_mirage.c — SAGE-generated hook implementations.
 * Auto-regenerated; do not edit by hand.
 */
#include <stdio.h>
#include <string.h>
#include "hooking.h"
#include <tlhelp32.h>
#include <slpublic.h>
#include "log.h"
#include "config.h"

/* Case-insensitive suffix test for ANSI paths: Windows paths compare without
 * regard to case, so a sample probing "C:\Program Files\7-zip" must match the
 * same way the real filesystem would. */
static BOOL mirage_path_ends_with_ascii(LPCSTR path, const char *suffix)
{
	size_t path_len;
	size_t suffix_len;

	if (path == NULL || suffix == NULL)
		return FALSE;

	path_len = strlen(path);
	suffix_len = strlen(suffix);

	if (suffix_len == 0 || path_len < suffix_len)
		return FALSE;

	return _stricmp(path + (path_len - suffix_len), suffix) == 0 ? TRUE : FALSE;
}

        HOOKDEF(BOOL, WINAPI, PathFileExistsA, LPCSTR pszPath)
        {
            BOOL ret;
	lasterror_t lasterror;

	ret = Old_PathFileExistsA(pszPath);

	if (!g_config.no_stealth && !ret && pszPath != NULL &&
			(mirage_path_ends_with_ascii(pszPath, "\\7-Zip") ||
			 mirage_path_ends_with_ascii(pszPath, "\\WinRAR") ||
			 mirage_path_ends_with_ascii(pszPath, "\\WinZip"))) {
		get_lasterrors(&lasterror);

		ret = TRUE;

		set_lasterrors(&lasterror);
	}

	LOQ_bool("misc", "s", "Path", pszPath);
	return ret;
        }

        HOOKDEF(BOOL, WINAPI, PathFileExistsW, LPCWSTR pszPath)
        {
            BOOL ret;
	lasterror_t lasterror;

	ret = Old_PathFileExistsW(pszPath);

	if (!g_config.no_stealth && !ret && pszPath != NULL &&
			(wcsstr(pszPath, L"7-Zip") != NULL ||
			 wcsstr(pszPath, L"WinRAR") != NULL ||
			 wcsstr(pszPath, L"WinZip") != NULL)) {
		get_lasterrors(&lasterror);

		ret = TRUE;

		set_lasterrors(&lasterror);
	}

	LOQ_bool("misc", "u", "Path", pszPath);
	return ret;
        }

        HOOKDEF(VOID, WINAPI, GetNativeSystemInfo, LPSYSTEM_INFO lpSystemInfo)
        {
            int ret = 0;
	lasterror_t lasterror;

	Old_GetNativeSystemInfo(lpSystemInfo);

	get_lasterrors(&lasterror);

	if (!g_config.no_stealth && lpSystemInfo != NULL &&
			lpSystemInfo->dwNumberOfProcessors <= 1) {
		lpSystemInfo->dwNumberOfProcessors = 4;
		ret = 1;
	}

	set_lasterrors(&lasterror);

	LOQ_void("misc", "");
	return;
        }

        HOOKDEF(DWORD, WINAPI, GetEnvironmentVariableA, LPCSTR lpName, LPSTR lpBuffer, DWORD nSize)
        {
            DWORD ret;
	DWORD forced_len;
	lasterror_t lasterror;
	const char *forced_userprofile = "C:\\Users\\jsmith";

	ret = Old_GetEnvironmentVariableA(lpName, lpBuffer, nSize);

	/* Samples read USERPROFILE and concatenate it with the two shell-history
	 * paths they then open:
	 *   %USERPROFILE%\AppData\Roaming\Microsoft\Windows\PowerShell\
	 *       PSReadline\ConsoleHost_history.txt
	 *   %USERPROFILE%\AppData\Local\Microsoft\Windows\cmd.exe\history.txt
	 * A zero return leaves the constructed paths malformed and the check
	 * short-circuits, while a sandbox-flavoured account name in the returned
	 * path (analyst, sandbox, malware, user-with-a-serial-number) is itself an
	 * evasion signal. Hand back a plausible lived-in profile directory so both
	 * paths resolve under an ordinary user account and the companion
	 * GetFileAttributesW / ReadFile hooks can serve them their history content.
	 * The real API's buffer contract is preserved: on a large enough buffer the
	 * path is copied and its length (excluding the terminating null) returned;
	 * otherwise the required size including the null is returned and the buffer
	 * left alone, so the caller reallocates and queries again. */
	if (!g_config.no_stealth && lpName != NULL &&
			!lstrcmpiA(lpName, "USERPROFILE")) {
		get_lasterrors(&lasterror);

		forced_len = (DWORD)strlen(forced_userprofile);

		if (lpBuffer != NULL && nSize > forced_len) {
			memcpy(lpBuffer, forced_userprofile, forced_len + 1);
			ret = forced_len;
		}
		else {
			ret = forced_len + 1;
		}

		/* The real call may have failed with ERROR_ENVVAR_NOT_FOUND; clear it
		 * so a caller checking GetLastError() after our non-zero return sees a
		 * consistent success. */
		lasterror.Win32Error = 0;
		lasterror.NtstatusError = 0;

		set_lasterrors(&lasterror);
	}

	LOQ_nonzero("misc", "s", "Name", lpName);
	return ret;
        }

        HOOKDEF(HRESULT, WINAPI, SLIsGenuineLocal, const SLID* pAppId, SL_GENUINE_STATE* pGenuineState, PVOID pvReserved)
        {
            HRESULT ret;
	lasterror_t lasterror;

	ret = Old_SLIsGenuineLocal(pAppId, pGenuineState, pvReserved);

	/* Samples call SLIsGenuineLocal for the Windows AppId
	 * {55c92734-d682-4d71-983e-d6ec3f16059f} and gate on two things: the
	 * HRESULT must be S_OK (a non-S_OK return aborts the payload outright),
	 * and *pGenuineState must read SL_GEN_STATE_IS_GENUINE (0) for isGenuine
	 * to evaluate true. Any other genuine-state, or an outright call failure,
	 * is treated as an unactivated/throwaway analysis VM. Force the licensing
	 * verdict to look like an activated retail machine: write
	 * SL_GEN_STATE_IS_GENUINE into *pGenuineState and return S_OK so both the
	 * success-but-not-genuine and the outright-failure evasion branches are
	 * neutralised and the sample runs its normal behaviour. */
	if (!g_config.no_stealth) {
		get_lasterrors(&lasterror);

		if (pGenuineState != NULL)
			*pGenuineState = SL_GEN_STATE_IS_GENUINE;
		ret = S_OK;

		set_lasterrors(&lasterror);
	}

	LOQ_hresult("misc", "p", "AppId", pAppId);
	return ret;
        }

        HOOKDEF(VOID, WINAPI, Sleep, DWORD dwMilliseconds)
        {
            int ret = 0;
	DWORD requested = dwMilliseconds;
	lasterror_t lasterror;

	/* Samples take a wall-clock timing sample, call Sleep(~5000ms) as a bare
	 * gating delay, then take a second sample (e.g. GetCursorPos before/after,
	 * or a GetTickCount delta) and rely on the delay actually having elapsed —
	 * the delay is used directly, not compared against a threshold, so a stall
	 * of several seconds per check adds up and either drags the analysis past
	 * its timeout or makes the sample abort if it detects the sleep was skipped
	 * (before == after with no time having passed). Force the real wait to
	 * return immediately by handing Old_Sleep a dwMilliseconds of 0, but advance
	 * capemon's shared faked-time accumulator (time_skipped, kept in NT 100ns
	 * units, which the GetTickCount/GetTickCount64/QueryPerformanceCounter hooks
	 * divide back to milliseconds) by the originally requested interval. A
	 * GetTickCount taken before and after the call therefore still shows a
	 * ~requested-ms elapsed delta, so the sample sees time pass consistently
	 * while the sandbox spends no real time blocked. Lasterror is preserved
	 * around the accumulator update and the forced argument so the shortened
	 * wait leaves no other trace. */
	if (!g_config.no_stealth && requested != 0) {
		get_lasterrors(&lasterror);

		time_skipped.QuadPart += (LONGLONG)requested * 10000;
		dwMilliseconds = 0;

		set_lasterrors(&lasterror);
	}

	Old_Sleep(dwMilliseconds);

	LOQ_void("misc", "i", "Milliseconds", requested);
	return;
        }