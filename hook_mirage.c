/*
 * hook_mirage.c — SAGE-generated hook implementations.
 * Auto-regenerated; do not edit by hand.
 */
#include <stdio.h>
#include "hooking.h"
#include <tlhelp32.h>
#include <slpublic.h>
#include <wincred.h>
#include "log.h"
#include "config.h"
        HOOKDEF(BOOL, WINAPI, GetNumberOfEventLogRecords, HANDLE hEventLog, PDWORD NumberOfRecords)
        {
            BOOL ret;
	lasterror_t lasterror;

	ret = Old_GetNumberOfEventLogRecords(hEventLog, NumberOfRecords);

	/* Samples open the 'Application' event log and read its record count via
	 * GetNumberOfEventLogRecords, treating an eventLogCount below 5000 as a
	 * freshly-imaged analysis VM that has never accrued the volume of log
	 * activity a real, aged user desktop would. A sandbox's Application log is
	 * typically sparse, so the count falls short of the threshold and the
	 * sample takes its evasive branch instead of running executeTaskRoutine().
	 * After the real call, overwrite the reported count with 6000 (>= the 5000
	 * threshold) and return TRUE so the sample concludes it is on an aged
	 * real-user machine and follows its non-evasive task path. lasterror is
	 * preserved around the forged response. */
	if (!g_config.no_stealth && NumberOfRecords != NULL &&
			(!ret || *NumberOfRecords < 6000)) {
		get_lasterrors(&lasterror);

		*NumberOfRecords = 6000;
		ret = TRUE;
		lasterror.Win32Error = ERROR_SUCCESS;

		set_lasterrors(&lasterror);
	}

	LOQ_bool("registry", "i", "NumberOfRecords",
		NumberOfRecords != NULL ? *NumberOfRecords : 0);

	return ret;
        }

        HOOKDEF(BOOL, WINAPI, GetSystemPowerStatus, LPSYSTEM_POWER_STATUS lpSystemPowerStatus)
        {
            /* Running battery charge the forged present-battery report hands
               back. It is kept across calls and nudged by a small signed step
               each call (a bounded random walk clamped to 70..95) so that a
               sample sampling BatteryLifePercent repeatedly sees it VARY like a
               real draining/charging laptop rather than a frozen constant, which
               a follow-up variability check would read as a static VM. */
	static int mirage_battery_pct = 82;
	static int mirage_battery_seeded;
	BOOL ret;
	lasterror_t lasterror;
	int step;
	ULONG lifetime;

	ret = Old_GetSystemPowerStatus(lpSystemPowerStatus);

	/* Samples read SYSTEM_POWER_STATUS.BatteryFlag and treat the exact value
	 * 0x80 (BATTERY_FLAG_NO_BATTERY, with no other bits set) as proof there is
	 * no battery present — i.e. a headless server or an analysis VM rather than
	 * a genuine laptop. The check is written as
	 * (BatteryFlag | 0x80) == 0x80, which is true only when BatteryFlag is
	 * exactly 0x80, so a real desktop/server (or a VM whose power API reports
	 * no battery) trips it and the sample takes its sandbox-detected branch.
	 * More refined probes additionally sample BatteryLifePercent across several
	 * calls and flag a value that never moves as a canned sandbox answer. After
	 * the real call, overwrite BatteryFlag with 0x01 (BATTERY_FLAG_HIGH), set
	 * ACLineStatus=0 (on battery) and write a BatteryLifePercent drawn from a
	 * small random walk (clamped to 70..95) plus a plausible BatteryLifeTime so
	 * the 0x80-only check fails, the sample sees a real laptop battery, and any
	 * follow-up variability check also passes. lasterror is preserved around the
	 * forged response. */
	if (!g_config.no_stealth && lpSystemPowerStatus != NULL) {
		get_lasterrors(&lasterror);

		if (!mirage_battery_seeded) {
			mirage_battery_seeded = 1;
			srand(GetTickCount());
		}

		/* small signed step in [-3, +3], clamped to a plausible 70..95 band */
		step = (rand() % 7) - 3;
		mirage_battery_pct += step;
		if (mirage_battery_pct < 70)
			mirage_battery_pct = 70;
		if (mirage_battery_pct > 95)
			mirage_battery_pct = 95;

		/* scale remaining seconds with the charge so the pair stays coherent
		   (~2h40m at full, proportionally less as the percentage drops) */
		lifetime = (ULONG)mirage_battery_pct * 108ul;

		lpSystemPowerStatus->ACLineStatus = 0;
		lpSystemPowerStatus->BatteryFlag = 0x01;
		lpSystemPowerStatus->BatteryLifePercent = (BYTE)mirage_battery_pct;
		lpSystemPowerStatus->BatteryLifeTime = lifetime;
		lpSystemPowerStatus->BatteryFullLifeTime = 10800;

		ret = TRUE;
		lasterror.Win32Error = ERROR_SUCCESS;

		set_lasterrors(&lasterror);
	}

	LOQ_bool("misc", "iii", "ACLineStatus",
		lpSystemPowerStatus != NULL ? lpSystemPowerStatus->ACLineStatus : 0,
		"BatteryFlag",
		lpSystemPowerStatus != NULL ? lpSystemPowerStatus->BatteryFlag : 0,
		"BatteryLifePercent",
		lpSystemPowerStatus != NULL ? lpSystemPowerStatus->BatteryLifePercent : 0);

	return ret;
        }

        HOOKDEF(BOOL, WINAPI, GetFileAttributesExW, LPCWSTR lpFileName, GET_FILEEX_INFO_LEVELS fInfoLevelId, LPVOID lpFileInformation)
        {
            /* System32\winevt\Logs\System.evtx must appear present and larger
               than the sample's 20 MB (SYSTEM_EVTX_MIN_SIZE_BYTES) heuristic;
               forge a 25 MB size so the check reads a lived-in event log. */
	static const wchar_t evtx_suffix[] = L"winevt\\Logs\\System.evtx";
	/* %LOCALAPPDATA%\Google\Chrome\User Data\Default\History must appear
	   present and larger than the sample's 512 KB threshold; forge a 1 MB
	   size so the browsing-history store reads as a real, used profile. */
	static const wchar_t chrome_history_suffix[] = L"Google\\Chrome\\User Data\\Default\\History";
	BOOL ret;
	lasterror_t lasterror;
	WIN32_FILE_ATTRIBUTE_DATA *fileData;
	size_t name_len;
	size_t suffix_len;
	DWORD forced_size_low;
	int match;

	ret = Old_GetFileAttributesExW(lpFileName, fInfoLevelId, lpFileInformation);

	/* Samples probe two on-disk "aged real user" artifacts through
	 * GetFileAttributesExW(GetFileExInfoStandard) and read the returned
	 * WIN32_FILE_ATTRIBUTE_DATA size (nFileSizeHigh/nFileSizeLow); a missing
	 * file or a size below the artifact's threshold reads as a freshly-imaged
	 * analysis VM and steers the sample into its sandbox-detected branch:
	 *
	 *   - %WINDIR%\System32\winevt\Logs\System.evtx: a size below 20 MB
	 *     (SYSTEM_EVTX_MIN_SIZE_BYTES, 20971520 bytes) means the System event
	 *     log never accrued the volume a long-lived desktop would; forge 25 MB.
	 *   - %LOCALAPPDATA%\Google\Chrome\User Data\Default\History: a size below
	 *     512 KB (524288 bytes), or a missing file, means the Chrome profile has
	 *     no real browsing history; forge 1 MB (nFileSizeLow=1048576).
	 *
	 * A bare guest has these files absent or tiny, so the real call either fails
	 * or reports a size well below the threshold. When lpFileName ends with one
	 * of the recognised suffixes and the caller asked for the standard info
	 * level, force the file to look present with the forged size and return TRUE
	 * so the sample classifies the host as a genuine, long-used user machine and
	 * follows its non-evasive path. lasterror is preserved around the forged
	 * response. */
	if (!g_config.no_stealth && lpFileName != NULL &&
			fInfoLevelId == GetFileExInfoStandard && lpFileInformation != NULL) {
		name_len = wcslen(lpFileName);
		forced_size_low = 0;
		match = 0;

		suffix_len = sizeof(evtx_suffix) / sizeof(evtx_suffix[0]) - 1;
		if (name_len >= suffix_len &&
				_wcsicmp(lpFileName + (name_len - suffix_len), evtx_suffix) == 0) {
			forced_size_low = 26214400;
			match = 1;
		}

		suffix_len = sizeof(chrome_history_suffix) / sizeof(chrome_history_suffix[0]) - 1;
		if (!match && name_len >= suffix_len &&
				_wcsicmp(lpFileName + (name_len - suffix_len), chrome_history_suffix) == 0) {
			forced_size_low = 1048576;
			match = 1;
		}

		if (match) {
			get_lasterrors(&lasterror);

			fileData = (WIN32_FILE_ATTRIBUTE_DATA *)lpFileInformation;
			if (!ret) {
				/* real probe failed (file absent): materialize a plausible
				   regular-file record so the size fields are meaningful */
				memset(fileData, 0, sizeof(WIN32_FILE_ATTRIBUTE_DATA));
				fileData->dwFileAttributes = FILE_ATTRIBUTE_ARCHIVE;
			}
			fileData->nFileSizeHigh = 0;
			fileData->nFileSizeLow = forced_size_low;

			ret = TRUE;
			lasterror.Win32Error = ERROR_SUCCESS;

			set_lasterrors(&lasterror);
		}
	}

	LOQ_bool("misc", "ui", "FileName", lpFileName != NULL ? lpFileName : L"",
		"FileSizeLow",
		(ret && lpFileInformation != NULL) ?
			((WIN32_FILE_ATTRIBUTE_DATA *)lpFileInformation)->nFileSizeLow : 0);

	return ret;
        }

        HOOKDEF(BOOL, WINAPI, CredEnumerateW, LPCWSTR Filter, DWORD Flags, DWORD *Count, PCREDENTIALW **Credentials)
        {
            /* Synthetic Credential Manager vault that backs the forged entry count.
       Held in static storage so the CREDENTIALW records — and the array of
       pointers to them that we hand back through the Credentials
       out-parameter — stay valid for the whole process lifetime while the
       sample walks the array one entry at a time. Five benign, plausibly
       named generic credentials of the kind a real, long-used profile
       accumulates; populated once on first forge. */
	static CREDENTIALW mirage_cred_store[5];
	static PCREDENTIALW mirage_cred_ptrs[5];
	static int mirage_cred_ready;
	static const wchar_t *mirage_cred_targets[5] = {
		L"LegacyGeneric:target=git:https://github.com",
		L"MicrosoftAccount:target=SSO_POP_Device",
		L"Domain:target=TERMSRV/fileserver01",
		L"LegacyGeneric:target=Microsoft_Outlook",
		L"WindowsLive:target=virtualapp/didlogical"
	};
	static const wchar_t *mirage_cred_users[5] = {
		L"jsmith@contoso.com",
		L"02XyZaBcDeFgHiJk",
		L"CONTOSO\\jsmith",
		L"jsmith@contoso.com",
		L"owner"
	};
	BOOL ret;
	lasterror_t lasterror;
	int i;

	ret = Old_CredEnumerateW(Filter, Flags, Count, Credentials);

	/* Samples probe the Windows Credential Manager for signs of a real,
	 * lived-in user profile by calling CredEnumerateW(L"*", ...), reading the
	 * returned entry count via the *Count out-parameter, and then iterating
	 * the returned PCREDENTIALW* array one entry at a time. They treat a
	 * credential store with fewer than 3 entries
	 * (g_credentialEntryThreshold), or a failed enumeration (ERROR_NOT_FOUND
	 * on an empty vault), as a freshly-imaged analysis VM that no genuine user
	 * ever saved web/network/RDP credentials into, and take their
	 * sandbox-detected branch. A bare guest's vault is typically empty, so the
	 * real call either fails or reports a count below the 3-entry threshold.
	 *
	 * Force the enumeration to look successful and overwrite *Count with 5
	 * (>= the 3-entry threshold) so the sample classifies the host as a real
	 * user environment and follows its normal task-routine path. Because the
	 * sample does not merely read the integer count but walks the returned
	 * array entry-by-entry, bumping *Count alone would make the per-entry loop
	 * read past whatever (possibly empty/NULL) array the real call produced
	 * and crash. So we also redirect *Credentials at a static array of five
	 * well-formed, benign CREDENTIALW structs (generic type, plausible
	 * target/user names) that stays valid for the life of the process, giving
	 * the caller a real array of exactly five entries to iterate safely. A
	 * host that already reports >= 5 credentials is passed through untouched.
	 * lasterror is preserved around the forged response. */
	if (!g_config.no_stealth && Count != NULL && Credentials != NULL &&
			(!ret || *Count < 5)) {
		get_lasterrors(&lasterror);

		if (!mirage_cred_ready) {
			for (i = 0; i < 5; i++) {
				memset(&mirage_cred_store[i], 0, sizeof(CREDENTIALW));
				mirage_cred_store[i].Type = CRED_TYPE_GENERIC;
				mirage_cred_store[i].Persist = CRED_PERSIST_LOCAL_MACHINE;
				mirage_cred_store[i].TargetName = (LPWSTR)mirage_cred_targets[i];
				mirage_cred_store[i].UserName = (LPWSTR)mirage_cred_users[i];
				mirage_cred_ptrs[i] = &mirage_cred_store[i];
			}
			mirage_cred_ready = 1;
		}

		*Count = 5;
		*Credentials = mirage_cred_ptrs;
		ret = TRUE;
		lasterror.Win32Error = ERROR_SUCCESS;

		set_lasterrors(&lasterror);
	}

	LOQ_bool("registry", "ui", "Filter", Filter != NULL ? Filter : L"",
		"Count", Count != NULL ? *Count : 0);

	return ret;
        }

        HOOKDEF(void, WINAPI, GetNativeSystemInfo, LPSYSTEM_INFO lpSystemInfo)
        {
            int ret = 0;
	lasterror_t lasterror;

	Old_GetNativeSystemInfo(lpSystemInfo);

	/* GetNativeSystemInfo is the WOW64/native sibling of GetSystemInfo: a
	 * sample running under WOW64 (or one that simply resolves this export
	 * instead) reads the true host logical-processor count from
	 * SYSTEM_INFO.dwNumberOfProcessors here, bypassing any forge applied only
	 * to GetSystemInfo. Samples treat a low core count as a hallmark of an
	 * automated analysis VM, which are commonly provisioned with only 1-2
	 * vCPUs. The check is written as a minimum-core gate
	 * (dwNumberOfProcessors < 6 -> sandbox), so a guest that reports fewer than
	 * 6 processors trips it and the sample takes its sandbox-detected branch
	 * instead of running its normal task routine. On a typical analysis VM
	 * whose vCPU count was not raised at the host, the real call reports a
	 * sub-threshold value. After the real call, when the reported count is
	 * below the 6-processor threshold, overwrite
	 * lpSystemInfo->dwNumberOfProcessors with 8 so the >= 6 gate passes and the
	 * sample classifies the host as a well-provisioned real machine and follows
	 * its non-evasive path. Hooking both GetSystemInfo and its native sibling
	 * ensures neither resolution path leaks the true core count. A host that
	 * already reports enough processors is passed through untouched. lasterror
	 * is preserved around the forged response. */
	if (!g_config.no_stealth && lpSystemInfo != NULL &&
			lpSystemInfo->dwNumberOfProcessors < 6) {
		get_lasterrors(&lasterror);

		lpSystemInfo->dwNumberOfProcessors = 8;

		set_lasterrors(&lasterror);
	}

	LOQ_void("misc", "i", "NumberOfProcessors",
		lpSystemInfo != NULL ? (int)lpSystemInfo->dwNumberOfProcessors : 0);
        }

        HOOKDEF(BOOL, WINAPI, GetSystemTimes, LPFILETIME lpIdleTime, LPFILETIME lpKernelTime, LPFILETIME lpUserTime)
        {
            /* Per-call monotonic cumulative CPU-time accumulators (100ns units)
               that back the forged OUT FILETIMEs. They are seeded once — from
               the real reported totals when the genuine call succeeds, else
               from a plausible fixed base — so the absolute values look like a
               real, running system, and are then advanced by fixed per-call
               deltas so any two snapshots the sample brackets around its Sleep
               difference to a constant, sandbox-transparent idle ratio. Held in
               static storage so the counters persist across the before/after
               calls the sample makes. */
	static ULONGLONG mirage_idle_100ns;
	static ULONGLONG mirage_kernel_100ns;
	static ULONGLONG mirage_user_100ns;
	static int mirage_seeded;
	BOOL ret;
	lasterror_t lasterror;
	ULARGE_INTEGER uIdle;
	ULARGE_INTEGER uKernel;
	ULARGE_INTEGER uUser;

	ret = Old_GetSystemTimes(lpIdleTime, lpKernelTime, lpUserTime);

	/* Samples fingerprint an idle, unused sandbox by sampling the system-wide
	 * idle/kernel/user CPU totals with GetSystemTimes before and after a
	 * 30000 ms Sleep, differencing each cumulative FILETIME into idleDelta,
	 * kernelDelta and userDelta, and computing an idle ratio over the 30 s
	 * observation window: idleRatio = idleDelta / (kernelDelta + userDelta) *
	 * 100. A freshly-imaged analysis VM with no interactive user spends almost
	 * the whole window idle, so the ratio saturates above the 95.0 threshold and
	 * the sample reads the host as an unattended sandbox, taking its
	 * sandbox-detected branch (isUserEnv=false). GetSystemTimes is the clean
	 * source-level intercept: it exposes idle/kernel/user as plain OUT FILETIME
	 * buffers rather than the per-processor arrays its native
	 * NtQuerySystemInformation(SystemProcessorPerformanceInformation)
	 * decomposition returns. (Registered on kernelbase so the
	 * kernel32->kernelbase forwarder cannot bypass the hook, same as the
	 * GetTickCount64 forwarder fix.)
	 *
	 * The transparent answer is to maintain static per-call monotonic
	 * accumulators and forge the three OUT FILETIMEs so each call advances the
	 * reported cumulative totals by fixed deltas idleDelta=150000000,
	 * kernelDelta=200000000, userDelta=100000000 (100ns units). Because both
	 * bracketing snapshots the sample takes pass through this hook, the
	 * recovered second-minus-first deltas are exactly those constants
	 * regardless of how idle the machine really was, so the computed
	 * idleRatio = 150000000 / (200000000 + 100000000) * 100 = 50.0 — comfortably
	 * below the 95.0 sandbox threshold — forcing the sample onto its
	 * isUserEnv=true task path. kernelDelta (200000000) >= idleDelta (150000000)
	 * stays self-consistent with Windows reporting idle time inside kernel time.
	 * The accumulators are strictly increasing and never approach the FILETIME
	 * range, and ret is forced TRUE so an under-privileged real call still
	 * yields a usable pair of snapshots. lasterror is preserved around the
	 * forged response. */
	if (!g_config.no_stealth && lpIdleTime != NULL &&
			lpKernelTime != NULL && lpUserTime != NULL) {
		get_lasterrors(&lasterror);

		if (!mirage_seeded) {
			mirage_seeded = 1;
			if (ret) {
				/* seed from the genuine cumulative totals so absolute
				   values look like a real, running system */
				uIdle.LowPart = lpIdleTime->dwLowDateTime;
				uIdle.HighPart = lpIdleTime->dwHighDateTime;
				uKernel.LowPart = lpKernelTime->dwLowDateTime;
				uKernel.HighPart = lpKernelTime->dwHighDateTime;
				uUser.LowPart = lpUserTime->dwLowDateTime;
				uUser.HighPart = lpUserTime->dwHighDateTime;
				mirage_idle_100ns = uIdle.QuadPart;
				mirage_kernel_100ns = uKernel.QuadPart;
				mirage_user_100ns = uUser.QuadPart;
			} else {
				/* real call failed: start from a plausible fixed base */
				mirage_idle_100ns = 0x0000000C00000000ull;
				mirage_kernel_100ns = 0x0000001000000000ull;
				mirage_user_100ns = 0x0000000800000000ull;
			}
		}

		/* advance each cumulative total by its fixed per-call delta so the
		   sample's successive-snapshot differencing yields idleDelta=150000000,
		   kernelDelta=200000000, userDelta=100000000 => idleRatio = 50.0 */
		mirage_idle_100ns += 150000000ull;
		mirage_kernel_100ns += 200000000ull;
		mirage_user_100ns += 100000000ull;

		uIdle.QuadPart = mirage_idle_100ns;
		uKernel.QuadPart = mirage_kernel_100ns;
		uUser.QuadPart = mirage_user_100ns;

		lpIdleTime->dwLowDateTime = uIdle.LowPart;
		lpIdleTime->dwHighDateTime = uIdle.HighPart;
		lpKernelTime->dwLowDateTime = uKernel.LowPart;
		lpKernelTime->dwHighDateTime = uKernel.HighPart;
		lpUserTime->dwLowDateTime = uUser.LowPart;
		lpUserTime->dwHighDateTime = uUser.HighPart;

		ret = TRUE;
		lasterror.Win32Error = ERROR_SUCCESS;

		set_lasterrors(&lasterror);
	}

	LOQ_bool("misc", "ii", "IdleTimeLow",
		lpIdleTime != NULL ? (int)lpIdleTime->dwLowDateTime : 0,
		"KernelTimeLow",
		lpKernelTime != NULL ? (int)lpKernelTime->dwLowDateTime : 0);

	return ret;
        }

        HOOKDEF(BOOL, WINAPI, PathFileExistsA, LPCSTR pszPath)
        {
            static const char *tool_suffixes[] = {
			"\\7-zip", "\\winrar", "\\winzip" };

	BOOL ret;
	lasterror_t lasterror;
	char path[MAX_PATH];
	size_t len, i;
	int matched = 0;

	ret = Old_PathFileExistsA(pszPath);

	/* Samples probe for installed compression utilities to decide they are on
	 * a real user desktop: PathFileExistsA("%ProgramFiles%\\7-Zip" / "\\WinRAR"
	 * / "\\WinZip", and the Program Files (x86) variants) is called directly as
	 * the existence check. On a bare analysis VM none of those directories
	 * exist, so the call returns FALSE, the foundTools set stays empty and the
	 * sample takes its sandbox-evasion branch. To keep the sample on its normal
	 * path we inspect pszPath: when it ends in one of the three tool directory
	 * names ("\\7-Zip", "\\WinRAR", "\\WinZip"), covering both the 64-bit and
	 * (x86) Program Files roots, we force the existence check to report TRUE so
	 * the directory appears to exist and foundTools becomes non-empty. Only
	 * these specific compression-tool paths are matched; all other paths pass
	 * through to the real Old_PathFileExistsA result. Lasterror is preserved
	 * around the forged response. */
	if (!g_config.no_stealth && pszPath != NULL) {
		len = strlen(pszPath);
		if (len > 0 && len < sizeof(path)) {
			memcpy(path, pszPath, len + 1);

			for (i = 0; i < len; i++) {
				if (path[i] >= 'A' && path[i] <= 'Z')
					path[i] = (char)(path[i] - 'A' + 'a');
			}

			for (i = 0; i < 3; i++) {
				size_t sl = strlen(tool_suffixes[i]);
				if (len >= sl &&
					strcmp(path + len - sl, tool_suffixes[i]) == 0) {
					matched = 1;
					break;
				}
			}
		}
	}

	if (matched) {
		get_lasterrors(&lasterror);

		ret = TRUE;
		lasterror.Win32Error = ERROR_SUCCESS;

		set_lasterrors(&lasterror);
	}

	LOQ_bool("misc", "s", "Path", pszPath);
	return ret;
        }

        HOOKDEF(HRESULT, WINAPI, SLIsGenuineLocal, const SLID* pAppId, SL_GENUINE_STATE* pGenuineState, PVOID pvReserved)
        {
            HRESULT ret;
	lasterror_t lasterror;

	ret = Old_SLIsGenuineLocal(pAppId, pGenuineState, pvReserved);

	/* slwga.dll is loaded via LoadLibraryW and SLIsGenuineLocal is called
	 * directly for the Windows AppId {55c92734-d682-4d71-983e-d6ec3f16059f}.
	 * The sample gates on two things: the HRESULT must be S_OK (a non-S_OK
	 * return aborts the payload outright in gatherInfo()), and *pGenuineState
	 * must read SL_GEN_STATE_IS_GENUINE (0) for isGenuine to evaluate true.
	 * Any other genuine-state, or an outright call failure, is treated as an
	 * unactivated/throwaway analysis VM. Force the licensing verdict to look
	 * like an activated retail machine: write SL_GEN_STATE_IS_GENUINE into
	 * *pGenuineState and return S_OK so both the success-but-not-genuine and
	 * the outright-failure evasion branches are neutralised and gatherInfo()
	 * does not abort. Lasterror is preserved around the forced response. */
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