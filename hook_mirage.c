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