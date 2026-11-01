/*
 * hook_mirage.c — SAGE-generated hook implementations.
 * Auto-regenerated; do not edit by hand.
 */
#include <stdio.h>
#include "hooking.h"
#include <tlhelp32.h>
#include <slpublic.h>
#include "log.h"
#include "config.h"
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
