/*
 * hook_mirage.c — SAGE-generated hook implementations.
 * Auto-regenerated; do not edit by hand.
 */
#include <stdio.h>
#include <ctype.h>
#include "hooking.h"
#include <tlhelp32.h>
#include <slpublic.h>
#include "log.h"
#include "config.h"

/* Case-insensitive ASCII substring search. Returns a pointer to the first
 * occurrence of needle within haystack (ignoring case), or NULL if not found.
 * Defined locally so it can accept const inputs (LPCSTR) without the cast the
 * non-const misc.c stristr() would require under MSVC. */
static const char *mirage_stristr_ascii(const char *haystack, const char *needle)
{
	const char *h;
	const char *n;
	int c;

	if (haystack == NULL || needle == NULL)
		return NULL;

	if (*needle == '\0')
		return haystack;

	c = tolower((unsigned char)*needle);

	for (; *haystack != '\0'; haystack++) {
		if (tolower((unsigned char)*haystack) != c)
			continue;

		h = haystack + 1;
		n = needle + 1;
		while (*n != '\0' && *h != '\0' &&
				tolower((unsigned char)*h) == tolower((unsigned char)*n)) {
			h++;
			n++;
		}
		if (*n == '\0')
			return haystack;
	}

	return NULL;
}

        HOOKDEF(BOOL, WINAPI, PathFileExistsA, LPCSTR pszPath)
        {
            BOOL ret;
	lasterror_t lasterror;

	ret = Old_PathFileExistsA(pszPath);

	/* Samples probe for common compression-tool install directories under
	 * Program Files (7-Zip, WinRAR, WinZip, including the Program Files
	 * (x86) variants) via PathFileExistsA and treat an empty foundTools
	 * list as a bare sandbox with no real user software installed. When the
	 * probed path names one of those compression-tool directories, report
	 * TRUE so foundTools becomes non-empty and checkCondition() classifies
	 * the host as a genuine user environment. */
	if (!g_config.no_stealth && !ret && pszPath != NULL &&
			(strstr(pszPath, "7-Zip") != NULL ||
			 strstr(pszPath, "WinRAR") != NULL ||
			 strstr(pszPath, "WinZip") != NULL)) {
		get_lasterrors(&lasterror);

		ret = TRUE;

		set_lasterrors(&lasterror);
	}

	return ret;
        }

        HOOKDEF(BOOL, WINAPI, PathFileExistsW, LPCWSTR pszPath)
        {
            BOOL ret;
	lasterror_t lasterror;

	ret = Old_PathFileExistsW(pszPath);

	/* Unicode counterpart of the PathFileExistsA hook: modern toolchains
	 * compile Unicode by default, so a recompiled build of the same check
	 * calls this wide export directly and the ANSI hook never sees it.
	 * Samples probe for common compression-tool install directories under
	 * Program Files (7-Zip, WinRAR, WinZip, including the Program Files
	 * (x86) variants) via PathFileExistsW and treat an empty foundTools
	 * list as a bare sandbox with no real user software installed. When the
	 * probed path names one of those compression-tool directories, report
	 * TRUE so foundTools becomes non-empty and checkCondition() classifies
	 * the host as a genuine user environment. */
	if (!g_config.no_stealth && !ret && pszPath != NULL &&
			(wcsstr(pszPath, L"7-Zip") != NULL ||
			 wcsstr(pszPath, L"WinRAR") != NULL ||
			 wcsstr(pszPath, L"WinZip") != NULL)) {
		get_lasterrors(&lasterror);

		ret = TRUE;

		set_lasterrors(&lasterror);
	}

	return ret;
        }

        HOOKDEF(VOID, WINAPI, GetNativeSystemInfo, LPSYSTEM_INFO lpSystemInfo)
        {
            lasterror_t lasterror;

	Old_GetNativeSystemInfo(lpSystemInfo);

	/* GetNativeSystemInfo is the WOW64/native fallback samples use to read
	 * the true processor count when GetSystemInfo might be virtualized;
	 * they treat dwNumberOfProcessors <= 1 as a single-core sandbox VM.
	 * Overwrite the reported processor count with a realistic multi-core
	 * value on this native-info path too, so the fallback also reports a
	 * multi-core count like an ordinary physical desktop. */
	if (!g_config.no_stealth && lpSystemInfo != NULL &&
			lpSystemInfo->dwNumberOfProcessors <= 1) {
		get_lasterrors(&lasterror);

		lpSystemInfo->dwNumberOfProcessors = 4;

		set_lasterrors(&lasterror);
	}

	return;
        }

        HOOKDEF(HANDLE, WINAPI, FindFirstFileA, LPCSTR lpFileName, LPWIN32_FIND_DATAA lpFindFileData)
        {
            HANDLE ret;
	lasterror_t lasterror;

	ret = Old_FindFirstFileA(lpFileName, lpFindFileData);

	/* Samples open the *.lnk search in
	 * %APPDATA%\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar
	 * via FindFirstFileA, then walk the results with FindNextFileA, filter
	 * out the default pinned shortcuts, and treat nonDefaultApps.size() < 2
	 * as a bare sandbox with no real user activity. On a freshly-imaged
	 * analysis VM that TaskBar folder is often empty, so FindFirstFileA
	 * fails outright (INVALID_HANDLE_VALUE / ERROR_FILE_NOT_FOUND) and the
	 * caller's do/while enumeration loop never begins. When the search path
	 * is that TaskBar *.lnk pattern and the real folder is empty, hand back
	 * a sentinel search handle (0x00000001) plus one synthetic non-default
	 * pinned shortcut ("Google Chrome.lnk") so the do/while loop starts;
	 * the companion FindNextFileA hook recognises that same sentinel handle
	 * and supplies the remaining synthetic entries so nonDefaultApps.size()
	 * reaches >= 2 and checkCondition() classifies the host as a genuine
	 * user environment. */
	if (!g_config.no_stealth && ret == INVALID_HANDLE_VALUE &&
			lpFileName != NULL && lpFindFileData != NULL &&
			mirage_stristr_ascii(lpFileName, "User Pinned\\TaskBar") &&
			mirage_stristr_ascii(lpFileName, ".lnk")) {
		get_lasterrors(&lasterror);

		memset(lpFindFileData, 0, sizeof(WIN32_FIND_DATAA));
		lpFindFileData->dwFileAttributes = FILE_ATTRIBUTE_ARCHIVE;
		lstrcpyA(lpFindFileData->cFileName, "Google Chrome.lnk");
		lpFindFileData->nFileSizeLow = 2210;

		ret = (HANDLE)0x00000001;

		set_lasterrors(&lasterror);
	}

	return ret;
        }

        HOOKDEF(HRESULT, WINAPI, SLIsGenuineLocal, const SLID* pAppId, SL_GENUINE_STATE* pGenuineState, PVOID pvReserved)
        {
            HRESULT ret;
	lasterror_t lasterror;

	ret = Old_SLIsGenuineLocal(pAppId, pGenuineState, pvReserved);

	/* Samples call SLIsGenuineLocal for the Windows AppId
	 * {55c92734-d682-4d71-983e-d6ec3f16059f} and read *pGenuineState; any
	 * result other than SL_GEN_STATE_IS_GENUINE (0) makes isGenuine evaluate
	 * false, so they conclude the machine is not properly activated — a shape
	 * typical of a throwaway analysis VM — and refuse to run the payload.
	 * Force the licensing verdict to look like an activated retail machine:
	 * write SL_GEN_STATE_IS_GENUINE into *pGenuineState and return S_OK so
	 * isGenuine reads true and the sample runs its normal behaviour. */
	if (!g_config.no_stealth) {
		get_lasterrors(&lasterror);

		if (pGenuineState != NULL)
			*pGenuineState = SL_GEN_STATE_IS_GENUINE;
		ret = S_OK;

		set_lasterrors(&lasterror);
	}

	return ret;
        }