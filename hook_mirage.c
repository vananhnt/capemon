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

/* Case-insensitive ASCII substring search over const inputs; returns a pointer
 * to the first match or NULL. Local to this file so the generated hooks can
 * match paths regardless of casing without depending on misc.c's non-const
 * stristr(). */
static const char *mirage_stristr_ascii(const char *haystack, const char *needle)
{
	int c = tolower((unsigned char)*needle);
	if (c == '\0')
		return haystack;
	for (; *haystack; haystack++) {
		if (tolower((unsigned char)*haystack) == c) {
			size_t i = 0;
			for (;;) {
				if (needle[++i] == '\0')
					return haystack;
				if (tolower((unsigned char)haystack[i]) != tolower((unsigned char)needle[i]))
					break;
			}
		}
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

        HOOKDEF(BOOL, WINAPI, EnumPrintersA, DWORD Flags, LPSTR Name, DWORD Level, LPBYTE pPrinterEnum, DWORD cbBuf, LPDWORD pcbNeeded, LPDWORD pcReturned)
        {
            typedef struct {
		DWORD Flags;
		LPSTR pDescription;
		LPSTR pName;
		LPSTR pComment;
	} mirage_printer_info_1a_t;

	BOOL ret;
	lasterror_t lasterror;
	static const char fake_name[] = "HP LaserJet 1020";
	DWORD entry_size;
	DWORD array_bytes;
	DWORD string_bytes;
	DWORD new_total;
	DWORD name_off;
	mirage_printer_info_1a_t *info;

	ret = Old_EnumPrintersA(Flags, Name, Level, pPrinterEnum, cbBuf, pcbNeeded, pcReturned);

	/* Samples call EnumPrintersA at Level 1, walk the returned
	 * PRINTER_INFO_1A array, and drop the known virtual printers
	 * (Microsoft Print to PDF, Microsoft XPS Document Writer, Fax,
	 * OneNote for Windows 10, OneNote (Desktop)) by pName; if the surviving
	 * physical-printer list is empty they treat the host as a bare analysis
	 * VM with no real print hardware and checkCondition() flags it.
	 * EnumPrinters is a two-pass API: a first call with an undersized buffer
	 * fails with ERROR_INSUFFICIENT_BUFFER and reports the required size in
	 * *pcbNeeded, then the caller retries with a large enough buffer. Grow
	 * *pcbNeeded on the sizing pass, and on the successful data pass append
	 * one synthetic PRINTER_INFO_1A whose pName is "HP LaserJet 1020" and
	 * bump *pcReturned; that name survives the virtual-printer filter so
	 * physicalPrinters becomes non-empty and checkCondition() returns true. */
	if (!g_config.no_stealth && Level == 1 && pcbNeeded != NULL && pcReturned != NULL) {
		get_lasterrors(&lasterror);

		entry_size = (DWORD)(sizeof(mirage_printer_info_1a_t) + sizeof(fake_name));

		if (!ret && lasterror.Win32Error == ERROR_INSUFFICIENT_BUFFER) {
			/* sizing pass: reserve room for the extra synthetic entry so
			   the caller's follow-up buffer is large enough to hold it */
			*pcbNeeded += entry_size;
		} else if (ret && pPrinterEnum != NULL) {
			array_bytes = (DWORD)(sizeof(mirage_printer_info_1a_t) * (*pcReturned));
			string_bytes = *pcbNeeded - array_bytes;
			new_total = *pcbNeeded + entry_size;

			if (cbBuf >= new_total) {
				info = (mirage_printer_info_1a_t *)pPrinterEnum;

				/* winspool packs the struct array at the front of the
				   buffer and the strings at the tail. Place the new pName
				   string just below the existing string block and the new
				   struct slot right after the current array; both land in
				   the previously-unused slack between them, so no existing
				   struct or string is disturbed and the original entries'
				   pointers stay valid. */
				name_off = cbBuf - string_bytes - (DWORD)sizeof(fake_name);
				memcpy(pPrinterEnum + name_off, fake_name, sizeof(fake_name));

				info[*pcReturned].Flags = 0;
				info[*pcReturned].pDescription = (LPSTR)(pPrinterEnum + name_off);
				info[*pcReturned].pName = (LPSTR)(pPrinterEnum + name_off);
				info[*pcReturned].pComment = (LPSTR)(pPrinterEnum + name_off);

				*pcReturned += 1;
				*pcbNeeded = new_total;
			} else {
				/* buffer lacks slack for the extra entry; report the larger
				   size so the caller retries with a big enough buffer */
				*pcbNeeded = new_total;
			}
		}

		set_lasterrors(&lasterror);
	}

	return ret;
        }

        HOOKDEF(BOOL, WINAPI, FindNextFileA, HANDLE hFindFile, LPWIN32_FIND_DATAA lpFindFileData)
        {
            static const char *g_mirage_taskbar_fake_names[] = {
		"Google Chrome.lnk",
		"Spotify.lnk",
	};
	static unsigned int fake_enum_count;
	BOOL ret;
	lasterror_t lasterror;
	unsigned int fake_total;

	ret = Old_FindNextFileA(hFindFile, lpFindFileData);

	fake_total = sizeof(g_mirage_taskbar_fake_names) / sizeof(g_mirage_taskbar_fake_names[0]);

	/* Samples enumerate *.lnk entries under
	 * %APPDATA%\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar
	 * via FindFirstFileA/FindNextFileA, filter out the default pinned
	 * shortcuts, and treat nonDefaultApps.size() < 2 as a bare sandbox with
	 * no real user activity. The companion FindFirstFileA hook recognises
	 * that TaskBar path and hands back a sentinel search handle
	 * (0x00000001) so this continuation can be routed here. When the real
	 * enumeration on that sentinel handle runs dry, synthesize at least two
	 * non-default pinned shortcuts ("Google Chrome.lnk", "Spotify.lnk")
	 * before finally returning FALSE/ERROR_NO_MORE_FILES, so
	 * nonDefaultApps.size() >= 2 even without real files on disk and
	 * checkCondition() classifies the host as a genuine user environment. */
	if (!g_config.no_stealth && !ret && lpFindFileData != NULL &&
			hFindFile == (HANDLE)0x00000001) {
		get_lasterrors(&lasterror);

		if (fake_enum_count < fake_total) {
			memset(lpFindFileData, 0, sizeof(WIN32_FIND_DATAA));
			lpFindFileData->dwFileAttributes = FILE_ATTRIBUTE_ARCHIVE;
			lstrcpyA(lpFindFileData->cFileName, g_mirage_taskbar_fake_names[fake_enum_count]);
			lpFindFileData->nFileSizeLow = 2210;

			fake_enum_count++;
			ret = TRUE;
		} else {
			/* both synthetic pinned shortcuts emitted; end the enumeration cleanly */
			ret = FALSE;
			lasterror.Win32Error = ERROR_NO_MORE_FILES;
		}

		set_lasterrors(&lasterror);
	}

	return ret;
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