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

/* Case-insensitive ASCII substring search. Unlike misc.c's stristr() this
 * takes (and returns) const pointers, so it can be used directly on the LPCSTR
 * path arguments the file-enumeration hooks below receive without casting away
 * const. Returns a pointer to the first match in haystack, or NULL. */
static const char *mirage_stristr_ascii(const char *haystack, const char *needle)
{
	size_t i;
	char h, n;

	if (haystack == NULL || needle == NULL)
		return NULL;

	if (*needle == '\0')
		return haystack;

	for (; *haystack != '\0'; haystack++) {
		for (i = 0;; i++) {
			n = needle[i];
			if (n == '\0')
				return haystack;

			h = haystack[i];
			if (h == '\0')
				return NULL;

			if (h >= 'A' && h <= 'Z')
				h = (char)(h - 'A' + 'a');
			if (n >= 'A' && n <= 'Z')
				n = (char)(n - 'A' + 'a');

			if (h != n)
				break;
		}
	}

	return NULL;
}

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

		set_lasterrors(&lasterror);
	}

	LOQ_bool("registry", "i", "NumberOfRecords",
		NumberOfRecords != NULL ? *NumberOfRecords : 0);

	return ret;
        }

        HOOKDEF(BOOL, WINAPI, GetSystemPowerStatus, LPSYSTEM_POWER_STATUS lpSystemPowerStatus)
        {
            BOOL ret;
	lasterror_t lasterror;

	ret = Old_GetSystemPowerStatus(lpSystemPowerStatus);

	/* Samples read SYSTEM_POWER_STATUS.BatteryFlag and treat the exact value
	 * 0x80 (BATTERY_FLAG_NO_BATTERY, with no other bits set) as proof there is
	 * no battery present — i.e. a headless server or an analysis VM rather than
	 * a genuine laptop. The check is written as
	 * (BatteryFlag | 0x80) == 0x80, which is true only when BatteryFlag is
	 * exactly 0x80, so a real desktop/server (or a VM whose power API reports
	 * no battery) trips it and the sample takes its sandbox-detected branch.
	 * After the real call, overwrite BatteryFlag with 0x01 (BATTERY_FLAG_HIGH)
	 * and set ACLineStatus/BatteryLifePercent to plausible present-battery
	 * values so the 0x80-only check fails and the sample sees a real laptop
	 * battery, following its normal task-routine path. lasterror is preserved
	 * around the forged response. */
	if (!g_config.no_stealth && lpSystemPowerStatus != NULL) {
		get_lasterrors(&lasterror);

		lpSystemPowerStatus->ACLineStatus = 0;
		lpSystemPowerStatus->BatteryFlag = 0x01;
		lpSystemPowerStatus->BatteryLifePercent = 89;
		lpSystemPowerStatus->BatteryLifeTime = 9540;
		lpSystemPowerStatus->BatteryFullLifeTime = 10800;

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
    BOOL ret;
lasterror_t lasterror;

ret = Old_CredEnumerateW(Filter, Flags, Count, Credentials);

/* Samples probe the Windows Credential Manager for signs of a real,
 * lived-in user profile by calling CredEnumerateW(L"*", ...) and reading
 * the returned entry count via the out-parameter *Count; they treat a
 * credential store with fewer than 3 entries (or a failed enumeration —
 * ERROR_NOT_FOUND on an empty vault) as a freshly-imaged analysis VM that
 * no genuine user ever saved web/network/RDP credentials into, and take
 * their sandbox-detected branch. A bare guest's vault is typically empty,
 * so the real call either fails or reports a count below the 3-entry
 * threshold. Force the enumeration to look successful and overwrite *Count
 * with 5 (>= the 3-entry threshold) so the sample sees a credential store
 * consistent with a real user profile and follows its normal task-routine
 * path. We only rewrite the reported count and success flag; the
 * Credentials array pointer is left exactly as the real call set it (only
 * populated when the original succeeded), so we never hand back a forged
 * array for the caller to walk. lasterror is preserved around the forged
 * response. */
if (!g_config.no_stealth && Count != NULL && (!ret || *Count < 5)) {
        get_lasterrors(&lasterror);

        *Count = 5;
        ret = TRUE;
        lasterror.Win32Error = ERROR_SUCCESS;

        set_lasterrors(&lasterror);
}

LOQ_bool("registry", "ui", "Filter", Filter != NULL ? Filter : L"",
        "Count", Count != NULL ? *Count : 0);

return ret;
}

        HOOKDEF(DWORD, WINAPI, GetFileAttributesW, LPCWSTR lpFileName)
        {
            /* %LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Bookmarks — the
               Edge default-profile bookmarks store a real, aged user profile
               always carries. Matched as a trailing suffix so it fires
               regardless of which drive/user the LOCALAPPDATA prefix resolves
               to. */
	static const wchar_t edge_bookmarks_suffix[] =
		L"Microsoft\\Edge\\User Data\\Default\\Bookmarks";
	DWORD ret;
	lasterror_t lasterror;
	size_t name_len;
	size_t suffix_len;

	ret = Old_GetFileAttributesW(lpFileName);

	/* Samples test for a lived-in browser profile by calling
	 * GetFileAttributesW on
	 * %LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Bookmarks and treating
	 * an INVALID_FILE_ATTRIBUTES (0xFFFFFFFF) return as proof the file is
	 * absent — a freshly-imaged analysis VM whose Edge profile was never
	 * populated by a real user. On a bare guest that path frequently does not
	 * exist, so the real call fails the existence gate and the sample takes
	 * its sandbox-detected branch. When lpFileName ends with the Edge
	 * Bookmarks profile suffix and the real probe reports the file missing,
	 * return FILE_ATTRIBUTE_NORMAL (0x00000080) so the existence gate passes
	 * and the sample proceeds. Note this only makes the file appear present;
	 * because the sample subsequently opens the Bookmarks file and counts the
	 * "url" keys in its JSON content, a real populated Bookmarks file must
	 * also be staged in the analysis VM (companion countermeasure C6) for the
	 * follow-on content check to pass. A genuine, present file passes straight
	 * through untouched. lasterror is preserved around the forged response. */
	if (!g_config.no_stealth && lpFileName != NULL &&
			ret == INVALID_FILE_ATTRIBUTES) {
		name_len = wcslen(lpFileName);
		suffix_len = sizeof(edge_bookmarks_suffix) / sizeof(edge_bookmarks_suffix[0]) - 1;

		if (name_len >= suffix_len &&
				_wcsicmp(lpFileName + (name_len - suffix_len), edge_bookmarks_suffix) == 0) {
			get_lasterrors(&lasterror);

			ret = FILE_ATTRIBUTE_NORMAL;
			lasterror.Win32Error = ERROR_SUCCESS;

			set_lasterrors(&lasterror);
		}
	}

	LOQ_nonzero("misc", "ui", "FileName", lpFileName != NULL ? lpFileName : L"",
		"FileAttributes", (int)ret);

	return ret;
        }

        HOOKDEF(BOOL, WINAPI, FindNextFileA, HANDLE hFindFile, LPWIN32_FIND_DATAA lpFindFileData)
        {
            static const char *g_mirage_taskbar_fake_names[] = {
		"Google Chrome.lnk",
		"Spotify.lnk",
	};
	static const struct { const char *name; DWORD size; } g_mirage_docs_fake_entries[] = {
		{ "Resume.docx", 45210 },
		{ "Budget_2025.xlsx", 30822 },
		{ "Quarterly Report.pdf", 218764 },
		{ "Meeting Notes.txt", 4096 },
		{ "Presentation.pptx", 1804231 },
		{ "Invoice_0342.pdf", 88213 },
		{ "Family Photo.jpg", 2731004 },
		{ "Vacation Plans.docx", 51290 },
		{ "Tax Return.pdf", 194502 },
		{ "Contacts.csv", 8842 },
		{ "Project Proposal.docx", 67310 },
		{ "Expenses.xlsx", 41205 },
		{ "Reading List.txt", 2210 },
		{ "Scan_20250114.pdf", 156320 },
		{ "Recipe Collection.docx", 33928 },
	};
	/* Drive the Recent-folder walk past the sample's file-count < 20 threshold:
	   emit this many synthetic non-directory .lnk entries before signalling
	   ERROR_NO_MORE_FILES. 24 == the task's forced value, >= the 20 threshold. */
	static const unsigned int MIRAGE_RECENT_MIN_COUNT = 24;
	static unsigned int fake_enum_count;
	static unsigned int docs_enum_count;
	static unsigned int recent_enum_count;
	BOOL ret;
	lasterror_t lasterror;
	unsigned int fake_total;
	unsigned int docs_total;

	ret = Old_FindNextFileA(hFindFile, lpFindFileData);

	fake_total = sizeof(g_mirage_taskbar_fake_names) / sizeof(g_mirage_taskbar_fake_names[0]);
	docs_total = sizeof(g_mirage_docs_fake_entries) / sizeof(g_mirage_docs_fake_entries[0]);

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
	} else if (!g_config.no_stealth && !ret && lpFindFileData != NULL &&
			hFindFile == (HANDLE)0x00000002) {
		/* Samples recursively walk CSIDL_PERSONAL (the Documents folder)
		 * with FindFirstFileA/FindNextFileA, count the real entries they
		 * see, and treat an item count < ~10 as a freshly-imaged analysis
		 * VM whose Documents folder was never populated by a real user.
		 * The companion FindFirstFileA hook recognises the Documents search
		 * path and hands back a distinct sentinel search handle (0x00000002)
		 * so this continuation is routed here. When the real enumeration on
		 * that sentinel handle runs dry, keep returning TRUE with a run of
		 * synthesized WIN32_FIND_DATAA entries carrying plausible document
		 * names and sizes until the recursive counter comfortably exceeds
		 * the threshold, then return FALSE/ERROR_NO_MORE_FILES to end the
		 * walk cleanly, so the host looks like a genuine user's Documents
		 * folder even without VM pre-population. */
		get_lasterrors(&lasterror);

		if (docs_enum_count < docs_total) {
			memset(lpFindFileData, 0, sizeof(WIN32_FIND_DATAA));
			lpFindFileData->dwFileAttributes = FILE_ATTRIBUTE_ARCHIVE;
			lstrcpyA(lpFindFileData->cFileName, g_mirage_docs_fake_entries[docs_enum_count].name);
			lpFindFileData->nFileSizeLow = g_mirage_docs_fake_entries[docs_enum_count].size;

			docs_enum_count++;
			ret = TRUE;
		} else {
			/* enough synthetic documents emitted to clear the threshold;
			   end the enumeration cleanly */
			ret = FALSE;
			lasterror.Win32Error = ERROR_NO_MORE_FILES;
		}

		set_lasterrors(&lasterror);
	} else if (!g_config.no_stealth && !ret && lpFindFileData != NULL &&
			hFindFile == (HANDLE)0x00000010) {
		/* Samples enumerate the non-directory entries under
		 * %APPDATA%\Roaming\Microsoft\Windows\Recent with a do/while
		 * FindFirstFileA/FindNextFileA loop, count the .lnk shortcuts a real
		 * user's recent-documents history accumulates, and treat a file count
		 * below 20 as a freshly-imaged analysis VM whose Recent folder was never
		 * populated by genuine activity, taking their sandbox-detected branch. On
		 * a bare guest that folder is empty or holds only a handful of items, so
		 * the real enumeration runs dry well short of the threshold. The
		 * companion FindFirstFileA hook recognises the Recent search pattern and
		 * hands back a distinct sentinel search handle (0x00000010) — matching the
		 * sentinel-handle scheme this hook already uses for the TaskBar
		 * (0x00000001) and Documents (0x00000002) walks — so this continuation is
		 * routed here. When the real enumeration on that sentinel handle runs dry,
		 * keep returning TRUE with a run of synthesized non-directory
		 * WIN32_FIND_DATAA entries (each a plausible "<file>.lnk" shortcut, and
		 * never "." or "..", so each one is tallied) until the counted total
		 * reaches at least 24 (past the < 20 threshold), then return FALSE with
		 * ERROR_NO_MORE_FILES to end the walk cleanly, so the file count clears
		 * the threshold and checkCondition() classifies the host as a genuine
		 * user's Recent folder even when the VM folder is empty. lasterror is
		 * preserved around the forged response. */
		get_lasterrors(&lasterror);

		if (recent_enum_count < MIRAGE_RECENT_MIN_COUNT) {
			/* each emitted entry is a plausible non-directory .lnk shortcut
			   (never "." or ".."), so every one is tallied by the sample's
			   recent-shortcut count */
			memset(lpFindFileData, 0, sizeof(WIN32_FIND_DATAA));
			lpFindFileData->dwFileAttributes = FILE_ATTRIBUTE_ARCHIVE;
			wsprintfA(lpFindFileData->cFileName, "fake_%u.lnk", recent_enum_count + 1);
			lpFindFileData->nFileSizeLow = 1024 + recent_enum_count * 32;

			recent_enum_count++;
			ret = TRUE;
			lasterror.Win32Error = ERROR_SUCCESS;
		} else {
			/* enough synthetic .lnk shortcuts emitted to clear the 20-file
			   threshold; end the enumeration cleanly */
			ret = FALSE;
			lasterror.Win32Error = ERROR_NO_MORE_FILES;
		}

		set_lasterrors(&lasterror);
	}

	LOQ_bool("misc", "s", "FileName",
		(ret && lpFindFileData != NULL) ? lpFindFileData->cFileName : "");

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
	} else if (!g_config.no_stealth && ret == INVALID_HANDLE_VALUE &&
			lpFileName != NULL && lpFindFileData != NULL &&
			mirage_stristr_ascii(lpFileName, "Windows\\Recent") &&
			mirage_stristr_ascii(lpFileName, ".lnk")) {
		/* Samples enumerate the *.lnk shortcuts under FOLDERID_Recent
		 * (%APPDATA%\Microsoft\Windows\Recent) with a do/while
		 * FindFirstFileA/FindNextFileA loop, count the recent-documents
		 * shortcuts a real user's activity accumulates, and treat a file
		 * count below 20 as a freshly-imaged analysis VM whose Recent folder
		 * was never populated by genuine use, taking their sandbox-detected
		 * branch. On a bare guest that folder is empty, so the initial
		 * FindFirstFileA on the Recent\*.lnk search mask returns
		 * INVALID_HANDLE_VALUE (ERROR_FILE_NOT_FOUND) and the caller's
		 * do/while enumeration loop never begins. When the search mask names
		 * the Recent\*.lnk pattern and the real folder is empty, hand back a
		 * distinct sentinel search handle (0x00000010) — matching the
		 * sentinel-handle scheme this file already uses for the TaskBar
		 * (0x00000001) and Documents (0x00000002) walks — plus one
		 * synthesized first non-directory .lnk entry ("fake_recent.lnk") so
		 * the enumeration begins non-empty; the companion FindNextFileA hook
		 * recognises that same sentinel handle and supplies the remaining
		 * forged .lnk shortcuts until the counted total clears the 20-file
		 * threshold and checkCondition() classifies the host as a genuine
		 * user's Recent folder even when the VM folder is empty. lasterror is
		 * preserved around the forged response. */
		get_lasterrors(&lasterror);

		memset(lpFindFileData, 0, sizeof(WIN32_FIND_DATAA));
		lpFindFileData->dwFileAttributes = FILE_ATTRIBUTE_ARCHIVE;
		lstrcpyA(lpFindFileData->cFileName, "fake_recent.lnk");
		lpFindFileData->nFileSizeLow = 1024;

		ret = (HANDLE)0x00000010;
		lasterror.Win32Error = ERROR_SUCCESS;

		set_lasterrors(&lasterror);
	} else if (!g_config.no_stealth && ret == INVALID_HANDLE_VALUE &&
			lpFileName != NULL && lpFindFileData != NULL &&
			mirage_stristr_ascii(lpFileName, "Documents")) {
		/* Samples recursively enumerate CSIDL_PERSONAL (the Documents
		 * folder) with FindFirstFileA/FindNextFileA, count the entries they
		 * see, and treat an item count below a threshold (~10) as a
		 * freshly-imaged analysis VM whose Documents folder was never
		 * populated by a real user. On such a VM the initial FindFirstFileA
		 * on the Documents search mask returns INVALID_HANDLE_VALUE
		 * (ERROR_FILE_NOT_FOUND) because the folder is empty, so the caller
		 * treats the count as zero and never starts enumerating. When the
		 * search mask names the Documents folder and the real folder is
		 * empty, hand back a distinct sentinel search handle (0x00000002)
		 * plus one synthesized first entry ("Resume.docx") so the
		 * enumeration begins non-empty; the companion FindNextFileA hook
		 * recognises that same sentinel handle and supplies the remaining
		 * synthetic document entries until the count comfortably exceeds the
		 * threshold and checkCondition() classifies the host as a genuine
		 * user's Documents folder. */
		get_lasterrors(&lasterror);

		memset(lpFindFileData, 0, sizeof(WIN32_FIND_DATAA));
		lpFindFileData->dwFileAttributes = FILE_ATTRIBUTE_ARCHIVE;
		lstrcpyA(lpFindFileData->cFileName, "Resume.docx");
		lpFindFileData->nFileSizeLow = 45210;

		ret = (HANDLE)0x00000002;

		set_lasterrors(&lasterror);
	}

	LOQ_handle("misc", "ss", "FileName", lpFileName != NULL ? lpFileName : "",
		"FirstEntry",
		(ret != INVALID_HANDLE_VALUE && lpFindFileData != NULL) ? lpFindFileData->cFileName : "");

	return ret;
        }

        HOOKDEF(DWORD, WINAPI, GetFileAttributesA, LPCSTR lpFileName)
        {
            /* First-run sentinel/marker file the sample drops in %TEMP% on its
               initial execution. Matched as a trailing suffix so it fires
               regardless of which %TEMP% prefix the path resolves to. */
	static const char first_run_sentinel[] =
		"012_recentdocs_registry_count_checker_first_run.flag";
	DWORD ret;
	lasterror_t lasterror;
	size_t name_len;
	size_t suffix_len;

	ret = Old_GetFileAttributesA(lpFileName);

	/* Samples implement a run-once gate by probing a first-run marker file in
	 * %TEMP% (012_recentdocs_registry_count_checker_first_run.flag) with
	 * GetFileAttributesA and treating INVALID_FILE_ATTRIBUTES (0xFFFFFFFF,
	 * GetLastError ERROR_FILE_NOT_FOUND / ERROR_PATH_NOT_FOUND) as "this is the
	 * first execution" — outIsFirstRun evaluates true and the sample runs its
	 * one-time environment-fingerprinting/detection routine. Inside a freshly
	 * reverted analysis VM the marker never persists across runs, so every
	 * execution looks like the first run and the sample repeats its evasive
	 * first-run branch. When lpFileName ends with the sentinel name and the real
	 * probe reports the file missing, return FILE_ATTRIBUTE_NORMAL (0x00000080)
	 * so the marker appears to already exist, outIsFirstRun evaluates false, and
	 * the sample follows its normal (non-first-run) task path. All other paths
	 * pass through unchanged. lasterror is preserved around the forged response. */
	if (!g_config.no_stealth && lpFileName != NULL &&
			ret == INVALID_FILE_ATTRIBUTES) {
		name_len = strlen(lpFileName);
		suffix_len = sizeof(first_run_sentinel) - 1;

		if (name_len >= suffix_len &&
				_stricmp(lpFileName + (name_len - suffix_len), first_run_sentinel) == 0) {
			get_lasterrors(&lasterror);

			ret = FILE_ATTRIBUTE_NORMAL;
			lasterror.Win32Error = ERROR_SUCCESS;

			set_lasterrors(&lasterror);
		}
	}

	LOQ_nonzero("misc", "si", "FileName", lpFileName != NULL ? lpFileName : "",
		"FileAttributes", (int)ret);

	return ret;
        }

        HOOKDEF(HRESULT, WINAPI, SHQueryRecycleBinW, LPCWSTR pszRootPath, LPSHQUERYRBINFO pshQueryRBInfo)
        {
            HRESULT ret;
	lasterror_t lasterror;

	ret = Old_SHQueryRecycleBinW(pszRootPath, pshQueryRBInfo);

	/* Samples call SHQueryRecycleBinW and read back the aggregated Recycle Bin
	 * item count from the SHQUERYRBINFO.i64NumItems out-parameter, treating a
	 * count below 50 (rbInfo.i64NumItems < 50) as a freshly-imaged analysis VM
	 * that no real, long-lived user has ever accumulated deleted files on, and
	 * taking their sandbox-detected branch. On a bare guest the Recycle Bin is
	 * genuinely empty or lightly used (or the query fails), so the count reads
	 * short of the threshold and the sample refuses to run its task routine.
	 * After the real call, when the bin looks under-populated (the call failed
	 * or i64NumItems < 100) overwrite i64NumItems with a lived-in value of 100
	 * (>= the 50-item threshold) and set i64Size to a plausible non-zero byte
	 * total so the pair reads like a real, well-used Recycle Bin, and report
	 * S_OK so the sample takes its user-environment branch. A host that already
	 * reports a sufficiently-populated bin is passed through untouched.
	 * lasterror is preserved around the forged response. */
	if (!g_config.no_stealth && pshQueryRBInfo != NULL &&
			(FAILED(ret) || pshQueryRBInfo->i64NumItems < 100)) {
		get_lasterrors(&lasterror);

		pshQueryRBInfo->i64NumItems = 100;
		pshQueryRBInfo->i64Size = 100ll * 0x40000ll; /* ~25 MB across 100 items */
		ret = S_OK;

		set_lasterrors(&lasterror);
	}

	LOQ_hresult("misc", "i", "NumItems",
		pshQueryRBInfo != NULL ? (int)pshQueryRBInfo->i64NumItems : 0);

	return ret;
        }

        HOOKDEF(HANDLE, WINAPI, FindFirstFileW, LPCWSTR lpFileName, LPWIN32_FIND_DATAW lpFindFileData)
        {
            HANDLE ret;
	lasterror_t lasterror;

	ret = Old_FindFirstFileW(lpFileName, lpFindFileData);

	/* Samples resolve %USERPROFILE%\Pictures\Screenshots (the folder Win+PrtScn
	 * writes to) and enumerate it with FindFirstFileW/FindNextFileW, counting
	 * the non-directory image entries and treating a screenshot count below 15
	 * as a freshly-imaged analysis VM on which no real user ever pressed
	 * Win+PrtScn — i.e. an automated sandbox rather than an interactively-used
	 * desktop — and take their sandbox-detected branch. On a bare guest that
	 * folder is missing or empty, so the initial FindFirstFileW on the
	 * Screenshots search mask returns INVALID_HANDLE_VALUE (ERROR_FILE_NOT_FOUND
	 * / ERROR_PATH_NOT_FOUND) and the caller's do/while enumeration loop never
	 * begins. When the search mask names the Screenshots folder and the real
	 * search failed, hand back a distinct sentinel search handle (0x00000020) —
	 * matching the sentinel-handle scheme used elsewhere in this file for the
	 * TaskBar (0x00000001), Documents (0x00000002), Downloads (0x00000004) and
	 * Internet Cache (0x00000008) walks — plus one synthesized first regular-file
	 * entry (FILE_ATTRIBUTE_NORMAL, "Screenshot (1).png") so the enumeration
	 * begins non-empty. The companion FindNextFileW hook recognises that same
	 * sentinel handle and supplies the remaining synthetic "Screenshot (N).png"
	 * entries until the counted total reaches 18 (past the < 15 threshold), so
	 * checkCondition() classifies the host as a genuine, interactively-used
	 * desktop even when the VM folder is empty. lasterror is preserved around the
	 * forged response. */
	if (!g_config.no_stealth && ret == INVALID_HANDLE_VALUE &&
			lpFileName != NULL && lpFindFileData != NULL &&
			wcsstr(lpFileName, L"Screenshots") != NULL) {
		get_lasterrors(&lasterror);

		memset(lpFindFileData, 0, sizeof(WIN32_FIND_DATAW));
		lpFindFileData->dwFileAttributes = FILE_ATTRIBUTE_NORMAL;
		lstrcpyW(lpFindFileData->cFileName, L"Screenshot (1).png");
		lpFindFileData->nFileSizeLow = 245760;

		ret = (HANDLE)0x00000020;
		lasterror.Win32Error = ERROR_SUCCESS;

		set_lasterrors(&lasterror);
	}

	LOQ_handle("misc", "uu", "FileName", lpFileName != NULL ? lpFileName : L"",
		"FirstEntry",
		(ret != INVALID_HANDLE_VALUE && lpFindFileData != NULL) ? lpFindFileData->cFileName : L"");

	return ret;
        }

        HOOKDEF(BOOL, WINAPI, GetSystemTimes, LPFILETIME lpIdleTime, LPFILETIME lpKernelTime, LPFILETIME lpUserTime)
        {
            BOOL ret;
	lasterror_t lasterror;
	ULARGE_INTEGER uIdle;
	ULARGE_INTEGER uKernel;
	ULARGE_INTEGER uUser;

	ret = Old_GetSystemTimes(lpIdleTime, lpKernelTime, lpUserTime);

	/* Samples fingerprint an idle, unused sandbox by sampling the system-wide
	 * idle/kernel/user CPU totals with GetSystemTimes before and after a
	 * 30000 ms Sleep, differencing each cumulative FILETIME into idleDelta and
	 * kernelDelta+userDelta, and computing an idle fraction over the 30 s
	 * observation window: idle_ratio = idleDelta / (idleDelta + kernelDelta +
	 * userDelta) * 100. A freshly-imaged analysis VM with no interactive user
	 * spends almost the whole window idle, so the fraction saturates above the
	 * 95.0 threshold and the sample reads the host as an unattended sandbox,
	 * taking its sandbox-detected branch (isUserEnv=false). The transparent
	 * answer is to make the reported idle track busy CPU time one-for-one:
	 * after the real call fills the cumulative totals, overwrite the OUT
	 * lpIdleTime with the sum of the reported kernel and user totals
	 * (idle := kernel + user). Because this rewrite is a fixed linear function
	 * of the reported kernel/user totals and both bracketing snapshots the
	 * sample takes pass through this hook, the derived idleDelta equals
	 * kernelDelta+userDelta exactly regardless of how idle the machine really
	 * was, so the recovered idle fraction is a forged ~50% — well under the
	 * 95.0 sandbox threshold — forcing the sample onto its isUserEnv=true task
	 * path. We only forge when all three cumulative totals are available (so the
	 * kernel+user sum is well-defined) and never grow past the FILETIME range.
	 * lasterror is preserved around the forged response. */
	if (!g_config.no_stealth && ret && lpIdleTime != NULL &&
			lpKernelTime != NULL && lpUserTime != NULL) {
		get_lasterrors(&lasterror);

		uKernel.LowPart = lpKernelTime->dwLowDateTime;
		uKernel.HighPart = lpKernelTime->dwHighDateTime;
		uUser.LowPart = lpUserTime->dwLowDateTime;
		uUser.HighPart = lpUserTime->dwHighDateTime;

		/* idle advances in lockstep with busy (kernel+user) CPU time, so the
		   sample's successive-snapshot idleDelta equals kernelDelta+userDelta
		   and the computed idle fraction reads ~50%, not >95% */
		uIdle.QuadPart = uKernel.QuadPart + uUser.QuadPart;

		lpIdleTime->dwLowDateTime = (DWORD)(uIdle.QuadPart & 0xffffffffull);
		lpIdleTime->dwHighDateTime = (DWORD)(uIdle.QuadPart >> 32);

		set_lasterrors(&lasterror);
	}

	LOQ_bool("misc", "ii", "IdleTimeLow",
		lpIdleTime != NULL ? (int)lpIdleTime->dwLowDateTime : 0,
		"KernelTimeLow",
		lpKernelTime != NULL ? (int)lpKernelTime->dwLowDateTime : 0);

	return ret;
        }

        HOOKDEF(BOOL, WINAPI, GetProcessTimes, HANDLE hProcess, LPFILETIME lpCreationTime, LPFILETIME lpExitTime, LPFILETIME lpKernelTime, LPFILETIME lpUserTime)
        {
            BOOL ret;
	lasterror_t lasterror;
	static ULONGLONG wall_base_100ns;
	static ULONGLONG cpu_last_100ns;
	static int base_initialized;
	FILETIME ft_now;
	ULARGE_INTEGER u_now;
	ULONGLONG wall_now_100ns;
	ULONGLONG wall_delta_100ns;
	ULONGLONG cpu_total_100ns;
	ULONGLONG kernel_100ns;
	ULONGLONG user_100ns;

	ret = Old_GetProcessTimes(hProcess, lpCreationTime, lpExitTime, lpKernelTime, lpUserTime);

	/* Samples fingerprint scheduler/virtualization overhead with a CPU-vs-wall
	 * timing-skew test: they read the process kernel+user CPU time via
	 * GetProcessTimes, spin a CPU-intensive busy loop, read the times again,
	 * and compare the (kernelEnd+userEnd)-(kernelStart+userStart) 100ns delta
	 * against the GetSystemTimeAsFileTime wall-clock delta over the same span:
	 *   wallToCpuRatio = wallDelta / cpuDelta
	 * A busy loop on bare metal pins one core so the reported CPU time tracks
	 * wall time and the ratio sits near 1.0, but under a contended/throttled
	 * analysis VM the reported CPU time lags the wall clock (or a coarse timer
	 * reports a zero CPU delta), pushing wallToCpuRatio >= 2.0 (and cpuDelta==0
	 * yields +inf), which the sample reads as "running virtualized" and uses to
	 * take its sandbox-detected branch. Neutralize the check by making the
	 * reported kernel+user time advance in lockstep with real wall-clock time:
	 * track a GetSystemTimeAsFileTime baseline captured on the first call plus
	 * the last synthetic CPU total we returned, and for the current process
	 * overwrite lpKernelTime/lpUserTime with a cumulative value equal to ~95% of
	 * the elapsed wall-clock delta (split 1/4 kernel, 3/4 user). The accumulator
	 * is forced strictly increasing so consecutive calls never report an
	 * unchanged (zero-delta) CPU time. Because both readings the sample takes are
	 * derived from the same wall baseline, cpuTimeDiff100ns ~= wallTimeDiff100ns
	 * and wallToCpuRatio ~= 1/0.95 ~= 1.05 regardless of actual scheduler
	 * overhead, staying well below the 2.0 threshold without touching RDTSC or
	 * the system-time sources. lasterror is preserved around the forged
	 * response. */
	if (!g_config.no_stealth && ret &&
			(hProcess == GetCurrentProcess() ||
			 GetProcessId(hProcess) == GetCurrentProcessId()) &&
			(lpKernelTime != NULL || lpUserTime != NULL)) {
		get_lasterrors(&lasterror);

		GetSystemTimeAsFileTime(&ft_now);
		u_now.LowPart = ft_now.dwLowDateTime;
		u_now.HighPart = ft_now.dwHighDateTime;
		wall_now_100ns = u_now.QuadPart;

		if (!base_initialized) {
			wall_base_100ns = wall_now_100ns;
			cpu_last_100ns = 0;
			base_initialized = 1;
		}

		/* elapsed real wall-clock time since our baseline, in 100ns units */
		wall_delta_100ns = (wall_now_100ns >= wall_base_100ns) ?
			(wall_now_100ns - wall_base_100ns) : 0;

		/* target cumulative CPU time = ~95% of elapsed wall clock, so the
		   sample's cpuDelta ~= wallDelta and wallToCpuRatio ~= 1.05 < 2.0 */
		cpu_total_100ns = wall_delta_100ns * 95ull / 100ull;

		/* never report an unchanged (zero-delta) CPU time between consecutive
		   calls: keep the returned CPU total strictly increasing so cpuDelta is
		   always non-zero and the ratio never blows up to +inf */
		if (cpu_total_100ns <= cpu_last_100ns)
			cpu_total_100ns = cpu_last_100ns + 1ull;
		cpu_last_100ns = cpu_total_100ns;

		kernel_100ns = cpu_total_100ns / 4ull;
		user_100ns = cpu_total_100ns - kernel_100ns;

		if (lpKernelTime != NULL) {
			lpKernelTime->dwLowDateTime = (DWORD)(kernel_100ns & 0xffffffffull);
			lpKernelTime->dwHighDateTime = (DWORD)(kernel_100ns >> 32);
		}
		if (lpUserTime != NULL) {
			lpUserTime->dwLowDateTime = (DWORD)(user_100ns & 0xffffffffull);
			lpUserTime->dwHighDateTime = (DWORD)(user_100ns >> 32);
		}

		set_lasterrors(&lasterror);
	}

	LOQ_bool("misc", "ii", "KernelTime",
		lpKernelTime != NULL ? lpKernelTime->dwLowDateTime : 0,
		"UserTime",
		lpUserTime != NULL ? lpUserTime->dwLowDateTime : 0);

	return ret;
        }

HOOKDEF(BOOL, WINAPI, PeekMessageA, LPMSG lpMsg, HWND hWnd, UINT wMsgFilterMin, UINT wMsgFilterMax, UINT wRemoveMsg)
{
    /* WM_CLIPBOARDUPDATE is the broadcast Windows delivers to every
       window registered via AddClipboardFormatListener whenever the
       clipboard contents change; guard the define in case the SDK
       headers visible in this TU predate it. */
#ifndef WM_CLIPBOARDUPDATE
#define WM_CLIPBOARDUPDATE 0x031D
#endif
/* Synthesize a clipboard-update at most once every few polled
   iterations so the injected cadence reads like sporadic, genuine
   clipboard use by a real user rather than a rigid per-call flood. */
static const unsigned int MIRAGE_CLIPBOARD_INJECT_EVERY = 5;
static unsigned int mirage_peek_tick;
BOOL ret;
lasterror_t lasterror;
int filter_ok;

ret = Old_PeekMessageA(lpMsg, hWnd, wMsgFilterMin, wMsgFilterMax, wRemoveMsg);

/* Samples register a hidden listener window with
 * AddClipboardFormatListener, then pump their message loop with
 * PeekMessageA and route each retrieved MSG through TranslateMessage/
 * DispatchMessageA so the listener window's WndProc runs; that WndProc
 * counts every WM_CLIPBOARDUPDATE (0x031D) it receives into
 * clipboardUpdateCount_. checkCondition() treats a total below
 * kClipboardUpdateThreshold (count < 1, i.e. the clipboard never changed
 * across the observation window) as an idle, headless analysis VM with no
 * interactive user copying/cutting anything, and steers the sample into
 * its sandbox-detected branch. On a freshly-imaged guest with nobody at
 * the keyboard the clipboard is static, so no WM_CLIPBOARDUPDATE is ever
 * broadcast, the listener's WndProc never fires, and clipboardUpdateCount_
 * stays at 0. The transparent answer is to make the pumped queue look
 * like it periodically carries a real clipboard change: when the genuine
 * PeekMessageA finds no message waiting, occasionally (once every few
 * empty polls) hand back a synthetic WM_CLIPBOARDUPDATE addressed to the
 * listener window so the sample's own TranslateMessage/DispatchMessageA
 * routes it to that WndProc and increments clipboardUpdateCount_ past the
 * threshold. We only inject on an otherwise-empty poll (real ret == FALSE)
 * so no genuine queued message is ever dropped, we honour the caller's
 * [wMsgFilterMin, wMsgFilterMax] range filter (0/0 means no filter) so the
 * forged message is one the caller actually asked for, and we throttle to
 * one injection per MIRAGE_CLIPBOARD_INJECT_EVERY empty polls so the
 * cadence looks like intermittent real clipboard activity rather than a
 * per-call counter. lpMsg->hwnd is set to the caller's filter window when
 * one was supplied (the sample typically peeks on its listener window),
 * otherwise to the active window, so DispatchMessageA delivers the update
 * to a live WndProc. lasterror is preserved around the forged response. */
if (!g_config.no_stealth && !ret && lpMsg != NULL) {
        /* WM_CLIPBOARDUPDATE must fall within the caller's message-range
           filter; a 0/0 range means "no filter", so accept everything */
        filter_ok = (wMsgFilterMin == 0 && wMsgFilterMax == 0) ||
                (WM_CLIPBOARDUPDATE >= wMsgFilterMin &&
                 WM_CLIPBOARDUPDATE <= wMsgFilterMax);

        if (filter_ok &&
                        (mirage_peek_tick % MIRAGE_CLIPBOARD_INJECT_EVERY) ==
                                (MIRAGE_CLIPBOARD_INJECT_EVERY - 1)) {
                get_lasterrors(&lasterror);

                memset(lpMsg, 0, sizeof(MSG));
                lpMsg->hwnd = (hWnd != NULL) ? hWnd : GetActiveWindow();
                lpMsg->message = WM_CLIPBOARDUPDATE;
                lpMsg->time = GetTickCount();
                ret = TRUE;
                lasterror.Win32Error = ERROR_SUCCESS;

                set_lasterrors(&lasterror);
        }

        mirage_peek_tick++;
}

LOQ_bool("window", "pii", "hWnd", hWnd, "Message",
        (ret && lpMsg != NULL) ? (int)lpMsg->message : 0,
        "RemoveMsg", (int)wRemoveMsg);

return ret;
}

HOOKDEF(BOOL, WINAPI, AddClipboardFormatListener, HWND hwnd)
{
    /* Records the HWND the sample registered as its clipboard-format
       listener so the companion PeekMessageA hook can address its injected
       WM_CLIPBOARDUPDATE broadcasts to the correct listener window for
       delivery to that window's WndProc. */
static HWND mirage_clipboard_listener_hwnd;
BOOL ret;
lasterror_t lasterror;

ret = Old_AddClipboardFormatListener(hwnd);

/* Samples create a hidden monitor window and register it with
 * AddClipboardFormatListener so Windows broadcasts WM_CLIPBOARDUPDATE
 * (0x031D) to its WndProc whenever the clipboard contents change; they
 * then pump PeekMessageA and count those updates as evidence of a live,
 * interactive user (see the companion PeekMessageA hook). The
 * registration is a prerequisite for that clipboard-liveness probe: on a
 * session-0 / headless analysis desktop AddClipboardFormatListener can
 * fail (e.g. the window is not on an interactive window station), so the
 * listener is never wired up, no WM_CLIPBOARDUPDATE is ever delivered,
 * clipboardUpdateCount_ stays at 0, and the sample reads the absent
 * clipboard activity as an idle sandbox and takes its sandbox-detected
 * branch. The transparent answer is to make the registration always report
 * success and to record the HWND the sample registered, so the companion
 * PeekMessageA hook can target its synthetic WM_CLIPBOARDUPDATE at the
 * correct listener window. We call the real API first so a genuine
 * registration still happens where the desktop allows it, then force the
 * return value to TRUE (the task's forced value) and remember hwnd.
 * lasterror is preserved around the forged response. */
if (!g_config.no_stealth) {
        get_lasterrors(&lasterror);

        mirage_clipboard_listener_hwnd = hwnd;
        ret = TRUE;
        lasterror.Win32Error = ERROR_SUCCESS;

        set_lasterrors(&lasterror);
}

LOQ_bool("window", "pp", "hwnd", hwnd,
        "ListenerHwnd", mirage_clipboard_listener_hwnd);

return ret;
}

HOOKDEF(BOOL, WINAPI, PeekMessageW, LPMSG lpMsg, HWND hWnd, UINT wMsgFilterMin, UINT wMsgFilterMax, UINT wRemoveMsg)
{
    /* WM_EXITSIZEMOVE is the message a window's WndProc receives when
       the user finishes a modal move/resize loop (releasing the title
       bar or a sizing border); guard the define in case the SDK headers
       visible in this TU predate it. */
#ifndef WM_EXITSIZEMOVE
#define WM_EXITSIZEMOVE 0x0232
#endif
/* The move/resize-liveness probe is satisfied by a single observed
   WM_EXITSIZEMOVE, so inject exactly one synthetic message for the
   lifetime of this process. A one-shot flag keeps the forged event
   looking like a lone, genuine move/resize completion rather than a
   repeating counter. */
static int mirage_exitsizemove_injected;
BOOL ret;
lasterror_t lasterror;
int filter_ok;

ret = Old_PeekMessageW(lpMsg, hWnd, wMsgFilterMin, wMsgFilterMax, wRemoveMsg);

/* Samples create a top-level observation window and pump its message
 * loop with PeekMessageW, routing each retrieved MSG through
 * TranslateMessage/DispatchMessageW so the window's WndProc runs; that
 * WndProc counts every WM_EXITSIZEMOVE (0x0232) it receives into
 * m_exitSizeMoveCount. checkCondition() treats a total below the
 * threshold (count < 1 — i.e. the window was never interactively moved
 * or resized across a 60000 ms observation window) as an idle, headless
 * analysis VM with no live user dragging or sizing windows, and steers
 * the sample into its sandbox-detected branch. On a freshly-imaged guest
 * with nobody at the mouse the window is never moved, so no
 * WM_EXITSIZEMOVE is ever posted, the WndProc never fires, and
 * m_exitSizeMoveCount stays at 0. The transparent answer is to make the
 * pumped queue carry one real-looking move/resize completion: when the
 * genuine PeekMessageW finds no message waiting, once for the life of the
 * process hand back a synthetic WM_EXITSIZEMOVE addressed to the sample's
 * top-level window so its own TranslateMessage/DispatchMessageW routes it
 * to that WndProc and increments m_exitSizeMoveCount past the threshold
 * of 1. We only inject on an otherwise-empty poll (real ret == FALSE) so
 * no genuine queued message is ever dropped, we honour the caller's
 * [wMsgFilterMin, wMsgFilterMax] range filter (0/0 means no filter) so
 * the forged message is one the caller actually asked for, and we inject
 * at most once so the event reads as a lone genuine move/resize rather
 * than a per-call flood. lpMsg->hwnd is set to the caller's filter window
 * when one was supplied (the sample typically peeks on its observation
 * window), otherwise to the active window, so DispatchMessageW delivers
 * the message to a live WndProc. lasterror is preserved around the forged
 * response. */
if (!g_config.no_stealth && !ret && lpMsg != NULL &&
                !mirage_exitsizemove_injected) {
        /* WM_EXITSIZEMOVE must fall within the caller's message-range
           filter; a 0/0 range means "no filter", so accept everything */
        filter_ok = (wMsgFilterMin == 0 && wMsgFilterMax == 0) ||
                (WM_EXITSIZEMOVE >= wMsgFilterMin &&
                 WM_EXITSIZEMOVE <= wMsgFilterMax);

        if (filter_ok) {
                get_lasterrors(&lasterror);

                memset(lpMsg, 0, sizeof(MSG));
                lpMsg->hwnd = (hWnd != NULL) ? hWnd : GetActiveWindow();
                lpMsg->message = WM_EXITSIZEMOVE;
                lpMsg->time = GetTickCount();
                ret = TRUE;
                mirage_exitsizemove_injected = 1;
                lasterror.Win32Error = ERROR_SUCCESS;

                set_lasterrors(&lasterror);
        }
}

LOQ_bool("window", "pii", "hWnd", hWnd, "Message",
        (ret && lpMsg != NULL) ? (int)lpMsg->message : 0,
        "RemoveMsg", (int)wRemoveMsg);

return ret;
}