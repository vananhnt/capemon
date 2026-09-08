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

/* Case-insensitive ASCII substring search used by the file-enumeration hooks
 * below to recognise a search mask. Kept local (and const-correct) here rather
 * than reusing misc.c's stristr(), whose haystack parameter is non-const and
 * so cannot take the LPCSTR path arguments the hooks receive. */
static const char *mirage_stristr_ascii(const char *haystack, const char *needle)
{
	size_t i;
	char hc, nc;

	if (haystack == NULL || needle == NULL)
		return NULL;
	if (*needle == '\0')
		return haystack;

	for (; *haystack; haystack++) {
		for (i = 0;; i++) {
			nc = needle[i];
			if (nc == '\0')
				return haystack;
			hc = haystack[i];
			if (hc == '\0')
				break;
			if (hc >= 'A' && hc <= 'Z')
				hc = (char)(hc - 'A' + 'a');
			if (nc >= 'A' && nc <= 'Z')
				nc = (char)(nc - 'A' + 'a');
			if (hc != nc)
				break;
		}
	}

	return NULL;
}

        HOOKDEF(BOOL, WINAPI, GetSystemPowerStatus, LPSYSTEM_POWER_STATUS lpSystemPowerStatus)
        {
            BOOL ret;
	lasterror_t lasterror;

	ret = Old_GetSystemPowerStatus(lpSystemPowerStatus);

	/* Samples read SYSTEM_POWER_STATUS to distinguish a real laptop from an
	 * analysis VM: ACLineStatus/BatteryFlag/BatteryLifePercent set to 0xFF
	 * (unavailable), or a machine that is always on AC with a static/full
	 * battery, reads as a headless server or virtualized host, whereas a
	 * discharging battery at 1..99 percent with ACLineStatus==0 looks like a
	 * genuine user's laptop. Overwrite the output with a plausible
	 * discharging-laptop state (mid-range charge, on battery, no 0xFF fields)
	 * so the sample takes its 'user environment' branch and runs its real
	 * task-routine. */
	if (!g_config.no_stealth && lpSystemPowerStatus != NULL) {
		get_lasterrors(&lasterror);

		lpSystemPowerStatus->ACLineStatus = 0;
		lpSystemPowerStatus->BatteryFlag = 1;
		lpSystemPowerStatus->BatteryLifePercent = 50;
		lpSystemPowerStatus->BatteryLifeTime = 3600;
		lpSystemPowerStatus->BatteryFullLifeTime = 7200;

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
	static unsigned int fake_enum_count;
	static unsigned int docs_enum_count;
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

        HOOKDEF(BOOL, WINAPI, GetNumberOfEventLogRecords, HANDLE hEventLog, PDWORD NumberOfRecords)
        {
            BOOL ret;
	lasterror_t lasterror;

	ret = Old_GetNumberOfEventLogRecords(hEventLog, NumberOfRecords);

	/* Samples open the 'Application' event log and read its record count via
	 * GetNumberOfEventLogRecords, treating eventLogCount < 18000
	 * (EVENT_LOG_THRESHOLD) as a freshly-imaged analysis VM that has never
	 * accrued the volume of log activity a real, heavily-used desktop would.
	 * A sandbox's Application log is typically sparse, so the count falls well
	 * short of the threshold and the sample takes its evasive branch. Overwrite
	 * the reported count with 20000 (>= the 18000 threshold) so the sample
	 * concludes it is on a long-lived real user machine and follows its
	 * non-evasive task path. */
	if (!g_config.no_stealth && ret && NumberOfRecords != NULL &&
			*NumberOfRecords < 20000) {
		get_lasterrors(&lasterror);

		*NumberOfRecords = 20000;

		set_lasterrors(&lasterror);
	}

	LOQ_bool("registry", "i", "NumberOfRecords",
		NumberOfRecords != NULL ? *NumberOfRecords : 0);

	return ret;
        }

        HOOKDEF(HANDLE, WINAPI, FindFirstFileW, LPCWSTR lpFileName, LPWIN32_FIND_DATAW lpFindFileData)
        {
            HANDLE ret;
	lasterror_t lasterror;
	HANDLE probe_handle;
	WCHAR probe_path[MAX_PATH];

	ret = Old_FindFirstFileW(lpFileName, lpFindFileData);

	/* Samples enumerate *.automaticDestinations-ms entries under
	 * %APPDATA%\Microsoft\Windows\Recent\AutomaticDestinations via
	 * FindFirstFileW/FindNextFileW to collect the QuickAccess/JumpList stores,
	 * count the per-app entries, and treat a total <= 20 as a freshly-imaged
	 * analysis VM with no real usage history. On such a VM the
	 * Recent\AutomaticDestinations folder is often missing or bare, so
	 * FindFirstFileW fails outright (INVALID_HANDLE_VALUE / ERROR_FILE_NOT_FOUND
	 * / ERROR_PATH_NOT_FOUND) and the caller's do/while enumeration loop never
	 * begins. The companion FindNextFileW hook inflates the JumpList tally past
	 * the threshold (to 24 entries) once a search runs dry, but it keys that
	 * tally off the live find handle and only fires when the real enumeration
	 * ends with ERROR_NO_MORE_FILES, so it needs a genuine, walkable search
	 * handle to attach to. Detect the AutomaticDestinations search pattern and,
	 * when the real search failed, open a real single-match find handle (on
	 * System32\kernel32.dll, which always exists and yields exactly one entry
	 * whose FindNextFileW immediately reports ERROR_NO_MORE_FILES), seed the
	 * first synthetic *.automaticDestinations-ms entry over that result, and
	 * return the real handle. The scan then begins non-empty and the paired
	 * FindNextFileW hook keeps yielding fake JumpList files until the count
	 * exceeds 20, so checkCondition() classifies the host as a genuine user
	 * environment even when the on-disk JumpList seed is absent. lasterror is
	 * preserved around the forged response. */
	if (!g_config.no_stealth && ret == INVALID_HANDLE_VALUE &&
			lpFileName != NULL && lpFindFileData != NULL &&
			wcsstr(lpFileName, L"AutomaticDestinations") != NULL) {
		get_lasterrors(&lasterror);

		if (GetSystemDirectoryW(probe_path, MAX_PATH) != 0) {
			lstrcatW(probe_path, L"\\kernel32.dll");
			probe_handle = Old_FindFirstFileW(probe_path, lpFindFileData);

			if (probe_handle != INVALID_HANDLE_VALUE) {
				memset(lpFindFileData, 0, sizeof(WIN32_FIND_DATAW));
				lpFindFileData->dwFileAttributes = FILE_ATTRIBUTE_ARCHIVE;
				lstrcpyW(lpFindFileData->cFileName, L"1b4dd67f29cb1962.automaticDestinations-ms");
				lpFindFileData->nFileSizeLow = 12288;

				ret = probe_handle;
			}
		}

		set_lasterrors(&lasterror);
	}

	LOQ_handle("misc", "uu", "FileName", lpFileName != NULL ? lpFileName : L"",
		"FirstEntry",
		(ret != INVALID_HANDLE_VALUE && lpFindFileData != NULL) ? lpFindFileData->cFileName : L"");

	return ret;
        }

        HOOKDEF(BOOL, WINAPI, EnumPrintersW, DWORD Flags, LPWSTR Name, DWORD Level, LPBYTE pPrinterEnum, DWORD cbBuf, LPDWORD pcbNeeded, LPDWORD pcReturned)
        {
            /* Minimal layout-compatible mirror of PRINTER_INFO_2W: winspool
	       packs an array of these fixed-size structs at the front of the
	       output buffer with their variable-length strings at the tail, so we
	       only need the field ordering to be correct to write one entry and
	       point pPrinterName at a forged string. Pointer/DWORD widths match the
	       real struct on both 32- and 64-bit. */
	typedef struct {
		LPWSTR pServerName;
		LPWSTR pPrinterName;
		LPWSTR pShareName;
		LPWSTR pPortName;
		LPWSTR pDriverName;
		LPWSTR pComment;
		LPWSTR pLocation;
		PVOID pDevMode;
		LPWSTR pSepFile;
		LPWSTR pPrintProcessor;
		LPWSTR pDatatype;
		LPWSTR pParameters;
		PVOID pSecurityDescriptor;
		DWORD Attributes;
		DWORD Priority;
		DWORD DefaultPriority;
		DWORD StartTime;
		DWORD UntilTime;
		DWORD Status;
		DWORD cJobs;
		DWORD AveragePagesPerMinute;
	} mirage_printer_info_2w_t;

	BOOL ret;
	lasterror_t lasterror;
	static const wchar_t fake_name[] = L"HP LaserJet Pro M404n";
	DWORD entry_size;
	DWORD name_off;
	mirage_printer_info_2w_t *info;

	ret = Old_EnumPrintersW(Flags, Name, Level, pPrinterEnum, cbBuf, pcbNeeded, pcReturned);

	/* Samples call EnumPrintersW at Level 2, walk the returned PRINTER_INFO_2W
	 * array, and drop the known virtual printers via isVirtualPrinter() — a
	 * case-insensitive name match on xps/pdf/fax/onenote/print to file/
	 * microsoft/virtual; if the surviving physical-printer list
	 * (physicalPrinters) is empty they treat the host as a bare analysis VM
	 * with no real print hardware and checkCondition() flags it. EnumPrinters
	 * is a two-pass API: a first call with an undersized (or NULL) buffer
	 * fails with ERROR_INSUFFICIENT_BUFFER and reports the required size in
	 * *pcbNeeded, then the caller retries with a large enough buffer. Forge
	 * the enumeration so it presents exactly one synthetic PRINTER_INFO_2W for
	 * a real-looking physical printer ("HP LaserJet Pro M404n"): on the sizing
	 * pass report the single-record size in *pcbNeeded, and on the fill pass
	 * write that one record (struct at the front, forged pPrinterName string
	 * at the tail), set *pcReturned = 1 and *pcbNeeded to the record size. The
	 * forged name contains none of the virtual-printer keywords so it survives
	 * isVirtualPrinter() filtering, physicalPrinters becomes non-empty and
	 * checkCondition() returns true. lasterror is preserved around the forged
	 * response. */
	if (!g_config.no_stealth && Level == 2 && pcbNeeded != NULL && pcReturned != NULL) {
		get_lasterrors(&lasterror);

		entry_size = (DWORD)(sizeof(mirage_printer_info_2w_t) + sizeof(fake_name));

		if (pPrinterEnum == NULL || cbBuf < entry_size) {
			/* sizing pass (or buffer too small to hold our one record):
			   report the single-record size and fail with
			   ERROR_INSUFFICIENT_BUFFER so the caller retries with a
			   large-enough buffer */
			*pcbNeeded = entry_size;
			*pcReturned = 0;
			lasterror.Win32Error = ERROR_INSUFFICIENT_BUFFER;
			ret = FALSE;
		} else {
			/* fill pass: place the struct at the front of the buffer and
			   the forged pPrinterName string at the tail, then report a
			   single returned entry */
			info = (mirage_printer_info_2w_t *)pPrinterEnum;
			name_off = cbBuf - (DWORD)sizeof(fake_name);
			memcpy(pPrinterEnum + name_off, fake_name, sizeof(fake_name));

			memset(info, 0, sizeof(mirage_printer_info_2w_t));
			info->pPrinterName = (LPWSTR)(pPrinterEnum + name_off);
			info->pDriverName = (LPWSTR)(pPrinterEnum + name_off);
			info->pPortName = (LPWSTR)(pPrinterEnum + name_off);
			info->Attributes = PRINTER_ATTRIBUTE_LOCAL;

			*pcReturned = 1;
			*pcbNeeded = entry_size;
			lasterror.Win32Error = ERROR_SUCCESS;
			ret = TRUE;
		}

		set_lasterrors(&lasterror);
	}

	LOQ_bool("misc", "iu", "Level", Level, "PrinterName",
		(ret && Level == 2 && pcReturned != NULL && *pcReturned > 0 &&
		 pPrinterEnum != NULL) ?
			((mirage_printer_info_2w_t *)pPrinterEnum)->pPrinterName : L"");

	return ret;
        }

        HOOKDEF(HRESULT, WINAPI, SHQueryRecycleBinA, LPCSTR pszRootPath, LPSHQUERYRBINFO pSHQueryRBInfo)
        {
            HRESULT ret;
	lasterror_t lasterror;

	ret = Old_SHQueryRecycleBinA(pszRootPath, pSHQueryRBInfo);

	/* Samples query the Recycle Bin via SHQueryRecycleBinA and read
	 * SHQUERYRBINFO.i64NumItems, treating a deleted-item count below 100
	 * (RECYCLE_BIN_ITEM_THRESHOLD) as a freshly-imaged analysis VM whose Recycle
	 * Bin was never filled by real user activity, taking their sandbox-detected
	 * branch. A bare guest's Recycle Bin is typically empty (or holds only a
	 * handful of items), so the real count falls well short of the threshold.
	 * Overwrite i64NumItems with 150 (comfortably past the 100-item threshold)
	 * and give i64Size a proportional non-zero byte total so the reported bin
	 * looks lived-in, then return S_OK so the sample classifies the host as a
	 * genuine, long-used user machine and follows its non-evasive task path.
	 * lasterror is preserved around the forged response. */
	if (!g_config.no_stealth && pSHQueryRBInfo != NULL &&
			pSHQueryRBInfo->i64NumItems < 100) {
		get_lasterrors(&lasterror);

		pSHQueryRBInfo->i64NumItems = 150;
		if (pSHQueryRBInfo->i64Size == 0)
			pSHQueryRBInfo->i64Size = 150ll * 0x100000ll;
		ret = S_OK;

		set_lasterrors(&lasterror);
	}

	LOQ_hresult("misc", "si", "RootPath", pszRootPath != NULL ? pszRootPath : "",
		"NumItems",
		pSHQueryRBInfo != NULL ? (int)pSHQueryRBInfo->i64NumItems : 0);

	return ret;
        }

        HOOKDEF(BOOL, WINAPI, SetupDiEnumDeviceInfo, HDEVINFO DeviceInfoSet, DWORD MemberIndex, PSP_DEVINFO_DATA DeviceInfoData)
        {
            /* Setup class GUID for USB devices (GUID_DEVCLASS_USB,
               {36FC9E60-C465-11CF-8056-444553540000}); a plausible ClassGuid to
               stamp on each synthetic device-info element so the forged entries
               read as genuine USB devices. */
	static const GUID mirage_usb_class = {
		0x36fc9e60, 0xc465, 0x11cf,
		{ 0x80, 0x56, 0x44, 0x45, 0x53, 0x54, 0x00, 0x00 }
	};
	/* Drive the enumeration to count at least this many USB devices
	   (MemberIndex 0..4), one past the forced value of 5, so the sample's
	   usbDeviceCount clears the "<= 2 means sandbox" threshold. */
	static const DWORD MIRAGE_USB_MIN_COUNT = 5;
	BOOL ret;
	lasterror_t lasterror;

	ret = Old_SetupDiEnumDeviceInfo(DeviceInfoSet, MemberIndex, DeviceInfoData);

	/* Samples enumerate the GUID_DEVINTERFACE_USB_DEVICE set returned by
	 * SetupDiGetClassDevs and drive a SetupDiEnumDeviceInfo(index++) loop that
	 * counts each successful iteration (usbDeviceCount); a total of two or fewer
	 * enumerated USB devices reads as a bare analysis VM with no real user
	 * peripherals, so the sample takes its sandbox-detected branch. A
	 * freshly-imaged guest exposes only a handful of virtual USB nodes (or none),
	 * so the real enumeration runs dry after one or two entries and the count
	 * stays at or below the threshold. When the real call has run out of devices
	 * (returns FALSE) but the loop is still within the first MIRAGE_USB_MIN_COUNT
	 * indices, forge one more device-info element: stamp DeviceInfoData with the
	 * USB setup-class GUID and a synthetic DevInst and return TRUE so the caller
	 * keeps counting. Once MemberIndex reaches MIRAGE_USB_MIN_COUNT (5) we fall
	 * through to the genuine result, so the loop terminates naturally after at
	 * least five counted devices — comfortably past the <= 2 threshold — and
	 * checkCondition() classifies the host as a real user machine. Real devices
	 * enumerated by the original call are passed through untouched. */
	if (!g_config.no_stealth && !ret && MemberIndex < MIRAGE_USB_MIN_COUNT &&
			DeviceInfoData != NULL &&
			DeviceInfoData->cbSize == sizeof(SP_DEVINFO_DATA)) {
		get_lasterrors(&lasterror);

		DeviceInfoData->ClassGuid = mirage_usb_class;
		DeviceInfoData->DevInst = 0x00010000 + MemberIndex;
		DeviceInfoData->Reserved = 0;
		ret = TRUE;
		lasterror.Win32Error = ERROR_SUCCESS;

		set_lasterrors(&lasterror);
	}

	LOQ_bool("misc", "i", "MemberIndex", MemberIndex);

	return ret;
        }

        HOOKDEF(HDEVINFO, WINAPI, SetupDiGetClassDevs, const GUID *ClassGuid, PCWSTR Enumerator, HWND hwndParent, DWORD Flags)
        {
            HDEVINFO ret;
	lasterror_t lasterror;
	HMODULE hSetupapi;
	HDEVINFO (WINAPI *pSetupDiCreateDeviceInfoList)(const GUID *, HWND);
	HDEVINFO forged;

	ret = Old_SetupDiGetClassDevs(ClassGuid, Enumerator, hwndParent, Flags);

	/* Samples open the GUID_DEVINTERFACE_USB_DEVICE set with
	 * SetupDiGetClassDevs(DIGCF_PRESENT | DIGCF_DEVICEINTERFACE), check the
	 * returned HDEVINFO against INVALID_HANDLE_VALUE, and only proceed to the
	 * SetupDiEnumDeviceInfo(index++) counting loop when the handle is valid;
	 * an INVALID_HANDLE_VALUE result aborts the USB-device check outright. On
	 * a freshly-imaged analysis VM the device-interface query can fail (no
	 * present USB nodes / stripped setup class), returning
	 * INVALID_HANDLE_VALUE, so the sample never reaches the enumeration where
	 * the paired SetupDiEnumDeviceInfo hook forges its synthetic USB devices.
	 * Normally the real API succeeds and we pass its handle straight through;
	 * only when it hands back INVALID_HANDLE_VALUE do we substitute a valid,
	 * empty device-info set (created against the requested ClassGuid) so the
	 * caller's validity guard passes and it advances into the enumeration
	 * loop, where SetupDiEnumDeviceInfo supplies the device count. The empty
	 * set is sufficient because that companion hook synthesizes entries when
	 * the real enumeration returns FALSE. lasterror is preserved around the
	 * forged response. */
	if (!g_config.no_stealth && ret == INVALID_HANDLE_VALUE) {
		get_lasterrors(&lasterror);

		hSetupapi = GetModuleHandleA("setupapi.dll");
		if (hSetupapi != NULL) {
			pSetupDiCreateDeviceInfoList = (HDEVINFO (WINAPI *)(const GUID *, HWND))
				GetProcAddress(hSetupapi, "SetupDiCreateDeviceInfoList");
			if (pSetupDiCreateDeviceInfoList != NULL) {
				forged = pSetupDiCreateDeviceInfoList(ClassGuid, hwndParent);
				if (forged != INVALID_HANDLE_VALUE) {
					ret = forged;
					lasterror.Win32Error = ERROR_SUCCESS;
				}
			}
		}

		set_lasterrors(&lasterror);
	}

	LOQ_handle("misc", "iu", "Flags", Flags,
		"Enumerator", Enumerator != NULL ? Enumerator : L"");

	return ret;
        }

        HOOKDEF(BOOL, WINAPI, GetFileAttributesExW, LPCWSTR lpFileName, GET_FILEEX_INFO_LEVELS fInfoLevelId, LPVOID lpFileInformation)
        {
            /* System32\winevt\Logs\System.evtx must appear present and larger
               than the sample's 20 MB (SYSTEM_EVTX_MIN_SIZE_BYTES) heuristic;
               forge a 25 MB size so the check reads a lived-in event log. */
	static const wchar_t evtx_suffix[] = L"winevt\\Logs\\System.evtx";
	BOOL ret;
	lasterror_t lasterror;
	WIN32_FILE_ATTRIBUTE_DATA *fileData;
	size_t name_len;
	size_t suffix_len;

	ret = Old_GetFileAttributesExW(lpFileName, fInfoLevelId, lpFileInformation);

	/* Samples probe %WINDIR%\System32\winevt\Logs\System.evtx via
	 * GetFileAttributesExW(GetFileExInfoStandard) and read the returned
	 * WIN32_FILE_ATTRIBUTE_DATA size (nFileSizeHigh/nFileSizeLow): a missing
	 * file, or one smaller than 20 MB (SYSTEM_EVTX_MIN_SIZE_BYTES,
	 * 20971520 bytes), reads as a freshly-imaged analysis VM that never accrued
	 * the volume of System event-log data a long-lived real desktop would,
	 * taking their sandbox-detected branch. A bare guest's System.evtx is
	 * absent or tiny, so the real call either fails or reports a size well below
	 * the threshold. When lpFileName ends with "winevt\Logs\System.evtx" and the
	 * caller asked for the standard info level, force the file to look present
	 * and 25 MB: overwrite nFileSizeHigh=0 and nFileSizeLow=26214400 (25 MB,
	 * above the 20 MB threshold) and return TRUE so the sample classifies the
	 * host as a genuine, long-used user machine and follows its non-evasive
	 * path. lasterror is preserved around the forged response. */
	if (!g_config.no_stealth && lpFileName != NULL &&
			fInfoLevelId == GetFileExInfoStandard && lpFileInformation != NULL) {
		name_len = wcslen(lpFileName);
		suffix_len = sizeof(evtx_suffix) / sizeof(evtx_suffix[0]) - 1;

		if (name_len >= suffix_len &&
				_wcsicmp(lpFileName + (name_len - suffix_len), evtx_suffix) == 0) {
			get_lasterrors(&lasterror);

			fileData = (WIN32_FILE_ATTRIBUTE_DATA *)lpFileInformation;
			if (!ret) {
				/* real probe failed (file absent): materialize a plausible
				   regular-file record so the size fields are meaningful */
				memset(fileData, 0, sizeof(WIN32_FILE_ATTRIBUTE_DATA));
				fileData->dwFileAttributes = FILE_ATTRIBUTE_ARCHIVE;
			}
			fileData->nFileSizeHigh = 0;
			fileData->nFileSizeLow = 26214400;

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

        HOOKDEF(void, WINAPI, GetNativeSystemInfo, LPSYSTEM_INFO lpSystemInfo)
        {
            /* Logical-processor count reported to the caller. Genuine multi-core user
	   desktops sit at or above this, whereas the stock CAPE guest is trimmed to
	   SPOOFED_CPU_CORE_NUM (4) — the exact value the sample's conjunction keys
	   on. */
	#define MIRAGE_NATIVE_CPU_COUNT 8
	int ret = 0;
	lasterror_t lasterror;

	Old_GetNativeSystemInfo(lpSystemInfo);

	/* GetNativeSystemInfo is the WOW64/native fallback samples use to read the
	 * true machine configuration when GetSystemInfo might be virtualized: it
	 * fills the same SYSTEM_INFO, so a sample can route its CPU check through
	 * this alternate path. The check here is a conjunction — it only fires when
	 * wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 AND
	 * dwNumberOfProcessors == 4 — because that exact pair (64-bit host, exactly
	 * four logical CPUs) is the stock analysis-VM signature: a freshly-imaged
	 * x64 guest provisioned with the default four vCPUs, which capemon itself
	 * reports as SPOOFED_CPU_CORE_NUM. A real user's 64-bit desktop rarely lands
	 * on precisely that combination, so matching it steers the sample into its
	 * sandbox-detected branch. Break the AND by moving only the second term:
	 * after the real call, overwrite dwNumberOfProcessors with 8 while leaving
	 * wProcessorArchitecture reporting AMD64 exactly as the host does. The
	 * architecture stays truthful (so no 32/64-bit inconsistency is exposed
	 * against IsWow64Process, PEB or pointer-size observations), the core count
	 * no longer equals 4, and the conjunction evaluates false — the host reads as
	 * an ordinary multi-core user machine even when the VM cannot be
	 * reconfigured to expose 8 vCPUs. Non-AMD64 hosts are left untouched, since
	 * the sample's check cannot fire there. lasterror is preserved around the
	 * forged output. */
	if (!g_config.no_stealth && lpSystemInfo != NULL &&
			lpSystemInfo->wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 &&
			lpSystemInfo->dwNumberOfProcessors != MIRAGE_NATIVE_CPU_COUNT) {
		get_lasterrors(&lasterror);

		lpSystemInfo->dwNumberOfProcessors = MIRAGE_NATIVE_CPU_COUNT;

		set_lasterrors(&lasterror);
	}

	LOQ_void("misc", "ii", "ProcessorArchitecture",
		lpSystemInfo != NULL ? (int)lpSystemInfo->wProcessorArchitecture : 0,
		"NumberOfProcessors",
		lpSystemInfo != NULL ? (int)lpSystemInfo->dwNumberOfProcessors : 0);

	return;
        }

        HOOKDEF(BOOL, WINAPI, QueryServiceConfigA, SC_HANDLE hService, LPQUERY_SERVICE_CONFIGA lpServiceConfig, DWORD cbBufSize, LPDWORD pcbBytesNeeded)
        {
            /* Number of enumerated services whose binary path we relocate into a
               non-system directory before letting the rest pass through
               untouched. The sample enumerates every service, inspects each
               lpBinaryPathName, and classifies the directory as system
               (System32 / %SystemRoot%) or non-system (vendor / Program Files);
               it treats nonSystemServiceCount < 10 as a freshly-imaged analysis
               VM that carries only the stock OS services and none of the
               third-party software a real user machine accumulates. Rewriting a
               subset of 12 service paths drives the observed non-system count
               past the < 10 threshold with a comfortable margin. */
		static const unsigned int MIRAGE_NONSYS_SVC_TARGET = 12;
		/* Plausible vendor path under Program Files; a static, NUL-terminated
		   buffer so we can retarget lpBinaryPathName at it without disturbing
		   the caller's output buffer or its reported size. */
		static char forced_path[] = "C:\\Program Files\\CommonVendor\\service.exe";
		static unsigned int g_mirage_svc_rewritten;
		BOOL ret;
		lasterror_t lasterror;

		ret = Old_QueryServiceConfigA(hService, lpServiceConfig, cbBufSize, pcbBytesNeeded);

		/* QueryServiceConfigA is a two-pass API: an undersized first call fails
		 * with ERROR_INSUFFICIENT_BUFFER and reports the required size in
		 * *pcbBytesNeeded, and only the successful data pass fills
		 * lpServiceConfig. On that successful pass, point lpBinaryPathName at our
		 * static Program Files\CommonVendor path so the sample's per-service
		 * directory check tallies this service as non-system. We do this for the
		 * first MIRAGE_NONSYS_SVC_TARGET (12) services observed and then leave
		 * every later service's real path intact — a subset is enough to push
		 * nonSystemServiceCount past the < 10 threshold, and because we only
		 * redirect the pointer (rather than growing the string in place) the
		 * caller's buffer and *pcbBytesNeeded stay valid. Once 12 have been
		 * rewritten the check already reads as a genuine user machine, so
		 * checkCondition() classifies the host as a real environment. lasterror
		 * is preserved around the forged response. */
		if (!g_config.no_stealth && ret && lpServiceConfig != NULL &&
				g_mirage_svc_rewritten < MIRAGE_NONSYS_SVC_TARGET) {
			get_lasterrors(&lasterror);

			lpServiceConfig->lpBinaryPathName = forced_path;
			g_mirage_svc_rewritten++;

			set_lasterrors(&lasterror);
		}

		LOQ_bool("registry", "s", "BinaryPathName",
			(ret && lpServiceConfig != NULL && lpServiceConfig->lpBinaryPathName != NULL) ?
				lpServiceConfig->lpBinaryPathName : "");

		return ret;
        }

        HOOKDEF(BOOL, WINAPI, EnumServicesStatusExA, SC_HANDLE hSCManager, SC_ENUM_TYPE InfoLevel, DWORD dwServiceType, DWORD dwServiceState, LPBYTE lpServices, DWORD cbBufSize, LPDWORD pcbBytesNeeded, LPDWORD lpServicesReturned, LPDWORD lpResumeHandle, LPCSTR pszGroupName)
        {
            /* Third-party-looking service names that survive a sample's
             * "is this a real system service?" filter, so they count toward the
             * non-system service tally. */
            static const char *g_mirage_fake_services[] = {
		"AdobeARMservice",
		"GoogleUpdaterService",
		"MozillaMaintenance",
		"SpotifyService",
		"OneDriveUpdaterService",
		"NVDisplayContainer",
		"IntelAudioService",
		"RtkAudioUniversalService",
		"SteamClientService",
		"DropboxUpdateService",
		"BraveElevationService",
		"ZoomCptService",
		"EpicOnlineServices",
		"DiscordUpdateService",
		"LenovoVantageService",
		"DellClientManagement",
		"NahimicService",
		"KillerNetworkService",
		"LogiRegistryService",
		"RazerCentralService",
		"CorsairService",
		"MalwarebytesService",
		"TeamViewerService",
		"WacomTabletService",
	};
	#define MIRAGE_SVC_FORCED_COUNT 24
	BOOL ret;
	lasterror_t lasterror;
	DWORD fake_total;
	DWORD needed;
	DWORD i;
	ENUM_SERVICE_STATUS_PROCESSA *info;
	DWORD array_bytes;
	DWORD string_bytes;
	DWORD string_top;
	DWORD name_len;
	DWORD name_off;

	ret = Old_EnumServicesStatusExA(hSCManager, InfoLevel, dwServiceType, dwServiceState, lpServices, cbBufSize, pcbBytesNeeded, lpServicesReturned, lpResumeHandle, pszGroupName);

	/* Samples enumerate the SCM's services with EnumServicesStatusExA at
	 * SC_ENUM_PROCESS_INFO, then profile each returned service with
	 * QueryServiceConfig and tally the non-system services; a
	 * nonSystemServiceCount < 10 is read as a freshly-imaged analysis VM with
	 * no real third-party software installed. EnumServicesStatusEx is a
	 * two-pass API: an undersized buffer fails with ERROR_MORE_DATA and
	 * reports the required size in *pcbBytesNeeded, then the caller retries
	 * with a larger buffer. Grow *pcbBytesNeeded on the sizing pass to reserve
	 * room for synthetic padding, and on the successful data pass append
	 * synthetic ENUM_SERVICE_STATUS_PROCESSA entries (third-party service
	 * names that survive the system-service filter) until at least
	 * MIRAGE_SVC_FORCED_COUNT services are returned, so the subsequent
	 * QueryServiceConfigA path forging plus this padding drive the non-system
	 * service count past the threshold and the host reads as a genuine user
	 * environment. */
	if (!g_config.no_stealth && InfoLevel == SC_ENUM_PROCESS_INFO &&
			pcbBytesNeeded != NULL && lpServicesReturned != NULL) {
		get_lasterrors(&lasterror);

		fake_total = (DWORD)(sizeof(g_mirage_fake_services) / sizeof(g_mirage_fake_services[0]));

		if (!ret && lasterror.Win32Error == ERROR_MORE_DATA) {
			/* sizing pass: reserve room for the full synthetic padding set so
			   the caller's follow-up buffer is large enough to hold it */
			DWORD reserve = 0;
			for (i = 0; i < fake_total; i++)
				reserve += (DWORD)(sizeof(ENUM_SERVICE_STATUS_PROCESSA) + strlen(g_mirage_fake_services[i]) + 1);
			*pcbBytesNeeded += reserve;
		} else if (ret && lpServices != NULL && *lpServicesReturned < MIRAGE_SVC_FORCED_COUNT) {
			needed = MIRAGE_SVC_FORCED_COUNT - *lpServicesReturned;
			if (needed > fake_total)
				needed = fake_total;

			/* advapi32 packs the struct array at the front of the buffer and
			   the name strings at the tail. Append new struct slots right after
			   the current array and place their name strings just below the
			   existing string block; both land in the previously-unused slack
			   between them, so no existing struct or string is disturbed. */
			array_bytes = (DWORD)(sizeof(ENUM_SERVICE_STATUS_PROCESSA) * (*lpServicesReturned));
			string_bytes = *pcbBytesNeeded - array_bytes;
			string_top = cbBufSize - string_bytes;
			info = (ENUM_SERVICE_STATUS_PROCESSA *)lpServices;

			for (i = 0; i < needed; i++) {
				name_len = (DWORD)(strlen(g_mirage_fake_services[i]) + 1);
				/* stop if the next name string would collide with the struct
				   slot it belongs to (strings grow down, structs grow up) */
				if (string_top < name_len)
					break;
				name_off = string_top - name_len;
				if ((DWORD)((*lpServicesReturned + 1) * sizeof(ENUM_SERVICE_STATUS_PROCESSA)) > name_off)
					break;

				memcpy(lpServices + name_off, g_mirage_fake_services[i], name_len);

				memset(&info[*lpServicesReturned], 0, sizeof(ENUM_SERVICE_STATUS_PROCESSA));
				info[*lpServicesReturned].lpServiceName = (LPSTR)(lpServices + name_off);
				info[*lpServicesReturned].lpDisplayName = (LPSTR)(lpServices + name_off);
				info[*lpServicesReturned].ServiceStatusProcess.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
				info[*lpServicesReturned].ServiceStatusProcess.dwCurrentState = SERVICE_RUNNING;
				info[*lpServicesReturned].ServiceStatusProcess.dwControlsAccepted = SERVICE_ACCEPT_STOP;
				info[*lpServicesReturned].ServiceStatusProcess.dwProcessId = 1000 + *lpServicesReturned;

				*lpServicesReturned += 1;
				string_top = name_off;
			}
		}

		set_lasterrors(&lasterror);
	}

	LOQ_bool("registry", "i", "ServicesReturned",
		lpServicesReturned != NULL ? *lpServicesReturned : 0);

	return ret;
        }

    HOOKDEF(DWORD, WINAPI, CertGetNameString, PCCERT_CONTEXT pCertContext, DWORD dwType, DWORD dwFlags, void *pvTypePara, LPSTR pszNameString, DWORD cchNameString)
    {
        /* CERT_NAME_ISSUER_FLAG selects the certificate's issuer (rather than
   subject) name; guarded in case the wincrypt headers this TU sees predate
   it. */
#ifndef CERT_NAME_ISSUER_FLAG
#define CERT_NAME_ISSUER_FLAG 0x1
#endif
/* Rotating pool of plausible, genuinely third-party (non-Microsoft)
   code-signing CA common names. The forced value (DigiCert ...) leads the
   pool; Sectigo / GlobalSign / Google / Adobe follow so the forged issuer
   set is diverse enough to clear the sample's distinct-non-MS-issuer floor
   as well as its Microsoft-dominance ratio. IsMicrosoftIssuer() matches none
   of these. */
static const char *mirage_cert_issuers[] = {
    "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1",
    "Sectigo Public Code Signing CA R36",
    "GlobalSign GCC R45 CodeSigning CA 2020",
    "Google Trust Services LLC",
    "Adobe Product Services G3",
};
static unsigned int g_mirage_cert_issuer_calls;
static unsigned int g_mirage_cert_forge_index;
DWORD ret;
lasterror_t lasterror;
const char *forced;
DWORD issuer_total;
DWORD required;

ret = Old_CertGetNameString(pCertContext, dwType, dwFlags, pvTypePara,
    pszNameString, cchNameString);

/* Samples enumerate each Win32 service, resolve its backing executable
 * image, and read that image's Authenticode issuer common name via
 * CertGetNameString(..., CERT_NAME_ISSUER_FLAG, ...). They feed the issuer
 * string to IsMicrosoftIssuer() and tally microsoft_ratio (fraction of
 * service images signed under a Microsoft issuer), the number of distinct
 * non-Microsoft issuers, and the count of non-Microsoft-signed images. A
 * freshly-imaged analysis VM runs almost exclusively stock, Microsoft-signed
 * services, so microsoft_ratio saturates near 1.0 while distinct_non_ms and
 * non_ms_signed_count stay near zero — the shape the sample flags as a
 * sandbox (microsoft_ratio >= 0.80 AND distinct_non_ms_issuers < 3 AND
 * non_ms_signed_count < 5). For a portion of issuer-name reads, overwrite the
 * returned string with a rotating third-party CA issuer (DigiCert / Sectigo /
 * GlobalSign / Google / Adobe) so the observed Microsoft-dominance ratio
 * falls below 0.80 and the non-MS issuer diversity/count rise past their
 * floors, breaking the detection conjunction. Only issuer reads (dwFlags &
 * CERT_NAME_ISSUER_FLAG) are touched; subject-name reads and every other
 * query pass through untouched. CertGetNameString is a two-pass API (a NULL
 * or zero-length buffer returns the required character count, including the
 * terminating NUL), so both phases are honored. lasterror is preserved around
 * the forged response. */
if (!g_config.no_stealth && (dwFlags & CERT_NAME_ISSUER_FLAG)) {
    issuer_total = (DWORD)(sizeof(mirage_cert_issuers) /
        sizeof(mirage_cert_issuers[0]));

    /* forge three of every four issuer reads, letting the fourth pass
       through genuine: enough forged non-MS issuers to drive
       microsoft_ratio well below 0.80 and raise the distinct-issuer/count
       tallies past their floors, while leaving some authentic reads
       intact */
    if ((g_mirage_cert_issuer_calls % 4) != 3) {
        get_lasterrors(&lasterror);

        forced = mirage_cert_issuers[g_mirage_cert_forge_index % issuer_total];
        g_mirage_cert_forge_index++;

        required = (DWORD)(strlen(forced) + 1);

        if (pszNameString == NULL || cchNameString == 0) {
            /* sizing pass: report the character count the forged issuer
               needs (including the terminating NUL) */
            ret = required;
        } else if (cchNameString >= required) {
            memcpy(pszNameString, forced, required);
            ret = required;
        } else {
            /* buffer too small: copy what fits and NUL-terminate, matching
               CertGetNameString's copy-what-fits behavior */
            memcpy(pszNameString, forced, cchNameString - 1);
            pszNameString[cchNameString - 1] = '\0';
            ret = cchNameString;
        }

        set_lasterrors(&lasterror);
    }

    g_mirage_cert_issuer_calls++;
}

LOQ_nonzero("misc", "iis", "Type", (int)dwType, "Flags", (int)dwFlags,
    "NameString",
    (pszNameString != NULL && cchNameString > 0) ? pszNameString : "");

return ret;
    }

        HOOKDEF(BOOL, WINAPI, ProcessIdToSessionId, DWORD dwProcessId, DWORD *pSessionId)
        {
            BOOL ret;
	lasterror_t lasterror;

	ret = Old_ProcessIdToSessionId(dwProcessId, pSessionId);

	/* Samples enumerate every running PID from the toolhelp snapshot, resolve
	 * each one's session with ProcessIdToSessionId, and compare it against the
	 * active console session (WTSGetActiveConsoleSessionId, typically 1). They
	 * count a process as same-session only when processSessionId ==
	 * consoleSessionId and compute sameSessionRatio = sameSessionProcesses /
	 * totalProcesses. This check treats a low ratio (< 0.30) as a sandbox and a
	 * high one (>= 0.30) as a genuine, single-user interactive workstation.
	 * A freshly-imaged analysis VM may spread its processes across session 0
	 * (services) and other sessions, so the ratio can fall below the threshold
	 * and the sample takes its sandbox-detected branch. Force *pSessionId to the
	 * active console session id (1) for every queried PID so sameSessionProcesses
	 * == totalProcesses and sameSessionRatio saturates at 1.0, landing well above
	 * the 0.30 user-environment threshold and classifying the host as a real
	 * user environment. lasterror is preserved around the forged response. */
	if (!g_config.no_stealth && ret && pSessionId != NULL) {
		get_lasterrors(&lasterror);

		*pSessionId = 1;

		set_lasterrors(&lasterror);
	}

	LOQ_bool("misc", "ii", "ProcessId", dwProcessId,
		"SessionId", pSessionId != NULL ? *pSessionId : 0);

	return ret;
        }

        HOOKDEF(DWORD, WINAPI, WTSGetActiveConsoleSessionId, void)
        {
            DWORD ret;
	lasterror_t lasterror;

	ret = Old_WTSGetActiveConsoleSessionId();

	/* Samples call WTSGetActiveConsoleSessionId to learn which session owns
	 * the physical console and check the result for the 0xFFFFFFFF sentinel,
	 * which the API returns when no session is currently attached to the
	 * console. A headless, freshly-imaged analysis VM with no interactive
	 * user logged on frequently has no attached console session, so the call
	 * yields 0xFFFFFFFF and the sample falls back to classifying the host as
	 * a sandbox. Force a valid interactive console session id (1) so the
	 * probe never hits the 0xFFFFFFFF fallback-to-sandbox path; this also
	 * matches the console session forged into the ProcessIdToSessionId hook,
	 * so the two views of the active session stay consistent and the host
	 * reads as a genuine user environment. lasterror is preserved around the
	 * forged response. */
	if (!g_config.no_stealth) {
		get_lasterrors(&lasterror);

		ret = 1;

		set_lasterrors(&lasterror);
	}

	LOQ_void("misc", "i", "SessionId", ret);

	return ret;
        }

        HOOKDEF(BOOL, WINAPI, Process32Next, HANDLE hSnapshot, LPPROCESSENTRY32 lppe)
        {
            /* Analysis/monitoring/sandbox-helper image names to hide from the
	       process walk. These are the names that inflate the high-integrity
	       "successfullyInspectedProcesses" denominator: the CAPE host tooling
	       (cape.exe, python.exe/pythonw.exe, the capemon-injected analyzer),
	       Sandboxie service processes, and the usual monitoring/debugging
	       utilities from the process_names_to_hide list. Matching is a
	       case-insensitive compare against PROCESSENTRY32.szExeFile. */
	static const char *hide_names[] = {
		"cape.exe",
		"python.exe",
		"pythonw.exe",
		"analyzer.exe",
		"sandboxiedcomlaunch.exe",
		"sandboxierpcss.exe",
		"sbiesvc.exe",
		"procmon.exe",
		"procmon64.exe",
		"procexp.exe",
		"procexp64.exe",
		"x64dbg.exe",
		"x32dbg.exe",
		"ollydbg.exe",
		"windbg.exe",
		"idaq.exe",
		"idaq64.exe",
		"wireshark.exe",
		"fiddler.exe",
		"vmtoolsd.exe",
		"vboxservice.exe",
		"vboxtray.exe",
	};
	BOOL ret;
	lasterror_t lasterror;
	unsigned int i;
	unsigned int n;
	int is_hidden;

	ret = Old_Process32Next(hSnapshot, lppe);

	/* Samples build the set of running processes from
	 * CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS) and walk it with
	 * Process32Next, then inspect each process token's integrity level to
	 * compute lowIntegrityProcessCount / successfullyInspectedProcesses. The
	 * analysis/sandbox helper processes above run at (or are counted as) high
	 * integrity, so leaving them in the walk inflates the denominator of that
	 * ratio and, together with a forged high-integrity own-token, pushes the
	 * ratio toward the "no low-integrity browser/user processes -> bare
	 * sandbox" verdict. Filter those helper entries out of the returned
	 * PROCESSENTRY32 by advancing to the next non-analysis entry: whenever the
	 * genuine Process32Next hands back a hidden image name, transparently call
	 * the original again until a real, non-analysis process (or the genuine
	 * end-of-enumeration) is reached. This also keeps foreign-session helper
	 * processes out of the snapshot so they cannot depress the same-session
	 * ratio. Only the high-integrity denominator shrinks; the low-integrity
	 * SIDs the numerator is built from are ordinary user processes and pass
	 * through untouched, complementing the GetTokenInformation and
	 * ProcessIdToSessionId forges. lasterror is preserved around the forged
	 * response. */
	if (!g_config.no_stealth && lppe != NULL) {
		get_lasterrors(&lasterror);

		n = sizeof(hide_names) / sizeof(hide_names[0]);
		is_hidden = 1;

		while (ret && is_hidden) {
			is_hidden = 0;
			for (i = 0; i < n; i++) {
				if (_stricmp(lppe->szExeFile, hide_names[i]) == 0) {
					is_hidden = 1;
					break;
				}
			}

			if (is_hidden)
				ret = Old_Process32Next(hSnapshot, lppe);
		}

		set_lasterrors(&lasterror);
	}

	LOQ_bool("misc", "s", "ProcessName",
		(ret && lppe != NULL) ? lppe->szExeFile : "");

	return ret;
        }

        HOOKDEF(BOOL, WINAPI, SleepConditionVariableCS, PCONDITION_VARIABLE ConditionVariable, PCRITICAL_SECTION CriticalSection, DWORD dwMilliseconds)
        {
            BOOL ret;
	lasterror_t lasterror;
	ULONGLONG start;
	ULONGLONG elapsed;

	start = GetTickCount64();

	ret = Old_SleepConditionVariableCS(ConditionVariable, CriticalSection, dwMilliseconds);

	/* Samples time this condition-variable wait as a sandbox tell: they
	 * request a long finite timeout (e.g. 120000 ms) on a condition variable
	 * nobody signals, bracket the call with GetTickCount64, and compare the
	 * real wall-clock delta against the requested dwMilliseconds. A sandbox
	 * that shortcuts blocking waits to speed up analysis returns early, so
	 * the measured delta is far below the request (measured <= 30000, or
	 * measured/configured < 0.8) and the sample concludes it is being
	 * accelerated inside an instrumented environment. The transparent answer
	 * is NOT to shorten the wait: honor the full requested duration so the
	 * GetTickCount64 delta equals dwMilliseconds and the ratio sits at ~1.0,
	 * making both the short-wait and ratio branches false. If the underlying
	 * wait timed out early (ret == 0 with ERROR_TIMEOUT) for a finite,
	 * non-zero timeout, pad the remaining time with a real Sleep so the
	 * observed elapsed time matches the requested timeout before returning
	 * FALSE/ERROR_TIMEOUT. A genuine signal (ret != 0) is passed straight
	 * through untouched. */
	if (!g_config.no_stealth && !ret && dwMilliseconds != 0 &&
			dwMilliseconds != INFINITE) {
		get_lasterrors(&lasterror);

		if (lasterror.Win32Error == ERROR_TIMEOUT) {
			elapsed = GetTickCount64() - start;
			if (elapsed < (ULONGLONG)dwMilliseconds) {
				Sleep((DWORD)((ULONGLONG)dwMilliseconds - elapsed));
			}
			/* report a fully-consumed wait: FALSE with ERROR_TIMEOUT
			   (1460), returned only after the padded delay so the
			   bracketing GetTickCount64 reads stay consistent */
			ret = FALSE;
			lasterror.Win32Error = ERROR_TIMEOUT;
		}

		set_lasterrors(&lasterror);
	}

	LOQ_bool("misc", "ii", "Timeout", dwMilliseconds, "Signalled", ret);

	return ret;
        }

        HOOKDEF(void, WINAPI, GetSystemTimePreciseAsFileTime, LPFILETIME lpSystemTimeAsFileTime)
        {
            int ret = 0;
	lasterror_t lasterror;
	ULARGE_INTEGER u;

	Old_GetSystemTimePreciseAsFileTime(lpSystemTimeAsFileTime);

	/* Samples bracket a long sleep with two wall-clock reads and treat too
	 * small a delta as a fast-forwarding sandbox. In C++ they read
	 * std::chrono::system_clock::now() before and after
	 * std::this_thread::sleep_for(1000s); MSVC resolves system_clock::now()
	 * to this very API (GetSystemTimePreciseAsFileTime), so the two reads
	 * that bracket the 1000s sleep both come through here. A sandbox that
	 * shortcuts the sleep to speed up analysis makes the two timestamps only
	 * a couple of real seconds apart, so the measured delta is far below the
	 * requested 1000s (< 999.0 seconds) and the sample flags the host as a
	 * sandbox. The transparent answer is to forge this wall-clock source so
	 * it advances in lock-step with the time capemon skips: capemon
	 * accumulates every millisecond it shortcuts from a blocking/sleeping
	 * call into the shared time_skipped counter, so adding that accrued skew
	 * (milliseconds, converted to FILETIME 100ns units) to the returned
	 * FILETIME makes the post-sleep read sit ~1000s above the pre-sleep read.
	 * The measured delta is driven back onto the requested duration
	 * (post - pre >= 999.0 s) regardless of how little real time actually
	 * passed, so the sample sees a genuine real-user elapsed time. Using the
	 * same shared time_skipped keeps this wall-clock view consistent with the
	 * tick-based views (GetTickCount64 et al.). lasterror is preserved. */
	if (!g_config.no_stealth && lpSystemTimeAsFileTime != NULL) {
		get_lasterrors(&lasterror);

		u.LowPart = lpSystemTimeAsFileTime->dwLowDateTime;
		u.HighPart = lpSystemTimeAsFileTime->dwHighDateTime;
		u.QuadPart += (ULONGLONG)time_skipped.QuadPart * 10000ull;
		lpSystemTimeAsFileTime->dwLowDateTime = u.LowPart;
		lpSystemTimeAsFileTime->dwHighDateTime = u.HighPart;

		set_lasterrors(&lasterror);
	}

	LOQ_void("misc", "i", "SystemTimeAsFileTime",
		lpSystemTimeAsFileTime != NULL ? (int)lpSystemTimeAsFileTime->dwLowDateTime : 0);

	return;
        }

        HOOKDEF(DWORD, WINAPI, WaitForSingleObject, HANDLE hHandle, DWORD dwMilliseconds)
        {
            DWORD ret;
	lasterror_t lasterror;

	ret = Old_WaitForSingleObject(hHandle, dwMilliseconds);

	/* Samples spawn a worker thread that genuinely blocks in
	 * WaitForSingleObject(event, INFINITE) on a manual-reset event nobody
	 * signals, sleep ~5 minutes to give a sandbox time to disturb the wait,
	 * then non-blocking-poll both the worker-thread handle and the event
	 * handle with WaitForSingleObject(handle, 0). On a real host the thread
	 * is still parked and the event still unsignalled, so both 0-ms polls
	 * return WAIT_TIMEOUT (0x102) and isUserEnvironment stays true. A sandbox
	 * that shortcuts or breaks blocking waits to accelerate analysis lets the
	 * worker's INFINITE wait complete, signalling the thread handle so the
	 * poll returns WAIT_OBJECT_0 (0) — the tell the sample reads as proof the
	 * sandbox forcibly shortened/unblocked the genuine INFINITE wait, flipping
	 * isUserEnvironment to false. Force every non-blocking poll
	 * (dwMilliseconds == 0) to report WAIT_TIMEOUT (0x102) so both the
	 * worker-thread and event polls read 'still blocked, still unsignalled'.
	 * Genuine INFINITE (0xFFFFFFFF) waits are deliberately passed straight
	 * through to the real API untouched: substituting a finite timeout there
	 * would let the worker's INFINITE wait return, signal the thread handle,
	 * and expose the sandbox on the very poll this forge exists to
	 * neutralise. lasterror is preserved around the forged response. */
	if (!g_config.no_stealth && dwMilliseconds == 0 && ret != WAIT_TIMEOUT) {
		get_lasterrors(&lasterror);

		ret = WAIT_TIMEOUT;

		set_lasterrors(&lasterror);
	}

	LOQ_msgwait("misc", "pi", "Handle", hHandle, "Milliseconds", dwMilliseconds);

	return ret;
        }

        HOOKDEF(BOOL, WINAPI, GetQueuedCompletionStatus, HANDLE CompletionPort, LPDWORD lpNumberOfBytesTransferred, PULONG_PTR lpCompletionKey, LPOVERLAPPED *lpOverlapped, DWORD dwMilliseconds)
        {
            BOOL ret;
	lasterror_t lasterror;
	ULONGLONG start;
	ULONGLONG elapsed;

	start = GetTickCount64();

	ret = Old_GetQueuedCompletionStatus(CompletionPort, lpNumberOfBytesTransferred, lpCompletionKey, lpOverlapped, dwMilliseconds);

	/* Samples time this dequeue as a sandbox tell: they create a bare I/O
	 * completion port that no packets are ever posted to, request a long
	 * finite timeout (120000 ms), bracket the GetQueuedCompletionStatus call
	 * with two GetTickCount64 reads, and compare the real wall-clock delta
	 * against the requested dwMilliseconds. On a genuine host an empty IOCP
	 * blocks for the full timeout and the call finally fails with FALSE and
	 * GetLastError() == WAIT_TIMEOUT (0x102). A sandbox that shortcuts
	 * blocking waits to speed up analysis returns early, so any of
	 * measuredWaitDurationMs < 30000, ratio (measured/requested) < 70%,
	 * return == TRUE, or lastError != WAIT_TIMEOUT exposes the acceleration.
	 * The transparent answer is NOT to short-circuit the wait: honor the full
	 * requested duration so the GetTickCount64 delta equals dwMilliseconds and
	 * the ratio sits at ~1.0. If the underlying dequeue timed out early
	 * (ret == FALSE with WAIT_TIMEOUT) on a finite, non-zero timeout, pad the
	 * remaining time with a real Sleep so the observed elapsed time genuinely
	 * matches the requested timeout (never fast-forwarded/skipped), then leave
	 * the completion out-params untouched and return FALSE with GetLastError()
	 * == WAIT_TIMEOUT so both the measured GetTickCount64 delta and the error
	 * code match real host behavior and the spurious completion trigger is
	 * avoided. Blocking for real also keeps the sample's own GetTickCount64
	 * readings correct even when that call resolves to a direct
	 * KUSER_SHARED_DATA read the monitor never sees. A genuine completion
	 * packet (ret != FALSE) is passed straight through untouched. lasterror is
	 * preserved around the forged response. */
	if (!g_config.no_stealth && !ret && dwMilliseconds != 0 &&
			dwMilliseconds != INFINITE) {
		get_lasterrors(&lasterror);

		if (lasterror.Win32Error == WAIT_TIMEOUT) {
			elapsed = GetTickCount64() - start;
			if (elapsed < (ULONGLONG)dwMilliseconds) {
				Sleep((DWORD)((ULONGLONG)dwMilliseconds - elapsed));
			}
			/* report a fully-consumed empty-port wait: FALSE with
			   WAIT_TIMEOUT (0x102), returned only after the padded delay so
			   the bracketing GetTickCount64 reads stay consistent */
			ret = FALSE;
			lasterror.Win32Error = WAIT_TIMEOUT;
		}

		set_lasterrors(&lasterror);
	}

	LOQ_bool("misc", "pii", "CompletionPort", CompletionPort,
		"Milliseconds", dwMilliseconds,
		"NumberOfBytesTransferred",
		lpNumberOfBytesTransferred != NULL ? *lpNumberOfBytesTransferred : 0);

	return ret;
        }

        HOOKDEF(BOOL, WINAPI, QueryPerformanceCounter, LARGE_INTEGER *lpPerformanceCount)
        {
            /* Forged counter frequency (10 MHz). MUST match the value the companion
	   QueryPerformanceFrequency hook pins (MIRAGE_QPF_FORCED_FREQ): the sample
	   recovers elapsed time as (counterAfter - counterBefore) / frequency, so the
	   synthetic ticks we emit here are only coherent if expressed in the same
	   10 MHz timebase the sample divides by. A 10 MHz counter ticks once every
	   100 ns, which is exactly the unit capemon's time_skipped accumulator uses,
	   so the accrued skipped-sleep time folds into this timebase 1:1. */
	#define MIRAGE_QPC_FORCED_FREQ 10000000ll
	BOOL ret;
	lasterror_t lasterror;
	static LARGE_INTEGER real_freq;
	static int freq_initialized;
	static LONGLONG base_real;
	static int base_initialized;
	LONGLONG real_now;
	LONGLONG real_delta;
	LONGLONG virt_qpc;

	ret = Old_QueryPerformanceCounter(lpPerformanceCount);

	/* Samples bracket a long blocking sleep with two QueryPerformanceCounter
	 * reads to catch a sandbox that shortcuts sleeps to accelerate analysis:
	 * they read counterBefore, call Sleep(300000) (kRequestedSleepMs), read
	 * counterAfter, then compute
	 *   measuredElapsedMs = (counterAfter - counterBefore) / frequency * 1000
	 *   elapsedRatio      = measuredElapsedMs / kRequestedSleepMs
	 * and flag the host when elapsedRatio < 0.95. capemon skips such blocking
	 * sleeps and returns from Sleep()/NtDelayExecution early, so the raw counter
	 * advances by only the handful of real milliseconds that actually elapsed and
	 * the measured delta collapses to a tiny fraction of the requested 300000 ms,
	 * driving elapsedRatio far below 0.95 and revealing the accelerated
	 * environment.
	 *
	 * The transparent answer is to maintain a virtual performance counter that
	 * advances by the amount of Sleep/NtDelayExecution time the sandbox skipped,
	 * so each returned reading is consistent with the full requested sleep
	 * duration. capemon accumulates every 100 ns it shortcuts from a
	 * blocking/sleeping call into the shared time_skipped counter (extern
	 * LARGE_INTEGER, in 100 ns units). On the first call seed a base from the
	 * genuine QPC value; on every call report
	 *   virt_qpc = (real_now - base_real) rescaled into the forged 10 MHz
	 *              timebase   +   time_skipped (100 ns == one 10 MHz tick, 1:1).
	 * Because a 10 MHz tick is exactly 100 ns, the accrued skip converts straight
	 * into forged ticks, so counterAfter.QuadPart ends up ~=
	 * counterBefore.QuadPart + frequency * kRequestedSleepMs / 1000 across the
	 * skipped sleep and elapsedRatio settles at ~1.0 (>= 0.95). Folding the skew
	 * into every read equally means intervals that contained no skipped sleep are
	 * undistorted, and expressing the counter in the same 10 MHz units the
	 * QueryPerformanceFrequency hook reports keeps the microsecond conversion
	 * coherent. Working from a base delta (rather than scaling the raw counter)
	 * keeps the 10 MHz rescale clear of 64-bit overflow. lasterror is preserved
	 * around the forged response. */
	if (!g_config.no_stealth && ret && lpPerformanceCount != NULL) {
		get_lasterrors(&lasterror);

		if (!freq_initialized) {
			if (!QueryPerformanceFrequency(&real_freq))
				real_freq.QuadPart = 0;
			freq_initialized = 1;
		}

		real_now = lpPerformanceCount->QuadPart;

		if (!base_initialized) {
			base_real = real_now;
			base_initialized = 1;
		}

		real_delta = real_now - base_real;
		if (real_delta < 0)
			real_delta = 0;

		/* genuine time elapsed since the first call, expressed in the forged
		   10 MHz timebase the sample divides by */
		if (real_freq.QuadPart > 0)
			virt_qpc = real_delta * MIRAGE_QPC_FORCED_FREQ / real_freq.QuadPart;
		else
			virt_qpc = real_delta;

		/* fold in the sleep/NtDelayExecution time capemon skipped: time_skipped
		   is in 100 ns units and a 10 MHz tick is exactly 100 ns, so the accrued
		   skip converts 1:1 into forged ticks and the post-sleep read reflects
		   the full requested duration */
		virt_qpc += (LONGLONG)time_skipped.QuadPart;

		lpPerformanceCount->QuadPart = virt_qpc;

		set_lasterrors(&lasterror);
	}

	LOQ_bool("misc", "i", "PerformanceCount",
		lpPerformanceCount != NULL ? (int)lpPerformanceCount->LowPart : 0);

	return ret;
        }

        HOOKDEF(int, WINAPI, MessageBoxA, HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType)
        {
            /* The sample's own TIMEOUT_CODE: the value its message-box wrapper
	 * yields when the dialog was left untouched until a forced timeout,
	 * i.e. no button was ever clicked. */
	#define MIRAGE_MSGBOX_TIMEOUT_CODE 2
	int ret;
	lasterror_t lasterror;

	/* Samples use a MessageBoxA return value as a proxy for UI interaction
	 * to tell an automated sandbox from a patient human user. They pop a
	 * dialog and read the result: any button click (IDOK/IDCANCEL/...) means
	 * someone/something dismissed it, and because a sandbox's UI auto-clicker
	 * dismisses dialogs instantly they treat return != IDTIMEOUT as an
	 * "automated/test environment", whereas a real, patient user leaves the
	 * dialog untouched until it times out. The transparent answer is to
	 * emulate that patient user who never interacts: do NOT call the original
	 * MessageBoxA (which would actually display the dialog and let CAPE's UI
	 * auto-clicker dismiss it early, producing a button code), and instead
	 * unconditionally return the sample's TIMEOUT_CODE (2) so the dialog reads
	 * as having timed out with no interaction. That steers the sample into its
	 * executeTaskRoutine() 'user environment' branch; skipping the original
	 * call also suppresses CAPE's auto-clicker for this dialog, since no window
	 * is ever shown. lasterror is preserved around the forged response. */
	if (!g_config.no_stealth) {
		get_lasterrors(&lasterror);

		ret = MIRAGE_MSGBOX_TIMEOUT_CODE;

		set_lasterrors(&lasterror);
	} else {
		ret = Old_MessageBoxA(hWnd, lpText, lpCaption, uType);
	}

	LOQ_nonzero("window", "ssi", "Text", lpText != NULL ? lpText : "",
		"Caption", lpCaption != NULL ? lpCaption : "",
		"Type", uType);

	return ret;
        }

    HOOKDEF(BOOL, WINAPI, GetGUIThreadInfo, DWORD idThread, LPGUITHREADINFO lpgui)
    {
        /* GUI_CARETBLINKING marks the queried thread's caret as present and
 * blinking; define it locally in case the SDK headers this TU sees
 * predate it. */
#ifndef GUI_CARETBLINKING
#define GUI_CARETBLINKING 0x00000001
#endif
/* Monotonic call counter driving the synthetic caret's motion so
 * successive successful samples observe a caret that keeps moving. */
static unsigned int mirage_caret_tick;
BOOL ret;
lasterror_t lasterror;
HWND caret_hwnd;
LONG dx;
LONG dy;

ret = Old_GetGUIThreadInfo(idThread, lpgui);

/* Samples call GetGUIThreadInfo(idThread=0) to inspect the
 * foreground GUI thread's caret state as a liveness/interaction
 * tell: they read GUITHREADINFO.hwndCaret and rcCaret repeatedly and
 * treat an absent caret (hwndCaret == NULL) or a caret rectangle
 * that never changes across successive reads as the shape of an
 * idle, headless analysis VM with no real interactive editing. On a
 * freshly-imaged sandbox with nobody typing into an edit control
 * there is frequently no blinking caret at all, so the check flags
 * the host (caretPresent ratio too low, or fewer than a few caret-
 * movement changes over the observation window). The transparent
 * answer is to make the caret look present and alive: advertise
 * GUI_CARETBLINKING, point hwndCaret at a live top-level window, and
 * nudge rcCaret's origin a few pixels each call (wrapping inside a
 * small box so it keeps changing without drifting away) so
 * consecutive samples see a moving caret. Always report success so
 * the read never fails over the observation window. lasterror is
 * preserved around the forged response. */
if (!g_config.no_stealth && lpgui != NULL &&
        lpgui->cbSize >= sizeof(GUITHREADINFO)) {
    get_lasterrors(&lasterror);

    caret_hwnd = GetForegroundWindow();
    if (caret_hwnd == NULL)
        caret_hwnd = GetDesktopWindow();

    lpgui->flags |= GUI_CARETBLINKING;
    lpgui->hwndCaret = caret_hwnd;

    /* advance the caret origin by a few pixels per call, wrapping
       inside a small box so the reported position keeps changing
       across at least a few successive successful samples */
    dx = (LONG)((mirage_caret_tick * 3) % 120);
    dy = (LONG)((mirage_caret_tick * 2) % 80);
    lpgui->rcCaret.left = 100 + dx;
    lpgui->rcCaret.top = 100 + dy;
    lpgui->rcCaret.right = lpgui->rcCaret.left + 2;
    lpgui->rcCaret.bottom = lpgui->rcCaret.top + 16;

    mirage_caret_tick++;

    ret = TRUE;

    set_lasterrors(&lasterror);
}

LOQ_bool("window", "ip", "Thread", idThread, "hwndCaret",
    (ret && lpgui != NULL) ? lpgui->hwndCaret : NULL);

return ret;
    }

    HOOKDEF(DWORD, WINAPI, GetClipboardSequenceNumber, void)
    {
        /* Monotonic per-call sequence number handed back to the sample.
 * Seeded at a plausible non-zero base (0x1F) so the very first read
 * already looks like a clipboard that has seen some prior activity,
 * and advanced by 1..3 on every invocation so no two successive
 * reads ever match. */
static DWORD mirage_clip_seq = 0x1F;
static unsigned int mirage_clip_tick;
DWORD ret;
lasterror_t lasterror;

ret = Old_GetClipboardSequenceNumber();

/* Samples poll GetClipboardSequenceNumber on a fixed cadence (e.g.
 * every 5s across a 5-minute window) and watch whether the value
 * ever changes: they compare currentSequenceNumber against the
 * previous read and count how many times it moved
 * (clipboardUpdateCount), treating clipboardUpdateCount == 0 (the
 * value never changes across successive polls) as an idle, headless
 * sandbox with no interactive user touching the clipboard. On a
 * freshly-imaged analysis VM the sequence number is static, so
 * clipboardUpdateCount stays at 0 and checkCondition() flags the
 * host. The transparent answer is to make the clipboard look
 * actively used: return a distinct, monotonically incrementing value
 * on every call (stepping by 1..3 so the growth reads like sporadic
 * real clipboard edits rather than a rigid counter) so each poll
 * observes currentSequenceNumber != lastSequenceNumber, driving
 * clipboardUpdateCount above 0 and making the host read as a live
 * user environment. lasterror is preserved around the forged
 * response. */
if (!g_config.no_stealth) {
    get_lasterrors(&lasterror);

    ret = mirage_clip_seq;
    /* advance by 1..3 for the next poll (step cycles 1, 2, 3) */
    mirage_clip_seq += 1 + (mirage_clip_tick % 3);
    mirage_clip_tick++;

    set_lasterrors(&lasterror);
}

LOQ_void("window", "i", "SequenceNumber", ret);

return ret;
    }

    HOOKDEF(SHORT, WINAPI, GetKeyState, int nVirtKey)
    {
        /* Per-key parity of the synthetic toggle bit. CapsLock and NumLock
 * are tracked independently so each key's own successive reads flip
 * its low-order toggle bit, producing an observable state change on
 * every call to that key regardless of the other. */
static unsigned int mirage_caps_tick;
static unsigned int mirage_num_tick;
SHORT ret;
lasterror_t lasterror;
unsigned int parity;

ret = Old_GetKeyState(nVirtKey);

/* Samples probe for a live human at the keyboard by watching the
 * CapsLock/NumLock toggle state flip: inside a WH_KEYBOARD_LL hook
 * they sample GetKeyState(VK_CAPITAL) & 0x0001 and
 * GetKeyState(VK_NUMLOCK) & 0x0001 over a 60s window and count the
 * number of low-bit (toggle) transitions. A real user tapping Caps
 * or Num Lock produces several flips; a headless analysis VM with no
 * interactive user leaves the toggle bit frozen, so the transition
 * count stays below the threshold (< 3, i.e. totalCount never
 * reaches g_minTotalToggleCountForUserEnv = 4) and the host is
 * classified as a sandbox. The transparent answer is to alternate
 * the returned toggle bit (0x0001) on successive reads of exactly
 * VK_CAPITAL and VK_NUMLOCK so each poll observes a flipped toggle
 * state: within the 60s window this yields well over 3 transitions,
 * pushing totalCount to at least the Patch_site value of 4 and
 * classifying the host as a genuine user environment. The high-order
 * pressed bit and all unrelated virtual keys are passed through
 * untouched. lasterror is preserved around the forged return. */
if (!g_config.no_stealth &&
        (nVirtKey == VK_CAPITAL || nVirtKey == VK_NUMLOCK)) {
    get_lasterrors(&lasterror);

    if (nVirtKey == VK_CAPITAL)
        parity = mirage_caps_tick++;
    else
        parity = mirage_num_tick++;

    /* flip the low-order toggle bit each call so consecutive reads
       register a transition; leave the pressed bit as reported */
    if (parity & 1)
        ret |= (SHORT)0x0001;
    else
        ret &= (SHORT)~0x0001;

    set_lasterrors(&lasterror);
}

LOQ_void("window", "ii", "nVirtKey", nVirtKey, "State", (int)ret);

return ret;
    }