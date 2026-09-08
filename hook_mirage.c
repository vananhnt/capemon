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

/* Shared string helpers for the countermeasures below. Written out longhand
 * rather than leaning on the CRT so they stay usable from hooks that run
 * before/around CRT state, and so the case folding is plain ASCII rather than
 * locale-dependent. */

/* Case-insensitive "does this path end in <suffix>", tolerating a trailing
 * separator on the queried path and treating '/' and '\\' alike. */
static int mirage_path_ends_with_ascii(const char *path, const char *suffix)
{
	size_t path_len = 0;
	size_t suffix_len = 0;
	size_t i;

	if (path == NULL || suffix == NULL)
		return 0;

	while (path[path_len] != '\0')
		path_len++;
	while (suffix[suffix_len] != '\0')
		suffix_len++;

	while (path_len > 0 && (path[path_len - 1] == '\\' || path[path_len - 1] == '/'))
		path_len--;

	if (suffix_len == 0 || path_len < suffix_len)
		return 0;

	path += path_len - suffix_len;

	for (i = 0; i < suffix_len; i++) {
		char a = path[i];
		char b = suffix[i];

		if (a >= 'A' && a <= 'Z')
			a = (char)(a + 32);
		if (b >= 'A' && b <= 'Z')
			b = (char)(b + 32);
		if (a == '/')
			a = '\\';
		if (b == '/')
			b = '\\';
		if (a != b)
			return 0;
	}

	return 1;
}

/* Case-insensitive wcsstr: returns the first occurrence of needle in
 * haystack, or NULL. */
static const wchar_t *mirage_stristr_wide(const wchar_t *haystack, const wchar_t *needle)
{
	const wchar_t *h;
	size_t i = 0;

	if (haystack == NULL || needle == NULL)
		return NULL;

	if (needle[0] == L'\0')
		return haystack;

	for (h = haystack; *h != L'\0'; h++) {
		for (i = 0; needle[i] != L'\0'; i++) {
			wchar_t a = h[i];
			wchar_t b = needle[i];

			if (a >= L'A' && a <= L'Z')
				a = (wchar_t)(a + 32);
			if (b >= L'A' && b <= L'Z')
				b = (wchar_t)(b + 32);
			if (a != b)
				break;
		}
		if (needle[i] == L'\0')
			return h;
	}

	return NULL;
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

        HOOKDEF(BOOL, WINAPI, EnumPrintersA, DWORD Flags, LPSTR Name, DWORD Level, LPBYTE pPrinterEnum, DWORD cbBuf, LPDWORD pcbNeeded, LPDWORD pcReturned)
        {
            BOOL ret;
	lasterror_t lasterror;

	/* Synthetic physical-looking printer injected into the Level-1 enumeration.
	 * 'HP LaserJet 1020' is a real consumer laser model whose name contains none
	 * of the virtual-printer denylist tokens the sample strips (Microsoft Print
	 * to PDF, Microsoft XPS Document Writer, Fax, OneNote for Windows 10, OneNote
	 * (Desktop)), so it survives that filter and lands in physicalPrinters. */
	static const char printer_name[] = "HP LaserJet 1020";

	/* Bytes one PRINTER_INFO_1A record needs: the fixed struct plus its pName
	 * string (sizeof includes the NUL). The spooler packs strings at the high end
	 * of the caller's buffer with the struct array at the low end, so this is the
	 * minimum cbBuf that can hold our single entry. */
	DWORD needed = (DWORD)(sizeof(PRINTER_INFO_1A) + sizeof(printer_name));

	ret = Old_EnumPrintersA(Flags, Name, Level, pPrinterEnum, cbBuf,
		pcbNeeded, pcReturned);

	/* Samples call EnumPrintersA(PRINTER_ENUM_LOCAL|PRINTER_ENUM_CONNECTIONS,
	 * Level 1), read the returned PRINTER_INFO_1A[].pName list, drop the built-in
	 * virtual printers (Microsoft Print to PDF, Microsoft XPS Document Writer,
	 * Fax, OneNote for Windows 10, OneNote (Desktop)), and treat an empty
	 * physicalPrinters list (size() == 0) as proof of a throwaway analysis VM with
	 * no real user hardware, taking the evasive branch. A freshly-imaged sandbox
	 * exposes only those virtual printers, so after filtering physicalPrinters is
	 * empty. To neutralise this, present exactly one synthetic physical printer:
	 * on the sizing pass (buffer absent or too small for our record) report the
	 * inflated *pcbNeeded and fail with ERROR_INSUFFICIENT_BUFFER so the caller
	 * reallocates and calls again; on the data pass (buffer large enough) write a
	 * single PRINTER_INFO_1A whose pName is 'HP LaserJet 1020' — the string packed
	 * at the top of the buffer, the struct at the base — set *pcReturned = 1 and
	 * *pcbNeeded, and return TRUE. The name is not in the virtual-printer denylist,
	 * so it survives the sample's filter and physicalPrinters becomes non-empty,
	 * making the host look like an ordinary desktop with a physical printer. Only
	 * Level 1 is touched (the PRINTER_INFO_1A layout is hardcoded); other levels
	 * pass through untouched. Lasterror is preserved around the buffer write so the
	 * caller still observes a clean success state. */
	if (!g_config.no_stealth && Level == 1 &&
			pcReturned != NULL && pcbNeeded != NULL) {
		if (pPrinterEnum != NULL && cbBuf >= needed) {
			PRINTER_INFO_1A *info = (PRINTER_INFO_1A *)pPrinterEnum;
			char *strdst = (char *)pPrinterEnum + cbBuf - sizeof(printer_name);

			get_lasterrors(&lasterror);

			memcpy(strdst, printer_name, sizeof(printer_name));
			info->Flags = 0;
			info->pName = strdst;
			info->pDescription = strdst;
			info->pComment = NULL;
			*pcReturned = 1;
			*pcbNeeded = needed;
			ret = TRUE;

			set_lasterrors(&lasterror);
		} else {
			/* Sizing pass: force a retry with a buffer big enough for our entry.
			 * ERROR_INSUFFICIENT_BUFFER is the response we want the caller to see,
			 * so lasterror is set deliberately rather than restored here. */
			*pcReturned = 0;
			*pcbNeeded = needed;
			ret = FALSE;
			SetLastError(ERROR_INSUFFICIENT_BUFFER);
		}
	}

	LOQ_bool("misc", "is", "Flags", Flags, "Name", Name);
	return ret;
        }

        HOOKDEF(HANDLE, WINAPI, FindFirstFileW, LPCWSTR lpFileName, LPWIN32_FIND_DATAW lpFindFileData)
        {
            /* Forward declarations for the shared $Recycle.Bin cursor and entry
	 * writer, defined alongside the companion FindNextFileW hook in
	 * hook_file.c. */
	extern LONG g_mirage_recyclebin_index;
	extern void mirage_recyclebin_fill(LPWIN32_FIND_DATAW lpFindFileData, LONG index);

	HANDLE ret;
	lasterror_t lasterror;

	ret = Old_FindFirstFileW(lpFileName, lpFindFileData);

	/* Samples ask the shell namespace for CSIDL_BITBUCKET and walk it with
	 * IShellFolder::EnumObjects / IEnumIDList::Next; underneath, the shell
	 * folder enumerates C:\$Recycle.Bin\<SID>\ with FindFirstFileW /
	 * FindNextFileW and the sample counts the $I* metadata entries it gets
	 * back. Fewer than 100 deleted items reads as a freshly-imaged analysis
	 * VM with no user history, so the sample refuses to run. On a real
	 * sandbox image that directory is empty or missing entirely, so the
	 * genuine FindFirstFileW either fails or yields a couple of entries.
	 * When the queried path resolves under C:\$Recycle.Bin, discard the real
	 * enumeration and hand back a sentinel search handle plus the first
	 * synthetic entry; the companion FindNextFileW hook recognises that same
	 * sentinel (0x00000003) and supplies the rest, so the shell folder
	 * enumerator yields 120 $I entries — comfortably past the 100-item
	 * threshold — and the host looks like an ordinary long-lived desktop. */
	if (!g_config.no_stealth && lpFileName != NULL && lpFindFileData != NULL &&
			mirage_stristr_wide(lpFileName, L"$Recycle.Bin")) {
		get_lasterrors(&lasterror);

		/* Release the real search handle, if any, so replacing the
		 * enumeration wholesale doesn't leak it. */
		if (ret != INVALID_HANDLE_VALUE && ret != NULL)
			FindClose(ret);

		g_mirage_recyclebin_index = 0;
		mirage_recyclebin_fill(lpFindFileData, g_mirage_recyclebin_index++);

		ret = (HANDLE)(ULONG_PTR)0x00000003;

		lasterror.Win32Error = ERROR_SUCCESS;
		set_lasterrors(&lasterror);
	}

	LOQ_handle("misc", "F", "FileName", lpFileName);
	return ret;
        }

        HOOKDEF(DWORD, WINAPI, GetFileAttributesW, LPCWSTR lpFileName)
        {
            DWORD ret;
	lasterror_t lasterror;

	ret = Old_GetFileAttributesW(lpFileName);

	/* Samples look for shell history left behind by ordinary interactive use:
	 *   %USERPROFILE%\AppData\Roaming\Microsoft\Windows\PowerShell\
	 *       PSReadline\ConsoleHost_history.txt
	 *   %USERPROFILE%\AppData\Local\Microsoft\Windows\cmd.exe\history.txt
	 * and open them with an ifstream, treating is_open() == false as proof of
	 * a freshly-imaged analysis VM that nobody has ever typed a command on.
	 * The CRT's open path stats the file first, so on a sandbox image where
	 * neither file exists GetFileAttributesW returns INVALID_FILE_ATTRIBUTES
	 * and the open short-circuits before any read is attempted. When the
	 * queried path names one of those two shell-history files, report
	 * FILE_ATTRIBUTE_NORMAL (and clear the ERROR_FILE_NOT_FOUND the real call
	 * left behind) so the open proceeds and the host reads as a machine with
	 * genuine interactive shell history. */
	if (!g_config.no_stealth && ret == INVALID_FILE_ATTRIBUTES &&
			lpFileName != NULL &&
			(mirage_stristr_wide(lpFileName, L"ConsoleHost_history.txt") ||
			 mirage_stristr_wide(lpFileName, L"cmd.exe\\history.txt"))) {
		get_lasterrors(&lasterror);

		ret = FILE_ATTRIBUTE_NORMAL;
		lasterror.Win32Error = ERROR_SUCCESS;

		set_lasterrors(&lasterror);
	}

	LOQ_nonnegone("misc", "F", "FileName", lpFileName);
	return ret;
        }

        HOOKDEF(BOOL, WINAPI, ReadFile, HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped)
        {
            BOOL ret;
	lasterror_t lasterror;

	/* GetFinalPathNameByHandleW is Vista and later; resolved lazily so this
	 * countermeasure simply stays inert on older targets. */
	typedef DWORD (WINAPI *_GetFinalPathNameByHandleW)(HANDLE, LPWSTR, DWORD, DWORD);
	static _GetFinalPathNameByHandleW pGetFinalPathNameByHandleW;

	/* Plausible interactive commands, cycled to fill 80 history lines. The mix
	 * of cmd and PowerShell verbs suits either history file. */
	static const char *shellhist_commands[20] = {
		"dir",
		"cd C:\\Users\\%USERNAME%\\Documents",
		"ipconfig /all",
		"Get-Process",
		"cls",
		"notepad notes.txt",
		"Get-ChildItem -Recurse *.log",
		"ping 8.8.8.8",
		"tasklist",
		"cd ..",
		"Get-Service | Where-Object {$_.Status -eq 'Running'}",
		"copy report.docx D:\\backup",
		"net use",
		"Get-Content .\\setup.log -Tail 20",
		"systeminfo",
		"where python",
		"git status",
		"Set-Location $env:USERPROFILE\\Downloads",
		"del *.tmp",
		"Get-EventLog -LogName System -Newest 10"
	};

	/* The synthesised history text, built once on first use. Racing threads
	 * write identical bytes, so no lock is needed. */
	static char shellhist_buf[0x1000];
	static unsigned int shellhist_len;
	static int shellhist_built;

	/* Per-handle read cursors, so a caller reading the file in chunks (or
	 * looping to EOF, as an ifstream/Get-Content style reader does) sees the
	 * synthetic history exactly once and then a clean end-of-file. */
	static HANDLE shellhist_handle[8];
	static unsigned int shellhist_offset[8];
	static unsigned int shellhist_next_slot;

	const wchar_t *needles[2];
	wchar_t path[MAX_PATH * 2];
	const char *cmd;
	size_t cmdlen;
	unsigned int i, j, n, len, remaining;
	int is_history = 0;
	int slot = -1;
	DWORD pathlen, copied;

	ret = Old_ReadFile(hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped);

	/* Samples read the interactive shell history left behind by ordinary use:
	 *   %USERPROFILE%\AppData\Roaming\Microsoft\Windows\PowerShell\
	 *       PSReadline\ConsoleHost_history.txt
	 *   %USERPROFILE%\AppData\Local\Microsoft\Windows\cmd.exe\history.txt
	 * count the lines they get back, and treat a total of 50 or fewer as a
	 * freshly-imaged analysis VM nobody has ever typed commands on. The
	 * companion GetFileAttributesW hook lets the open succeed; on a sandbox
	 * image the file is still absent or empty, so the read itself yields
	 * nothing and the line count stays at zero. Resolving the path from the
	 * handle keeps the tracking inside this one hook: when it names one of
	 * those two history files, substitute 80 CRLF-terminated plausible
	 * commands, report the substituted length in *lpNumberOfBytesRead and
	 * return TRUE, so the counted total lands comfortably above the threshold
	 * and the host reads as a machine with genuine interactive shell history.
	 * The per-handle cursor serves that text once and then reports a normal
	 * EOF (zero bytes, TRUE), so a reader looping to end-of-file terminates. */
	if (!g_config.no_stealth && lpBuffer != NULL && nNumberOfBytesToRead != 0 &&
			hFile != NULL && hFile != INVALID_HANDLE_VALUE) {
		get_lasterrors(&lasterror);

		if (GetFileType(hFile) == FILE_TYPE_DISK) {
			if (pGetFinalPathNameByHandleW == NULL)
				pGetFinalPathNameByHandleW = (_GetFinalPathNameByHandleW)GetProcAddress(
					GetModuleHandleA("kernel32"), "GetFinalPathNameByHandleW");

			if (pGetFinalPathNameByHandleW != NULL) {
				memset(path, 0, sizeof(path));
				pathlen = pGetFinalPathNameByHandleW(hFile, path, (MAX_PATH * 2) - 1, 0);
				if (pathlen != 0 && pathlen < (MAX_PATH * 2)) {
					path[(MAX_PATH * 2) - 1] = L'\0';

					/* Case-insensitive match, folded in place. */
					for (i = 0; path[i] != L'\0'; i++) {
						if (path[i] >= L'A' && path[i] <= L'Z')
							path[i] = (wchar_t)(path[i] + 32);
					}

					needles[0] = L"consolehost_history.txt";
					needles[1] = L"cmd.exe\\history.txt";

					for (n = 0; n < 2 && !is_history; n++) {
						for (i = 0; path[i] != L'\0' && !is_history; i++) {
							for (j = 0; needles[n][j] != L'\0'; j++) {
								if (path[i + j] != needles[n][j])
									break;
							}
							if (needles[n][j] == L'\0')
								is_history = 1;
						}
					}
				}
			}
		}

		if (is_history) {
			if (!shellhist_built) {
				len = 0;
				for (i = 0; i < 80; i++) {
					cmd = shellhist_commands[i % 20];
					cmdlen = strlen(cmd);

					if (len + cmdlen + 2 > sizeof(shellhist_buf))
						break;

					memcpy(shellhist_buf + len, cmd, cmdlen);
					len += (unsigned int)cmdlen;
					shellhist_buf[len++] = '\r';
					shellhist_buf[len++] = '\n';
				}
				shellhist_len = len;
				shellhist_built = 1;
			}

			for (i = 0; i < 8; i++) {
				if (shellhist_handle[i] == hFile) {
					slot = (int)i;
					break;
				}
			}
			if (slot < 0) {
				for (i = 0; i < 8; i++) {
					if (shellhist_handle[i] == NULL) {
						slot = (int)i;
						break;
					}
				}
			}
			if (slot < 0) {
				/* Table full: recycle the oldest slot round-robin. */
				slot = (int)(shellhist_next_slot % 8);
				shellhist_next_slot++;
			}
			if (shellhist_handle[slot] != hFile) {
				shellhist_handle[slot] = hFile;
				shellhist_offset[slot] = 0;
			}

			if (shellhist_offset[slot] > shellhist_len)
				shellhist_offset[slot] = shellhist_len;

			remaining = shellhist_len - shellhist_offset[slot];
			copied = (DWORD)(remaining < nNumberOfBytesToRead ? remaining : nNumberOfBytesToRead);

			if (copied != 0)
				memcpy(lpBuffer, shellhist_buf + shellhist_offset[slot], copied);
			shellhist_offset[slot] += copied;

			if (lpNumberOfBytesRead != NULL)
				*lpNumberOfBytesRead = copied;

			ret = TRUE;
			lasterror.Win32Error = ERROR_SUCCESS;
			lasterror.NtstatusError = 0;
		}

		set_lasterrors(&lasterror);
	}

	LOQ_bool("misc", "pi", "FileHandle", hFile, "Length", nNumberOfBytesToRead);
	return ret;
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