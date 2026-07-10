/*
Cuckoo Sandbox - Automated Malware Analysis
Copyright (C) 2010-2015 Cuckoo Sandbox Developers, Optiv, Inc. (brad.spengler@optiv.com)

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <stdio.h>
#include "ntapi.h"
#include "hooking.h"
#include "misc.h"
#include "pipe.h"
#include "log.h"

#define StringAtomSize 0x100

extern void ProcessMessage(DWORD ProcessId, DWORD ThreadId);
extern void DumpSectionViewsForPid(DWORD Pid);

typedef DWORD (WINAPI * __GetWindowThreadProcessId)(
	__in HWND hWnd,
	__out_opt LPDWORD lpdwProcessId
);

__GetWindowThreadProcessId _GetWindowThreadProcessId;

DWORD WINAPI our_GetWindowThreadProcessId(
	__in HWND hWnd,
	__out_opt LPDWORD lpdwProcessId
) {
	lasterror_t lasterror;
	DWORD ret;

	get_lasterrors(&lasterror);
	if (!_GetWindowThreadProcessId) {
		_GetWindowThreadProcessId = (__GetWindowThreadProcessId)GetProcAddress(LoadLibraryA("user32"), "GetWindowThreadProcessId");
	}
	ret = _GetWindowThreadProcessId(hWnd, lpdwProcessId);
	set_lasterrors(&lasterror);
	return ret;
}

DWORD WINAPI GetThreadProcessId(
	__in DWORD ThreadId
) {
	lasterror_t lasterror;
	DWORD ret = 0;

	get_lasterrors(&lasterror);

	HANDLE hThread = OpenThread(THREAD_QUERY_LIMITED_INFORMATION, FALSE, ThreadId);
	if (hThread) {
		ret = GetProcessIdOfThread(hThread);
		CloseHandle(hThread);
	}

	set_lasterrors(&lasterror);
	return ret;
}

typedef DWORD(WINAPI * __GetClassNameA)(
	_In_  HWND   hWnd,
	_Out_ LPTSTR lpClassName,
	_In_  int	nMaxCount
);

__GetClassNameA _GetClassNameA;

DWORD WINAPI our_GetClassNameA(
	_In_  HWND   hWnd,
	_Out_ LPSTR lpClassName,
	_In_  int	nMaxCount
) {
	lasterror_t lasterror;
	DWORD ret;

	get_lasterrors(&lasterror);
	if (!_GetClassNameA) {
		_GetClassNameA = (__GetClassNameA)GetProcAddress(LoadLibraryA("user32"), "GetClassNameA");
	}
	ret = _GetClassNameA(hWnd, lpClassName, nMaxCount);
	set_lasterrors(&lasterror);
	return ret;
}

HOOKDEF(HWND, WINAPI, FindWindowA,
	__in_opt  LPCTSTR lpClassName,
	__in_opt  LPCTSTR lpWindowName
) {
	// The atom must be in the low-order word of lpClassName;
	// the high-order word must be zero (from MSDN documentation.)
	HWND ret = Old_FindWindowA(lpClassName, lpWindowName);
	if(((DWORD_PTR) lpClassName & 0xffff) == (DWORD_PTR) lpClassName) {
		LOQ_nonnull("windows", "is", "ClassName", lpClassName, "WindowName", lpWindowName);
	}
	else {
		LOQ_nonnull("windows", "ss", "ClassName", lpClassName, "WindowName", lpWindowName);
	}
	return ret;
}

HOOKDEF(HWND, WINAPI, FindWindowW,
	__in_opt  LPWSTR lpClassName,
	__in_opt  LPWSTR lpWindowName
) {
	HWND ret = Old_FindWindowW(lpClassName, lpWindowName);
	if(((DWORD_PTR) lpClassName & 0xffff) == (DWORD_PTR) lpClassName) {
		LOQ_nonnull("windows", "iu", "ClassName", lpClassName, "WindowName", lpWindowName);
	}
	else {
		LOQ_nonnull("windows", "uu", "ClassName", lpClassName, "WindowName", lpWindowName);
	}
	return ret;
}

HOOKDEF(HWND, WINAPI, FindWindowExA,
	__in_opt  HWND hwndParent,
	__in_opt  HWND hwndChildAfter,
	__in_opt  LPCTSTR lpszClass,
	__in_opt  LPCTSTR lpszWindow
) {
	HWND ret = Old_FindWindowExA(hwndParent, hwndChildAfter, lpszClass,
		lpszWindow);

	// lpszClass can be one of the predefined window controls.. which lay in
	// the 0..ffff range
	if(((DWORD_PTR) lpszClass & 0xffff) == (DWORD_PTR) lpszClass) {
		LOQ_nonnull("windows", "is", "ClassName", lpszClass, "WindowName", lpszWindow);
	}
	else {
		LOQ_nonnull("windows", "ss", "ClassName", lpszClass, "WindowName", lpszWindow);
	}
	return ret;
}

HOOKDEF(HWND, WINAPI, FindWindowExW,
	__in_opt  HWND hwndParent,
	__in_opt  HWND hwndChildAfter,
	__in_opt  LPWSTR lpszClass,
	__in_opt  LPWSTR lpszWindow
) {
	HWND ret = Old_FindWindowExW(hwndParent, hwndChildAfter, lpszClass,
		lpszWindow);
	// lpszClass can be one of the predefined window controls.. which lay in
	// the 0..ffff range
	if(((DWORD_PTR) lpszClass & 0xffff) == (DWORD_PTR) lpszClass) {
		LOQ_nonnull("windows", "iu", "ClassName", lpszClass, "WindowName", lpszWindow);
	}
	else {
		LOQ_nonnull("windows", "uu", "ClassName", lpszClass, "WindowName", lpszWindow);
	}
	return ret;
}

HOOKDEF(BOOL, WINAPI, PostMessageA,
	_In_  HWND hWnd,
	_In_  UINT Msg,
	_In_  WPARAM wParam,
	_In_  LPARAM lParam
) {
	BOOL ret = Old_PostMessageA(hWnd, Msg, wParam, lParam);

	LOQ_bool("windows", "ph", "WindowHandle", hWnd, "Message", Msg);

	return ret;
}

HOOKDEF(BOOL, WINAPI, PostMessageW,
	_In_  HWND hWnd,
	_In_  UINT Msg,
	_In_  WPARAM wParam,
	_In_  LPARAM lParam
) {
	BOOL ret = Old_PostMessageW(hWnd, Msg, wParam, lParam);

	LOQ_bool("windows", "ph", "WindowHandle", hWnd, "Message", Msg);

	return ret;
}

HOOKDEF(BOOL, WINAPI, PostThreadMessageA,
	_In_  DWORD idThread,
	_In_  UINT Msg,
	_In_  WPARAM wParam,
	_In_  LPARAM lParam
) {
	BOOL ret = Old_PostThreadMessageA(idThread, Msg, wParam, lParam);

	DWORD pid = GetThreadProcessId(idThread);

	if (pid && pid != GetCurrentProcessId()) {
		DumpSectionViewsForPid(pid);
		ProcessMessage(pid, 0);
	}

	LOQ_bool("windows", "iii", "ProcessId", pid, "ThreadId", idThread, "Message", Msg);

	return ret;
}

HOOKDEF(BOOL, WINAPI, PostThreadMessageW,
	_In_  DWORD idThread,
	_In_  UINT Msg,
	_In_  WPARAM wParam,
	_In_  LPARAM lParam
) {
	BOOL ret = Old_PostThreadMessageW(idThread, Msg, wParam, lParam);

	DWORD pid = GetThreadProcessId(idThread);

	if (pid && pid != GetCurrentProcessId()) {
		DumpSectionViewsForPid(pid);
		ProcessMessage(pid, 0);
	}

	LOQ_bool("windows", "iii", "ProcessId", pid, "ThreadId", idThread, "Message", Msg);

	return ret;
}

HOOKDEF(BOOL, WINAPI, SendMessageA,
	_In_  HWND hWnd,
	_In_  UINT Msg,
	_In_  WPARAM wParam,
	_In_  LPARAM lParam
) {
	BOOL ret = Old_SendMessageA(hWnd, Msg, wParam, lParam);

	LOQ_bool("windows", "ph", "WindowHandle", hWnd, "Message", Msg);

	return ret;
}

HOOKDEF(BOOL, WINAPI, SendMessageW,
	_In_  HWND hWnd,
	_In_  UINT Msg,
	_In_  WPARAM wParam,
	_In_  LPARAM lParam
	) {
	BOOL ret = Old_SendMessageW(hWnd, Msg, wParam, lParam);

	LOQ_bool("windows", "ph", "WindowHandle", hWnd, "Message", Msg);

	return ret;
}

HOOKDEF(BOOL, WINAPI, SendNotifyMessageA,
	_In_  HWND hWnd,
	_In_  UINT Msg,
	_In_  WPARAM wParam,
	_In_  LPARAM lParam
) {
	BOOL ret;
	DWORD pid;
	lasterror_t lasterror;

	ret = Old_SendNotifyMessageA(hWnd, Msg, wParam, lParam);

	LOQ_bool("windows", "ph", "WindowHandle", hWnd, "Message", Msg);

	get_lasterrors(&lasterror);
	if (hWnd) {
		our_GetWindowThreadProcessId(hWnd, &pid);
		if (pid != GetCurrentProcessId()) {
			DumpSectionViewsForPid(pid);
			ProcessMessage(pid, 0);
		}
	}
	set_lasterrors(&lasterror);

	return ret;
}

HOOKDEF(BOOL, WINAPI, SendNotifyMessageW,
	_In_  HWND hWnd,
	_In_  UINT Msg,
	_In_  WPARAM wParam,
	_In_  LPARAM lParam
	) {
	BOOL ret;
	DWORD pid;
	lasterror_t lasterror;

	ret = Old_SendNotifyMessageW(hWnd, Msg, wParam, lParam);

	LOQ_bool("windows", "ph", "WindowHandle", hWnd, "Message", Msg);

	get_lasterrors(&lasterror);
	if (hWnd) {
		our_GetWindowThreadProcessId(hWnd, &pid);
		if (pid != GetCurrentProcessId()) {
			DumpSectionViewsForPid(pid);
			ProcessMessage(pid, 0);
		}
	}
	set_lasterrors(&lasterror);

	return ret;
}

HOOKDEF(LONG, WINAPI, SetWindowLongA,
	_In_ HWND hWnd,
	_In_ int nIndex,
	_In_ LONG dwNewLong
	) {
	DWORD pid;
	lasterror_t lasterror;
	LONG ret;
	BOOL isbad = FALSE;

	ret = Old_SetWindowLongA(hWnd, nIndex, dwNewLong);

	get_lasterrors(&lasterror);
	if (nIndex == 0 && hWnd) {
		our_GetWindowThreadProcessId(hWnd, &pid);
		if (pid != GetCurrentProcessId()) {
			char classname[StringAtomSize];
			memset(classname, 0, StringAtomSize);
			our_GetClassNameA(hWnd, classname, StringAtomSize);
			if (!stricmp(classname, "Shell_TrayWnd")) {
				DumpSectionViewsForPid(pid);
				ProcessMessage(pid, 0);
				isbad = TRUE;
			}
		}
	}
	set_lasterrors(&lasterror);

	if (isbad)
		LOQ_nonzero("windows", "pip", "WindowHandle", hWnd, "Index", nIndex, "NewLong", dwNewLong);

	return ret;
}

HOOKDEF(LONG_PTR, WINAPI, SetWindowLongPtrA,
	_In_ HWND hWnd,
	_In_ int nIndex,
	_In_ LONG_PTR dwNewLong
	) {
	DWORD pid;
	lasterror_t lasterror;
	LONG_PTR ret;
	BOOL isbad = FALSE;

	ret = Old_SetWindowLongPtrA(hWnd, nIndex, dwNewLong);

	get_lasterrors(&lasterror);
	if (nIndex == 0 && hWnd) {
		our_GetWindowThreadProcessId(hWnd, &pid);
		if (pid != GetCurrentProcessId()) {
			char classname[StringAtomSize];
			memset(classname, 0, StringAtomSize);
			our_GetClassNameA(hWnd, classname, StringAtomSize);
			if (!stricmp(classname, "Shell_TrayWnd")) {
				DumpSectionViewsForPid(pid);
				ProcessMessage(pid, 0);
				isbad = TRUE;
			}
		}
	}
	set_lasterrors(&lasterror);

	if (isbad)
		LOQ_nonzero("windows", "pip", "WindowHandle", hWnd, "Index", nIndex, "NewLong", dwNewLong);

	return ret;
}

HOOKDEF(LONG, WINAPI, SetWindowLongW,
	_In_ HWND hWnd,
	_In_ int nIndex,
	_In_ LONG dwNewLong
	) {
	DWORD pid;
	lasterror_t lasterror;
	LONG ret;
	BOOL isbad = FALSE;

	ret = Old_SetWindowLongW(hWnd, nIndex, dwNewLong);

	get_lasterrors(&lasterror);
	if (nIndex == 0 && hWnd) {
		our_GetWindowThreadProcessId(hWnd, &pid);
		if (pid != GetCurrentProcessId()) {
			char classname[StringAtomSize];
			memset(classname, 0, StringAtomSize);
			our_GetClassNameA(hWnd, classname, StringAtomSize);
			if (!stricmp(classname, "Shell_TrayWnd")) {
				DumpSectionViewsForPid(pid);
				ProcessMessage(pid, 0);
				isbad = TRUE;
			}
		}
	}
	set_lasterrors(&lasterror);

	if (isbad)
		LOQ_nonzero("windows", "pip", "WindowHandle", hWnd, "Index", nIndex, "NewLong", dwNewLong);

	return ret;

}

HOOKDEF(LONG_PTR, WINAPI, SetWindowLongPtrW,
	_In_ HWND hWnd,
	_In_ int nIndex,
	_In_ LONG_PTR dwNewLong
	) {
	DWORD pid;
	lasterror_t lasterror;
	LONG_PTR ret;
	BOOL isbad = FALSE;

	ret = Old_SetWindowLongPtrW(hWnd, nIndex, dwNewLong);

	get_lasterrors(&lasterror);
	if (nIndex == 0 && hWnd) {
		our_GetWindowThreadProcessId(hWnd, &pid);
		if (pid != GetCurrentProcessId()) {
			char classname[StringAtomSize];
			memset(classname, 0, StringAtomSize);
			our_GetClassNameA(hWnd, classname, StringAtomSize);
			if (!stricmp(classname, "Shell_TrayWnd")) {
				DumpSectionViewsForPid(pid);
				ProcessMessage(pid, 0);
				isbad = TRUE;
			}
		}
	}
	set_lasterrors(&lasterror);

	if (isbad)
		LOQ_nonzero("windows", "pip", "WindowHandle", hWnd, "Index", nIndex, "NewLong", dwNewLong);

	return ret;

}

HOOKDEF(BOOL, WINAPI, EnumWindows,
	_In_  WNDENUMPROC lpEnumFunc,
	_In_  LPARAM lParam
) {

	BOOL ret = Old_EnumWindows(lpEnumFunc, lParam);
	LOQ_bool("windows", "");
	return ret;
}

HOOKDEF_NOTAIL(WINAPI, CreateWindowExA,
	__in DWORD dwExStyle,
	__in_opt LPCSTR lpClassName,
	__in_opt LPCSTR lpWindowName,
	__in DWORD dwStyle,
	__in int x,
	__in int y,
	__in int nWidth,
	__in int nHeight,
	__in_opt HWND hWndParent,
	__in_opt HMENU hMenu,
	__in_opt HINSTANCE hInstance,
	__in_opt LPVOID lpParam
) {
	HWND ret = (HWND)1;
	// lpClassName can be one of the predefined window controls.. which lay in
	// the 0..ffff range
	if (((DWORD_PTR)lpClassName & 0xffff) == (DWORD_PTR)lpClassName) {
		LOQ_nonnull("windows", "isiiiih", "ClassName", lpClassName, "WindowName", lpWindowName, "x", x, "y", y, "Width", nWidth, "Height", nHeight, "Style", dwStyle);
	}
	else {
		LOQ_nonnull("windows", "ssiiiih", "ClassName", lpClassName, "WindowName", lpWindowName, "x", x, "y", y, "Width", nWidth, "Height", nHeight, "Style", dwStyle);
	}

	return 0;
}

HOOKDEF_NOTAIL(WINAPI, CreateWindowExW,
	__in DWORD dwExStyle,
	__in_opt LPWSTR lpClassName,
	__in_opt LPWSTR lpWindowName,
	__in DWORD dwStyle,
	__in int x,
	__in int y,
	__in int nWidth,
	__in int nHeight,
	__in_opt HWND hWndParent,
	__in_opt HMENU hMenu,
	__in_opt HINSTANCE hInstance,
	__in_opt LPVOID lpParam
) {
	HWND ret = (HWND)1;
	// lpClassName can be one of the predefined window controls.. which lay in
	// the 0..ffff range
	if (((DWORD_PTR)lpClassName & 0xffff) == (DWORD_PTR)lpClassName) {
		LOQ_nonnull("windows", "iuiiiih", "ClassName", lpClassName, "WindowName", lpWindowName, "x", x, "y", y, "Width", nWidth, "Height", nHeight, "Style", dwStyle);
	}
	else {
		LOQ_nonnull("windows", "uuiiiih", "ClassName", lpClassName, "WindowName", lpWindowName, "x", x, "y", y, "Width", nWidth, "Height", nHeight, "Style", dwStyle);
	}
	return 0;
}

HOOKDEF(int, WINAPI, MessageBoxTimeoutW,
	__in HWND hwndOwner,
	__in LPCWSTR lpszText,
	__in LPCWSTR lpszCaption,
	__in UINT wStyle,
	__in WORD wLanguageId,
	__in DWORD dwTimeout
) {
	int ret = Old_MessageBoxTimeoutW(hwndOwner, lpszText, lpszCaption, wStyle, wLanguageId, dwTimeout);
	if (dwTimeout == INFINITE)
		LOQ_zero("windows", "uus", "Text", lpszText, "Caption", lpszCaption, "Timeout", "Infinite");
	else
		LOQ_zero("windows", "uui", "Text", lpszText, "Caption", lpszCaption, "Timeout", dwTimeout);
	return ret;
}


// ---- all unhooked-classified hooks (auto-generated, sanitized types) ----

HOOKDEF(BOOL, WINAPI, AddClipboardFormatListener,
	HWND hwnd
) {
	BOOL ret;
	ret = Old_AddClipboardFormatListener(hwnd);
	LOQ_bool("misc", "p", "hwnd", hwnd);
	return ret;
}

HOOKDEF(BOOL, WINAPI, AttachThreadInput,
	DWORD idAttach,
	DWORD idAttachTo,
	BOOL fAttach
) {
	BOOL ret;
	ret = Old_AttachThreadInput(idAttach, idAttachTo, fAttach);
	LOQ_bool("misc", "hhi", "idAttach", idAttach, "idAttachTo", idAttachTo, "fAttach", fAttach);
	return ret;
}

HOOKDEF(LRESULT, WINAPI, CallNextHookEx,
	HHOOK hhk,
	int nCode,
	WPARAM wParam,
	LPARAM lParam
) {
	LRESULT ret;
	ret = Old_CallNextHookEx(hhk, nCode, wParam, lParam);
	LOQ_nonzero("misc", "pihh", "hhk", hhk, "nCode", nCode, "wParam", wParam, "lParam", lParam);
	return ret;
}

HOOKDEF(BOOL, WINAPI, ChangeClipboardChain,
	HWND hWndRemove,
	HWND hWndNewNext
) {
	BOOL ret;
	ret = Old_ChangeClipboardChain(hWndRemove, hWndNewNext);
	LOQ_bool("misc", "pp", "hWndRemove", hWndRemove, "hWndNewNext", hWndNewNext);
	return ret;
}

HOOKDEF(BOOL, WINAPI, CloseClipboard,
	void
) {
	BOOL ret;
	ret = Old_CloseClipboard();
	LOQ_bool("misc", "");
	return ret;
}

HOOKDEF(LRESULT, WINAPI, DefWindowProc,
	HWND hWnd,
	UINT Msg,
	WPARAM wParam,
	LPARAM lParam
) {
	LRESULT ret;
	ret = Old_DefWindowProc(hWnd, Msg, wParam, lParam);
	LOQ_nonzero("misc", "phhh", "hWnd", hWnd, "Msg", Msg, "wParam", wParam, "lParam", lParam);
	return ret;
}

HOOKDEF(LRESULT, WINAPI, DefWindowProcA,
	HWND hWnd,
	UINT Msg,
	WPARAM wParam,
	LPARAM lParam
) {
	LRESULT ret;
	ret = Old_DefWindowProcA(hWnd, Msg, wParam, lParam);
	LOQ_nonzero("misc", "phhh", "hWnd", hWnd, "Msg", Msg, "wParam", wParam, "lParam", lParam);
	return ret;
}

HOOKDEF(LRESULT, WINAPI, DefWindowProcW,
	HWND hWnd,
	UINT Msg,
	WPARAM wParam,
	LPARAM lParam
) {
	LRESULT ret;
	ret = Old_DefWindowProcW(hWnd, Msg, wParam, lParam);
	LOQ_nonzero("misc", "phhh", "hWnd", hWnd, "Msg", Msg, "wParam", wParam, "lParam", lParam);
	return ret;
}

HOOKDEF(BOOL, WINAPI, DestroyWindow,
	HWND hWnd
) {
	BOOL ret;
	ret = Old_DestroyWindow(hWnd);
	LOQ_bool("misc", "p", "hWnd", hWnd);
	return ret;
}

HOOKDEF(LRESULT, WINAPI, DispatchMessage,
	PVOID lpMsg
) {
	LRESULT ret;
	ret = Old_DispatchMessage(lpMsg);
	LOQ_nonzero("misc", "p", "lpMsg", lpMsg);
	return ret;
}

HOOKDEF(LRESULT, WINAPI, DispatchMessageA,
	PVOID lpMsg
) {
	LRESULT ret;
	ret = Old_DispatchMessageA(lpMsg);
	LOQ_nonzero("misc", "p", "lpMsg", lpMsg);
	return ret;
}

HOOKDEF(LRESULT, WINAPI, DispatchMessageW,
	PVOID lpMsg
) {
	LRESULT ret;
	ret = Old_DispatchMessageW(lpMsg);
	LOQ_nonzero("misc", "p", "lpMsg", lpMsg);
	return ret;
}

HOOKDEF(BOOL, WINAPI, EndDialog,
	HWND hDlg,
	INT_PTR nResult
) {
	BOOL ret;
	ret = Old_EndDialog(hDlg, nResult);
	LOQ_bool("misc", "pi", "hDlg", hDlg, "nResult", nResult);
	return ret;
}

HOOKDEF(BOOL, WINAPI, EnumDisplaySettings,
	LPCTSTR lpszDeviceName,
	DWORD iModeNum,
	PVOID lpDevMode
) {
	BOOL ret;
	ret = Old_EnumDisplaySettings(lpszDeviceName, iModeNum, lpDevMode);
	LOQ_bool("misc", "shp", "lpszDeviceName", lpszDeviceName, "iModeNum", iModeNum, "lpDevMode", lpDevMode);
	return ret;
}

HOOKDEF(BOOL, WINAPI, EnumDisplaySettingsA,
	LPCSTR lpszDeviceName,
	DWORD iModeNum,
	PVOID lpDevMode
) {
	BOOL ret;
	ret = Old_EnumDisplaySettingsA(lpszDeviceName, iModeNum, lpDevMode);
	LOQ_bool("misc", "shp", "lpszDeviceName", lpszDeviceName, "iModeNum", iModeNum, "lpDevMode", lpDevMode);
	return ret;
}

HOOKDEF(DWORD, WINAPI, FormatMessageA,
	DWORD dwFlags,
	LPCVOID lpSource,
	DWORD dwMessageId,
	DWORD dwLanguageId,
	LPSTR lpBuffer,
	DWORD nSize,
	PVOID Arguments
) {
	DWORD ret;
	ret = Old_FormatMessageA(dwFlags, lpSource, dwMessageId, dwLanguageId, lpBuffer, nSize, Arguments);
	LOQ_nonzero("misc", "hphhphp", "dwFlags", dwFlags, "lpSource", lpSource, "dwMessageId", dwMessageId, "dwLanguageId", dwLanguageId, "lpBuffer", lpBuffer, "nSize", nSize, "Arguments", Arguments);
	return ret;
}

HOOKDEF(HWND, WINAPI, GetAncestor,
	HWND hwnd,
	UINT gaFlags
) {
	HWND ret;
	ret = Old_GetAncestor(hwnd, gaFlags);
	LOQ_nonzero("misc", "ph", "hwnd", hwnd, "gaFlags", gaFlags);
	return ret;
}

HOOKDEF(BOOL, WINAPI, GetClassInfoExA,
	HINSTANCE hInstance,
	LPCSTR lpszClass,
	PVOID lpwcx
) {
	BOOL ret;
	ret = Old_GetClassInfoExA(hInstance, lpszClass, lpwcx);
	LOQ_bool("misc", "psp", "hInstance", hInstance, "lpszClass", lpszClass, "lpwcx", lpwcx);
	return ret;
}

HOOKDEF(int, WINAPI, GetClassName,
	HWND hWnd,
	LPTSTR lpClassName,
	int nMaxCount
) {
	int ret;
	ret = Old_GetClassName(hWnd, lpClassName, nMaxCount);
	LOQ_nonzero("misc", "phi", "hWnd", hWnd, "lpClassName", lpClassName, "nMaxCount", nMaxCount);
	return ret;
}

HOOKDEF(HWND, WINAPI, GetClipboardOwner,
	void
) {
	HWND ret;
	ret = Old_GetClipboardOwner();
	LOQ_nonzero("misc", "");
	return ret;
}

HOOKDEF(DWORD, WINAPI, GetClipboardSequenceNumber,
	void
) {
	DWORD ret;
	ret = Old_GetClipboardSequenceNumber();
	LOQ_nonzero("misc", "");
	return ret;
}

HOOKDEF(HWND, WINAPI, GetConsoleWindow,
	void
) {
	HWND ret;
	ret = Old_GetConsoleWindow();
	LOQ_nonzero("misc", "");
	return ret;
}

HOOKDEF(BOOL, WINAPI, GetCursorInfo,
	PVOID pci
) {
	BOOL ret;
	ret = Old_GetCursorInfo(pci);
	LOQ_bool("misc", "p", "pci", pci);
	return ret;
}

HOOKDEF(HDC, WINAPI, GetDC,
	HWND hWnd
) {
	HDC ret;
	ret = Old_GetDC(hWnd);
	LOQ_nonzero("misc", "p", "hWnd", hWnd);
	return ret;
}

HOOKDEF(HWND, WINAPI, GetDesktopWindow,
	void
) {
	HWND ret;
	ret = Old_GetDesktopWindow();
	LOQ_nonzero("misc", "");
	return ret;
}

HOOKDEF(UINT, WINAPI, GetDoubleClickTime,
	void
) {
	UINT ret;
	ret = Old_GetDoubleClickTime();
	LOQ_nonzero("misc", "");
	return ret;
}

HOOKDEF(HWND, WINAPI, GetForegroundWindow,
	void
) {
	HWND ret;
	ret = Old_GetForegroundWindow();
	LOQ_nonzero("misc", "");
	return ret;
}

HOOKDEF(BOOL, WINAPI, GetGUIThreadInfo,
	DWORD idThread,
	PVOID pgui
) {
	BOOL ret;
	ret = Old_GetGUIThreadInfo(idThread, pgui);
	LOQ_bool("misc", "hp", "idThread", idThread, "pgui", pgui);
	return ret;
}

HOOKDEF(SHORT, WINAPI, GetKeyState,
	int nVirtKey
) {
	SHORT ret;
	ret = Old_GetKeyState(nVirtKey);
	LOQ_nonzero("misc", "i", "nVirtKey", nVirtKey);
	return ret;
}

HOOKDEF(BOOL, WINAPI, GetKeyboardLayoutNameA,
	LPSTR pwszKLID
) {
	BOOL ret;
	ret = Old_GetKeyboardLayoutNameA(pwszKLID);
	LOQ_bool("misc", "p", "pwszKLID", pwszKLID);
	return ret;
}

HOOKDEF(BOOL, WINAPI, GetKeyboardState,
	PBYTE lpKeyState
) {
	BOOL ret;
	ret = Old_GetKeyboardState(lpKeyState);
	LOQ_bool("misc", "h", "lpKeyState", lpKeyState);
	return ret;
}

HOOKDEF(BOOL, WINAPI, GetMessage,
	LPMSG lpMsg,
	HWND hWnd,
	UINT wMsgFilterMin,
	UINT wMsgFilterMax
) {
	BOOL ret;
	ret = Old_GetMessage(lpMsg, hWnd, wMsgFilterMin, wMsgFilterMax);
	LOQ_bool("misc", "hphh", "lpMsg", lpMsg, "hWnd", hWnd, "wMsgFilterMin", wMsgFilterMin, "wMsgFilterMax", wMsgFilterMax);
	return ret;
}

HOOKDEF(BOOL, WINAPI, GetMessageA,
	LPMSG lpMsg,
	HWND hWnd,
	UINT wMsgFilterMin,
	UINT wMsgFilterMax
) {
	BOOL ret;
	ret = Old_GetMessageA(lpMsg, hWnd, wMsgFilterMin, wMsgFilterMax);
	LOQ_bool("misc", "hphh", "lpMsg", lpMsg, "hWnd", hWnd, "wMsgFilterMin", wMsgFilterMin, "wMsgFilterMax", wMsgFilterMax);
	return ret;
}

HOOKDEF(BOOL, WINAPI, GetMessageW,
	LPMSG lpMsg,
	HWND hWnd,
	UINT wMsgFilterMin,
	UINT wMsgFilterMax
) {
	BOOL ret;
	ret = Old_GetMessageW(lpMsg, hWnd, wMsgFilterMin, wMsgFilterMax);
	LOQ_bool("misc", "hphh", "lpMsg", lpMsg, "hWnd", hWnd, "wMsgFilterMin", wMsgFilterMin, "wMsgFilterMax", wMsgFilterMax);
	return ret;
}

HOOKDEF(BOOL, WINAPI, GetMonitorInfo,
	HMONITOR hMonitor,
	PVOID lpmi
) {
	BOOL ret;
	ret = Old_GetMonitorInfo(hMonitor, lpmi);
	LOQ_bool("misc", "pp", "hMonitor", hMonitor, "lpmi", lpmi);
	return ret;
}

HOOKDEF(UINT, WINAPI, GetRawInputBuffer,
	PVOID pData,
	PUINT pcbSize,
	UINT cbSizeHeader
) {
	UINT ret;
	ret = Old_GetRawInputBuffer(pData, pcbSize, cbSizeHeader);
	LOQ_nonzero("misc", "phh", "pData", pData, "pcbSize", pcbSize, "cbSizeHeader", cbSizeHeader);
	return ret;
}

HOOKDEF(UINT, WINAPI, GetRawInputData,
	HRAWINPUT hRawInput,
	UINT uiCommand,
	LPVOID pData,
	PUINT pcbSize,
	UINT cbSizeHeader
) {
	UINT ret;
	ret = Old_GetRawInputData(hRawInput, uiCommand, pData, pcbSize, cbSizeHeader);
	LOQ_nonzero("misc", "phphh", "hRawInput", hRawInput, "uiCommand", uiCommand, "pData", pData, "pcbSize", pcbSize, "cbSizeHeader", cbSizeHeader);
	return ret;
}

HOOKDEF(HWND, WINAPI, GetWindow,
	HWND hWnd,
	UINT uCmd
) {
	HWND ret;
	ret = Old_GetWindow(hWnd, uCmd);
	LOQ_nonzero("misc", "ph", "hWnd", hWnd, "uCmd", uCmd);
	return ret;
}

HOOKDEF(LONG_PTR, WINAPI, GetWindowLongPtr,
	HWND hWnd,
	int nIndex
) {
	LONG_PTR ret;
	ret = Old_GetWindowLongPtr(hWnd, nIndex);
	LOQ_nonzero("misc", "pi", "hWnd", hWnd, "nIndex", nIndex);
	return ret;
}

HOOKDEF(LONG_PTR, WINAPI, GetWindowLongPtrA,
	HWND hWnd,
	int nIndex
) {
	LONG_PTR ret;
	ret = Old_GetWindowLongPtrA(hWnd, nIndex);
	LOQ_nonzero("misc", "pi", "hWnd", hWnd, "nIndex", nIndex);
	return ret;
}

HOOKDEF(LONG_PTR, WINAPI, GetWindowLongPtrW,
	HWND hWnd,
	int nIndex
) {
	LONG_PTR ret;
	ret = Old_GetWindowLongPtrW(hWnd, nIndex);
	LOQ_nonzero("misc", "pi", "hWnd", hWnd, "nIndex", nIndex);
	return ret;
}

HOOKDEF(BOOL, WINAPI, GetWindowRect,
	HWND hWnd,
	LPRECT lpRect
) {
	BOOL ret;
	ret = Old_GetWindowRect(hWnd, lpRect);
	LOQ_bool("misc", "ph", "hWnd", hWnd, "lpRect", lpRect);
	return ret;
}

HOOKDEF(int, WINAPI, GetWindowText,
	HWND hWnd,
	LPTSTR lpString,
	int nMaxCount
) {
	int ret;
	ret = Old_GetWindowText(hWnd, lpString, nMaxCount);
	LOQ_nonzero("misc", "phi", "hWnd", hWnd, "lpString", lpString, "nMaxCount", nMaxCount);
	return ret;
}

HOOKDEF(int, WINAPI, GetWindowTextA,
	HWND hWnd,
	LPSTR lpString,
	int nMaxCount
) {
	int ret;
	ret = Old_GetWindowTextA(hWnd, lpString, nMaxCount);
	LOQ_nonzero("misc", "ppi", "hWnd", hWnd, "lpString", lpString, "nMaxCount", nMaxCount);
	return ret;
}

HOOKDEF(BOOL, WINAPI, IsWindowVisible,
	HWND hWnd
) {
	BOOL ret;
	ret = Old_IsWindowVisible(hWnd);
	LOQ_bool("misc", "p", "hWnd", hWnd);
	return ret;
}

HOOKDEF(BOOL, WINAPI, KillTimer,
	HWND hWnd,
	UINT_PTR uIDEvent
) {
	BOOL ret;
	ret = Old_KillTimer(hWnd, uIDEvent);
	LOQ_bool("misc", "ph", "hWnd", hWnd, "uIDEvent", uIDEvent);
	return ret;
}

HOOKDEF(HCURSOR, WINAPI, LoadCursor,
	HINSTANCE hInstance,
	LPCTSTR lpCursorName
) {
	HCURSOR ret;
	ret = Old_LoadCursor(hInstance, lpCursorName);
	LOQ_nonzero("misc", "ps", "hInstance", hInstance, "lpCursorName", lpCursorName);
	return ret;
}

HOOKDEF(HCURSOR, WINAPI, LoadCursorW,
	HINSTANCE hInstance,
	LPCWSTR lpCursorName
) {
	HCURSOR ret;
	ret = Old_LoadCursorW(hInstance, lpCursorName);
	LOQ_nonzero("misc", "pu", "hInstance", hInstance, "lpCursorName", lpCursorName);
	return ret;
}

HOOKDEF(HICON, WINAPI, LoadIconW,
	HINSTANCE hInstance,
	LPCWSTR lpIconName
) {
	HICON ret;
	ret = Old_LoadIconW(hInstance, lpIconName);
	LOQ_nonzero("misc", "pu", "hInstance", hInstance, "lpIconName", lpIconName);
	return ret;
}

HOOKDEF(HMONITOR, WINAPI, MonitorFromWindow,
	HWND hwnd,
	DWORD dwFlags
) {
	HMONITOR ret;
	ret = Old_MonitorFromWindow(hwnd, dwFlags);
	LOQ_nonzero("misc", "ph", "hwnd", hwnd, "dwFlags", dwFlags);
	return ret;
}

HOOKDEF(BOOL, WINAPI, OpenClipboard,
	HWND hWndNewOwner
) {
	BOOL ret;
	ret = Old_OpenClipboard(hWndNewOwner);
	LOQ_bool("misc", "p", "hWndNewOwner", hWndNewOwner);
	return ret;
}

HOOKDEF(BOOL, WINAPI, PeekMessage,
	LPMSG lpMsg,
	HWND hWnd,
	UINT wMsgFilterMin,
	UINT wMsgFilterMax,
	UINT wRemoveMsg
) {
	BOOL ret;
	ret = Old_PeekMessage(lpMsg, hWnd, wMsgFilterMin, wMsgFilterMax, wRemoveMsg);
	LOQ_bool("misc", "hphhh", "lpMsg", lpMsg, "hWnd", hWnd, "wMsgFilterMin", wMsgFilterMin, "wMsgFilterMax", wMsgFilterMax, "wRemoveMsg", wRemoveMsg);
	return ret;
}

HOOKDEF(BOOL, WINAPI, PeekMessageA,
	LPMSG lpMsg,
	HWND hWnd,
	UINT wMsgFilterMin,
	UINT wMsgFilterMax,
	UINT wRemoveMsg
) {
	BOOL ret;
	ret = Old_PeekMessageA(lpMsg, hWnd, wMsgFilterMin, wMsgFilterMax, wRemoveMsg);
	LOQ_bool("misc", "hphhh", "lpMsg", lpMsg, "hWnd", hWnd, "wMsgFilterMin", wMsgFilterMin, "wMsgFilterMax", wMsgFilterMax, "wRemoveMsg", wRemoveMsg);
	return ret;
}

HOOKDEF(BOOL, WINAPI, PeekMessageW,
	LPMSG lpMsg,
	HWND hWnd,
	UINT wMsgFilterMin,
	UINT wMsgFilterMax,
	UINT wRemoveMsg
) {
	BOOL ret;
	ret = Old_PeekMessageW(lpMsg, hWnd, wMsgFilterMin, wMsgFilterMax, wRemoveMsg);
	LOQ_bool("misc", "hphhh", "lpMsg", lpMsg, "hWnd", hWnd, "wMsgFilterMin", wMsgFilterMin, "wMsgFilterMax", wMsgFilterMax, "wRemoveMsg", wRemoveMsg);
	return ret;
}

HOOKDEF(void, WINAPI, PostQuitMessage,
	int nExitCode
) {
	int ret = 0;
	Old_PostQuitMessage(nExitCode);
	LOQ_void("misc", "i", "nExitCode", nExitCode);
	return;
}

HOOKDEF(ATOM, WINAPI, RegisterClassA,
	PVOID lpWndClass
) {
	ATOM ret;
	ret = Old_RegisterClassA(lpWndClass);
	LOQ_nonzero("misc", "p", "lpWndClass", lpWndClass);
	return ret;
}

HOOKDEF(ATOM, WINAPI, RegisterClassExA,
	PVOID unnamedParam1
) {
	ATOM ret;
	ret = Old_RegisterClassExA(unnamedParam1);
	LOQ_nonzero("misc", "p", "unnamedParam1", unnamedParam1);
	return ret;
}

HOOKDEF(ATOM, WINAPI, RegisterClassExW,
	PVOID unnamedParam1
) {
	ATOM ret;
	ret = Old_RegisterClassExW(unnamedParam1);
	LOQ_nonzero("misc", "p", "unnamedParam1", unnamedParam1);
	return ret;
}

HOOKDEF(BOOL, WINAPI, RegisterHotKey,
	HWND hWnd,
	int id,
	UINT fsModifiers,
	UINT vk
) {
	BOOL ret;
	ret = Old_RegisterHotKey(hWnd, id, fsModifiers, vk);
	LOQ_bool("misc", "pihh", "hWnd", hWnd, "id", id, "fsModifiers", fsModifiers, "vk", vk);
	return ret;
}

HOOKDEF(BOOL, WINAPI, RegisterRawInputDevices,
	PVOID pRawInputDevices,
	UINT uiNumDevices,
	UINT cbSize
) {
	BOOL ret;
	ret = Old_RegisterRawInputDevices(pRawInputDevices, uiNumDevices, cbSize);
	LOQ_bool("misc", "phh", "pRawInputDevices", pRawInputDevices, "uiNumDevices", uiNumDevices, "cbSize", cbSize);
	return ret;
}

HOOKDEF(BOOL, WINAPI, RegisterShellHookWindow,
	HWND hwnd
) {
	BOOL ret;
	ret = Old_RegisterShellHookWindow(hwnd);
	LOQ_bool("misc", "p", "hwnd", hwnd);
	return ret;
}

HOOKDEF(UINT, WINAPI, RegisterWindowMessageA,
	LPCSTR lpString
) {
	UINT ret;
	ret = Old_RegisterWindowMessageA(lpString);
	LOQ_nonzero("misc", "s", "lpString", lpString);
	return ret;
}

HOOKDEF(int, WINAPI, ReleaseDC,
	HWND hWnd,
	HDC hDC
) {
	int ret;
	ret = Old_ReleaseDC(hWnd, hDC);
	LOQ_nonzero("misc", "pp", "hWnd", hWnd, "hDC", hDC);
	return ret;
}

HOOKDEF(BOOL, WINAPI, RemoveClipboardFormatListener,
	HWND hwnd
) {
	BOOL ret;
	ret = Old_RemoveClipboardFormatListener(hwnd);
	LOQ_bool("misc", "p", "hwnd", hwnd);
	return ret;
}

HOOKDEF(HWND, WINAPI, SetClipboardViewer,
	HWND hWndNewViewer
) {
	HWND ret;
	ret = Old_SetClipboardViewer(hWndNewViewer);
	LOQ_nonzero("misc", "p", "hWndNewViewer", hWndNewViewer);
	return ret;
}

HOOKDEF(BOOL, WINAPI, SetLayeredWindowAttributes,
	HWND hwnd,
	COLORREF crKey,
	BYTE bAlpha,
	DWORD dwFlags
) {
	BOOL ret;
	ret = Old_SetLayeredWindowAttributes(hwnd, crKey, bAlpha, dwFlags);
	LOQ_bool("misc", "phhh", "hwnd", hwnd, "crKey", crKey, "bAlpha", bAlpha, "dwFlags", dwFlags);
	return ret;
}

HOOKDEF(UINT_PTR, WINAPI, SetTimer,
	HWND hWnd,
	UINT_PTR nIDEvent,
	UINT uElapse,
	PVOID lpTimerFunc
) {
	UINT_PTR ret;
	ret = Old_SetTimer(hWnd, nIDEvent, uElapse, lpTimerFunc);
	LOQ_nonzero("misc", "phhp", "hWnd", hWnd, "nIDEvent", nIDEvent, "uElapse", uElapse, "lpTimerFunc", lpTimerFunc);
	return ret;
}

HOOKDEF(HWINEVENTHOOK, WINAPI, SetWinEventHook,
	DWORD eventMin,
	DWORD eventMax,
	HMODULE hmodWinEventProc,
	PVOID pfnWinEventProc,
	DWORD idProcess,
	DWORD idThread,
	DWORD dwFlags
) {
	HWINEVENTHOOK ret;
	ret = Old_SetWinEventHook(eventMin, eventMax, hmodWinEventProc, pfnWinEventProc, idProcess, idThread, dwFlags);
	LOQ_nonzero("misc", "hhpphhh", "eventMin", eventMin, "eventMax", eventMax, "hmodWinEventProc", hmodWinEventProc, "pfnWinEventProc", pfnWinEventProc, "idProcess", idProcess, "idThread", idThread, "dwFlags", dwFlags);
	return ret;
}

HOOKDEF(BOOL, WINAPI, ShowWindow,
	HWND hWnd,
	int nCmdShow
) {
	BOOL ret;
	ret = Old_ShowWindow(hWnd, nCmdShow);
	LOQ_bool("misc", "pi", "hWnd", hWnd, "nCmdShow", nCmdShow);
	return ret;
}

HOOKDEF(BOOL, WINAPI, TranslateMessage,
	PVOID lpMsg
) {
	BOOL ret;
	ret = Old_TranslateMessage(lpMsg);
	LOQ_bool("misc", "p", "lpMsg", lpMsg);
	return ret;
}

HOOKDEF(BOOL, WINAPI, UnhookWinEvent,
	HWINEVENTHOOK hWinEventHook
) {
	BOOL ret;
	ret = Old_UnhookWinEvent(hWinEventHook);
	LOQ_bool("misc", "p", "hWinEventHook", hWinEventHook);
	return ret;
}

HOOKDEF(BOOL, WINAPI, UnregisterClassA,
	LPCSTR lpClassName,
	HINSTANCE hInstance
) {
	BOOL ret;
	ret = Old_UnregisterClassA(lpClassName, hInstance);
	LOQ_bool("misc", "sp", "lpClassName", lpClassName, "hInstance", hInstance);
	return ret;
}

HOOKDEF(BOOL, WINAPI, UnregisterClassW,
	LPCWSTR lpClassName,
	HINSTANCE hInstance
) {
	BOOL ret;
	ret = Old_UnregisterClassW(lpClassName, hInstance);
	LOQ_bool("misc", "up", "lpClassName", lpClassName, "hInstance", hInstance);
	return ret;
}

HOOKDEF(BOOL, WINAPI, UpdateWindow,
	HWND hWnd
) {
	BOOL ret;
	ret = Old_UpdateWindow(hWnd);
	LOQ_bool("misc", "p", "hWnd", hWnd);
	return ret;
}

HOOKDEF(HWND, WINAPI, WindowFromPoint,
	POINT Point
) {
	HWND ret;
	ret = Old_WindowFromPoint(Point);
	LOQ_nonzero("misc", "h", "Point", Point);
	return ret;
}
