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

/* ==== complete_hooks.py generated batch (all-free) ==== */

// -> hook_window.c に追加 | category="windows" | winapi:Windows GDI
HOOKDEF(BOOL, WINAPI, BitBlt, // 呼出規約は WINAPI 仮定(socket/native/CRT系は要確認)
	_In_ HDC hdcDest,
	_In_ int nXDest,
	_In_ int nYDest,
	_In_ int nWidth,
	_In_ int nHeight,
	_In_ HDC hdcSrc,
	_In_ int nXSrc,
	_In_ int nYSrc,
	_In_ DWORD dwRop
) {
	BOOL ret;
	ret = Old_BitBlt(hdcDest, nXDest, nYDest, nWidth, nHeight, hdcSrc, nXSrc, nYSrc, dwRop);
	LOQ_bool("windows", "piiiipiii", "DcDest", hdcDest, "XDest", nXDest, "YDest", nYDest, "Width", nWidth, "Height", nHeight, "DcSrc", hdcSrc, "XSrc", nXSrc, "YSrc", nYSrc, "Rop", dwRop);
	return ret;
}

// -> hook_window.c に追加 | category="windows" | winapi:Hooks
// REVIEW: 戻り型 LRESULT の成功判定が曖昧 -> LOQ_nonzero を仮採用。0=成功のAPIなら LOQ_zero 等へ変更
// REVIEW: 引数 hhk: 型 HHOOK は自動解釈不可(構造体等)。アドレスのみ記録。内容が重要なら該当メンバを手動でログ
// REVIEW: 引数 wParam: 型 WPARAM を i(int32)で仮記録。要確認
// REVIEW: 引数 lParam: 型 LPARAM は自動解釈不可(構造体等)。アドレスのみ記録。内容が重要なら該当メンバを手動でログ
HOOKDEF(LRESULT, WINAPI, CallNextHookEx, // 呼出規約は WINAPI 仮定(socket/native/CRT系は要確認)
	_In_opt_ HHOOK hhk,
	_In_ int nCode,
	_In_ WPARAM wParam,
	_In_ LPARAM lParam
) {
	LRESULT ret;
	ret = Old_CallNextHookEx(hhk, nCode, wParam, lParam);
	LOQ_nonzero("windows", "piip", "Hk", hhk, "Code", nCode, "WParam", wParam, "LParam", lParam);
	return ret;
}

// -> hook_window.c に追加 | category="windows" | winapi:Windows GDI
HOOKDEF(HBITMAP, WINAPI, CreateCompatibleBitmap, // 呼出規約は WINAPI 仮定(socket/native/CRT系は要確認)
	_In_ HDC hdc,
	_In_ int nWidth,
	_In_ int nHeight
) {
	HBITMAP ret;
	ret = Old_CreateCompatibleBitmap(hdc, nWidth, nHeight);
	LOQ_nonnull("windows", "pii", "Dc", hdc, "Width", nWidth, "Height", nHeight);
	return ret;
}

// -> hook_window.c に追加 | category="windows" | winapi:Windows GDI
// REVIEW: 引数 pbmi: 型 const BITMAPINFO* は自動解釈不可(構造体等)。アドレスのみ記録。内容が重要なら該当メンバを手動でログ
HOOKDEF(HBITMAP, WINAPI, CreateDIBSection, // 呼出規約は WINAPI 仮定(socket/native/CRT系は要確認)
	_In_ HDC hdc,
	_In_ const BITMAPINFO* pbmi,
	_In_ UINT iUsage,
	_Out_ VOID** ppvBits,
	_In_ HANDLE hSection,
	_In_ DWORD dwOffset
) {
	HBITMAP ret;
	ret = Old_CreateDIBSection(hdc, pbmi, iUsage, ppvBits, hSection, dwOffset);
	LOQ_nonnull("windows", "ppiPpi", "Dc", hdc, "Bmi", pbmi, "IUsage", iUsage, "PvBits", ppvBits, "Section", hSection, "Offset", dwOffset);
	return ret;
}

// -> hook_window.c に追加 | category="windows" | winapi:Windows GDI
// REVIEW: 戻り型 HBRUSH の成功判定が曖昧 -> LOQ_nonzero を仮採用。0=成功のAPIなら LOQ_zero 等へ変更
// REVIEW: 引数 crColor: 型 COLORREF を i(int32)で仮記録。要確認
HOOKDEF(HBRUSH, WINAPI, CreateSolidBrush, // 呼出規約は WINAPI 仮定(socket/native/CRT系は要確認)
	_In_ COLORREF crColor
) {
	HBRUSH ret;
	ret = Old_CreateSolidBrush(crColor);
	LOQ_nonzero("windows", "i", "CrColor", crColor);
	return ret;
}

// -> hook_window.c に追加 | category="windows" | winapi:Messages and Message Queues
// REVIEW: 戻り型 LRESULT の成功判定が曖昧 -> LOQ_nonzero を仮採用。0=成功のAPIなら LOQ_zero 等へ変更
// REVIEW: 引数 lpmsg: 型 const MSG* は自動解釈不可(構造体等)。アドレスのみ記録。内容が重要なら該当メンバを手動でログ
HOOKDEF(LRESULT, WINAPI, DispatchMessageW, // 呼出規約は WINAPI 仮定(socket/native/CRT系は要確認)
	_In_ const MSG* lpmsg
) {
	LRESULT ret;
	ret = Old_DispatchMessageW(lpmsg);
	LOQ_nonzero("windows", "p", "Msg", lpmsg);
	return ret;
}

// -> hook_window.c に追加 | category="windows" | winapi:Windows GDI
// REVIEW: 戻り型 int の成功判定が曖昧 -> LOQ_nonzero を仮採用。0=成功のAPIなら LOQ_zero 等へ変更
// REVIEW: 引数 lprc: 型 const RECT* は自動解釈不可(構造体等)。アドレスのみ記録。内容が重要なら該当メンバを手動でログ
// REVIEW: 引数 hbr: 型 HBRUSH は自動解釈不可(構造体等)。アドレスのみ記録。内容が重要なら該当メンバを手動でログ
HOOKDEF(int, WINAPI, FillRect, // 呼出規約は WINAPI 仮定(socket/native/CRT系は要確認)
	_In_ HDC hDC,
	_In_ const RECT* lprc,
	_In_ HBRUSH hbr
) {
	int ret;
	ret = Old_FillRect(hDC, lprc, hbr);
	LOQ_nonzero("windows", "ppp", "DC", hDC, "Rc", lprc, "Br", hbr);
	return ret;
}

// -> hook_window.c に追加 | category="windows" | winapi:Windows GDI
// REVIEW: 戻り型 int の成功判定が曖昧 -> LOQ_nonzero を仮採用。0=成功のAPIなら LOQ_zero 等へ変更
// REVIEW: 引数 lpvBits: 生バッファ(void*)。アドレスのみ記録。長さ引数と対にして 'b'(size_t,buf)/'S'(int,buf) 指定にすれば内容を人間可読で記録できる
HOOKDEF(int, WINAPI, GetDIBits, // 呼出規約は WINAPI 仮定(socket/native/CRT系は要確認)
	_In_ HDC hdc,
	_In_ HBITMAP hbmp,
	_In_ UINT uStartScan,
	_In_ UINT cScanLines,
	_Out_ LPVOID lpvBits,
	_Inout_ LPBITMAPINFO lpbi,
	_In_ UINT uUsage
) {
	int ret;
	ret = Old_GetDIBits(hdc, hbmp, uStartScan, cScanLines, lpvBits, lpbi, uUsage);
	LOQ_nonzero("windows", "ppiipPi", "Dc", hdc, "Bmp", hbmp, "UStartScan", uStartScan, "CScanLines", cScanLines, "VBits", lpvBits, "Bi", lpbi, "UUsage", uUsage);
	return ret;
}

// -> hook_window.c に追加 | category="windows" | winapi:Windows
HOOKDEF(HWND, WINAPI, GetDesktopWindow, // 呼出規約は WINAPI 仮定(socket/native/CRT系は要確認)
	void
) {
	HWND ret;
	ret = Old_GetDesktopWindow();
	LOQ_nonnull("windows", "");
	return ret;
}

// -> hook_window.c に追加 | category="windows" | winapi:Windows
HOOKDEF(HWND, WINAPI, GetForegroundWindow, // 呼出規約は WINAPI 仮定(socket/native/CRT系は要確認)
	void
) {
	HWND ret;
	ret = Old_GetForegroundWindow();
	LOQ_nonnull("windows", "");
	return ret;
}

// -> hook_window.c に追加 | category="windows" | winapi:Window Station and Desktop
HOOKDEF(HWINSTA, WINAPI, GetProcessWindowStation, // 呼出規約は WINAPI 仮定(socket/native/CRT系は要確認)
	void
) {
	HWINSTA ret;
	ret = Old_GetProcessWindowStation();
	LOQ_nonnull("windows", "");
	return ret;
}

// -> hook_window.c に追加 | category="windows" | winapi:Windows
// REVIEW: 戻り型 DWORD の成功判定が曖昧 -> LOQ_nonzero を仮採用。0=成功のAPIなら LOQ_zero 等へ変更
HOOKDEF(DWORD, WINAPI, GetSysColor, // 呼出規約は WINAPI 仮定(socket/native/CRT系は要確認)
	_In_ int nIndex
) {
	DWORD ret;
	ret = Old_GetSysColor(nIndex);
	LOQ_nonzero("windows", "i", "Index", nIndex);
	return ret;
}

// -> hook_window.c に追加 | category="windows" | winapi:Window Station and Desktop
HOOKDEF(HDESK, WINAPI, GetThreadDesktop, // 呼出規約は WINAPI 仮定(socket/native/CRT系は要確認)
	_In_ DWORD dwThreadId
) {
	HDESK ret;
	ret = Old_GetThreadDesktop(dwThreadId);
	LOQ_nonnull("windows", "i", "ThreadId", dwThreadId);
	return ret;
}

// -> hook_window.c に追加 | category="windows" | winapi:Window Station and Desktop
// REVIEW: 引数 pvInfo: 生バッファ(void*)。アドレスのみ記録。長さ引数と対にして 'b'(size_t,buf)/'S'(int,buf) 指定にすれば内容を人間可読で記録できる
HOOKDEF(BOOL, WINAPI, GetUserObjectInformationW, // 呼出規約は WINAPI 仮定(socket/native/CRT系は要確認)
	_In_ HANDLE hObj,
	_In_ int nIndex,
	_Out_opt_ PVOID pvInfo,
	_In_ DWORD nLength,
	_Out_opt_ LPDWORD lpnLengthNeeded
) {
	BOOL ret;
	ret = Old_GetUserObjectInformationW(hObj, nIndex, pvInfo, nLength, lpnLengthNeeded);
	LOQ_bool("windows", "pipiI", "Obj", hObj, "Index", nIndex, "VInfo", pvInfo, "Length", nLength, "NLengthNeeded", lpnLengthNeeded);
	return ret;
}

// -> hook_window.c に追加 | category="windows" | winapi:Multilingual User Interface (MUI)
HOOKDEF(BOOL, WINAPI, GetUserPreferredUILanguages, // 呼出規約は WINAPI 仮定(socket/native/CRT系は要確認)
	_In_ DWORD dwFlags,
	_Out_ PULONG pulNumLanguages,
	_Out_opt_ PZZWSTR pwszLanguagesBuffer,
	_Inout_ PULONG pcchLanguagesBuffer
) {
	BOOL ret;
	ret = Old_GetUserPreferredUILanguages(dwFlags, pulNumLanguages, pwszLanguagesBuffer, pcchLanguagesBuffer);
	LOQ_bool("windows", "iIPI", "Flags", dwFlags, "UlNumLanguages", pulNumLanguages, "WszLanguagesBuffer", pwszLanguagesBuffer, "CchLanguagesBuffer", pcchLanguagesBuffer);
	return ret;
}

// -> hook_window.c に追加 | category="windows" | winapi:System Information Functions
// REVIEW: 戻り型 UINT の成功判定が曖昧 -> LOQ_nonzero を仮採用。0=成功のAPIなら LOQ_zero 等へ変更
HOOKDEF(UINT, WINAPI, GetWindowsDirectoryA, // 呼出規約は WINAPI 仮定(socket/native/CRT系は要確認)
	_Out_ LPSTR lpBuffer,
	_In_ UINT uSize
) {
	UINT ret;
	ret = Old_GetWindowsDirectoryA(lpBuffer, uSize);
	LOQ_nonzero("windows", "si", "Buffer", lpBuffer, "USize", uSize);
	return ret;
}

// -> hook_window.c に追加 | category="windows" | winapi:Multiple Display Monitors
// REVIEW: 戻り型 HMONITOR の成功判定が曖昧 -> LOQ_nonzero を仮採用。0=成功のAPIなら LOQ_zero 等へ変更
HOOKDEF(HMONITOR, WINAPI, MonitorFromWindow, // 呼出規約は WINAPI 仮定(socket/native/CRT系は要確認)
	_In_ HWND hwnd,
	_In_ DWORD dwFlags
) {
	HMONITOR ret;
	ret = Old_MonitorFromWindow(hwnd, dwFlags);
	LOQ_nonzero("windows", "pi", "Wnd", hwnd, "Flags", dwFlags);
	return ret;
}

// -> hook_window.c に追加 | category="windows" | winapi:Windows GDI
HOOKDEF(BOOL, WINAPI, OffsetRect, // 呼出規約は WINAPI 仮定(socket/native/CRT系は要確認)
	_Inout_ LPRECT lprc,
	_In_ int dx,
	_In_ int dy
) {
	BOOL ret;
	ret = Old_OffsetRect(lprc, dx, dy);
	LOQ_bool("windows", "Pii", "Rc", lprc, "Dx", dx, "Dy", dy);
	return ret;
}

// -> hook_window.c に追加 | category="windows" | winapi:Messages and Message Queues
HOOKDEF(BOOL, WINAPI, PeekMessageW, // 呼出規約は WINAPI 仮定(socket/native/CRT系は要確認)
	_Out_ LPMSG lpMsg,
	_In_opt_ HWND hWnd,
	_In_ UINT wMsgFilterMin,
	_In_ UINT wMsgFilterMax,
	_In_ UINT wRemoveMsg
) {
	BOOL ret;
	ret = Old_PeekMessageW(lpMsg, hWnd, wMsgFilterMin, wMsgFilterMax, wRemoveMsg);
	LOQ_bool("windows", "Ppiii", "Msg", lpMsg, "Wnd", hWnd, "WMsgFilterMin", wMsgFilterMin, "WMsgFilterMax", wMsgFilterMax, "WRemoveMsg", wRemoveMsg);
	return ret;
}

// -> hook_window.c に追加 | category="windows" | winapi:Messages and Message Queues
HOOKDEF(VOID, WINAPI, PostQuitMessage, // 呼出規約は WINAPI 仮定(socket/native/CRT系は要確認)
	_In_ int nExitCode
) {
	ULONG_PTR ret = 0; (void)ret;  // void 関数: LOQ 用ダミー
	Old_PostQuitMessage(nExitCode);
	LOQ_void("windows", "i", "ExitCode", nExitCode);
}

// -> hook_window.c に追加 | category="windows" | winapi:Painting and Drawing
// REVIEW: 引数 lprcUpdate: 型 const RECT* は自動解釈不可(構造体等)。アドレスのみ記録。内容が重要なら該当メンバを手動でログ
// REVIEW: 引数 hrgnUpdate: 型 HRGN は自動解釈不可(構造体等)。アドレスのみ記録。内容が重要なら該当メンバを手動でログ
HOOKDEF(BOOL, WINAPI, RedrawWindow, // 呼出規約は WINAPI 仮定(socket/native/CRT系は要確認)
	_In_ HWND hWnd,
	_In_ const RECT* lprcUpdate,
	_In_ HRGN hrgnUpdate,
	_In_ UINT flags
) {
	BOOL ret;
	ret = Old_RedrawWindow(hWnd, lprcUpdate, hrgnUpdate, flags);
	LOQ_bool("windows", "pppi", "Wnd", hWnd, "RcUpdate", lprcUpdate, "RgnUpdate", hrgnUpdate, "Lags", flags);
	return ret;
}

// -> hook_window.c に追加 | category="windows" | winapi:Windows Shell
HOOKDEF(HRESULT, WINAPI, SHGetDesktopFolder, // 呼出規約は WINAPI 仮定(socket/native/CRT系は要確認)
	_Out_ PVOID** ppshf
) {
	HRESULT ret;
	ret = Old_SHGetDesktopFolder(ppshf);
	LOQ_hresult("windows", "P", "Pshf", ppshf);
	return ret;
}

// -> hook_window.c に追加 | category="windows" | winapi:Windows Shell
HOOKDEF(HRESULT, WINAPI, SHGetSpecialFolderLocation, // 呼出規約は WINAPI 仮定(socket/native/CRT系は要確認)
	_In_ HWND hwndOwner,
	_In_ int nFolder,
	_Out_ PVOID* ppidl
) {
	HRESULT ret;
	ret = Old_SHGetSpecialFolderLocation(hwndOwner, nFolder, ppidl);
	LOQ_hresult("windows", "piP", "WndOwner", hwndOwner, "Folder", nFolder, "Pidl", ppidl);
	return ret;
}

// -> hook_window.c に追加 | category="windows" | winapi:Windows Shell
HOOKDEF(BOOL, WINAPI, SHGetSpecialFolderPathA, // 呼出規約は WINAPI 仮定(socket/native/CRT系は要確認)
	HWND hwndOwner,
	_Out_ LPSTR lpszPath,
	_In_ int csidl,
	_In_ BOOL fCreate
) {
	BOOL ret;
	ret = Old_SHGetSpecialFolderPathA(hwndOwner, lpszPath, csidl, fCreate);
	LOQ_bool("windows", "pfii", "WndOwner", hwndOwner, "SzPath", lpszPath, "Csidl", csidl, "Create", fCreate);
	return ret;
}

// -> hook_window.c に追加 | category="windows" | winapi:Keyboard Input
// REVIEW: 引数 lpMsg: 型 const MSG* は自動解釈不可(構造体等)。アドレスのみ記録。内容が重要なら該当メンバを手動でログ
HOOKDEF(BOOL, WINAPI, TranslateMessage, // 呼出規約は WINAPI 仮定(socket/native/CRT系は要確認)
	_In_ const MSG* lpMsg
) {
	BOOL ret;
	ret = Old_TranslateMessage(lpMsg);
	LOQ_bool("windows", "p", "Msg", lpMsg);
	return ret;
}
