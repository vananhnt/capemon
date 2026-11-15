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

/* SAGE_AGENT_BEGIN GetQueuedCompletionStatus */
HOOKDEF(BOOL, WINAPI, GetQueuedCompletionStatus,
	__in  HANDLE CompletionPort,
	__out LPDWORD lpNumberOfBytesTransferred,
	__out PULONG_PTR lpCompletionKey,
	__out LPOVERLAPPED *lpOverlapped,
	__in  DWORD dwMilliseconds
) {
	BOOL ret;

	if (!g_config.no_stealth && mirage_sleep_skip_active()
			&& dwMilliseconds > 1000 && dwMilliseconds != INFINITE) {
		/*
		 * IOCP timeout-behaviour check: the sample blocks on an empty
		 * completion port and compares the elapsed duration against the
		 * requested timeout. Don't actually block for the whole interval
		 * (that defeats fast analysis) and don't return instantly (a tiny
		 * delta is itself the sandbox tell). Instead wait briefly and, if
		 * it genuinely times out, credit the sleep-skip clock the balance
		 * of the requested timeout so the sample's tick delta reads
		 * ~dwMilliseconds while a real completion still returns promptly.
		 */
		ret = Old_GetQueuedCompletionStatus(CompletionPort, lpNumberOfBytesTransferred,
			lpCompletionKey, lpOverlapped, 10);
		if (!ret) {
			mirage_credit_skipped_ms(dwMilliseconds - 10);
			SetLastError(WAIT_TIMEOUT);
		}
		LOQ_bool("misc", "pii", "CompletionPort", CompletionPort,
			"Milliseconds", dwMilliseconds, "Spoofed", ret ? 0 : 1);
		return ret;
	}

	ret = Old_GetQueuedCompletionStatus(CompletionPort, lpNumberOfBytesTransferred,
		lpCompletionKey, lpOverlapped, dwMilliseconds);
	LOQ_bool("misc", "pii", "CompletionPort", CompletionPort,
		"Milliseconds", dwMilliseconds, "Spoofed", 0);
	return ret;
}
/* SAGE_AGENT_END GetQueuedCompletionStatus */
