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
#include "log.h"
#include "pipe.h"
#include "config.h"
#include "misc.h"

static BOOLEAN servicename_from_handle(SC_HANDLE hService, PWCHAR servicename)
{
	lasterror_t lasterror;
	DWORD byteneeded;
	LPQUERY_SERVICE_CONFIGW servconfig = calloc(1, 0x2000);
	BOOLEAN ret = FALSE;

	if (servconfig == NULL) {
		servicename[0] = L'\0';
		return ret;
	}
	get_lasterrors(&lasterror);
	// TODO: handle localized strings for Vista+
	ret = QueryServiceConfigW(hService, servconfig, 0x2000, &byteneeded);

	if (ret) {
		SC_HANDLE scmhandle = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE);
		if (scmhandle != NULL) {
			// appears to work just fine using the service's handle, but let's do it according to spec
			ret = GetServiceKeyNameW(scmhandle, servconfig->lpDisplayName, servicename, &byteneeded);
			CloseServiceHandle(scmhandle);
		}
		else {
			ret = FALSE;
		}
	}
	if (!ret)
		servicename[0] = L'\0';

	set_lasterrors(&lasterror);

	return ret;
}

HOOKDEF(SC_HANDLE, WINAPI, OpenSCManagerA,
	__in_opt  LPCTSTR lpMachineName,
	__in_opt  LPCTSTR lpDatabaseName,
	__in	  DWORD dwDesiredAccess
) {
	SC_HANDLE ret = Old_OpenSCManagerA(lpMachineName, lpDatabaseName,
		dwDesiredAccess);
	LOQ_nonnull("services", "ssh", "MachineName", lpMachineName, "DatabaseName", lpDatabaseName,
		"DesiredAccess", dwDesiredAccess);
	return ret;
}

HOOKDEF(SC_HANDLE, WINAPI, OpenSCManagerW,
	__in_opt  LPWSTR lpMachineName,
	__in_opt  LPWSTR lpDatabaseName,
	__in	  DWORD dwDesiredAccess
) {
	SC_HANDLE ret = Old_OpenSCManagerW(lpMachineName, lpDatabaseName,
		dwDesiredAccess);
	LOQ_nonnull("services", "uuh", "MachineName", lpMachineName, "DatabaseName", lpDatabaseName,
		"DesiredAccess", dwDesiredAccess);
	return ret;
}

HOOKDEF(SC_HANDLE, WINAPI, CreateServiceA,
	__in	   SC_HANDLE hSCManager,
	__in	   LPCSTR lpServiceName,
	__in_opt   LPCSTR lpDisplayName,
	__in	   DWORD dwDesiredAccess,
	__in	   DWORD dwServiceType,
	__in	   DWORD dwStartType,
	__in	   DWORD dwErrorControl,
	__in_opt   LPCSTR lpBinaryPathName,
	__in_opt   LPCSTR lpLoadOrderGroup,
	__out_opt  LPDWORD lpdwTagId,
	__in_opt   LPCSTR lpDependencies,
	__in_opt   LPCSTR lpServiceStartName,
	__in_opt   LPCSTR lpPassword
) {
	SC_HANDLE ret = Old_CreateServiceA(hSCManager, lpServiceName,
		lpDisplayName, dwDesiredAccess | SERVICE_QUERY_CONFIG, dwServiceType, dwStartType,
		dwErrorControl, lpBinaryPathName, lpLoadOrderGroup, lpdwTagId,
		lpDependencies, lpServiceStartName, lpPassword);
	LOQ_nonnull("services", "pssh3i3s", "ServiceControlHandle", hSCManager,
		"ServiceName", lpServiceName, "DisplayName", lpDisplayName,
		"DesiredAccess", dwDesiredAccess, "ServiceType", dwServiceType,
		"StartType", dwStartType, "ErrorControl", dwErrorControl,
		"BinaryPathName", lpBinaryPathName,
		"ServiceStartName", lpServiceStartName,
		"Password", lpPassword);

	return ret;
}

HOOKDEF(SC_HANDLE, WINAPI, CreateServiceW,
	__in	   SC_HANDLE hSCManager,
	__in	   LPWSTR lpServiceName,
	__in_opt   LPWSTR lpDisplayName,
	__in	   DWORD dwDesiredAccess,
	__in	   DWORD dwServiceType,
	__in	   DWORD dwStartType,
	__in	   DWORD dwErrorControl,
	__in_opt   LPWSTR lpBinaryPathName,
	__in_opt   LPWSTR lpLoadOrderGroup,
	__out_opt  LPDWORD lpdwTagId,
	__in_opt   LPWSTR lpDependencies,
	__in_opt   LPWSTR lpServiceStartName,
	__in_opt   LPWSTR lpPassword
) {
	SC_HANDLE ret = Old_CreateServiceW(hSCManager, lpServiceName,
		lpDisplayName, dwDesiredAccess | SERVICE_QUERY_CONFIG, dwServiceType, dwStartType,
		dwErrorControl, lpBinaryPathName, lpLoadOrderGroup, lpdwTagId,
		lpDependencies, lpServiceStartName, lpPassword);
	LOQ_nonnull("services", "puuh3i3u", "ServiceControlHandle", hSCManager,
		"ServiceName", lpServiceName, "DisplayName", lpDisplayName,
		"DesiredAccess", dwDesiredAccess, "ServiceType", dwServiceType,
		"StartType", dwStartType, "ErrorControl", dwErrorControl,
		"BinaryPathName", lpBinaryPathName,
		"ServiceStartName", lpServiceStartName,
		"Password", lpPassword);
	return ret;
}

HOOKDEF(SC_HANDLE, WINAPI, OpenServiceA,
	__in  SC_HANDLE hSCManager,
	__in  LPCTSTR lpServiceName,
	__in  DWORD dwDesiredAccess
)
{
/* Known VM guest-tooling service names. Samples open each of these by name
	   with OpenServiceA and treat a non-NULL handle (the service exists) as
	   proof the host runs the guest additions of a hypervisor: "VMTools",
	   "VGAuthService", "vm3dservice", "VMUSBArbService" and "VMwareService" are
	   VMware guest services, and "VBoxService" is the VirtualBox guest daemon.
	   On a real analysis VM those services are genuinely installed, so the real
	   OpenServiceA succeeds and the sample sets hasGuestService_ = true. */
	static const char *mirage_vm_service_names[] = {
		"VMTools",
		"VBoxService",
		"VGAuthService",
		"vm3dservice",
		"VMUSBArbService",
		"VMwareService",
	};
	lasterror_t lasterror;
	SC_HANDLE ret;
	unsigned int i;
	int is_vm_service;
	get_lasterrors(&lasterror);
	ret = Old_OpenServiceA(hSCManager, lpServiceName,
		dwDesiredAccess | SERVICE_QUERY_CONFIG);
	if (ret != NULL)
		set_lasterrors(&lasterror);
	else
		ret = Old_OpenServiceA(hSCManager, lpServiceName, dwDesiredAccess);

	/* Samples enumerate a fixed list of hypervisor guest-tooling service names
	 * and call OpenServiceA(name) for each, taking any non-NULL handle as
	 * evidence a guest service is present (hasGuestService_ = true) and, from
	 * that, that the host is a virtualized sandbox. When the requested service
	 * name matches one of those known VM guest services, force the open to look
	 * like the service does not exist: close any handle the real call opened (so
	 * no service handle leaks), return NULL, and set the last error to
	 * ERROR_SERVICE_DOES_NOT_EXIST (1060) — exactly what the SCM returns on a
	 * clean host that never installed that service — so the sample never finds a
	 * guest service and never sets hasGuestService_. Every other service name is
	 * passed through to the real OpenServiceA untouched. lasterror is preserved
	 * around the forged response. */
	if (!g_config.no_stealth && lpServiceName != NULL) {
		is_vm_service = 0;
		for (i = 0; i < sizeof(mirage_vm_service_names) /
				sizeof(mirage_vm_service_names[0]); i++) {
			if (_stricmp(lpServiceName, mirage_vm_service_names[i]) == 0) {
				is_vm_service = 1;
				break;
			}
		}

		if (is_vm_service) {
			get_lasterrors(&lasterror);

			if (ret != NULL) {
				CloseServiceHandle(ret);
				ret = NULL;
			}

			lasterror.Win32Error = ERROR_SERVICE_DOES_NOT_EXIST;

			set_lasterrors(&lasterror);
		}
	}

	LOQ_nonnull("services", "psh", "ServiceControlManager", hSCManager,
		"ServiceName", lpServiceName, "DesiredAccess", dwDesiredAccess);
	return ret;
}

HOOKDEF(SC_HANDLE, WINAPI, OpenServiceW,
	__in  SC_HANDLE hSCManager,
	__in  LPWSTR lpServiceName,
	__in  DWORD dwDesiredAccess
)
{
/* Synthetic pseudo SC_HANDLE handed back for a failed DiagTrack open so the
	   caller's null-check passes; the paired QueryServiceStatusEx hook forges
	   this same service's state to SERVICE_RUNNING regardless of the handle. */
	static const SC_HANDLE MIRAGE_DIAGTRACK_HANDLE = (SC_HANDLE)0xDA61C000;
	lasterror_t lasterror;
	SC_HANDLE ret;
	get_lasterrors(&lasterror);
	ret = Old_OpenServiceW(hSCManager, lpServiceName,
		dwDesiredAccess | SERVICE_QUERY_CONFIG);
	if (ret != NULL)
		set_lasterrors(&lasterror);
	else
		ret = Old_OpenServiceW(hSCManager, lpServiceName, dwDesiredAccess);

	/* Samples open the Connected User Experiences and Telemetry service
	 * ("DiagTrack") with OpenServiceW(SERVICE_QUERY_STATUS) as the first step of
	 * gatherInfo(): if the open fails (returns NULL) they conclude the always-on
	 * telemetry service a genuine, long-lived Windows desktop runs is absent,
	 * gatherInfo() returns false, and the sample early-exits into its
	 * sandbox-detected branch before it ever reaches the QueryServiceStatusEx
	 * state read. A freshly-imaged analysis VM frequently has DiagTrack
	 * stopped/disabled or removed, so the real open can fail outright. When the
	 * requested service is "DiagTrack" and the real open returned NULL, hand back
	 * a synthetic non-NULL pseudo SC_HANDLE so gatherInfo() proceeds to
	 * QueryServiceStatusEx (which is separately forged to SERVICE_RUNNING)
	 * instead of exiting early. Real, successful opens are passed through
	 * untouched. lasterror is preserved around the forged response. */
	if (!g_config.no_stealth && ret == NULL && lpServiceName != NULL &&
			_wcsicmp(lpServiceName, L"DiagTrack") == 0) {
		get_lasterrors(&lasterror);

		ret = MIRAGE_DIAGTRACK_HANDLE;
		lasterror.Win32Error = ERROR_SUCCESS;

		set_lasterrors(&lasterror);
	}

	LOQ_nonnull("services", "puh", "ServiceControlManager", hSCManager,
		"ServiceName", lpServiceName, "DesiredAccess", dwDesiredAccess);
	return ret;
}

extern wchar_t *our_process_path_w;

HOOKDEF(BOOL, WINAPI, StartServiceA,
	__in	  SC_HANDLE hService,
	__in	  DWORD dwNumServiceArgs,
	__in_opt  LPCTSTR *lpServiceArgVectors
) {
	PWCHAR servicename = calloc(1, 0x1000);
	BOOLEAN dispret = servicename_from_handle(hService, servicename);
	BOOL ret;

	if (dispret && !g_config.suspend_logging && (wcsicmp(servicename, L"osppsvc") || !g_config.file_of_interest || !wcsicmp(our_process_path_w, g_config.file_of_interest))) {
		pipe("SERVICE:%Z", servicename);
		raw_sleep(1000);
	}
	ret = Old_StartServiceA(hService, dwNumServiceArgs,
		lpServiceArgVectors);
	LOQ_bool("services", "pua", "ServiceHandle", hService, "ServiceName", servicename, "Arguments", dwNumServiceArgs,
		lpServiceArgVectors);
	free(servicename);
	return ret;
}

HOOKDEF(BOOL, WINAPI, StartServiceW,
	__in	  SC_HANDLE hService,
	__in	  DWORD dwNumServiceArgs,
	__in_opt  LPWSTR *lpServiceArgVectors
) {
	PWCHAR servicename = calloc(1, 0x1000);
	BOOLEAN dispret = servicename_from_handle(hService, servicename);
	BOOL ret;

	if (dispret && !g_config.suspend_logging && (wcsicmp(servicename, L"osppsvc") || !g_config.file_of_interest || !wcsicmp(our_process_path_w, g_config.file_of_interest))) {
		pipe("SERVICE:%Z", servicename);
		raw_sleep(1000);
	}
	ret = Old_StartServiceW(hService, dwNumServiceArgs,
		lpServiceArgVectors);
	LOQ_bool("services", "puA", "ServiceHandle", hService, "ServiceName", servicename, "Arguments", dwNumServiceArgs,
		lpServiceArgVectors);
	free(servicename);
	return ret;
}

HOOKDEF(BOOL, WINAPI, ControlService,
	__in   SC_HANDLE hService,
	__in   DWORD dwControl,
	__out  LPSERVICE_STATUS lpServiceStatus
) {
	PWCHAR servicename = calloc(1, 0x1000);
	BOOL ret;
	servicename_from_handle(hService, servicename);
	ret = Old_ControlService(hService, dwControl, lpServiceStatus);
	LOQ_bool("services", "pui", "ServiceHandle", hService, "ServiceName", servicename, "ControlCode", dwControl);
	free(servicename);
	return ret;
}

HOOKDEF(BOOL, WINAPI, DeleteService,
	__in  SC_HANDLE hService
) {
	PWCHAR servicename = calloc(1, 0x1000);
	BOOL ret;
	servicename_from_handle(hService, servicename);
	ret = Old_DeleteService(hService);
	LOQ_bool("services", "pu", "ServiceHandle", hService, "ServiceName", servicename);
	free(servicename);
	return ret;
}
