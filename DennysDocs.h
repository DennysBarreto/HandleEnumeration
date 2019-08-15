#define SECURITY_WIN32

#include <ws2tcpip.h>
#include <winsock2.h>
#include <iphlpapi.h>
#include <ip2string.h>
#include <Mstcpip.h>
#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <iostream>
#include <Psapi.h>
#include <tlhelp32.h>
#include <ShlObj.h>
#include <WtsApi32.h>
#include <vector>
#include <WinInet.h>
#include <sstream>
#include <typeinfo>
#include <ImageHlp.h>
#include <thread>
#include <memory>
#include <assert.h>
#include <tchar.h>
#include <cstdint>
#include <conio.h>
#include <comdef.h>
#include <Wbemidl.h>
#include <wincred.h>
#include <strsafe.h>
#include <Mq.h>
#include <AclAPI.h>
#include <sddl.h>
#include <UserEnv.h>
#include <Softpub.h>
#include <wincrypt.h>
#include <wintrust.h>
#include <mscat.h>
#include <algorithm>
#include <Security.h>
#include <io.h>
#include <Shlwapi.h>
#include "ntdll.h"

#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "Version.lib")
#pragma comment(lib, "Shell32.lib")
#pragma comment(lib, "Userenv.lib")
#pragma comment(lib, "Mqrt.lib.")
#pragma comment(lib, "WinInet.lib")
#pragma comment(lib, "Shell32.lib")
#pragma comment(lib, "Kernel32.lib")
#pragma comment(lib, "User32.lib")
#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "PsApi.lib")
#pragma comment(lib, "WtsApi32.lib")
#pragma comment(lib, "Dbghelp.lib")
#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "credui.lib")
#pragma comment(lib, "comsuppw.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "Secur32.lib")

#pragma warning(disable: 4996)
#pragma warning(push)
#pragma warning(suppress: 4200)
#pragma warning(disable: 4200)
#pragma warning(pop)

using namespace std;

namespace DennysDocs {
	typedef enum _HANDLE_TYPE {
		TYPE_NULL = 0,
		TYPE_DIRECTORY,
		TYPE_SYMBOLICLINK,
		TYPE_TOKEN,
		TYPE_JOB,
		TYPE_PROCESS,
		TYPE_THREAD,
		TYPE_USERAPCRESERVE,
		TYPE_IOCOMPLETIONRESERVE,
		TYPE_EVENT,
		TYPE_MUTANT,
		TYPE_SEMAPHORE,
		TYPE_TIMER,
		TYPE_KEYEDEVENT,
		TYPE_WINDOWSTATION,
		TYPE_DESKTOP,
		TYPE_TPWORKERFACTORY,
		TYPE_IOCOMPLETION,
		TYPE_FILE,
		TYPE_TMTM,
		TYPE_TMRM,
		TYPE_SECTION,
		TYPE_SESSION,
		TYPE_REGISTRY,
		TYPE_ALPCPORT,
		TYPE_WMIGUID,
		TYPE_ETWREGISTRATION,
		TYPE_ETWCONSUMER,
		TYPE_PCWOBJECT,
		TYPE_WAITCOMPLETIONPACKET,
		TYPE_IRTIMER
	}HANDLE_TYPE, *PHANDLE_TYPE;

	typedef struct _CHandleInfo {
		DWORD	AccessRight;
		BYTE	Attributes;
		DWORD	ProcessID;
		LPWSTR	HandleName;
		DWORD	ObjectTypeID;
		LPWSTR	ObjectTypeSTR;
		HANDLE	Handle;
		LPVOID	ObjectPTR;

		struct _TargetHandles {
			PHANDLE hProcess;
			PHANDLE Handle;
		}TargetHandles;

	}CHandleInfo, *PCHandleInfo;

	typedef BOOL(CALLBACK*	CHandleEnum)(CHandleInfo HandleInfo, DWORD ProcessId, LPVOID Param);

	LPVOID WINAPI MemoryAlloc(size_t sizeAlloc)
	{
		return LocalAlloc(LPTR, sizeAlloc);
	}

	LPVOID WINAPI MemoryFree(LPVOID pSource)
	{
		if (!pSource)
			return NULL;

		return LocalFree(*(HLOCAL*)&pSource);
	}

	BOOL __stdcall IsValidHandle(HANDLE Handle)
	{
		return !(Handle <= 0) && HandleToULong(Handle) % 0x4 == 0;
	}

	LPWSTR WINAPI DuplicateString(WCHAR* Source)
	{
		if (!Source)
			return '\0';

		return StrDupW(Source);
	}

	DWORD WINAPI FindProcessID(PCWSTR Process)
	{
		UNICODE_STRING uProcess;
		UNICODE_STRING currentProcess;

		DWORD cCount = 0;
		DWORD cMode = 1;

		DWORD cProcRet = 0;

		LONG cComp = 0;

		WTS_PROCESS_INFO_EXW *WTSENUM = NULL;

		WTSENUM = &WTS_PROCESS_INFO_EXW();

		if (!WTSEnumerateProcessesExW(WTS_CURRENT_SERVER_HANDLE,
			&cMode, WTS_ANY_SESSION, (LPWSTR*)&WTSENUM, &cCount))
		{
			return 0;
		}

		RtlCreateUnicodeString(&uProcess, Process);

		for (DWORD i = 0; i < cCount; i++)
		{
			RtlCreateUnicodeString(&currentProcess, WTSENUM[i].pProcessName);

			cComp = RtlCompareUnicodeString(&uProcess, &currentProcess, TRUE);

			RtlFreeUnicodeString(&currentProcess);

			if (cComp == 0)
			{
				cProcRet = WTSENUM[i].ProcessId;
				break;
			}
		}

		RtlFreeUnicodeString(&uProcess);

		WTSFreeMemoryExW(WTS_TYPE_CLASS::WTSTypeProcessInfoLevel1, WTSENUM, cCount);

		return cProcRet;
	}

	LPWSTR WINAPI GetObjectHandleName(HANDLE hHandle)
	{
		if (!DennysDocs::IsValidHandle(hHandle))
			return L'\0';

		LPWSTR HandleObjectName = 0;

		POBJECT_NAME_INFORMATION	pObject = NULL;
		ULONG						pLengthNeed = 0;

		NTSTATUS Status = 0;

		pObject = &OBJECT_NAME_INFORMATION();
		HandleObjectName = L'\0';

		__try
		{
			Status = NtQueryObject(hHandle, ObjectNameInformation, pObject, 0, &pLengthNeed);

			if (Status == STATUS_INFO_LENGTH_MISMATCH)
			{
				pObject = (POBJECT_NAME_INFORMATION)MemoryAlloc(pLengthNeed);
				Status = NtQueryObject(hHandle, ObjectNameInformation,
					pObject, pLengthNeed, &pLengthNeed);

				if (NT_SUCCESS(Status))
				{
					HandleObjectName = DennysDocs::DuplicateString(pObject->Name.Buffer);
				}

				MemoryFree(pObject);
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			return HandleObjectName;
		}

		return HandleObjectName;
	}

	BOOL __stdcall GetObjectTypeInfo(HANDLE Handle, POBJECT_TYPE_INFORMATION* OutValue)
	{
		ULONG SizeRequired = 0;

		NTSTATUS Status = 0;

		Status = NtQueryObject(Handle,
			ObjectTypeInformation, 0, 0, &SizeRequired);

		if (SizeRequired == 0)
			return FALSE;

		*(LPVOID*)&(*OutValue) = DennysDocs::MemoryAlloc(SizeRequired);

		Status = NtQueryObject(Handle, ObjectTypeInformation, *OutValue,
			SizeRequired, &SizeRequired);

		if (Status == STATUS_SUCCESS)
			return TRUE;

		return FALSE;
	}

	BOOL WINAPI IsEqualStringW(WCHAR* Compare1, WCHAR* Compare2, BOOL CaseInSensitive)
	{
		UNICODE_STRING uCompare1, uCompare2;

		BOOL IsEqual = FALSE;

		if (!RtlCreateUnicodeString(&uCompare1, Compare1))
			return FALSE;

		if (!RtlCreateUnicodeString(&uCompare2, Compare2))
			return FALSE;

		IsEqual = RtlEqualUnicodeString(&uCompare1, &uCompare2, CaseInSensitive);

		RtlFreeUnicodeString(&uCompare1);
		RtlFreeUnicodeString(&uCompare2);

		return IsEqual;
	}

	HANDLE_TYPE WINAPI GetHandleTypeIndexByName(PWSTR TypeName)
	{
		HANDLE_TYPE Ret = static_cast<HANDLE_TYPE>(0);

		if (IsEqualStringW(TypeName, L"ALPC Port", FALSE))
			Ret = HANDLE_TYPE::TYPE_ALPCPORT;
		else if (IsEqualStringW(TypeName, L"Desktop", FALSE))
			Ret = HANDLE_TYPE::TYPE_DESKTOP;
		else if (IsEqualStringW(TypeName, L"Directory", FALSE))
			Ret = HANDLE_TYPE::TYPE_DIRECTORY;
		else if (IsEqualStringW(TypeName, L"EtwConsumer", FALSE))
			Ret = HANDLE_TYPE::TYPE_ETWCONSUMER;
		else if (IsEqualStringW(TypeName, L"EtwRegistration", FALSE))
			Ret = HANDLE_TYPE::TYPE_ETWREGISTRATION;
		else if (IsEqualStringW(TypeName, L"Event", FALSE))
			Ret = HANDLE_TYPE::TYPE_EVENT;
		else if (IsEqualStringW(TypeName, L"File", FALSE))
			Ret = HANDLE_TYPE::TYPE_FILE;
		else if (IsEqualStringW(TypeName, L"IoCompletion", FALSE))
			Ret = HANDLE_TYPE::TYPE_IOCOMPLETION;
		else if (IsEqualStringW(TypeName, L"IoCompletionReserve", FALSE))
			Ret = HANDLE_TYPE::TYPE_IOCOMPLETIONRESERVE;
		else if (IsEqualStringW(TypeName, L"IRTimer", FALSE))
			Ret = HANDLE_TYPE::TYPE_IRTIMER;
		else if (IsEqualStringW(TypeName, L"Job", FALSE))
			Ret = HANDLE_TYPE::TYPE_JOB;
		else if (IsEqualStringW(TypeName, L"KeyedEvent", FALSE))
			Ret = HANDLE_TYPE::TYPE_KEYEDEVENT;
		else if (IsEqualStringW(TypeName, L"Mutant", FALSE))
			Ret = HANDLE_TYPE::TYPE_MUTANT;
		else if (IsEqualStringW(TypeName, L"PcwObject", FALSE))
			Ret = HANDLE_TYPE::TYPE_PCWOBJECT;
		else if (IsEqualStringW(TypeName, L"Process", FALSE))
			Ret = HANDLE_TYPE::TYPE_PROCESS;
		else if (IsEqualStringW(TypeName, L"Key", FALSE))
			Ret = HANDLE_TYPE::TYPE_REGISTRY;
		else if (IsEqualStringW(TypeName, L"Section", FALSE))
			Ret = HANDLE_TYPE::TYPE_SECTION;
		else if (IsEqualStringW(TypeName, L"Semaphore", FALSE))
			Ret = HANDLE_TYPE::TYPE_SEMAPHORE;
		else if (IsEqualStringW(TypeName, L"Session", FALSE))
			Ret = HANDLE_TYPE::TYPE_SESSION;
		else if (IsEqualStringW(TypeName, L"SymbolicLink", FALSE))
			Ret = HANDLE_TYPE::TYPE_SYMBOLICLINK;
		else if (IsEqualStringW(TypeName, L"Thread", FALSE))
			Ret = HANDLE_TYPE::TYPE_THREAD;
		else if (IsEqualStringW(TypeName, L"Timer", FALSE))
			Ret = HANDLE_TYPE::TYPE_TIMER;
		else if (IsEqualStringW(TypeName, L"TmRm", FALSE))
			Ret = HANDLE_TYPE::TYPE_TMRM;
		else if (IsEqualStringW(TypeName, L"TmTm", FALSE))
			Ret = HANDLE_TYPE::TYPE_TMTM;
		else if (IsEqualStringW(TypeName, L"Token", FALSE))
			Ret = HANDLE_TYPE::TYPE_TOKEN;
		else if (IsEqualStringW(TypeName, L"TpWorkerFactory", FALSE))
			Ret = HANDLE_TYPE::TYPE_TPWORKERFACTORY;
		else if (IsEqualStringW(TypeName, L"UserApcReserve", FALSE))
			Ret = HANDLE_TYPE::TYPE_USERAPCRESERVE;
		else if (IsEqualStringW(TypeName, L"WindowStation", FALSE))
			Ret = HANDLE_TYPE::TYPE_WINDOWSTATION;
		else if (IsEqualStringW(TypeName, L"WaitCompletionPacket", FALSE))
			Ret = HANDLE_TYPE::TYPE_WAITCOMPLETIONPACKET;
		else if (IsEqualStringW(TypeName, L"WmiGuid", FALSE))
			Ret = HANDLE_TYPE::TYPE_WMIGUID;

		return Ret;
	}

	BOOL WINAPI HandleEnumerateCallback(DWORD ProcessID, CHandleEnum CCallback, LPVOID infoAdded)
	{
		static RTL_CRITICAL_SECTION HandleSync = { 0 };
		static unsigned long SizeRequired = 8192;

		PSYSTEM_HANDLE_INFORMATION SystemHandle = nullptr;
		PFILE_FS_DEVICE_INFORMATION DeviceInfo = nullptr;
		POBJECT_TYPE_INFORMATION ObjInfo = nullptr;
		CHandleInfo* CHandleInformation = nullptr;

		HANDLE hProcess = 0;
		HANDLE Handle = 0;
		HANDLE hThread = 0;

		NTSTATUS Status = 0;

		BOOL IsPipeHandle = FALSE;

		BOOL StopEnumeration = FALSE;

		WCHAR* HandleNameObject;

		DWORD WaitSignal = 0;

		IO_STATUS_BLOCK StatusBlock;

		WCHAR EmptyString[2];

		if (CCallback == nullptr)
			return FALSE;

		EmptyString[0] = L'\0';

		*(LPVOID*)&CHandleInformation = MemoryAlloc(sizeof(CHandleInfo));
		*(LPVOID*)&SystemHandle = MemoryAlloc(SizeRequired);
		*(LPVOID*)&DeviceInfo = MemoryAlloc(sizeof(FILE_FS_DEVICE_INFORMATION));

		Status = NtQuerySystemInformation(SystemHandleInformation, SystemHandle, SizeRequired, 0);

		if (Status == STATUS_UNSUCCESSFUL)
		{
			MemoryFree(CHandleInformation);
			MemoryFree(SystemHandle);
			return FALSE;
		}

		if (Status == STATUS_INFO_LENGTH_MISMATCH)
		{
			if (HandleSync.LockSemaphore == NULL)
				RtlInitializeCriticalSection(&HandleSync);

			if ((SystemHandle->HandleCount * sizeof(SYSTEM_HANDLE)) > SizeRequired)
				SizeRequired = SystemHandle->HandleCount * sizeof(SYSTEM_HANDLE);

			RtlEnterCriticalSection(&HandleSync);

			do {
				*(LPVOID*)&SystemHandle = MemoryFree(SystemHandle);
				*(LPVOID*)&SystemHandle = MemoryAlloc(SizeRequired);

				Status = NtQuerySystemInformation(SystemHandleInformation, SystemHandle, SizeRequired, 0);

				if (Status == STATUS_UNSUCCESSFUL)
				{
					MemoryFree(DeviceInfo);
					MemoryFree(CHandleInformation);
					MemoryFree(SystemHandle);
					RtlLeaveCriticalSection(&HandleSync);

					return FALSE;
				}
				else if (Status == STATUS_SUCCESS)
				{
					break;
				}

				SizeRequired += 8192;

			} while (Status == STATUS_INFO_LENGTH_MISMATCH);

			RtlLeaveCriticalSection(&HandleSync);
		}

		for (ULONG i = 0, atual = 0; i < SystemHandle->HandleCount; i++)
		{
			HandleNameObject = EmptyString;
			IsPipeHandle = FALSE;
			ObjInfo = NULL;

			if (ProcessID == SystemHandle->Handles[i].ProcessId || ProcessID == 0)
			{
				if (SystemHandle->Handles[i].ProcessId != atual)
				{
					NtClose(hProcess);
					hProcess = OpenProcess(PROCESS_DUP_HANDLE, 0, SystemHandle->Handles[i].ProcessId);
					atual = SystemHandle->Handles[i].ProcessId;
				}

				if (hProcess <= 0)
					continue;

				Status = NtDuplicateObject(
					hProcess,
					ULongToHandle(SystemHandle->Handles[i].Handle),
					NtCurrentProcess(),
					&Handle,
					0, 0, DUPLICATE_SAME_ACCESS);

				if (Handle <= 0)
					continue;

				CHandleInformation->TargetHandles.hProcess = &hProcess;
				CHandleInformation->TargetHandles.Handle = &Handle;

				if (GetObjectTypeInfo(Handle, &ObjInfo) == TRUE)
				{
					CHandleInformation->ObjectTypeID = GetHandleTypeIndexByName(ObjInfo->TypeName.Buffer);
					CHandleInformation->ObjectTypeSTR = ObjInfo->TypeName.Buffer;
				}

				if (CHandleInformation->ObjectTypeID == DennysDocs::HANDLE_TYPE::TYPE_FILE)
				{
					Status = NtQueryVolumeInformationFile(
						Handle,
						&StatusBlock,
						DeviceInfo,
						sizeof(FILE_FS_DEVICE_INFORMATION),
						FileFsDeviceInformation);
				}

				if (DeviceInfo->DeviceType == FILE_DEVICE_NAMED_PIPE)
				{
					hThread = CreateThread(NULL, NULL,
						LPTHREAD_START_ROUTINE(GetObjectHandleName),
						Handle,
						CREATE_SUSPENDED, NULL);

					if (hThread > 0)
					{
						Status = NtResumeThread(hThread, 0);

						WaitSignal = WaitForSingleObject(hThread, 100);

						if (WaitSignal == WAIT_OBJECT_0)
						{
							GetExitCodeThread(hThread, (LPDWORD)&HandleNameObject);
						}
						else
						{
							Status = NtTerminateThread(hThread, 0);
						}

						NtClose(hThread);
					}
				}
				else
				{
					HandleNameObject = GetObjectHandleName(Handle);
				}

				CHandleInformation->AccessRight = SystemHandle->Handles[i].GrantedAccess;
				CHandleInformation->Attributes = SystemHandle->Handles[i].Flags;
				CHandleInformation->Handle = ULongToHandle(SystemHandle->Handles[i].Handle);
				CHandleInformation->HandleName = HandleNameObject;
				CHandleInformation->ObjectPTR = SystemHandle->Handles[i].Object;
				CHandleInformation->ProcessID = SystemHandle->Handles[i].ProcessId;

				StopEnumeration = !CCallback(*CHandleInformation, CHandleInformation->ProcessID, infoAdded);

				NtClose(Handle);

				if (ObjInfo != nullptr)
					MemoryFree(ObjInfo);

				if (HandleNameObject != EmptyString)
					MemoryFree(HandleNameObject);
			}

			RtlZeroMemory(DeviceInfo, sizeof(FILE_FS_DEVICE_INFORMATION));
			RtlZeroMemory(CHandleInformation, sizeof(CHandleInfo));

			if (StopEnumeration)
			{
				break;
			}
		}

		NtClose(hProcess);
		RtlSecureZeroMemory(CHandleInformation, sizeof(CHandleInfo));

		MemoryFree(DeviceInfo);
		MemoryFree(CHandleInformation);
		MemoryFree(SystemHandle);

		return TRUE;
	}
}