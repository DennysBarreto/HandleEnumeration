#include "DennysDocs.h"

using namespace DennysDocs;

BOOL CALLBACK EnumContext(CHandleInfo HandleInfo, DWORD ProcessId, LPVOID lpParam)
{
	LPWSTR HandleName = NULL;

	HandleName = HandleInfo.HandleName;

	if (HandleInfo.ObjectTypeID == HANDLE_TYPE::TYPE_FILE)
	{
		//HandleName = DennysDocs::ConvertToUserPath(HandleName);
	}

	printf("PID: %d (%ws) | Handle: 0x%x -> %ws\n",
		ProcessId,
		HandleInfo.ObjectTypeSTR,
		HandleInfo.Handle,
		HandleName);

	if (HandleInfo.ObjectTypeID == HANDLE_TYPE::TYPE_FILE)
	{
		//*(LPVOID*)&HandleName = DennysDocs::MemoryFree(HandleName);
	}

	return TRUE;
}

int _tmain(int argc, TCHAR** argv)
{
	DWORD	ProcessId = 0;
	BOOL	Status = 0;

	ProcessId = DennysDocs::FindProcessID(L"notepad.exe");
	
	//ProcessId == 0 -> Enumerates all handles of all processes

	Status = HandleEnumerateCallback(ProcessId, EnumContext, NULL);

	return SleepEx(0xFFFFFF, FALSE);
}
