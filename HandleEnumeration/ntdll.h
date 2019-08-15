#pragma comment(lib, "ntdll.lib")

typedef long NTSTATUS;

#define STATUS_BUFFER_TOO_SMALL		((NTSTATUS)0xC0000023L)
#define STATUS_INFO_LENGTH_MISMATCH 0xC0000004

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
#endif

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS       ((NTSTATUS)0x00000000L)
#endif

#ifndef STATUS_UNSUCCESSFUL
#define STATUS_UNSUCCESSFUL ((NTSTATUS)0xC0000001L)
#endif

#define NtCurrentProcess() ((HANDLE) -1)
#define NtCurrentThread()  ((HANDLE) -2)

typedef struct _UNICODE_STRING
{
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef enum _POOL_TYPE {
	NonPagedPool,
	PagedPool,
	NonPagedPoolMustSucceed,
	DontUseThisType,
	NonPagedPoolCacheAligned,
	PagedPoolCacheAligned,
	NonPagedPoolCacheAlignedMustS,
	MaxPoolType
} POOL_TYPE;

typedef enum _SYSTEM_INFORMATION_CLASS
{
	SystemBasicInformation,                         // 0x00 SYSTEM_BASIC_INFORMATION
	SystemProcessorInformation,                     // 0x01 SYSTEM_PROCESSOR_INFORMATION
	SystemPerformanceInformation,                   // 0x02
	SystemTimeOfDayInformation,                     // 0x03
	SystemPathInformation,                          // 0x04
	SystemProcessInformation,                       // 0x05
	SystemCallCountInformation,                     // 0x06
	SystemDeviceInformation,                        // 0x07
	SystemProcessorPerformanceInformation,          // 0x08
	SystemFlagsInformation,                         // 0x09
	SystemCallTimeInformation,                      // 0x0A
	SystemModuleInformation,                        // 0x0B SYSTEM_MODULE_INFORMATION
	SystemLocksInformation,                         // 0x0C
	SystemStackTraceInformation,                    // 0x0D
	SystemPagedPoolInformation,                     // 0x0E
	SystemNonPagedPoolInformation,                  // 0x0F
	SystemHandleInformation,                        // 0x10
	SystemObjectInformation,                        // 0x11
	SystemPageFileInformation,                      // 0x12
	SystemVdmInstemulInformation,                   // 0x13
	SystemVdmBopInformation,                        // 0x14
	SystemFileCacheInformation,                     // 0x15
	SystemPoolTagInformation,                       // 0x16
	SystemInterruptInformation,                     // 0x17
	SystemDpcBehaviorInformation,                   // 0x18
	SystemFullMemoryInformation,                    // 0x19
	SystemLoadGdiDriverInformation,                 // 0x1A
	SystemUnloadGdiDriverInformation,               // 0x1B
	SystemTimeAdjustmentInformation,                // 0x1C
	SystemSummaryMemoryInformation,                 // 0x1D
	SystemMirrorMemoryInformation,                  // 0x1E
	SystemPerformanceTraceInformation,              // 0x1F
	SystemObsolete0,                                // 0x20
	SystemExceptionInformation,                     // 0x21
	SystemCrashDumpStateInformation,                // 0x22
	SystemKernelDebuggerInformation,                // 0x23
	SystemContextSwitchInformation,                 // 0x24
	SystemRegistryQuotaInformation,                 // 0x25
	SystemExtendServiceTableInformation,            // 0x26
	SystemPrioritySeperation,                       // 0x27
	SystemPlugPlayBusInformation,                   // 0x28
	SystemDockInformation,                          // 0x29
	SystemPowerInformationNative,                   // 0x2A
	SystemProcessorSpeedInformation,                // 0x2B
	SystemCurrentTimeZoneInformation,               // 0x2C
	SystemLookasideInformation,                     // 0x2D
	SystemTimeSlipNotification,                     // 0x2E
	SystemSessionCreate,                            // 0x2F
	SystemSessionDetach,                            // 0x30
	SystemSessionInformation,                       // 0x31
	SystemRangeStartInformation,                    // 0x32
	SystemVerifierInformation,                      // 0x33
	SystemAddVerifier,                              // 0x34
	SystemSessionProcessesInformation,              // 0x35
	SystemLoadGdiDriverInSystemSpaceInformation,    // 0x36
	SystemNumaProcessorMap,                         // 0x37
	SystemPrefetcherInformation,                    // 0x38
	SystemExtendedProcessInformation,               // 0x39
	SystemRecommendedSharedDataAlignment,           // 0x3A
	SystemComPlusPackage,                           // 0x3B
	SystemNumaAvailableMemory,                      // 0x3C
	SystemProcessorPowerInformation,                // 0x3D
	SystemEmulationBasicInformation,                // 0x3E
	SystemEmulationProcessorInformation,            // 0x3F
	SystemExtendedHanfleInformation,                // 0x40
	SystemLostDelayedWriteInformation,              // 0x41
	SystemBigPoolInformation,                       // 0x42
	SystemSessionPoolTagInformation,                // 0x43
	SystemSessionMappedViewInformation,             // 0x44
	SystemHotpatchInformation,                      // 0x45
	SystemObjectSecurityMode,                       // 0x46
	SystemWatchDogTimerHandler,                     // 0x47
	SystemWatchDogTimerInformation,                 // 0x48
	SystemLogicalProcessorInformation,              // 0x49
	SystemWo64SharedInformationObosolete,           // 0x4A
	SystemRegisterFirmwareTableInformationHandler,  // 0x4B
	SystemFirmwareTableInformation,                 // 0x4C
	SystemModuleInformationEx,                      // 0x4D
	SystemVerifierTriageInformation,                // 0x4E
	SystemSuperfetchInformation,                    // 0x4F
	SystemMemoryListInformation,                    // 0x50
	SystemFileCacheInformationEx,                   // 0x51
	SystemThreadPriorityClientIdInformation,        // 0x52
	SystemProcessorIdleCycleTimeInformation,        // 0x53
	SystemVerifierCancellationInformation,          // 0x54
	SystemProcessorPowerInformationEx,              // 0x55
	SystemRefTraceInformation,                      // 0x56
	SystemSpecialPoolInformation,                   // 0x57
	SystemProcessIdInformation,                     // 0x58
	SystemErrorPortInformation,                     // 0x59
	SystemBootEnvironmentInformation,               // 0x5A SYSTEM_BOOT_ENVIRONMENT_INFORMATION
	SystemHypervisorInformation,                    // 0x5B
	SystemVerifierInformationEx,                    // 0x5C
	SystemTimeZoneInformation,                      // 0x5D
	SystemImageFileExecutionOptionsInformation,     // 0x5E
	SystemCoverageInformation,                      // 0x5F
	SystemPrefetchPathInformation,                  // 0x60
	SystemVerifierFaultsInformation,                // 0x61
	MaxSystemInfoClass                              // 0x67
} SYSTEM_INFORMATION_CLASS, *PSYSTEM_INFORMATION_CLASS;

typedef enum _PROCESSINFOCLASS {
	ProcessBasicInformation,                // 0x00
	ProcessQuotaLimits,                     // 0x01
	ProcessIoCounters,                      // 0x02
	ProcessVmCounters,                      // 0x03
	ProcessTimes,                           // 0x04
	ProcessBasePriority,                    // 0x05
	ProcessRaisePriority,                   // 0x06
	ProcessDebugPort,                       // 0x07
	ProcessExceptionPort,                   // 0x08
	ProcessAccessToken,                     // 0x09
	ProcessLdtInformation,                  // 0x0A
	ProcessLdtSize,                         // 0x0B
	ProcessDefaultHardErrorMode,            // 0x0C
	ProcessIoPortHandlers,                  // 0x0D Note: this is kernel mode only
	ProcessPooledUsageAndLimits,            // 0x0E
	ProcessWorkingSetWatch,                 // 0x0F
	ProcessUserModeIOPL,                    // 0x10
	ProcessEnableAlignmentFaultFixup,       // 0x11
	ProcessPriorityClass,                   // 0x12
	ProcessWx86Information,                 // 0x13
	ProcessHandleCount,                     // 0x14
	ProcessAffinityMask,                    // 0x15
	ProcessPriorityBoost,                   // 0x16
	ProcessDeviceMap,                       // 0x17
	ProcessSessionInformation,              // 0x18
	ProcessForegroundInformation,           // 0x19
	ProcessWow64Information,                // 0x1A
	ProcessImageFileName,                   // 0x1B
	ProcessLUIDDeviceMapsEnabled,           // 0x1C
	ProcessBreakOnTermination,              // 0x1D
	ProcessDebugObjectHandle,               // 0x1E
	ProcessDebugFlags,                      // 0x1F
	ProcessHandleTracing,                   // 0x20
	ProcessIoPriority,                      // 0x21
	ProcessExecuteFlags,                    // 0x22
	ProcessTlsInformation,
	ProcessCookie,
	ProcessImageInformation,
	ProcessCycleTime,
	ProcessPagePriority,
	ProcessInstrumentationCallback,
	ProcessThreadStackAllocation,
	ProcessWorkingSetWatchEx,
	ProcessImageFileNameWin32,
	ProcessImageFileMapping,
	ProcessAffinityUpdateMode,
	ProcessMemoryAllocationMode,
	ProcessGroupInformation,
	ProcessTokenVirtualizationEnabled,
	ProcessConsoleHostProcess,
	ProcessWindowInformation,
	MaxProcessInfoClass                     // MaxProcessInfoClass should always be the last enum
} PROCESSINFOCLASS;

typedef enum _FSINFOCLASS {
	FileFsVolumeInformation = 1,
	FileFsLabelInformation,                 // 0x02
	FileFsSizeInformation,                  // 0x03
	FileFsDeviceInformation,                // 0x04
	FileFsAttributeInformation,             // 0x05
	FileFsControlInformation,               // 0x06
	FileFsFullSizeInformation,              // 0x07
	FileFsObjectIdInformation,              // 0x08
	FileFsDriverPathInformation,            // 0x09
	FileFsVolumeFlagsInformation,           // 0x0A
	FileFsMaximumInformation                // 0x0B
} FS_INFORMATION_CLASS, *PFS_INFORMATION_CLASS;

typedef enum _OBJECT_INFORMATION_CLASS {
	ObjectBasicInformation, // OBJECT_BASIC_INFORMATION
	ObjectNameInformation, // OBJECT_NAME_INFORMATION
	ObjectTypeInformation, // OBJECT_TYPE_INFORMATION
	ObjectTypesInformation, // OBJECT_TYPES_INFORMATION
	ObjectHandleFlagInformation, // OBJECT_HANDLE_FLAG_INFORMATION
	ObjectSessionInformation,
	ObjectSessionObjectInformation,
	MaxObjectInfoClass
} OBJECT_INFORMATION_CLASS;

typedef struct _SYSTEM_HANDLE
{
	ULONG ProcessId;
	BYTE ObjectTypeNumber;
	BYTE Flags;
	USHORT Handle;
	PVOID Object;
	ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE, *PSYSTEM_HANDLE;

typedef struct _SYSTEM_HANDLE_INFORMATION
{
	ULONG HandleCount;
	SYSTEM_HANDLE Handles[1];
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

typedef struct _FILE_FS_DEVICE_INFORMATION {
	DEVICE_TYPE DeviceType;
	ULONG Characteristics;
} FILE_FS_DEVICE_INFORMATION, *PFILE_FS_DEVICE_INFORMATION;

typedef struct _OBJECT_NAME_INFORMATION {
	UNICODE_STRING Name;
} OBJECT_NAME_INFORMATION, *POBJECT_NAME_INFORMATION;

typedef struct _OBJECT_TYPE_INFORMATION {
	UNICODE_STRING TypeName;
	ULONG TotalNumberOfObjects;
	ULONG TotalNumberOfHandles;
	ULONG TotalPagedPoolUsage;
	ULONG TotalNonPagedPoolUsage;
	ULONG TotalNamePoolUsage;
	ULONG TotalHandleTableUsage;
	ULONG HighWaterNumberOfObjects;
	ULONG HighWaterNumberOfHandles;
	ULONG HighWaterPagedPoolUsage;
	ULONG HighWaterNonPagedPoolUsage;
	ULONG HighWaterNamePoolUsage;
	ULONG HighWaterHandleTableUsage;
	ULONG InvalidAttributes;
	GENERIC_MAPPING GenericMapping;
	ULONG ValidAccessMask;
	BOOLEAN SecurityRequired;
	BOOLEAN MaintainHandleCount;
	POOL_TYPE PoolType;
	ULONG DefaultPagedPoolCharge;
	ULONG DefaultNonPagedPoolCharge;
} OBJECT_TYPE_INFORMATION, *POBJECT_TYPE_INFORMATION;

typedef struct _IO_STATUS_BLOCK
{
	union
	{
		NTSTATUS Status;
		PVOID Pointer;
	};

	ULONG_PTR Information;

} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

extern "C"
{
	NTSYSAPI NTSTATUS NTAPI RtlInitializeCriticalSection(
		IN  PRTL_CRITICAL_SECTION CriticalSection
	);

	NTSYSAPI NTSTATUS NTAPI RtlEnterCriticalSection(
		IN PRTL_CRITICAL_SECTION CriticalSection
	);


	NTSYSAPI NTSTATUS NTAPI RtlLeaveCriticalSection(
		IN PRTL_CRITICAL_SECTION CriticalSection
	);

	NTSYSAPI NTSTATUS NTAPI NtQuerySystemInformation(
		IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
		OUT PVOID SystemInformation,
		IN ULONG SystemInformationLength,
		OUT PULONG ReturnLength
	);

	NTSYSAPI NTSTATUS NTAPI NtQueryVolumeInformationFile(
		IN HANDLE FileHandle,
		OUT PIO_STATUS_BLOCK IoStatusBlock,
		OUT PVOID FsInformation,
		IN ULONG Length,
		IN FS_INFORMATION_CLASS FsInformationClass
	);

	NTSYSAPI NTSTATUS NTAPI NtDuplicateObject(
		IN HANDLE SourceProcessHandle,
		IN HANDLE SourceHandle,
		IN HANDLE TargetProcessHandle OPTIONAL,
		OUT PHANDLE TargetHandle OPTIONAL,
		IN ACCESS_MASK DesiredAccess,
		IN ULONG HandleAttributes,
		IN ULONG Options
	);

	NTSYSAPI NTSTATUS NTAPI NtQueryObject(
		IN HANDLE ObjectHandle,
		IN OBJECT_INFORMATION_CLASS ObjectInformationClass,
		OUT PVOID ObjectInformation,
		IN ULONG Length,
		OUT PULONG ResultLength OPTIONAL
	);

	NTSYSAPI NTSTATUS NTAPI NtClose(
		IN  HANDLE Handle
	);

	NTSYSAPI NTSTATUS NTAPI NtResumeThread(
		IN HANDLE ThreadHandle,
		OUT PULONG PreviousSuspendCount OPTIONAL
	);

	NTSYSAPI NTSTATUS NTAPI NtTerminateThread(
		HANDLE Thread,
		NTSTATUS ExitStatus
	);

	NTSYSAPI BOOLEAN NTAPI RtlCreateUnicodeString(
		OUT PUNICODE_STRING DestinationString,
		IN PCWSTR SourceString
	);

	NTSYSAPI LONG NTAPI RtlCompareUnicodeString(
		IN PUNICODE_STRING String1,
		IN PUNICODE_STRING String2,
		IN BOOLEAN CaseInSensitive
	);

	NTSYSAPI BOOLEAN NTAPI RtlEqualUnicodeString(
		IN PUNICODE_STRING String1,
		IN PUNICODE_STRING String2,
		IN BOOLEAN CaseInSensitive
	);

	NTSYSAPI VOID NTAPI RtlFreeUnicodeString(
		IN  PUNICODE_STRING UnicodeString
	);
}
