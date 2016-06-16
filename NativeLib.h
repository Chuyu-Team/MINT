#pragma once

#ifndef NATIVELIB
#define NATIVELIB

#pragma comment(lib,"ntdll.lib")

// 本机API定义
#pragma region NativeDefine

// Native API错误处理
#pragma region NtError

// NT status macros

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#define NT_INFORMATION(Status) ((((ULONG)(Status)) >> 30) == 1)
#define NT_WARNING(Status) ((((ULONG)(Status)) >> 30) == 2)
#define NT_ERROR(Status) ((((ULONG)(Status)) >> 30) == 3)

#define NT_FACILITY_MASK 0xfff
#define NT_FACILITY_SHIFT 16
#define NT_FACILITY(Status) ((((ULONG)(Status)) >> NT_FACILITY_SHIFT) & NT_FACILITY_MASK)

#define NT_NTWIN32(Status) (NT_FACILITY(Status) == FACILITY_NTWIN32)
#define WIN32_FROM_NTSTATUS(Status) (((ULONG)(Status)) & 0xffff)

#define RTL_ERRORMODE_NOGPFAULTERRORBOX 0x0020
#define RTL_ERRORMODE_NOOPENFILEERRORBOX 0x0040

#pragma endregion

// NLS
#pragma region NLS

#define MAXIMUM_LEADBYTES 12

typedef struct _CPTABLEINFO
{
	USHORT CodePage;
	USHORT MaximumCharacterSize;
	USHORT DefaultChar;
	USHORT UniDefaultChar;
	USHORT TransDefaultChar;
	USHORT TransUniDefaultChar;
	USHORT DBCSCodePage;
	UCHAR LeadByte[MAXIMUM_LEADBYTES];
	PUSHORT MultiByteTable;
	PVOID WideCharTable;
	PUSHORT DBCSRanges;
	PUSHORT DBCSOffsets;
} CPTABLEINFO, *PCPTABLEINFO;

typedef struct _NLSTABLEINFO
{
	CPTABLEINFO OemTableInfo;
	CPTABLEINFO AnsiTableInfo;
	PUSHORT UpperCaseTable;
	PUSHORT LowerCaseTable;
} NLSTABLEINFO, *PNLSTABLEINFO;

#pragma endregion

// 字符串
#pragma region String

typedef struct _STRING
{
	USHORT Length;
	USHORT MaximumLength;
	PSTR Buffer;
} STRING, *PSTRING, ANSI_STRING, *PANSI_STRING, OEM_STRING, *POEM_STRING;

typedef const STRING *PCSTRING;
typedef const ANSI_STRING *PCANSI_STRING;
typedef const OEM_STRING *PCOEM_STRING;

typedef struct _UNICODE_STRING
{
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;
typedef const UNICODE_STRING *PCUNICODE_STRING;

#define UNICODE_NULL ((WCHAR)0) // winnt

#define UNICODE_STRING_MAX_CHARS (32767) // winnt

#define RTL_CONSTANT_STRING(s) { sizeof(s) - sizeof((s)[0]), sizeof(s), s }

// RtlDuplicateUnicodeString

#define RTL_DUPLICATE_UNICODE_STRING_NULL_TERMINATE (0x00000001)
#define RTL_DUPLICATE_UNICODE_STRING_ALLOCATE_NULL_STRING (0x00000002)

// RtlHashUnicodeString

#define HASH_STRING_ALGORITHM_DEFAULT 0
#define HASH_STRING_ALGORITHM_X65599 1
#define HASH_STRING_ALGORITHM_INVALID 0xffffffff

// RtlFindCharInUnicodeString

#define RTL_FIND_CHAR_IN_UNICODE_STRING_START_AT_END 0x00000001
#define RTL_FIND_CHAR_IN_UNICODE_STRING_COMPLEMENT_CHAR_SET 0x00000002
#define RTL_FIND_CHAR_IN_UNICODE_STRING_CASE_INSENSITIVE 0x00000004

// NormForm

typedef enum _RTL_NORM_FORM
{
	NormOther = 0x0,
	NormC = 0x1,
	NormD = 0x2,
	NormKC = 0x5,
	NormKD = 0x6,
	NormIdna = 0xd,
	DisallowUnassigned = 0x100,
	NormCDisallowUnassigned = 0x101,
	NormDDisallowUnassigned = 0x102,
	NormKCDisallowUnassigned = 0x105,
	NormKDDisallowUnassigned = 0x106,
	NormIdnaDisallowUnassigned = 0x10d
} RTL_NORM_FORM;

// SID, SD, Access masks, ACL, ACE

#define MAX_UNICODE_STACK_BUFFER_LENGTH 256

#pragma endregion

// 同步
#pragma region Synchronization

typedef enum _EVENT_TYPE
{
	NotificationEvent,
	SynchronizationEvent
} EVENT_TYPE;

typedef enum _TIMER_TYPE
{
	NotificationTimer,
	SynchronizationTimer
} TIMER_TYPE;

typedef enum _WAIT_TYPE
{
	WaitAll,
	WaitAny,
	WaitNotification
} WAIT_TYPE;

#pragma endregion

// 对象
#pragma region Object

#define OBJ_INHERIT                         0x00000002L
#define OBJ_PERMANENT                       0x00000010L
#define OBJ_EXCLUSIVE                       0x00000020L
#define OBJ_CASE_INSENSITIVE                0x00000040L
#define OBJ_OPENIF                          0x00000080L
#define OBJ_OPENLINK                        0x00000100L
#define OBJ_KERNEL_HANDLE                   0x00000200L
#define OBJ_FORCE_ACCESS_CHECK              0x00000400L
#define OBJ_IGNORE_IMPERSONATED_DEVICEMAP   0x00000800L
#define OBJ_DONT_REPARSE                    0x00001000L
#define OBJ_VALID_ATTRIBUTES                0x00001FF2L

typedef struct _OBJECT_ATTRIBUTES
{
	ULONG Length;
	HANDLE RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG Attributes;
	PVOID SecurityDescriptor;        // Points to type SECURITY_DESCRIPTOR
	PVOID SecurityQualityOfService;  // Points to type SECURITY_QUALITY_OF_SERVICE
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;
typedef const OBJECT_ATTRIBUTES *PCOBJECT_ATTRIBUTES;

#define OBJECT_TYPE_CREATE 0x0001
#define OBJECT_TYPE_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED | 0x1)

#define DIRECTORY_QUERY 0x0001
#define DIRECTORY_TRAVERSE 0x0002
#define DIRECTORY_CREATE_OBJECT 0x0004
#define DIRECTORY_CREATE_SUBDIRECTORY 0x0008
#define DIRECTORY_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED | 0xf)

#define SYMBOLIC_LINK_QUERY 0x0001
#define SYMBOLIC_LINK_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED | 0x1)

#define OBJ_PROTECT_CLOSE 0x00000001
#ifndef OBJ_INHERIT
#define OBJ_INHERIT 0x00000002L
#endif
#define OBJ_AUDIT_OBJECT_CLOSE 0x00000004

typedef enum _OBJECT_INFORMATION_CLASS
{
	ObjectBasicInformation,
	ObjectNameInformation,
	ObjectTypeInformation,
	ObjectTypesInformation,
	ObjectHandleFlagInformation,
	ObjectSessionInformation,
	MaxObjectInfoClass
} OBJECT_INFORMATION_CLASS;

typedef struct _OBJECT_BASIC_INFORMATION
{
	ULONG Attributes;
	ACCESS_MASK GrantedAccess;
	ULONG HandleCount;
	ULONG PointerCount;
	ULONG PagedPoolCharge;
	ULONG NonPagedPoolCharge;
	ULONG Reserved[3];
	ULONG NameInfoSize;
	ULONG TypeInfoSize;
	ULONG SecurityDescriptorSize;
	LARGE_INTEGER CreationTime;
} OBJECT_BASIC_INFORMATION, *POBJECT_BASIC_INFORMATION;

typedef struct _OBJECT_NAME_INFORMATION
{
	UNICODE_STRING Name;
} OBJECT_NAME_INFORMATION, *POBJECT_NAME_INFORMATION;

typedef struct _OBJECT_TYPE_INFORMATION
{
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
	UCHAR TypeIndex; // since WINBLUE
	CHAR ReservedByte;
	ULONG PoolType;
	ULONG DefaultPagedPoolCharge;
	ULONG DefaultNonPagedPoolCharge;
} OBJECT_TYPE_INFORMATION, *POBJECT_TYPE_INFORMATION;

typedef struct _OBJECT_TYPES_INFORMATION
{
	ULONG NumberOfTypes;
} OBJECT_TYPES_INFORMATION, *POBJECT_TYPES_INFORMATION;

typedef struct _OBJECT_HANDLE_FLAG_INFORMATION
{
	BOOLEAN Inherit;
	BOOLEAN ProtectFromClose;
} OBJECT_HANDLE_FLAG_INFORMATION, *POBJECT_HANDLE_FLAG_INFORMATION;

// NtDuplicateObject

#define DUPLICATE_CLOSE_SOURCE 0x00000001
#define DUPLICATE_SAME_ACCESS 0x00000002
#define DUPLICATE_SAME_ATTRIBUTES 0x00000004

typedef struct _OBJECT_DIRECTORY_INFORMATION
{
	UNICODE_STRING Name;
	UNICODE_STRING TypeName;
} OBJECT_DIRECTORY_INFORMATION, *POBJECT_DIRECTORY_INFORMATION;

#pragma endregion

// 内存
#pragma region Memory

// private
typedef enum _MEMORY_INFORMATION_CLASS
{
	MemoryBasicInformation, // MEMORY_BASIC_INFORMATION
	MemoryWorkingSetInformation, // MEMORY_WORKING_SET_INFORMATION
	MemoryMappedFilenameInformation, // UNICODE_STRING
	MemoryRegionInformation, // MEMORY_REGION_INFORMATION
	MemoryWorkingSetExInformation, // MEMORY_WORKING_SET_EX_INFORMATION
	MemorySharedCommitInformation, // MEMORY_SHARED_COMMIT_INFORMATION
	MemoryImageInformation // MEMORY_IMAGE_INFORMATION
} MEMORY_INFORMATION_CLASS;

typedef struct _MEMORY_WORKING_SET_BLOCK
{
	ULONG_PTR Protection : 5;
	ULONG_PTR ShareCount : 3;
	ULONG_PTR Shared : 1;
	ULONG_PTR Node : 3;
#ifdef _WIN64
	ULONG_PTR VirtualPage : 52;
#else
	ULONG VirtualPage : 20;
#endif
} MEMORY_WORKING_SET_BLOCK, *PMEMORY_WORKING_SET_BLOCK;

typedef struct _MEMORY_WORKING_SET_INFORMATION
{
	ULONG_PTR NumberOfEntries;
	MEMORY_WORKING_SET_BLOCK WorkingSetInfo[1];
} MEMORY_WORKING_SET_INFORMATION, *PMEMORY_WORKING_SET_INFORMATION;

// private
typedef struct _MEMORY_REGION_INFORMATION
{
	PVOID AllocationBase;
	ULONG AllocationProtect;
	ULONG RegionType;
	SIZE_T RegionSize;
} MEMORY_REGION_INFORMATION, *PMEMORY_REGION_INFORMATION;

// private
typedef struct _MEMORY_WORKING_SET_EX_BLOCK
{
	union
	{
		struct
		{
			ULONG_PTR Valid : 1;
			ULONG_PTR ShareCount : 3;
			ULONG_PTR Win32Protection : 11;
			ULONG_PTR Shared : 1;
			ULONG_PTR Node : 6;
			ULONG_PTR Locked : 1;
			ULONG_PTR LargePage : 1;
			ULONG_PTR Priority : 3;
			ULONG_PTR Reserved : 3;
			ULONG_PTR SharedOriginal : 1;
			ULONG_PTR Bad : 1;
#ifdef _WIN64
			ULONG_PTR ReservedUlong : 32;
#endif
		};
		struct
		{
			ULONG_PTR Valid : 1;
			ULONG_PTR Reserved0 : 14;
			ULONG_PTR Shared : 1;
			ULONG_PTR Reserved1 : 5;
			ULONG_PTR PageTable : 1;
			ULONG_PTR Location : 2;
			ULONG_PTR Priority : 3;
			ULONG_PTR ModifiedList : 1;
			ULONG_PTR Reserved2 : 2;
			ULONG_PTR SharedOriginal : 1;
			ULONG_PTR Bad : 1;
#ifdef _WIN64
			ULONG_PTR ReservedUlong : 32;
#endif
		} Invalid;
	};
} MEMORY_WORKING_SET_EX_BLOCK, *PMEMORY_WORKING_SET_EX_BLOCK;

// private
typedef struct _MEMORY_WORKING_SET_EX_INFORMATION
{
	PVOID VirtualAddress;
	union
	{
		MEMORY_WORKING_SET_EX_BLOCK VirtualAttributes;
		ULONG_PTR Long;
	} u1;
} MEMORY_WORKING_SET_EX_INFORMATION, *PMEMORY_WORKING_SET_EX_INFORMATION;

// private
typedef struct _MEMORY_SHARED_COMMIT_INFORMATION
{
	SIZE_T CommitSize;
} MEMORY_SHARED_COMMIT_INFORMATION, *PMEMORY_SHARED_COMMIT_INFORMATION;

// private
typedef struct _MEMORY_IMAGE_INFORMATION
{
	PVOID ImageBase;
	SIZE_T SizeOfImage;
	union
	{
		ULONG ImageFlags;
		struct
		{
			ULONG ImagePartialMap : 1;
			ULONG ImageNotExecutable : 1;
			ULONG Reserved : 30;
		};
	};
} MEMORY_IMAGE_INFORMATION, *PMEMORY_IMAGE_INFORMATION;

#define MMPFNLIST_ZERO 0
#define MMPFNLIST_FREE 1
#define MMPFNLIST_STANDBY 2
#define MMPFNLIST_MODIFIED 3
#define MMPFNLIST_MODIFIEDNOWRITE 4
#define MMPFNLIST_BAD 5
#define MMPFNLIST_ACTIVE 6
#define MMPFNLIST_TRANSITION 7

#define MMPFNUSE_PROCESSPRIVATE 0
#define MMPFNUSE_FILE 1
#define MMPFNUSE_PAGEFILEMAPPED 2
#define MMPFNUSE_PAGETABLE 3
#define MMPFNUSE_PAGEDPOOL 4
#define MMPFNUSE_NONPAGEDPOOL 5
#define MMPFNUSE_SYSTEMPTE 6
#define MMPFNUSE_SESSIONPRIVATE 7
#define MMPFNUSE_METAFILE 8
#define MMPFNUSE_AWEPAGE 9
#define MMPFNUSE_DRIVERLOCKPAGE 10

typedef struct _MEMORY_FRAME_INFORMATION
{
	ULONGLONG UseDescription : 4; // MMPFNUSE_*
	ULONGLONG ListDescription : 3; // MMPFNLIST_*
	ULONGLONG Reserved0 : 1; // reserved for future expansion
	ULONGLONG Pinned : 1; // 1 - pinned, 0 - not pinned
	ULONGLONG DontUse : 48; // *_INFORMATION overlay
	ULONGLONG Priority : 3; // rev
	ULONGLONG Reserved : 4; // reserved for future expansion
} MEMORY_FRAME_INFORMATION;

typedef struct _FILEOFFSET_INFORMATION
{
	ULONGLONG DontUse : 9; // MEMORY_FRAME_INFORMATION overlay
	ULONGLONG Offset : 48; // mapped files
	ULONGLONG Reserved : 7; // reserved for future expansion
} FILEOFFSET_INFORMATION;

typedef struct _PAGEDIR_INFORMATION
{
	ULONGLONG DontUse : 9; // MEMORY_FRAME_INFORMATION overlay
	ULONGLONG PageDirectoryBase : 48; // private pages
	ULONGLONG Reserved : 7; // reserved for future expansion
} PAGEDIR_INFORMATION;

typedef struct _MMPFN_IDENTITY
{
	union
	{
		MEMORY_FRAME_INFORMATION e1; // all
		FILEOFFSET_INFORMATION e2; // mapped files
		PAGEDIR_INFORMATION e3; // private pages
	} u1;
	ULONG_PTR PageFrameIndex; // all
	union
	{
		PVOID FileObject; // mapped files
		PVOID VirtualAddress; // everything else
	} u2;
} MMPFN_IDENTITY, *PMMPFN_IDENTITY;

typedef struct _MMPFN_MEMSNAP_INFORMATION
{
	ULONG_PTR InitialPageFrameIndex;
	ULONG_PTR Count;
} MMPFN_MEMSNAP_INFORMATION, *PMMPFN_MEMSNAP_INFORMATION;

typedef enum _SECTION_INFORMATION_CLASS
{
	SectionBasicInformation,
	SectionImageInformation,
	SectionRelocationInformation, // name:wow64:whNtQuerySection_SectionRelocationInformation
	MaxSectionInfoClass
} SECTION_INFORMATION_CLASS;

typedef struct _SECTION_BASIC_INFORMATION
{
	PVOID BaseAddress;
	ULONG AllocationAttributes;
	LARGE_INTEGER MaximumSize;
} SECTION_BASIC_INFORMATION, *PSECTION_BASIC_INFORMATION;

// symbols
typedef struct _SECTION_IMAGE_INFORMATION
{
	PVOID TransferAddress;
	ULONG ZeroBits;
	SIZE_T MaximumStackSize;
	SIZE_T CommittedStackSize;
	ULONG SubSystemType;
	union
	{
		struct
		{
			USHORT SubSystemMinorVersion;
			USHORT SubSystemMajorVersion;
		};
		ULONG SubSystemVersion;
	};
	ULONG GpValue;
	USHORT ImageCharacteristics;
	USHORT DllCharacteristics;
	USHORT Machine;
	BOOLEAN ImageContainsCode;
	union
	{
		UCHAR ImageFlags;
		struct
		{
			UCHAR ComPlusNativeReady : 1;
			UCHAR ComPlusILOnly : 1;
			UCHAR ImageDynamicallyRelocated : 1;
			UCHAR ImageMappedFlat : 1;
			UCHAR BaseBelow4gb : 1;
			UCHAR Reserved : 3;
		};
	};
	ULONG LoaderFlags;
	ULONG ImageFileSize;
	ULONG CheckSum;
} SECTION_IMAGE_INFORMATION, *PSECTION_IMAGE_INFORMATION;

typedef enum _SECTION_INHERIT
{
	ViewShare = 1,
	ViewUnmap = 2
} SECTION_INHERIT;

#define SEC_BASED 0x200000
#define SEC_NO_CHANGE 0x400000
#define SEC_GLOBAL 0x20000000

#define MEM_EXECUTE_OPTION_DISABLE 0x1
#define MEM_EXECUTE_OPTION_ENABLE 0x2
#define MEM_EXECUTE_OPTION_DISABLE_THUNK_EMULATION 0x4
#define MEM_EXECUTE_OPTION_PERMANENT 0x8
#define MEM_EXECUTE_OPTION_EXECUTE_DISPATCH_ENABLE 0x10
#define MEM_EXECUTE_OPTION_IMAGE_DISPATCH_ENABLE 0x20
#define MEM_EXECUTE_OPTION_VALID_FLAGS 0x3f

// Virtual memory

// begin_private

typedef enum _VIRTUAL_MEMORY_INFORMATION_CLASS
{
	VmPrefetchInformation,
	VmPagePriorityInformation,
	VmCfgCallTargetInformation
} VIRTUAL_MEMORY_INFORMATION_CLASS;

typedef struct _MEMORY_RANGE_ENTRY
{
	PVOID VirtualAddress;
	SIZE_T NumberOfBytes;
} MEMORY_RANGE_ENTRY, *PMEMORY_RANGE_ENTRY;

// end_private

// Partitions

// private
typedef enum _MEMORY_PARTITION_INFORMATION_CLASS
{
	SystemMemoryPartitionInformation,
	SystemMemoryPartitionMoveMemory,
	SystemMemoryPartitionAddPagefile,
	SystemMemoryPartitionCombineMemory
} MEMORY_PARTITION_INFORMATION_CLASS;

#pragma endregion

// 堆
#pragma region Heap

typedef struct _RTL_HEAP_ENTRY
{
	SIZE_T Size;
	USHORT Flags;
	USHORT AllocatorBackTraceIndex;
	union
	{
		struct
		{
			SIZE_T Settable;
			ULONG Tag;
		} s1;
		struct
		{
			SIZE_T CommittedSize;
			PVOID FirstBlock;
		} s2;
	} u;
} RTL_HEAP_ENTRY, *PRTL_HEAP_ENTRY;

#define RTL_HEAP_BUSY (USHORT)0x0001
#define RTL_HEAP_SEGMENT (USHORT)0x0002
#define RTL_HEAP_SETTABLE_VALUE (USHORT)0x0010
#define RTL_HEAP_SETTABLE_FLAG1 (USHORT)0x0020
#define RTL_HEAP_SETTABLE_FLAG2 (USHORT)0x0040
#define RTL_HEAP_SETTABLE_FLAG3 (USHORT)0x0080
#define RTL_HEAP_SETTABLE_FLAGS (USHORT)0x00e0
#define RTL_HEAP_UNCOMMITTED_RANGE (USHORT)0x0100
#define RTL_HEAP_PROTECTED_ENTRY (USHORT)0x0200

typedef struct _RTL_HEAP_TAG
{
	ULONG NumberOfAllocations;
	ULONG NumberOfFrees;
	SIZE_T BytesAllocated;
	USHORT TagIndex;
	USHORT CreatorBackTraceIndex;
	WCHAR TagName[24];
} RTL_HEAP_TAG, *PRTL_HEAP_TAG;

typedef struct _RTL_HEAP_INFORMATION
{
	PVOID BaseAddress;
	ULONG Flags;
	USHORT EntryOverhead;
	USHORT CreatorBackTraceIndex;
	SIZE_T BytesAllocated;
	SIZE_T BytesCommitted;
	ULONG NumberOfTags;
	ULONG NumberOfEntries;
	ULONG NumberOfPseudoTags;
	ULONG PseudoTagGranularity;
	ULONG Reserved[5];
	PRTL_HEAP_TAG Tags;
	PRTL_HEAP_ENTRY Entries;
} RTL_HEAP_INFORMATION, *PRTL_HEAP_INFORMATION;

typedef struct _RTL_PROCESS_HEAPS
{
	ULONG NumberOfHeaps;
	RTL_HEAP_INFORMATION Heaps[1];
} RTL_PROCESS_HEAPS, *PRTL_PROCESS_HEAPS;

typedef NTSTATUS(NTAPI *PRTL_HEAP_COMMIT_ROUTINE)(
	_In_ PVOID Base,
	_Inout_ PVOID *CommitAddress,
	_Inout_ PSIZE_T CommitSize
	);

typedef struct _RTL_HEAP_PARAMETERS
{
	ULONG Length;
	SIZE_T SegmentReserve;
	SIZE_T SegmentCommit;
	SIZE_T DeCommitFreeBlockThreshold;
	SIZE_T DeCommitTotalFreeThreshold;
	SIZE_T MaximumAllocationSize;
	SIZE_T VirtualMemoryThreshold;
	SIZE_T InitialCommit;
	SIZE_T InitialReserve;
	PRTL_HEAP_COMMIT_ROUTINE CommitRoutine;
	SIZE_T Reserved[2];
} RTL_HEAP_PARAMETERS, *PRTL_HEAP_PARAMETERS;

#define HEAP_SETTABLE_USER_VALUE 0x00000100
#define HEAP_SETTABLE_USER_FLAG1 0x00000200
#define HEAP_SETTABLE_USER_FLAG2 0x00000400
#define HEAP_SETTABLE_USER_FLAG3 0x00000800
#define HEAP_SETTABLE_USER_FLAGS 0x00000e00

#define HEAP_CLASS_0 0x00000000 // Process heap
#define HEAP_CLASS_1 0x00001000 // Private heap
#define HEAP_CLASS_2 0x00002000 // Kernel heap
#define HEAP_CLASS_3 0x00003000 // GDI heap
#define HEAP_CLASS_4 0x00004000 // User heap
#define HEAP_CLASS_5 0x00005000 // Console heap
#define HEAP_CLASS_6 0x00006000 // User desktop heap
#define HEAP_CLASS_7 0x00007000 // CSR shared heap
#define HEAP_CLASS_8 0x00008000 // CSR port heap
#define HEAP_CLASS_MASK 0x0000f000

typedef struct _RTL_HEAP_TAG_INFO
{
	ULONG NumberOfAllocations;
	ULONG NumberOfFrees;
	SIZE_T BytesAllocated;
} RTL_HEAP_TAG_INFO, *PRTL_HEAP_TAG_INFO;

#define RTL_HEAP_MAKE_TAG HEAP_MAKE_TAG_FLAGS

typedef NTSTATUS(NTAPI *PRTL_ENUM_HEAPS_ROUTINE)(
	_In_ PVOID HeapHandle,
	_In_ PVOID Parameter
	);

typedef struct _RTL_HEAP_USAGE_ENTRY
{
	struct _RTL_HEAP_USAGE_ENTRY *Next;
	PVOID Address;
	SIZE_T Size;
	USHORT AllocatorBackTraceIndex;
	USHORT TagIndex;
} RTL_HEAP_USAGE_ENTRY, *PRTL_HEAP_USAGE_ENTRY;

typedef struct _RTL_HEAP_USAGE
{
	ULONG Length;
	SIZE_T BytesAllocated;
	SIZE_T BytesCommitted;
	SIZE_T BytesReserved;
	SIZE_T BytesReservedMaximum;
	PRTL_HEAP_USAGE_ENTRY Entries;
	PRTL_HEAP_USAGE_ENTRY AddedEntries;
	PRTL_HEAP_USAGE_ENTRY RemovedEntries;
	ULONG_PTR Reserved[8];
} RTL_HEAP_USAGE, *PRTL_HEAP_USAGE;

#define HEAP_USAGE_ALLOCATED_BLOCKS HEAP_REALLOC_IN_PLACE_ONLY
#define HEAP_USAGE_FREE_BUFFER HEAP_ZERO_MEMORY

typedef struct _RTL_HEAP_WALK_ENTRY
{
	PVOID DataAddress;
	SIZE_T DataSize;
	UCHAR OverheadBytes;
	UCHAR SegmentIndex;
	USHORT Flags;
	union
	{
		struct
		{
			SIZE_T Settable;
			USHORT TagIndex;
			USHORT AllocatorBackTraceIndex;
			ULONG Reserved[2];
		} Block;
		struct
		{
			ULONG CommittedSize;
			ULONG UnCommittedSize;
			PVOID FirstEntry;
			PVOID LastEntry;
		} Segment;
	};
} RTL_HEAP_WALK_ENTRY, *PRTL_HEAP_WALK_ENTRY;

// rev
#define HeapDebuggingInformation 0x80000002

// rev
typedef NTSTATUS(NTAPI *PRTL_HEAP_LEAK_ENUMERATION_ROUTINE)(
	_In_ LONG Reserved,
	_In_ PVOID HeapHandle,
	_In_ PVOID BaseAddress,
	_In_ SIZE_T BlockSize,
	_In_ ULONG StackTraceDepth,
	_In_ PVOID *StackTrace
	);

// symbols
typedef struct _HEAP_DEBUGGING_INFORMATION
{
	PVOID InterceptorFunction;
	USHORT InterceptorValue;
	ULONG ExtendedOptions;
	ULONG StackTraceDepth;
	SIZE_T MinTotalBlockSize;
	SIZE_T MaxTotalBlockSize;
	PRTL_HEAP_LEAK_ENUMERATION_ROUTINE HeapLeakEnumerationRoutine;
} HEAP_DEBUGGING_INFORMATION, *PHEAP_DEBUGGING_INFORMATION;

#pragma endregion

// ClientID
#pragma region ClientID

typedef struct _CLIENT_ID
{
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

#pragma endregion

// KPriority
#pragma region KPriority

typedef LONG KPRIORITY;

#pragma endregion

// KUserSharedData
#pragma region KUserSharedData

typedef enum _ALTERNATIVE_ARCHITECTURE_TYPE
{
	StandardDesign,
	NEC98x86,
	EndAlternatives
} ALTERNATIVE_ARCHITECTURE_TYPE;

#define PROCESSOR_FEATURE_MAX 64

#define MAX_WOW64_SHARED_ENTRIES 16

#define NX_SUPPORT_POLICY_ALWAYSOFF 0
#define NX_SUPPORT_POLICY_ALWAYSON 1
#define NX_SUPPORT_POLICY_OPTIN 2
#define NX_SUPPORT_POLICY_OPTOUT 3

typedef enum _NT_PRODUCT_TYPE
{
	NtProductWinNt = 1,
	NtProductLanManNt,
	NtProductServer
} NT_PRODUCT_TYPE, *PNT_PRODUCT_TYPE;

#include <pshpack4.h>
typedef struct _KSYSTEM_TIME
{
	ULONG LowPart;
	LONG High1Time;
	LONG High2Time;
} KSYSTEM_TIME, *PKSYSTEM_TIME;
#include <poppack.h>

#include <pshpack4.h>
typedef struct _KUSER_SHARED_DATA
{
	ULONG TickCountLowDeprecated;
	ULONG TickCountMultiplier;

	volatile KSYSTEM_TIME InterruptTime;
	volatile KSYSTEM_TIME SystemTime;
	volatile KSYSTEM_TIME TimeZoneBias;

	USHORT ImageNumberLow;
	USHORT ImageNumberHigh;

	WCHAR NtSystemRoot[260];

	ULONG MaxStackTraceDepth;

	ULONG CryptoExponent;

	ULONG TimeZoneId;
	ULONG LargePageMinimum;
	ULONG AitSamplingValue;
	ULONG AppCompatFlag;
	ULONGLONG RNGSeedVersion;
	ULONG GlobalValidationRunlevel;
	LONG TimeZoneBiasStamp;
	ULONG Reserved2;

	/*ULONG*/ NT_PRODUCT_TYPE NtProductType;
	BOOLEAN ProductTypeIsValid;
	UCHAR Reserved0[1];
	USHORT NativeProcessorArchitecture;

	ULONG NtMajorVersion;
	ULONG NtMinorVersion;

	BOOLEAN ProcessorFeatures[PROCESSOR_FEATURE_MAX];

	ULONG Reserved1;
	ULONG Reserved3;

	volatile ULONG TimeSlip;

	ALTERNATIVE_ARCHITECTURE_TYPE AlternativeArchitecture;
	ULONG AltArchitecturePad[1];

	LARGE_INTEGER SystemExpirationDate;

	ULONG SuiteMask;

	BOOLEAN KdDebuggerEnabled;
	union
	{
		UCHAR MitigationPolicies;
		struct
		{
			UCHAR NXSupportPolicy : 2;
			UCHAR SEHValidationPolicy : 2;
			UCHAR CurDirDevicesSkippedForDlls : 2;
			UCHAR Reserved : 2;
		};
	};
	UCHAR Reserved6[2];

	volatile ULONG ActiveConsoleId;

	volatile ULONG DismountCount;

	ULONG ComPlusPackage;

	ULONG LastSystemRITEventTickCount;

	ULONG NumberOfPhysicalPages;

	BOOLEAN SafeBootMode;
	UCHAR Reserved12[3];

	union
	{
		ULONG SharedDataFlags;
		struct
		{
			ULONG DbgErrorPortPresent : 1;
			ULONG DbgElevationEnabled : 1;
			ULONG DbgVirtEnabled : 1;
			ULONG DbgInstallerDetectEnabled : 1;
			ULONG DbgLkgEnabled : 1;
			ULONG DbgDynProcessorEnabled : 1;
			ULONG DbgConsoleBrokerEnabled : 1;
			ULONG DbgSecureBootEnabled : 1;
			ULONG SpareBits : 24;
		};
	};
	ULONG DataFlagsPad[1];

	ULONGLONG TestRetInstruction;
	ULONGLONG QpcFrequency;
	ULONGLONG SystemCallPad[3];

	union
	{
		volatile KSYSTEM_TIME TickCount;
		volatile ULONG64 TickCountQuad;
		ULONG ReservedTickCountOverlay[3];
	};
	ULONG TickCountPad[1];

	ULONG Cookie;
	ULONG CookiePad[1];

	LONGLONG ConsoleSessionForegroundProcessId;
	ULONGLONG TimeUpdateSequence;
	ULONGLONG BaselineSystemTimeQpc;
	ULONGLONG BaselineInterruptTimeQpc;
	ULONGLONG QpcSystemTimeIncrement;
	ULONGLONG QpcInterruptTimeIncrement;
	ULONG QpcSystemTimeIncrement32;
	ULONG QpcInterruptTimeIncrement32;
	UCHAR QpcSystemTimeIncrementShift;
	UCHAR QpcInterruptTimeIncrementShift;
	UCHAR Reserved8[14];

	USHORT UserModeGlobalLogger[16];
	ULONG ImageFileExecutionOptions;

	ULONG LangGenerationCount;
	ULONGLONG Reserved4;
	volatile ULONG64 InterruptTimeBias;
	volatile ULONG64 QpcBias;

	volatile ULONG ActiveProcessorCount;
	volatile UCHAR ActiveGroupCount;
	UCHAR Reserved9;
	union
	{
		USHORT QpcData;
		struct
		{
			UCHAR QpcBypassEnabled : 1;
			UCHAR QpcShift : 1;
		};
	};

	LARGE_INTEGER TimeZoneBiasEffectiveStart;
	LARGE_INTEGER TimeZoneBiasEffectiveEnd;
	XSTATE_CONFIGURATION XState;
} KUSER_SHARED_DATA, *PKUSER_SHARED_DATA;
#include <poppack.h>

#pragma endregion

// KWaitReason
#pragma region KWaitReason

typedef enum _KWAIT_REASON
{
	Executive,
	FreePage,
	PageIn,
	PoolAllocation,
	DelayExecution,
	Suspended,
	UserRequest,
	WrExecutive,
	WrFreePage,
	WrPageIn,
	WrPoolAllocation,
	WrDelayExecution,
	WrSuspended,
	WrUserRequest,
	WrEventPair,
	WrQueue,
	WrLpcReceive,
	WrLpcReply,
	WrVirtualMemory,
	WrPageOut,
	WrRendezvous,
	WrKeyedEvent,
	WrTerminated,
	WrProcessInSwap,
	WrCpuRateControl,
	WrCalloutStack,
	WrKernel,
	WrResource,
	WrPushLock,
	WrMutex,
	WrQuantumEnd,
	WrDispatchInt,
	WrPreempted,
	WrYieldExecution,
	WrFastMutex,
	WrGuardedMutex,
	WrRundown,
	WrAlertByThreadId,
	WrDeferredPreempt,
	MaximumWaitReason
} KWAIT_REASON, *PKWAIT_REASON;

#pragma endregion

// GDI
#pragma region GDI

#define GDI_MAX_HANDLE_COUNT 0x4000

#define GDI_HANDLE_INDEX_SHIFT 0
#define GDI_HANDLE_INDEX_BITS 16
#define GDI_HANDLE_INDEX_MASK 0xffff

#define GDI_HANDLE_TYPE_SHIFT 16
#define GDI_HANDLE_TYPE_BITS 5
#define GDI_HANDLE_TYPE_MASK 0x1f

#define GDI_HANDLE_ALTTYPE_SHIFT 21
#define GDI_HANDLE_ALTTYPE_BITS 2
#define GDI_HANDLE_ALTTYPE_MASK 0x3

#define GDI_HANDLE_STOCK_SHIFT 23
#define GDI_HANDLE_STOCK_BITS 1
#define GDI_HANDLE_STOCK_MASK 0x1

#define GDI_HANDLE_UNIQUE_SHIFT 24
#define GDI_HANDLE_UNIQUE_BITS 8
#define GDI_HANDLE_UNIQUE_MASK 0xff

#define GDI_HANDLE_INDEX(Handle) ((ULONG)(Handle) & GDI_HANDLE_INDEX_MASK)
#define GDI_HANDLE_TYPE(Handle) (((ULONG)(Handle) >> GDI_HANDLE_TYPE_SHIFT) & GDI_HANDLE_TYPE_MASK)
#define GDI_HANDLE_ALTTYPE(Handle) (((ULONG)(Handle) >> GDI_HANDLE_ALTTYPE_SHIFT) & GDI_HANDLE_ALTTYPE_MASK)
#define GDI_HANDLE_STOCK(Handle) (((ULONG)(Handle) >> GDI_HANDLE_STOCK_SHIFT)) & GDI_HANDLE_STOCK_MASK)

#define GDI_MAKE_HANDLE(Index, Unique) ((ULONG)(((ULONG)(Unique) << GDI_HANDLE_INDEX_BITS) | (ULONG)(Index)))

// GDI server-side types

#define GDI_DEF_TYPE 0 // invalid handle
#define GDI_DC_TYPE 1
#define GDI_DD_DIRECTDRAW_TYPE 2
#define GDI_DD_SURFACE_TYPE 3
#define GDI_RGN_TYPE 4
#define GDI_SURF_TYPE 5
#define GDI_CLIENTOBJ_TYPE 6
#define GDI_PATH_TYPE 7
#define GDI_PAL_TYPE 8
#define GDI_ICMLCS_TYPE 9
#define GDI_LFONT_TYPE 10
#define GDI_RFONT_TYPE 11
#define GDI_PFE_TYPE 12
#define GDI_PFT_TYPE 13
#define GDI_ICMCXF_TYPE 14
#define GDI_ICMDLL_TYPE 15
#define GDI_BRUSH_TYPE 16
#define GDI_PFF_TYPE 17 // unused
#define GDI_CACHE_TYPE 18 // unused
#define GDI_SPACE_TYPE 19
#define GDI_DBRUSH_TYPE 20 // unused
#define GDI_META_TYPE 21
#define GDI_EFSTATE_TYPE 22
#define GDI_BMFD_TYPE 23 // unused
#define GDI_VTFD_TYPE 24 // unused
#define GDI_TTFD_TYPE 25 // unused
#define GDI_RC_TYPE 26 // unused
#define GDI_TEMP_TYPE 27 // unused
#define GDI_DRVOBJ_TYPE 28
#define GDI_DCIOBJ_TYPE 29 // unused
#define GDI_SPOOL_TYPE 30

// GDI client-side types

#define GDI_CLIENT_TYPE_FROM_HANDLE(Handle) ((ULONG)(Handle) & ((GDI_HANDLE_ALTTYPE_MASK << GDI_HANDLE_ALTTYPE_SHIFT) | \
    (GDI_HANDLE_TYPE_MASK << GDI_HANDLE_TYPE_SHIFT)))
#define GDI_CLIENT_TYPE_FROM_UNIQUE(Unique) GDI_CLIENT_TYPE_FROM_HANDLE((ULONG)(Unique) << 16)

#define GDI_ALTTYPE_1 (1 << GDI_HANDLE_ALTTYPE_SHIFT)
#define GDI_ALTTYPE_2 (2 << GDI_HANDLE_ALTTYPE_SHIFT)
#define GDI_ALTTYPE_3 (3 << GDI_HANDLE_ALTTYPE_SHIFT)

#define GDI_CLIENT_BITMAP_TYPE (GDI_SURF_TYPE << GDI_HANDLE_TYPE_SHIFT)
#define GDI_CLIENT_BRUSH_TYPE (GDI_BRUSH_TYPE << GDI_HANDLE_TYPE_SHIFT)
#define GDI_CLIENT_CLIENTOBJ_TYPE (GDI_CLIENTOBJ_TYPE << GDI_HANDLE_TYPE_SHIFT)
#define GDI_CLIENT_DC_TYPE (GDI_DC_TYPE << GDI_HANDLE_TYPE_SHIFT)
#define GDI_CLIENT_FONT_TYPE (GDI_LFONT_TYPE << GDI_HANDLE_TYPE_SHIFT)
#define GDI_CLIENT_PALETTE_TYPE (GDI_PAL_TYPE << GDI_HANDLE_TYPE_SHIFT)
#define GDI_CLIENT_REGION_TYPE (GDI_RGN_TYPE << GDI_HANDLE_TYPE_SHIFT)

#define GDI_CLIENT_ALTDC_TYPE (GDI_CLIENT_DC_TYPE | GDI_ALTTYPE_1)
#define GDI_CLIENT_DIBSECTION_TYPE (GDI_CLIENT_BITMAP_TYPE | GDI_ALTTYPE_1)
#define GDI_CLIENT_EXTPEN_TYPE (GDI_CLIENT_BRUSH_TYPE | GDI_ALTTYPE_2)
#define GDI_CLIENT_METADC16_TYPE (GDI_CLIENT_CLIENTOBJ_TYPE | GDI_ALTTYPE_3)
#define GDI_CLIENT_METAFILE_TYPE (GDI_CLIENT_CLIENTOBJ_TYPE | GDI_ALTTYPE_2)
#define GDI_CLIENT_METAFILE16_TYPE (GDI_CLIENT_CLIENTOBJ_TYPE | GDI_ALTTYPE_1)
#define GDI_CLIENT_PEN_TYPE (GDI_CLIENT_BRUSH_TYPE | GDI_ALTTYPE_1)

typedef struct _GDI_HANDLE_ENTRY
{
	union
	{
		PVOID Object;
		PVOID NextFree;
	};
	union
	{
		struct
		{
			USHORT ProcessId;
			USHORT Lock : 1;
			USHORT Count : 15;
		};
		ULONG Value;
	} Owner;
	USHORT Unique;
	UCHAR Type;
	UCHAR Flags;
	PVOID UserPointer;
} GDI_HANDLE_ENTRY, *PGDI_HANDLE_ENTRY;

typedef struct _GDI_SHARED_MEMORY
{
	GDI_HANDLE_ENTRY Handles[GDI_MAX_HANDLE_COUNT];
} GDI_SHARED_MEMORY, *PGDI_SHARED_MEMORY;

#define GDI_HANDLE_BUFFER_SIZE32 34
#define GDI_HANDLE_BUFFER_SIZE64 60

#ifndef WIN64
#define GDI_HANDLE_BUFFER_SIZE GDI_HANDLE_BUFFER_SIZE32
#else
#define GDI_HANDLE_BUFFER_SIZE GDI_HANDLE_BUFFER_SIZE64
#endif

typedef ULONG GDI_HANDLE_BUFFER[GDI_HANDLE_BUFFER_SIZE];

typedef ULONG GDI_HANDLE_BUFFER32[GDI_HANDLE_BUFFER_SIZE32];
typedef ULONG GDI_HANDLE_BUFFER64[GDI_HANDLE_BUFFER_SIZE64];

#pragma endregion

// ProcessEnvironmentBlock
#pragma region ProcessEnvironmentBlock

#define FLS_MAXIMUM_AVAILABLE 128
#define TLS_MINIMUM_AVAILABLE 64
#define TLS_EXPANSION_SLOTS 1024

typedef struct _PEB_LDR_DATA
{
	ULONG Length;
	BOOLEAN Initialized;
	HANDLE SsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
	PVOID EntryInProgress;
	BOOLEAN ShutdownInProgress;
	HANDLE ShutdownThreadId;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _INITIAL_TEB
{
	struct
	{
		PVOID OldStackBase;
		PVOID OldStackLimit;
	} OldInitialTeb;
	PVOID StackBase;
	PVOID StackLimit;
	PVOID StackAllocationBase;
} INITIAL_TEB, *PINITIAL_TEB;

typedef struct _WOW64_PROCESS
{
	PVOID Wow64;
} WOW64_PROCESS, *PWOW64_PROCESS;

typedef struct _RTL_USER_PROCESS_PARAMETERS *PRTL_USER_PROCESS_PARAMETERS;
typedef struct _RTL_CRITICAL_SECTION *PRTL_CRITICAL_SECTION;

// symbols
typedef struct _PEB
{
	BOOLEAN InheritedAddressSpace;
	BOOLEAN ReadImageFileExecOptions;
	BOOLEAN BeingDebugged;
	union
	{
		BOOLEAN BitField;
		struct
		{
			BOOLEAN ImageUsesLargePages : 1;
			BOOLEAN IsProtectedProcess : 1;
			BOOLEAN IsImageDynamicallyRelocated : 1;
			BOOLEAN SkipPatchingUser32Forwarders : 1;
			BOOLEAN IsPackagedProcess : 1;
			BOOLEAN IsAppContainer : 1;
			BOOLEAN IsProtectedProcessLight : 1;
			BOOLEAN SpareBits : 1;
		};
	};
	HANDLE Mutant;

	PVOID ImageBaseAddress;
	PPEB_LDR_DATA Ldr;
	PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
	PVOID SubSystemData;
	PVOID ProcessHeap;
	PRTL_CRITICAL_SECTION FastPebLock;
	PVOID AtlThunkSListPtr;
	PVOID IFEOKey;
	union
	{
		ULONG CrossProcessFlags;
		struct
		{
			ULONG ProcessInJob : 1;
			ULONG ProcessInitializing : 1;
			ULONG ProcessUsingVEH : 1;
			ULONG ProcessUsingVCH : 1;
			ULONG ProcessUsingFTH : 1;
			ULONG ReservedBits0 : 27;
		};
	};
	union
	{
		PVOID KernelCallbackTable;
		PVOID UserSharedInfoPtr;
	};
	ULONG SystemReserved[1];
	ULONG AtlThunkSListPtr32;
	PVOID ApiSetMap;
	ULONG TlsExpansionCounter;
	PVOID TlsBitmap;
	ULONG TlsBitmapBits[2];
	PVOID ReadOnlySharedMemoryBase;
	PVOID HotpatchInformation;
	PVOID *ReadOnlyStaticServerData;
	PVOID AnsiCodePageData;
	PVOID OemCodePageData;
	PVOID UnicodeCaseTableData;

	ULONG NumberOfProcessors;
	ULONG NtGlobalFlag;

	LARGE_INTEGER CriticalSectionTimeout;
	SIZE_T HeapSegmentReserve;
	SIZE_T HeapSegmentCommit;
	SIZE_T HeapDeCommitTotalFreeThreshold;
	SIZE_T HeapDeCommitFreeBlockThreshold;

	ULONG NumberOfHeaps;
	ULONG MaximumNumberOfHeaps;
	PVOID *ProcessHeaps;

	PVOID GdiSharedHandleTable;
	PVOID ProcessStarterHelper;
	ULONG GdiDCAttributeList;

	PRTL_CRITICAL_SECTION LoaderLock;

	ULONG OSMajorVersion;
	ULONG OSMinorVersion;
	USHORT OSBuildNumber;
	USHORT OSCSDVersion;
	ULONG OSPlatformId;
	ULONG ImageSubsystem;
	ULONG ImageSubsystemMajorVersion;
	ULONG ImageSubsystemMinorVersion;
	ULONG_PTR ImageProcessAffinityMask;
	GDI_HANDLE_BUFFER GdiHandleBuffer;
	PVOID PostProcessInitRoutine;

	PVOID TlsExpansionBitmap;
	ULONG TlsExpansionBitmapBits[32];

	ULONG SessionId;

	ULARGE_INTEGER AppCompatFlags;
	ULARGE_INTEGER AppCompatFlagsUser;
	PVOID pShimData;
	PVOID AppCompatInfo;

	UNICODE_STRING CSDVersion;

	PVOID ActivationContextData;
	PVOID ProcessAssemblyStorageMap;
	PVOID SystemDefaultActivationContextData;
	PVOID SystemAssemblyStorageMap;

	SIZE_T MinimumStackCommit;

	PVOID *FlsCallback;
	LIST_ENTRY FlsListHead;
	PVOID FlsBitmap;
	ULONG FlsBitmapBits[FLS_MAXIMUM_AVAILABLE / (sizeof(ULONG) * 8)];
	ULONG FlsHighIndex;

	PVOID WerRegistrationData;
	PVOID WerShipAssertPtr;
	PVOID pContextData;
	PVOID pImageHeaderHash;
	union
	{
		ULONG TracingFlags;
		struct
		{
			ULONG HeapTracingEnabled : 1;
			ULONG CritSecTracingEnabled : 1;
			ULONG LibLoaderTracingEnabled : 1;
			ULONG SpareTracingBits : 29;
		};
	};
	ULONGLONG CsrServerReadOnlySharedMemoryBase;
} PEB, *PPEB;

#pragma endregion

// ThreadEnvironmentBlock
#pragma region ThreadEnvironmentBlock

#define GDI_BATCH_BUFFER_SIZE 310

typedef struct _GDI_TEB_BATCH
{
	ULONG Offset;
	ULONG_PTR HDC;
	ULONG Buffer[GDI_BATCH_BUFFER_SIZE];
} GDI_TEB_BATCH, *PGDI_TEB_BATCH;

typedef struct _TEB_ACTIVE_FRAME_CONTEXT
{
	ULONG Flags;
	PSTR FrameName;
} TEB_ACTIVE_FRAME_CONTEXT, *PTEB_ACTIVE_FRAME_CONTEXT;

typedef struct _TEB_ACTIVE_FRAME
{
	ULONG Flags;
	struct _TEB_ACTIVE_FRAME *Previous;
	PTEB_ACTIVE_FRAME_CONTEXT Context;
} TEB_ACTIVE_FRAME, *PTEB_ACTIVE_FRAME;

typedef struct _TEB
{
	NT_TIB NtTib;

	PVOID EnvironmentPointer;
	CLIENT_ID ClientId;
	PVOID ActiveRpcHandle;
	PVOID ThreadLocalStoragePointer;
	PPEB ProcessEnvironmentBlock;

	ULONG LastErrorValue;
	ULONG CountOfOwnedCriticalSections;
	PVOID CsrClientThread;
	PVOID Win32ThreadInfo;
	ULONG User32Reserved[26];
	ULONG UserReserved[5];
	PVOID WOW32Reserved;
	LCID CurrentLocale;
	ULONG FpSoftwareStatusRegister;
	PVOID SystemReserved1[54];
	NTSTATUS ExceptionCode;
	PVOID ActivationContextStackPointer;
#ifdef _WIN64
	UCHAR SpareBytes[24];
#else
	UCHAR SpareBytes[36];
#endif
	ULONG TxFsContext;

	GDI_TEB_BATCH GdiTebBatch;
	CLIENT_ID RealClientId;
	HANDLE GdiCachedProcessHandle;
	ULONG GdiClientPID;
	ULONG GdiClientTID;
	PVOID GdiThreadLocalInfo;
	ULONG_PTR Win32ClientInfo[62];
	PVOID glDispatchTable[233];
	ULONG_PTR glReserved1[29];
	PVOID glReserved2;
	PVOID glSectionInfo;
	PVOID glSection;
	PVOID glTable;
	PVOID glCurrentRC;
	PVOID glContext;

	NTSTATUS LastStatusValue;
	UNICODE_STRING StaticUnicodeString;
	WCHAR StaticUnicodeBuffer[261];

	PVOID DeallocationStack;
	PVOID TlsSlots[64];
	LIST_ENTRY TlsLinks;

	PVOID Vdm;
	PVOID ReservedForNtRpc;
	PVOID DbgSsReserved[2];

	ULONG HardErrorMode;
#ifdef _WIN64
	PVOID Instrumentation[11];
#else
	PVOID Instrumentation[9];
#endif
	GUID ActivityId;

	PVOID SubProcessTag;
	PVOID EtwLocalData;
	PVOID EtwTraceData;
	PVOID WinSockData;
	ULONG GdiBatchCount;

	union
	{
		PROCESSOR_NUMBER CurrentIdealProcessor;
		ULONG IdealProcessorValue;
		struct
		{
			UCHAR ReservedPad0;
			UCHAR ReservedPad1;
			UCHAR ReservedPad2;
			UCHAR IdealProcessor;
		};
	};

	ULONG GuaranteedStackBytes;
	PVOID ReservedForPerf;
	PVOID ReservedForOle;
	ULONG WaitingOnLoaderLock;
	PVOID SavedPriorityState;
	ULONG_PTR SoftPatchPtr1;
	PVOID ThreadPoolData;
	PVOID *TlsExpansionSlots;
#ifdef _WIN64
	PVOID DeallocationBStore;
	PVOID BStoreLimit;
#endif
	ULONG MuiGeneration;
	ULONG IsImpersonating;
	PVOID NlsCache;
	PVOID pShimData;
	ULONG HeapVirtualAffinity;
	HANDLE CurrentTransactionHandle;
	PTEB_ACTIVE_FRAME ActiveFrame;
	PVOID FlsData;

	PVOID PreferredLanguages;
	PVOID UserPrefLanguages;
	PVOID MergedPrefLanguages;
	ULONG MuiImpersonation;

	union
	{
		USHORT CrossTebFlags;
		USHORT SpareCrossTebBits : 16;
	};
	union
	{
		USHORT SameTebFlags;
		struct
		{
			USHORT SafeThunkCall : 1;
			USHORT InDebugPrint : 1;
			USHORT HasFiberData : 1;
			USHORT SkipThreadAttach : 1;
			USHORT WerInShipAssertCode : 1;
			USHORT RanProcessInit : 1;
			USHORT ClonedThread : 1;
			USHORT SuppressDebugMsg : 1;
			USHORT DisableUserStackWalk : 1;
			USHORT RtlExceptionAttached : 1;
			USHORT InitialThread : 1;
			USHORT SessionAware : 1;
			USHORT SpareSameTebBits : 4;
		};
	};

	PVOID TxnScopeEnterCallback;
	PVOID TxnScopeExitCallback;
	PVOID TxnScopeContext;
	ULONG LockCount;
	ULONG SpareUlong0;
	PVOID ResourceRetValue;
	PVOID ReservedForWdf;
} TEB, *PTEB;

#pragma endregion

// 模块信息
#pragma region ModuleInformation

typedef struct _RTL_PROCESS_MODULE_INFORMATION
{
	HANDLE Section;
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, *PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES
{
	ULONG NumberOfModules;
	RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, *PRTL_PROCESS_MODULES;

// private
typedef struct _RTL_PROCESS_MODULE_INFORMATION_EX
{
	USHORT NextOffset;
	RTL_PROCESS_MODULE_INFORMATION BaseInfo;
	ULONG ImageChecksum;
	ULONG TimeDateStamp;
	PVOID DefaultBase;
} RTL_PROCESS_MODULE_INFORMATION_EX, *PRTL_PROCESS_MODULE_INFORMATION_EX;

#pragma endregion

// 系统信息结构
#pragma region SystemInformation

// rev
// private
// source:http://www.microsoft.com/whdc/system/Sysinternals/MoreThan64proc.mspx
typedef enum _SYSTEM_INFORMATION_CLASS
{
	SystemBasicInformation, // q: SYSTEM_BASIC_INFORMATION
	SystemProcessorInformation, // q: SYSTEM_PROCESSOR_INFORMATION
	SystemPerformanceInformation, // q: SYSTEM_PERFORMANCE_INFORMATION
	SystemTimeOfDayInformation, // q: SYSTEM_TIMEOFDAY_INFORMATION
	SystemPathInformation, // not implemented
	SystemProcessInformation, // q: SYSTEM_PROCESS_INFORMATION
	SystemCallCountInformation, // q: SYSTEM_CALL_COUNT_INFORMATION
	SystemDeviceInformation, // q: SYSTEM_DEVICE_INFORMATION
	SystemProcessorPerformanceInformation, // q: SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION
	SystemFlagsInformation, // q: SYSTEM_FLAGS_INFORMATION
	SystemCallTimeInformation, // not implemented // 10
	SystemModuleInformation, // q: RTL_PROCESS_MODULES
	SystemLocksInformation,
	SystemStackTraceInformation,
	SystemPagedPoolInformation, // not implemented
	SystemNonPagedPoolInformation, // not implemented
	SystemHandleInformation, // q: SYSTEM_HANDLE_INFORMATION
	SystemObjectInformation, // q: SYSTEM_OBJECTTYPE_INFORMATION mixed with SYSTEM_OBJECT_INFORMATION
	SystemPageFileInformation, // q: SYSTEM_PAGEFILE_INFORMATION
	SystemVdmInstemulInformation, // q
	SystemVdmBopInformation, // not implemented // 20
	SystemFileCacheInformation, // q: SYSTEM_FILECACHE_INFORMATION; s (requires SeIncreaseQuotaPrivilege) (info for WorkingSetTypeSystemCache)
	SystemPoolTagInformation, // q: SYSTEM_POOLTAG_INFORMATION
	SystemInterruptInformation, // q: SYSTEM_INTERRUPT_INFORMATION
	SystemDpcBehaviorInformation, // q: SYSTEM_DPC_BEHAVIOR_INFORMATION; s: SYSTEM_DPC_BEHAVIOR_INFORMATION (requires SeLoadDriverPrivilege)
	SystemFullMemoryInformation, // not implemented
	SystemLoadGdiDriverInformation, // s (kernel-mode only)
	SystemUnloadGdiDriverInformation, // s (kernel-mode only)
	SystemTimeAdjustmentInformation, // q: SYSTEM_QUERY_TIME_ADJUST_INFORMATION; s: SYSTEM_SET_TIME_ADJUST_INFORMATION (requires SeSystemtimePrivilege)
	SystemSummaryMemoryInformation, // not implemented
	SystemMirrorMemoryInformation, // s (requires license value "Kernel-MemoryMirroringSupported") (requires SeShutdownPrivilege) // 30
	SystemPerformanceTraceInformation, // s
	SystemObsolete0, // not implemented
	SystemExceptionInformation, // q: SYSTEM_EXCEPTION_INFORMATION
	SystemCrashDumpStateInformation, // s (requires SeDebugPrivilege)
	SystemKernelDebuggerInformation, // q: SYSTEM_KERNEL_DEBUGGER_INFORMATION
	SystemContextSwitchInformation, // q: SYSTEM_CONTEXT_SWITCH_INFORMATION
	SystemRegistryQuotaInformation, // q: SYSTEM_REGISTRY_QUOTA_INFORMATION; s (requires SeIncreaseQuotaPrivilege)
	SystemExtendServiceTableInformation, // s (requires SeLoadDriverPrivilege) // loads win32k only
	SystemPrioritySeperation, // s (requires SeTcbPrivilege)
	SystemVerifierAddDriverInformation, // s (requires SeDebugPrivilege) // 40
	SystemVerifierRemoveDriverInformation, // s (requires SeDebugPrivilege)
	SystemProcessorIdleInformation, // q: SYSTEM_PROCESSOR_IDLE_INFORMATION
	SystemLegacyDriverInformation, // q: SYSTEM_LEGACY_DRIVER_INFORMATION
	SystemCurrentTimeZoneInformation, // q
	SystemLookasideInformation, // q: SYSTEM_LOOKASIDE_INFORMATION
	SystemTimeSlipNotification, // s (requires SeSystemtimePrivilege)
	SystemSessionCreate, // not implemented
	SystemSessionDetach, // not implemented
	SystemSessionInformation, // not implemented
	SystemRangeStartInformation, // q // 50
	SystemVerifierInformation, // q: SYSTEM_VERIFIER_INFORMATION; s (requires SeDebugPrivilege)
	SystemVerifierThunkExtend, // s (kernel-mode only)
	SystemSessionProcessInformation, // q: SYSTEM_SESSION_PROCESS_INFORMATION
	SystemLoadGdiDriverInSystemSpace, // s (kernel-mode only) (same as SystemLoadGdiDriverInformation)
	SystemNumaProcessorMap, // q
	SystemPrefetcherInformation, // q: PREFETCHER_INFORMATION; s: PREFETCHER_INFORMATION // PfSnQueryPrefetcherInformation
	SystemExtendedProcessInformation, // q: SYSTEM_PROCESS_INFORMATION
	SystemRecommendedSharedDataAlignment, // q
	SystemComPlusPackage, // q; s
	SystemNumaAvailableMemory, // 60
	SystemProcessorPowerInformation, // q: SYSTEM_PROCESSOR_POWER_INFORMATION
	SystemEmulationBasicInformation, // q
	SystemEmulationProcessorInformation,
	SystemExtendedHandleInformation, // q: SYSTEM_HANDLE_INFORMATION_EX
	SystemLostDelayedWriteInformation, // q: ULONG
	SystemBigPoolInformation, // q: SYSTEM_BIGPOOL_INFORMATION
	SystemSessionPoolTagInformation, // q: SYSTEM_SESSION_POOLTAG_INFORMATION
	SystemSessionMappedViewInformation, // q: SYSTEM_SESSION_MAPPED_VIEW_INFORMATION
	SystemHotpatchInformation, // q; s
	SystemObjectSecurityMode, // q // 70
	SystemWatchdogTimerHandler, // s (kernel-mode only)
	SystemWatchdogTimerInformation, // q (kernel-mode only); s (kernel-mode only)
	SystemLogicalProcessorInformation, // q: SYSTEM_LOGICAL_PROCESSOR_INFORMATION
	SystemWow64SharedInformationObsolete, // not implemented
	SystemRegisterFirmwareTableInformationHandler, // s (kernel-mode only)
	SystemFirmwareTableInformation, // not implemented
	SystemModuleInformationEx, // q: RTL_PROCESS_MODULE_INFORMATION_EX
	SystemVerifierTriageInformation, // not implemented
	SystemSuperfetchInformation, // q: SUPERFETCH_INFORMATION; s: SUPERFETCH_INFORMATION // PfQuerySuperfetchInformation
	SystemMemoryListInformation, // q: SYSTEM_MEMORY_LIST_INFORMATION; s: SYSTEM_MEMORY_LIST_COMMAND (requires SeProfileSingleProcessPrivilege) // 80
	SystemFileCacheInformationEx, // q: SYSTEM_FILECACHE_INFORMATION; s (requires SeIncreaseQuotaPrivilege) (same as SystemFileCacheInformation)
	SystemThreadPriorityClientIdInformation, // s: SYSTEM_THREAD_CID_PRIORITY_INFORMATION (requires SeIncreaseBasePriorityPrivilege)
	SystemProcessorIdleCycleTimeInformation, // q: SYSTEM_PROCESSOR_IDLE_CYCLE_TIME_INFORMATION[]
	SystemVerifierCancellationInformation, // not implemented // name:wow64:whNT32QuerySystemVerifierCancellationInformation
	SystemProcessorPowerInformationEx, // not implemented
	SystemRefTraceInformation, // q; s // ObQueryRefTraceInformation
	SystemSpecialPoolInformation, // q; s (requires SeDebugPrivilege) // MmSpecialPoolTag, then MmSpecialPoolCatchOverruns != 0
	SystemProcessIdInformation, // q: SYSTEM_PROCESS_ID_INFORMATION
	SystemErrorPortInformation, // s (requires SeTcbPrivilege)
	SystemBootEnvironmentInformation, // q: SYSTEM_BOOT_ENVIRONMENT_INFORMATION // 90
	SystemHypervisorInformation, // q; s (kernel-mode only)
	SystemVerifierInformationEx, // q; s
	SystemTimeZoneInformation, // s (requires SeTimeZonePrivilege)
	SystemImageFileExecutionOptionsInformation, // s: SYSTEM_IMAGE_FILE_EXECUTION_OPTIONS_INFORMATION (requires SeTcbPrivilege)
	SystemCoverageInformation, // q; s // name:wow64:whNT32QuerySystemCoverageInformation; ExpCovQueryInformation
	SystemPrefetchPatchInformation, // not implemented
	SystemVerifierFaultsInformation, // s (requires SeDebugPrivilege)
	SystemSystemPartitionInformation, // q: SYSTEM_SYSTEM_PARTITION_INFORMATION
	SystemSystemDiskInformation, // q: SYSTEM_SYSTEM_DISK_INFORMATION
	SystemProcessorPerformanceDistribution, // q: SYSTEM_PROCESSOR_PERFORMANCE_DISTRIBUTION // 100
	SystemNumaProximityNodeInformation, // q
	SystemDynamicTimeZoneInformation, // q; s (requires SeTimeZonePrivilege)
	SystemCodeIntegrityInformation, // q // SeCodeIntegrityQueryInformation
	SystemProcessorMicrocodeUpdateInformation, // s
	SystemProcessorBrandString, // q // HaliQuerySystemInformation -> HalpGetProcessorBrandString, info class 23
	SystemVirtualAddressInformation, // q: SYSTEM_VA_LIST_INFORMATION[]; s: SYSTEM_VA_LIST_INFORMATION[] (requires SeIncreaseQuotaPrivilege) // MmQuerySystemVaInformation
	SystemLogicalProcessorAndGroupInformation, // q: SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX // since WIN7 // KeQueryLogicalProcessorRelationship
	SystemProcessorCycleTimeInformation, // q: SYSTEM_PROCESSOR_CYCLE_TIME_INFORMATION[]
	SystemStoreInformation, // q; s // SmQueryStoreInformation
	SystemRegistryAppendString, // s: SYSTEM_REGISTRY_APPEND_STRING_PARAMETERS // 110
	SystemAitSamplingValue, // s: ULONG (requires SeProfileSingleProcessPrivilege)
	SystemVhdBootInformation, // q: SYSTEM_VHD_BOOT_INFORMATION
	SystemCpuQuotaInformation, // q; s // PsQueryCpuQuotaInformation
	SystemNativeBasicInformation, // not implemented
	SystemSpare1, // not implemented
	SystemLowPriorityIoInformation, // q: SYSTEM_LOW_PRIORITY_IO_INFORMATION
	SystemTpmBootEntropyInformation, // q: TPM_BOOT_ENTROPY_NT_RESULT // ExQueryTpmBootEntropyInformation
	SystemVerifierCountersInformation, // q: SYSTEM_VERIFIER_COUNTERS_INFORMATION
	SystemPagedPoolInformationEx, // q: SYSTEM_FILECACHE_INFORMATION; s (requires SeIncreaseQuotaPrivilege) (info for WorkingSetTypePagedPool)
	SystemSystemPtesInformationEx, // q: SYSTEM_FILECACHE_INFORMATION; s (requires SeIncreaseQuotaPrivilege) (info for WorkingSetTypeSystemPtes) // 120
	SystemNodeDistanceInformation, // q
	SystemAcpiAuditInformation, // q: SYSTEM_ACPI_AUDIT_INFORMATION // HaliQuerySystemInformation -> HalpAuditQueryResults, info class 26
	SystemBasicPerformanceInformation, // q: SYSTEM_BASIC_PERFORMANCE_INFORMATION // name:wow64:whNtQuerySystemInformation_SystemBasicPerformanceInformation
	SystemQueryPerformanceCounterInformation, // q: SYSTEM_QUERY_PERFORMANCE_COUNTER_INFORMATION // since WIN7 SP1
	SystemSessionBigPoolInformation, // since WIN8
	SystemBootGraphicsInformation,
	SystemScrubPhysicalMemoryInformation,
	SystemBadPageInformation,
	SystemProcessorProfileControlArea,
	SystemCombinePhysicalMemoryInformation, // 130
	SystemEntropyInterruptTimingCallback,
	SystemConsoleInformation,
	SystemPlatformBinaryInformation,
	SystemThrottleNotificationInformation,
	SystemHypervisorProcessorCountInformation,
	SystemDeviceDataInformation,
	SystemDeviceDataEnumerationInformation,
	SystemMemoryTopologyInformation,
	SystemMemoryChannelInformation,
	SystemBootLogoInformation, // 140
	SystemProcessorPerformanceInformationEx, // q: SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION_EX // since WINBLUE
	SystemSpare0,
	SystemSecureBootPolicyInformation,
	SystemPageFileInformationEx, // q: SYSTEM_PAGEFILE_INFORMATION_EX
	SystemSecureBootInformation,
	SystemEntropyInterruptTimingRawInformation,
	SystemPortableWorkspaceEfiLauncherInformation,
	SystemFullProcessInformation, // q: SYSTEM_PROCESS_INFORMATION with SYSTEM_PROCESS_INFORMATION_EXTENSION (requires admin)
	SystemKernelDebuggerInformationEx, // q: SYSTEM_KERNEL_DEBUGGER_INFORMATION_EX
	SystemBootMetadataInformation, // 150
	SystemSoftRebootInformation,
	SystemElamCertificateInformation,
	SystemOfflineDumpConfigInformation,
	SystemProcessorFeaturesInformation, // q: SYSTEM_PROCESSOR_FEATURES_INFORMATION
	SystemRegistryReconciliationInformation,
	SystemEdidInformation,
	SystemManufacturingInformation, // q: SYSTEM_MANUFACTURING_INFORMATION // since THRESHOLD
	SystemEnergyEstimationConfigInformation, // q: SYSTEM_ENERGY_ESTIMATION_CONFIG_INFORMATION
	SystemHypervisorDetailInformation, // q: SYSTEM_HYPERVISOR_DETAIL_INFORMATION
	SystemProcessorCycleStatsInformation, // q: SYSTEM_PROCESSOR_CYCLE_STATS_INFORMATION // 160
	SystemVmGenerationCountInformation,
	SystemTrustedPlatformModuleInformation, // q: SYSTEM_TPM_INFORMATION
	SystemKernelDebuggerFlags,
	SystemCodeIntegrityPolicyInformation,
	SystemIsolatedUserModeInformation,
	SystemHardwareSecurityTestInterfaceResultsInformation,
	SystemSingleModuleInformation, // q: SYSTEM_SINGLE_MODULE_INFORMATION
	SystemAllowedCpuSetsInformation,
	SystemDmaProtectionInformation, // q: SYSTEM_DMA_PROTECTION_INFORMATION
	SystemInterruptCpuSetsInformation,
	SystemSecureBootPolicyFullInformation,
	SystemCodeIntegrityPolicyFullInformation,
	SystemAffinitizedInterruptProcessorInformation,
	SystemRootSiloInformation, // q: SYSTEM_ROOT_SILO_INFORMATION
	SystemCpuSetInformation, // q: SYSTEM_CPU_SET_INFORMATION // since THRESHOLD2
	SystemCpuSetTagInformation, // q: SYSTEM_CPU_SET_TAG_INFORMATION
	SystemWin32WerStartCallout,
	SystemSecureKernelProfileInformation,
	MaxSystemInfoClass
} SYSTEM_INFORMATION_CLASS;

typedef struct _SYSTEM_BASIC_INFORMATION
{
	ULONG Reserved;
	ULONG TimerResolution;
	ULONG PageSize;
	ULONG NumberOfPhysicalPages;
	ULONG LowestPhysicalPageNumber;
	ULONG HighestPhysicalPageNumber;
	ULONG AllocationGranularity;
	ULONG_PTR MinimumUserModeAddress;
	ULONG_PTR MaximumUserModeAddress;
	ULONG_PTR ActiveProcessorsAffinityMask;
	CCHAR NumberOfProcessors;
} SYSTEM_BASIC_INFORMATION, *PSYSTEM_BASIC_INFORMATION;

typedef struct _SYSTEM_PROCESSOR_INFORMATION
{
	USHORT ProcessorArchitecture;
	USHORT ProcessorLevel;
	USHORT ProcessorRevision;
	USHORT Reserved;
	ULONG ProcessorFeatureBits;
} SYSTEM_PROCESSOR_INFORMATION, *PSYSTEM_PROCESSOR_INFORMATION;

typedef struct _SYSTEM_PERFORMANCE_INFORMATION
{
	LARGE_INTEGER IdleProcessTime;
	LARGE_INTEGER IoReadTransferCount;
	LARGE_INTEGER IoWriteTransferCount;
	LARGE_INTEGER IoOtherTransferCount;
	ULONG IoReadOperationCount;
	ULONG IoWriteOperationCount;
	ULONG IoOtherOperationCount;
	ULONG AvailablePages;
	ULONG CommittedPages;
	ULONG CommitLimit;
	ULONG PeakCommitment;
	ULONG PageFaultCount;
	ULONG CopyOnWriteCount;
	ULONG TransitionCount;
	ULONG CacheTransitionCount;
	ULONG DemandZeroCount;
	ULONG PageReadCount;
	ULONG PageReadIoCount;
	ULONG CacheReadCount;
	ULONG CacheIoCount;
	ULONG DirtyPagesWriteCount;
	ULONG DirtyWriteIoCount;
	ULONG MappedPagesWriteCount;
	ULONG MappedWriteIoCount;
	ULONG PagedPoolPages;
	ULONG NonPagedPoolPages;
	ULONG PagedPoolAllocs;
	ULONG PagedPoolFrees;
	ULONG NonPagedPoolAllocs;
	ULONG NonPagedPoolFrees;
	ULONG FreeSystemPtes;
	ULONG ResidentSystemCodePage;
	ULONG TotalSystemDriverPages;
	ULONG TotalSystemCodePages;
	ULONG NonPagedPoolLookasideHits;
	ULONG PagedPoolLookasideHits;
	ULONG AvailablePagedPoolPages;
	ULONG ResidentSystemCachePage;
	ULONG ResidentPagedPoolPage;
	ULONG ResidentSystemDriverPage;
	ULONG CcFastReadNoWait;
	ULONG CcFastReadWait;
	ULONG CcFastReadResourceMiss;
	ULONG CcFastReadNotPossible;
	ULONG CcFastMdlReadNoWait;
	ULONG CcFastMdlReadWait;
	ULONG CcFastMdlReadResourceMiss;
	ULONG CcFastMdlReadNotPossible;
	ULONG CcMapDataNoWait;
	ULONG CcMapDataWait;
	ULONG CcMapDataNoWaitMiss;
	ULONG CcMapDataWaitMiss;
	ULONG CcPinMappedDataCount;
	ULONG CcPinReadNoWait;
	ULONG CcPinReadWait;
	ULONG CcPinReadNoWaitMiss;
	ULONG CcPinReadWaitMiss;
	ULONG CcCopyReadNoWait;
	ULONG CcCopyReadWait;
	ULONG CcCopyReadNoWaitMiss;
	ULONG CcCopyReadWaitMiss;
	ULONG CcMdlReadNoWait;
	ULONG CcMdlReadWait;
	ULONG CcMdlReadNoWaitMiss;
	ULONG CcMdlReadWaitMiss;
	ULONG CcReadAheadIos;
	ULONG CcLazyWriteIos;
	ULONG CcLazyWritePages;
	ULONG CcDataFlushes;
	ULONG CcDataPages;
	ULONG ContextSwitches;
	ULONG FirstLevelTbFills;
	ULONG SecondLevelTbFills;
	ULONG SystemCalls;
	ULONGLONG CcTotalDirtyPages; // since THRESHOLD
	ULONGLONG CcDirtyPageThreshold; // since THRESHOLD
	LONGLONG ResidentAvailablePages; // since THRESHOLD
	ULONGLONG SharedCommittedPages; // since THRESHOLD
} SYSTEM_PERFORMANCE_INFORMATION, *PSYSTEM_PERFORMANCE_INFORMATION;

typedef struct _SYSTEM_TIMEOFDAY_INFORMATION
{
	LARGE_INTEGER BootTime;
	LARGE_INTEGER CurrentTime;
	LARGE_INTEGER TimeZoneBias;
	ULONG TimeZoneId;
	ULONG Reserved;
	ULONGLONG BootTimeBias;
	ULONGLONG SleepTimeBias;
} SYSTEM_TIMEOFDAY_INFORMATION, *PSYSTEM_TIMEOFDAY_INFORMATION;

typedef struct _SYSTEM_THREAD_INFORMATION
{
	LARGE_INTEGER KernelTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER CreateTime;
	ULONG WaitTime;
	PVOID StartAddress;
	CLIENT_ID ClientId;
	KPRIORITY Priority;
	LONG BasePriority;
	ULONG ContextSwitches;
	ULONG ThreadState;
	KWAIT_REASON WaitReason;
} SYSTEM_THREAD_INFORMATION, *PSYSTEM_THREAD_INFORMATION;

typedef struct _TEB *PTEB;

// private
typedef struct _SYSTEM_EXTENDED_THREAD_INFORMATION
{
	SYSTEM_THREAD_INFORMATION ThreadInfo;
	PVOID StackBase;
	PVOID StackLimit;
	PVOID Win32StartAddress;
	PTEB TebBase; // since VISTA
	ULONG_PTR Reserved2;
	ULONG_PTR Reserved3;
	ULONG_PTR Reserved4;
} SYSTEM_EXTENDED_THREAD_INFORMATION, *PSYSTEM_EXTENDED_THREAD_INFORMATION;

typedef struct _SYSTEM_PROCESS_INFORMATION
{
	ULONG NextEntryOffset;
	ULONG NumberOfThreads;
	LARGE_INTEGER WorkingSetPrivateSize; // since VISTA
	ULONG HardFaultCount; // since WIN7
	ULONG NumberOfThreadsHighWatermark; // since WIN7
	ULONGLONG CycleTime; // since WIN7
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER KernelTime;
	UNICODE_STRING ImageName;
	KPRIORITY BasePriority;
	HANDLE UniqueProcessId;
	HANDLE InheritedFromUniqueProcessId;
	ULONG HandleCount;
	ULONG SessionId;
	ULONG_PTR UniqueProcessKey; // since VISTA (requires SystemExtendedProcessInformation)
	SIZE_T PeakVirtualSize;
	SIZE_T VirtualSize;
	ULONG PageFaultCount;
	SIZE_T PeakWorkingSetSize;
	SIZE_T WorkingSetSize;
	SIZE_T QuotaPeakPagedPoolUsage;
	SIZE_T QuotaPagedPoolUsage;
	SIZE_T QuotaPeakNonPagedPoolUsage;
	SIZE_T QuotaNonPagedPoolUsage;
	SIZE_T PagefileUsage;
	SIZE_T PeakPagefileUsage;
	SIZE_T PrivatePageCount;
	LARGE_INTEGER ReadOperationCount;
	LARGE_INTEGER WriteOperationCount;
	LARGE_INTEGER OtherOperationCount;
	LARGE_INTEGER ReadTransferCount;
	LARGE_INTEGER WriteTransferCount;
	LARGE_INTEGER OtherTransferCount;
	SYSTEM_THREAD_INFORMATION Threads[1];
} SYSTEM_PROCESS_INFORMATION, *PSYSTEM_PROCESS_INFORMATION;

typedef struct _SYSTEM_CALL_COUNT_INFORMATION
{
	ULONG Length;
	ULONG NumberOfTables;
} SYSTEM_CALL_COUNT_INFORMATION, *PSYSTEM_CALL_COUNT_INFORMATION;

typedef struct _SYSTEM_DEVICE_INFORMATION
{
	ULONG NumberOfDisks;
	ULONG NumberOfFloppies;
	ULONG NumberOfCdRoms;
	ULONG NumberOfTapes;
	ULONG NumberOfSerialPorts;
	ULONG NumberOfParallelPorts;
} SYSTEM_DEVICE_INFORMATION, *PSYSTEM_DEVICE_INFORMATION;

typedef struct _SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION
{
	LARGE_INTEGER IdleTime;
	LARGE_INTEGER KernelTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER DpcTime;
	LARGE_INTEGER InterruptTime;
	ULONG InterruptCount;
} SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION, *PSYSTEM_PROCESSOR_PERFORMANCE_INFORMATION;

typedef struct _SYSTEM_FLAGS_INFORMATION
{
	ULONG Flags; // NtGlobalFlag
} SYSTEM_FLAGS_INFORMATION, *PSYSTEM_FLAGS_INFORMATION;

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO
{
	USHORT UniqueProcessId;
	USHORT CreatorBackTraceIndex;
	UCHAR ObjectTypeIndex;
	UCHAR HandleAttributes;
	USHORT HandleValue;
	PVOID Object;
	ULONG GrantedAccess;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO, *PSYSTEM_HANDLE_TABLE_ENTRY_INFO;

typedef struct _SYSTEM_HANDLE_INFORMATION
{
	ULONG NumberOfHandles;
	SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

typedef struct _SYSTEM_OBJECTTYPE_INFORMATION
{
	ULONG NextEntryOffset;
	ULONG NumberOfObjects;
	ULONG NumberOfHandles;
	ULONG TypeIndex;
	ULONG InvalidAttributes;
	GENERIC_MAPPING GenericMapping;
	ULONG ValidAccessMask;
	ULONG PoolType;
	BOOLEAN SecurityRequired;
	BOOLEAN WaitableObject;
	UNICODE_STRING TypeName;
} SYSTEM_OBJECTTYPE_INFORMATION, *PSYSTEM_OBJECTTYPE_INFORMATION;

typedef struct _SYSTEM_OBJECT_INFORMATION
{
	ULONG NextEntryOffset;
	PVOID Object;
	HANDLE CreatorUniqueProcess;
	USHORT CreatorBackTraceIndex;
	USHORT Flags;
	LONG PointerCount;
	LONG HandleCount;
	ULONG PagedPoolCharge;
	ULONG NonPagedPoolCharge;
	HANDLE ExclusiveProcessId;
	PVOID SecurityDescriptor;
	UNICODE_STRING NameInfo;
} SYSTEM_OBJECT_INFORMATION, *PSYSTEM_OBJECT_INFORMATION;

typedef struct _SYSTEM_PAGEFILE_INFORMATION
{
	ULONG NextEntryOffset;
	ULONG TotalSize;
	ULONG TotalInUse;
	ULONG PeakUsage;
	UNICODE_STRING PageFileName;
} SYSTEM_PAGEFILE_INFORMATION, *PSYSTEM_PAGEFILE_INFORMATION;

#define MM_WORKING_SET_MAX_HARD_ENABLE 0x1
#define MM_WORKING_SET_MAX_HARD_DISABLE 0x2
#define MM_WORKING_SET_MIN_HARD_ENABLE 0x4
#define MM_WORKING_SET_MIN_HARD_DISABLE 0x8

typedef struct _SYSTEM_FILECACHE_INFORMATION
{
	SIZE_T CurrentSize;
	SIZE_T PeakSize;
	ULONG PageFaultCount;
	SIZE_T MinimumWorkingSet;
	SIZE_T MaximumWorkingSet;
	SIZE_T CurrentSizeIncludingTransitionInPages;
	SIZE_T PeakSizeIncludingTransitionInPages;
	ULONG TransitionRePurposeCount;
	ULONG Flags;
} SYSTEM_FILECACHE_INFORMATION, *PSYSTEM_FILECACHE_INFORMATION;

// Can be used instead of SYSTEM_FILECACHE_INFORMATION
typedef struct _SYSTEM_BASIC_WORKING_SET_INFORMATION
{
	SIZE_T CurrentSize;
	SIZE_T PeakSize;
	ULONG PageFaultCount;
} SYSTEM_BASIC_WORKING_SET_INFORMATION, *PSYSTEM_BASIC_WORKING_SET_INFORMATION;

typedef struct _SYSTEM_POOLTAG
{
	union
	{
		UCHAR Tag[4];
		ULONG TagUlong;
	};
	ULONG PagedAllocs;
	ULONG PagedFrees;
	SIZE_T PagedUsed;
	ULONG NonPagedAllocs;
	ULONG NonPagedFrees;
	SIZE_T NonPagedUsed;
} SYSTEM_POOLTAG, *PSYSTEM_POOLTAG;

typedef struct _SYSTEM_POOLTAG_INFORMATION
{
	ULONG Count;
	SYSTEM_POOLTAG TagInfo[1];
} SYSTEM_POOLTAG_INFORMATION, *PSYSTEM_POOLTAG_INFORMATION;

typedef struct _SYSTEM_INTERRUPT_INFORMATION
{
	ULONG ContextSwitches;
	ULONG DpcCount;
	ULONG DpcRate;
	ULONG TimeIncrement;
	ULONG DpcBypassCount;
	ULONG ApcBypassCount;
} SYSTEM_INTERRUPT_INFORMATION, *PSYSTEM_INTERRUPT_INFORMATION;

typedef struct _SYSTEM_DPC_BEHAVIOR_INFORMATION
{
	ULONG Spare;
	ULONG DpcQueueDepth;
	ULONG MinimumDpcRate;
	ULONG AdjustDpcThreshold;
	ULONG IdealDpcRate;
} SYSTEM_DPC_BEHAVIOR_INFORMATION, *PSYSTEM_DPC_BEHAVIOR_INFORMATION;

typedef struct _SYSTEM_QUERY_TIME_ADJUST_INFORMATION
{
	ULONG TimeAdjustment;
	ULONG TimeIncrement;
	BOOLEAN Enable;
} SYSTEM_QUERY_TIME_ADJUST_INFORMATION, *PSYSTEM_QUERY_TIME_ADJUST_INFORMATION;

typedef struct _SYSTEM_SET_TIME_ADJUST_INFORMATION
{
	ULONG TimeAdjustment;
	BOOLEAN Enable;
} SYSTEM_SET_TIME_ADJUST_INFORMATION, *PSYSTEM_SET_TIME_ADJUST_INFORMATION;

typedef struct _SYSTEM_EXCEPTION_INFORMATION
{
	ULONG AlignmentFixupCount;
	ULONG ExceptionDispatchCount;
	ULONG FloatingEmulationCount;
	ULONG ByteWordEmulationCount;
} SYSTEM_EXCEPTION_INFORMATION, *PSYSTEM_EXCEPTION_INFORMATION;

typedef struct _SYSTEM_KERNEL_DEBUGGER_INFORMATION
{
	BOOLEAN KernelDebuggerEnabled;
	BOOLEAN KernelDebuggerNotPresent;
} SYSTEM_KERNEL_DEBUGGER_INFORMATION, *PSYSTEM_KERNEL_DEBUGGER_INFORMATION;

typedef struct _SYSTEM_CONTEXT_SWITCH_INFORMATION
{
	ULONG ContextSwitches;
	ULONG FindAny;
	ULONG FindLast;
	ULONG FindIdeal;
	ULONG IdleAny;
	ULONG IdleCurrent;
	ULONG IdleLast;
	ULONG IdleIdeal;
	ULONG PreemptAny;
	ULONG PreemptCurrent;
	ULONG PreemptLast;
	ULONG SwitchToIdle;
} SYSTEM_CONTEXT_SWITCH_INFORMATION, *PSYSTEM_CONTEXT_SWITCH_INFORMATION;

typedef struct _SYSTEM_REGISTRY_QUOTA_INFORMATION
{
	ULONG RegistryQuotaAllowed;
	ULONG RegistryQuotaUsed;
	SIZE_T PagedPoolSize;
} SYSTEM_REGISTRY_QUOTA_INFORMATION, *PSYSTEM_REGISTRY_QUOTA_INFORMATION;

typedef struct _SYSTEM_PROCESSOR_IDLE_INFORMATION
{
	ULONGLONG IdleTime;
	ULONGLONG C1Time;
	ULONGLONG C2Time;
	ULONGLONG C3Time;
	ULONG C1Transitions;
	ULONG C2Transitions;
	ULONG C3Transitions;
	ULONG Padding;
} SYSTEM_PROCESSOR_IDLE_INFORMATION, *PSYSTEM_PROCESSOR_IDLE_INFORMATION;

typedef struct _SYSTEM_LEGACY_DRIVER_INFORMATION
{
	ULONG VetoType;
	UNICODE_STRING VetoList;
} SYSTEM_LEGACY_DRIVER_INFORMATION, *PSYSTEM_LEGACY_DRIVER_INFORMATION;

typedef struct _SYSTEM_LOOKASIDE_INFORMATION
{
	USHORT CurrentDepth;
	USHORT MaximumDepth;
	ULONG TotalAllocates;
	ULONG AllocateMisses;
	ULONG TotalFrees;
	ULONG FreeMisses;
	ULONG Type;
	ULONG Tag;
	ULONG Size;
} SYSTEM_LOOKASIDE_INFORMATION, *PSYSTEM_LOOKASIDE_INFORMATION;

typedef struct _SYSTEM_VERIFIER_INFORMATION
{
	ULONG NextEntryOffset;
	ULONG Level;
	UNICODE_STRING DriverName;

	ULONG RaiseIrqls;
	ULONG AcquireSpinLocks;
	ULONG SynchronizeExecutions;
	ULONG AllocationsAttempted;

	ULONG AllocationsSucceeded;
	ULONG AllocationsSucceededSpecialPool;
	ULONG AllocationsWithNoTag;
	ULONG TrimRequests;

	ULONG Trims;
	ULONG AllocationsFailed;
	ULONG AllocationsFailedDeliberately;
	ULONG Loads;

	ULONG Unloads;
	ULONG UnTrackedPool;
	ULONG CurrentPagedPoolAllocations;
	ULONG CurrentNonPagedPoolAllocations;

	ULONG PeakPagedPoolAllocations;
	ULONG PeakNonPagedPoolAllocations;

	SIZE_T PagedPoolUsageInBytes;
	SIZE_T NonPagedPoolUsageInBytes;
	SIZE_T PeakPagedPoolUsageInBytes;
	SIZE_T PeakNonPagedPoolUsageInBytes;
} SYSTEM_VERIFIER_INFORMATION, *PSYSTEM_VERIFIER_INFORMATION;

typedef struct _SYSTEM_SESSION_PROCESS_INFORMATION
{
	ULONG SessionId;
	ULONG SizeOfBuf;
	PVOID Buffer;
} SYSTEM_SESSION_PROCESS_INFORMATION, *PSYSTEM_SESSION_PROCESS_INFORMATION;

typedef struct _SYSTEM_PROCESSOR_POWER_INFORMATION
{
	UCHAR CurrentFrequency;
	UCHAR ThermalLimitFrequency;
	UCHAR ConstantThrottleFrequency;
	UCHAR DegradedThrottleFrequency;
	UCHAR LastBusyFrequency;
	UCHAR LastC3Frequency;
	UCHAR LastAdjustedBusyFrequency;
	UCHAR ProcessorMinThrottle;
	UCHAR ProcessorMaxThrottle;
	ULONG NumberOfFrequencies;
	ULONG PromotionCount;
	ULONG DemotionCount;
	ULONG ErrorCount;
	ULONG RetryCount;
	ULONGLONG CurrentFrequencyTime;
	ULONGLONG CurrentProcessorTime;
	ULONGLONG CurrentProcessorIdleTime;
	ULONGLONG LastProcessorTime;
	ULONGLONG LastProcessorIdleTime;
} SYSTEM_PROCESSOR_POWER_INFORMATION, *PSYSTEM_PROCESSOR_POWER_INFORMATION;

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX
{
	PVOID Object;
	ULONG_PTR UniqueProcessId;
	ULONG_PTR HandleValue;
	ULONG GrantedAccess;
	USHORT CreatorBackTraceIndex;
	USHORT ObjectTypeIndex;
	ULONG HandleAttributes;
	ULONG Reserved;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX, *PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX;

typedef struct _SYSTEM_HANDLE_INFORMATION_EX
{
	ULONG_PTR NumberOfHandles;
	ULONG_PTR Reserved;
	SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Handles[1];
} SYSTEM_HANDLE_INFORMATION_EX, *PSYSTEM_HANDLE_INFORMATION_EX;

typedef struct _SYSTEM_BIGPOOL_ENTRY
{
	union
	{
		PVOID VirtualAddress;
		ULONG_PTR NonPaged : 1;
	};
	SIZE_T SizeInBytes;
	union
	{
		UCHAR Tag[4];
		ULONG TagUlong;
	};
} SYSTEM_BIGPOOL_ENTRY, *PSYSTEM_BIGPOOL_ENTRY;

typedef struct _SYSTEM_BIGPOOL_INFORMATION
{
	ULONG Count;
	SYSTEM_BIGPOOL_ENTRY AllocatedInfo[1];
} SYSTEM_BIGPOOL_INFORMATION, *PSYSTEM_BIGPOOL_INFORMATION;

typedef struct _SYSTEM_POOL_ENTRY
{
	BOOLEAN Allocated;
	BOOLEAN Spare0;
	USHORT AllocatorBackTraceIndex;
	ULONG Size;
	union
	{
		UCHAR Tag[4];
		ULONG TagUlong;
		PVOID ProcessChargedQuota;
	};
} SYSTEM_POOL_ENTRY, *PSYSTEM_POOL_ENTRY;

typedef struct _SYSTEM_POOL_INFORMATION
{
	SIZE_T TotalSize;
	PVOID FirstEntry;
	USHORT EntryOverhead;
	BOOLEAN PoolTagPresent;
	BOOLEAN Spare0;
	ULONG NumberOfEntries;
	SYSTEM_POOL_ENTRY Entries[1];
} SYSTEM_POOL_INFORMATION, *PSYSTEM_POOL_INFORMATION;

typedef struct _SYSTEM_SESSION_POOLTAG_INFORMATION
{
	SIZE_T NextEntryOffset;
	ULONG SessionId;
	ULONG Count;
	SYSTEM_POOLTAG TagInfo[1];
} SYSTEM_SESSION_POOLTAG_INFORMATION, *PSYSTEM_SESSION_POOLTAG_INFORMATION;

typedef struct _SYSTEM_SESSION_MAPPED_VIEW_INFORMATION
{
	SIZE_T NextEntryOffset;
	ULONG SessionId;
	ULONG ViewFailures;
	SIZE_T NumberOfBytesAvailable;
	SIZE_T NumberOfBytesAvailableContiguous;
} SYSTEM_SESSION_MAPPED_VIEW_INFORMATION, *PSYSTEM_SESSION_MAPPED_VIEW_INFORMATION;

// private
typedef struct _SYSTEM_MEMORY_LIST_INFORMATION
{
	ULONG_PTR ZeroPageCount;
	ULONG_PTR FreePageCount;
	ULONG_PTR ModifiedPageCount;
	ULONG_PTR ModifiedNoWritePageCount;
	ULONG_PTR BadPageCount;
	ULONG_PTR PageCountByPriority[8];
	ULONG_PTR RepurposedPagesByPriority[8];
	ULONG_PTR ModifiedPageCountPageFile;
} SYSTEM_MEMORY_LIST_INFORMATION, *PSYSTEM_MEMORY_LIST_INFORMATION;

// private
typedef enum _SYSTEM_MEMORY_LIST_COMMAND
{
	MemoryCaptureAccessedBits,
	MemoryCaptureAndResetAccessedBits,
	MemoryEmptyWorkingSets,
	MemoryFlushModifiedList,
	MemoryPurgeStandbyList,
	MemoryPurgeLowPriorityStandbyList,
	MemoryCommandMax
} SYSTEM_MEMORY_LIST_COMMAND;

// private
typedef struct _SYSTEM_THREAD_CID_PRIORITY_INFORMATION
{
	CLIENT_ID ClientId;
	KPRIORITY Priority;
} SYSTEM_THREAD_CID_PRIORITY_INFORMATION, *PSYSTEM_THREAD_CID_PRIORITY_INFORMATION;

// private
typedef struct _SYSTEM_PROCESSOR_IDLE_CYCLE_TIME_INFORMATION
{
	ULONGLONG CycleTime;
} SYSTEM_PROCESSOR_IDLE_CYCLE_TIME_INFORMATION, *PSYSTEM_PROCESSOR_IDLE_CYCLE_TIME_INFORMATION;

// private
typedef struct _SYSTEM_REF_TRACE_INFORMATION
{
	BOOLEAN TraceEnable;
	BOOLEAN TracePermanent;
	UNICODE_STRING TraceProcessName;
	UNICODE_STRING TracePoolTags;
} SYSTEM_REF_TRACE_INFORMATION, *PSYSTEM_REF_TRACE_INFORMATION;

// private
typedef struct _SYSTEM_PROCESS_ID_INFORMATION
{
	HANDLE ProcessId;
	UNICODE_STRING ImageName;
} SYSTEM_PROCESS_ID_INFORMATION, *PSYSTEM_PROCESS_ID_INFORMATION;

// private
typedef struct _SYSTEM_BOOT_ENVIRONMENT_INFORMATION
{
	GUID BootIdentifier;
	FIRMWARE_TYPE FirmwareType;
} SYSTEM_BOOT_ENVIRONMENT_INFORMATION, PSYSTEM_BOOT_ENVIRONMENT_INFORMATION;

// private
typedef struct _SYSTEM_IMAGE_FILE_EXECUTION_OPTIONS_INFORMATION
{
	ULONG FlagsToEnable;
	ULONG FlagsToDisable;
} SYSTEM_IMAGE_FILE_EXECUTION_OPTIONS_INFORMATION, *PSYSTEM_IMAGE_FILE_EXECUTION_OPTIONS_INFORMATION;

// private
typedef struct _SYSTEM_SYSTEM_PARTITION_INFORMATION
{
	UNICODE_STRING SystemPartition;
} SYSTEM_SYSTEM_PARTITION_INFORMATION, *PSYSTEM_SYSTEM_PARTITION_INFORMATION;

// private
typedef struct _SYSTEM_SYSTEM_DISK_INFORMATION
{
	UNICODE_STRING SystemDisk;
} SYSTEM_SYSTEM_DISK_INFORMATION, *PSYSTEM_SYSTEM_DISK_INFORMATION;

// private
typedef struct _SYSTEM_PROCESSOR_PERFORMANCE_HITCOUNT
{
	LARGE_INTEGER Hits; // ULONG in WIN8
	UCHAR PercentFrequency;
} SYSTEM_PROCESSOR_PERFORMANCE_HITCOUNT, *PSYSTEM_PROCESSOR_PERFORMANCE_HITCOUNT;

// private
typedef struct _SYSTEM_PROCESSOR_PERFORMANCE_STATE_DISTRIBUTION
{
	ULONG ProcessorNumber;
	ULONG StateCount;
	SYSTEM_PROCESSOR_PERFORMANCE_HITCOUNT States[1];
} SYSTEM_PROCESSOR_PERFORMANCE_STATE_DISTRIBUTION, *PSYSTEM_PROCESSOR_PERFORMANCE_STATE_DISTRIBUTION;

// private
typedef struct _SYSTEM_PROCESSOR_PERFORMANCE_DISTRIBUTION
{
	ULONG ProcessorCount;
	ULONG Offsets[1];
} SYSTEM_PROCESSOR_PERFORMANCE_DISTRIBUTION, *PSYSTEM_PROCESSOR_PERFORMANCE_DISTRIBUTION;

// private
typedef enum _SYSTEM_VA_TYPE
{
	SystemVaTypeAll,
	SystemVaTypeNonPagedPool,
	SystemVaTypePagedPool,
	SystemVaTypeSystemCache,
	SystemVaTypeSystemPtes,
	SystemVaTypeSessionSpace,
	SystemVaTypeMax
} SYSTEM_VA_TYPE, *PSYSTEM_VA_TYPE;

// private
typedef struct _SYSTEM_VA_LIST_INFORMATION
{
	SIZE_T VirtualSize;
	SIZE_T VirtualPeak;
	SIZE_T VirtualLimit;
	SIZE_T AllocationFailures;
} SYSTEM_VA_LIST_INFORMATION, *PSYSTEM_VA_LIST_INFORMATION;

// private
typedef struct _SYSTEM_REGISTRY_APPEND_STRING_PARAMETERS
{
	HANDLE KeyHandle;
	PUNICODE_STRING ValueNamePointer;
	PULONG RequiredLengthPointer;
	PUCHAR Buffer;
	ULONG BufferLength;
	ULONG Type;
	PUCHAR AppendBuffer;
	ULONG AppendBufferLength;
	BOOLEAN CreateIfDoesntExist;
	BOOLEAN TruncateExistingValue;
} SYSTEM_REGISTRY_APPEND_STRING_PARAMETERS, *PSYSTEM_REGISTRY_APPEND_STRING_PARAMETERS;

// msdn
typedef struct _SYSTEM_VHD_BOOT_INFORMATION
{
	BOOLEAN OsDiskIsVhd;
	ULONG OsVhdFilePathOffset;
	WCHAR OsVhdParentVolume[ANYSIZE_ARRAY];
} SYSTEM_VHD_BOOT_INFORMATION, *PSYSTEM_VHD_BOOT_INFORMATION;

// private
typedef struct _SYSTEM_LOW_PRIORITY_IO_INFORMATION
{
	ULONG LowPriReadOperations;
	ULONG LowPriWriteOperations;
	ULONG KernelBumpedToNormalOperations;
	ULONG LowPriPagingReadOperations;
	ULONG KernelPagingReadsBumpedToNormal;
	ULONG LowPriPagingWriteOperations;
	ULONG KernelPagingWritesBumpedToNormal;
	ULONG BoostedIrpCount;
	ULONG BoostedPagingIrpCount;
	ULONG BlanketBoostCount;
} SYSTEM_LOW_PRIORITY_IO_INFORMATION, *PSYSTEM_LOW_PRIORITY_IO_INFORMATION;

// symbols
typedef enum _TPM_BOOT_ENTROPY_RESULT_CODE
{
	TpmBootEntropyStructureUninitialized,
	TpmBootEntropyDisabledByPolicy,
	TpmBootEntropyNoTpmFound,
	TpmBootEntropyTpmError,
	TpmBootEntropySuccess
} TPM_BOOT_ENTROPY_RESULT_CODE;

// Contents of KeLoaderBlock->Extension->TpmBootEntropyResult (TPM_BOOT_ENTROPY_LDR_RESULT).
// EntropyData is truncated to 40 bytes.

// private
typedef struct _TPM_BOOT_ENTROPY_NT_RESULT
{
	ULONGLONG Policy;
	TPM_BOOT_ENTROPY_RESULT_CODE ResultCode;
	NTSTATUS ResultStatus;
	ULONGLONG Time;
	ULONG EntropyLength;
	UCHAR EntropyData[40];
} TPM_BOOT_ENTROPY_NT_RESULT, *PTPM_BOOT_ENTROPY_NT_RESULT;

// private
typedef struct _SYSTEM_VERIFIER_COUNTERS_INFORMATION
{
	SYSTEM_VERIFIER_INFORMATION Legacy;
	ULONG RaiseIrqls;
	ULONG AcquireSpinLocks;
	ULONG SynchronizeExecutions;
	ULONG AllocationsWithNoTag;
	ULONG AllocationsFailed;
	ULONG AllocationsFailedDeliberately;
	SIZE_T LockedBytes;
	SIZE_T PeakLockedBytes;
	SIZE_T MappedLockedBytes;
	SIZE_T PeakMappedLockedBytes;
	SIZE_T MappedIoSpaceBytes;
	SIZE_T PeakMappedIoSpaceBytes;
	SIZE_T PagesForMdlBytes;
	SIZE_T PeakPagesForMdlBytes;
	SIZE_T ContiguousMemoryBytes;
	SIZE_T PeakContiguousMemoryBytes;
} SYSTEM_VERIFIER_COUNTERS_INFORMATION, *PSYSTEM_VERIFIER_COUNTERS_INFORMATION;

// private
typedef struct _SYSTEM_ACPI_AUDIT_INFORMATION
{
	ULONG RsdpCount;
	ULONG SameRsdt : 1;
	ULONG SlicPresent : 1;
	ULONG SlicDifferent : 1;
} SYSTEM_ACPI_AUDIT_INFORMATION, *PSYSTEM_ACPI_AUDIT_INFORMATION;

// private
typedef struct _SYSTEM_BASIC_PERFORMANCE_INFORMATION
{
	SIZE_T AvailablePages;
	SIZE_T CommittedPages;
	SIZE_T CommitLimit;
	SIZE_T PeakCommitment;
} SYSTEM_BASIC_PERFORMANCE_INFORMATION, *PSYSTEM_BASIC_PERFORMANCE_INFORMATION;

// begin_msdn

typedef struct _QUERY_PERFORMANCE_COUNTER_FLAGS
{
	union
	{
		struct
		{
			ULONG KernelTransition : 1;
			ULONG Reserved : 31;
		};
		ULONG ul;
	};
} QUERY_PERFORMANCE_COUNTER_FLAGS;

typedef struct _SYSTEM_QUERY_PERFORMANCE_COUNTER_INFORMATION
{
	ULONG Version;
	QUERY_PERFORMANCE_COUNTER_FLAGS Flags;
	QUERY_PERFORMANCE_COUNTER_FLAGS ValidFlags;
} SYSTEM_QUERY_PERFORMANCE_COUNTER_INFORMATION, *PSYSTEM_QUERY_PERFORMANCE_COUNTER_INFORMATION;

// end_msdn

// private
typedef struct _SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION_EX
{
	LARGE_INTEGER IdleTime;
	LARGE_INTEGER KernelTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER DpcTime;
	LARGE_INTEGER InterruptTime;
	ULONG InterruptCount;
	ULONG Spare0;
	LARGE_INTEGER AvailableTime;
	LARGE_INTEGER Spare1;
	LARGE_INTEGER Spare2;
} SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION_EX, *PSYSTEM_PROCESSOR_PERFORMANCE_INFORMATION_EX;

// private
typedef struct _SYSTEM_PAGEFILE_INFORMATION_EX
{
	SYSTEM_PAGEFILE_INFORMATION Info;
	ULONG MinimumSize;
	ULONG MaximumSize;
} SYSTEM_PAGEFILE_INFORMATION_EX, *PSYSTEM_PAGEFILE_INFORMATION_EX;

// private
typedef struct _PROCESS_DISK_COUNTERS
{
	ULONGLONG BytesRead;
	ULONGLONG BytesWritten;
	ULONGLONG ReadOperationCount;
	ULONGLONG WriteOperationCount;
	ULONGLONG FlushOperationCount;
} PROCESS_DISK_COUNTERS, *PPROCESS_DISK_COUNTERS;

// private
typedef struct _PROCESS_ENERGY_VALUES
{
	ULONGLONG Cycles[2][4];
	ULONGLONG DiskEnergy;
	ULONGLONG NetworkTailEnergy;
	ULONGLONG MBBTailEnergy;
	ULONGLONG NetworkTxRxBytes;
	ULONGLONG MBBTxRxBytes;
	union
	{
		struct
		{
			ULONG Foreground : 1;
		};
		ULONG WindowInformation;
	};
	ULONG PixelArea;
	LONGLONG PixelReportTimestamp;
	ULONGLONG PixelTime;
	LONGLONG ForegroundReportTimestamp;
	ULONGLONG ForegroundTime;
} PROCESS_ENERGY_VALUES, *PPROCESS_ENERGY_VALUES;

// private
typedef struct _SYSTEM_PROCESS_INFORMATION_EXTENSION
{
	PROCESS_DISK_COUNTERS DiskCounters;
	ULONGLONG ContextSwitches;
	union
	{
		ULONG Flags;
		struct
		{
			ULONG HasStrongId : 1;
			ULONG Spare : 31;
		};
	};
	ULONG UserSidOffset;
	ULONG PackageFullNameOffset; // since THRESHOLD
	PROCESS_ENERGY_VALUES EnergyValues; // since THRESHOLD
	ULONG AppIdOffset; // since THRESHOLD
	SIZE_T SharedCommitCharge; // since THRESHOLD2
} SYSTEM_PROCESS_INFORMATION_EXTENSION, *PSYSTEM_PROCESS_INFORMATION_EXTENSION;

// private
typedef struct _SYSTEM_KERNEL_DEBUGGER_INFORMATION_EX
{
	BOOLEAN DebuggerAllowed;
	BOOLEAN DebuggerEnabled;
	BOOLEAN DebuggerPresent;
} SYSTEM_KERNEL_DEBUGGER_INFORMATION_EX, *PSYSTEM_KERNEL_DEBUGGER_INFORMATION_EX;

// private
typedef struct _SYSTEM_PROCESSOR_FEATURES_INFORMATION
{
	ULONGLONG ProcessorFeatureBits;
	ULONGLONG Reserved[3];
} SYSTEM_PROCESSOR_FEATURES_INFORMATION, *PSYSTEM_PROCESSOR_FEATURES_INFORMATION;

// private
typedef struct _SYSTEM_MANUFACTURING_INFORMATION
{
	ULONG Options;
	UNICODE_STRING ProfileName;
} SYSTEM_MANUFACTURING_INFORMATION, *PSYSTEM_MANUFACTURING_INFORMATION;

// private
typedef struct _SYSTEM_ENERGY_ESTIMATION_CONFIG_INFORMATION
{
	BOOLEAN Enabled;
} SYSTEM_ENERGY_ESTIMATION_CONFIG_INFORMATION, *PSYSTEM_ENERGY_ESTIMATION_CONFIG_INFORMATION;

// private
typedef struct _HV_DETAILS
{
	ULONG Data[4];
} HV_DETAILS, *PHV_DETAILS;

// private
typedef struct _SYSTEM_HYPERVISOR_DETAIL_INFORMATION
{
	HV_DETAILS HvVendorAndMaxFunction;
	HV_DETAILS HypervisorInterface;
	HV_DETAILS HypervisorVersion;
	HV_DETAILS HvFeatures;
	HV_DETAILS HwFeatures;
	HV_DETAILS EnlightenmentInfo;
	HV_DETAILS ImplementationLimits;
} SYSTEM_HYPERVISOR_DETAIL_INFORMATION, *PSYSTEM_HYPERVISOR_DETAIL_INFORMATION;

// private
typedef struct _SYSTEM_PROCESSOR_CYCLE_STATS_INFORMATION
{
	ULONGLONG Cycles[2][4];
} SYSTEM_PROCESSOR_CYCLE_STATS_INFORMATION, *PSYSTEM_PROCESSOR_CYCLE_STATS_INFORMATION;

// private
typedef struct _SYSTEM_TPM_INFORMATION
{
	ULONG Flags;
} SYSTEM_TPM_INFORMATION, *PSYSTEM_TPM_INFORMATION;

// private
typedef struct _SYSTEM_DMA_PROTECTION_INFORMATION
{
	BOOLEAN DmaProtectionsAvailable;
	BOOLEAN DmaProtectionsInUse;
} SYSTEM_DMA_PROTECTION_INFORMATION, *PSYSTEM_DMA_PROTECTION_INFORMATION;

// private
typedef struct _SYSTEM_SINGLE_MODULE_INFORMATION
{
	PVOID TargetModuleAddress;
	RTL_PROCESS_MODULE_INFORMATION_EX ExInfo;
} SYSTEM_SINGLE_MODULE_INFORMATION, *PSYSTEM_SINGLE_MODULE_INFORMATION;

// private
typedef struct _SYSTEM_ROOT_SILO_INFORMATION
{
	ULONG NumberOfSilos;
	HANDLE SiloIdList[1];
} SYSTEM_ROOT_SILO_INFORMATION, *PSYSTEM_ROOT_SILO_INFORMATION;

// private
typedef struct _SYSTEM_CPU_SET_TAG_INFORMATION
{
	ULONGLONG Tag;
	ULONGLONG CpuSets[1];
} SYSTEM_CPU_SET_TAG_INFORMATION, *PSYSTEM_CPU_SET_TAG_INFORMATION;

#pragma endregion

// IO (文件)
#pragma region FileInformation

// Create disposition

#define FILE_SUPERSEDE 0x00000000
#define FILE_OPEN 0x00000001
#define FILE_CREATE 0x00000002
#define FILE_OPEN_IF 0x00000003
#define FILE_OVERWRITE 0x00000004
#define FILE_OVERWRITE_IF 0x00000005
#define FILE_MAXIMUM_DISPOSITION 0x00000005

// Create/open flags

#define FILE_DIRECTORY_FILE 0x00000001
#define FILE_WRITE_THROUGH 0x00000002
#define FILE_SEQUENTIAL_ONLY 0x00000004
#define FILE_NO_INTERMEDIATE_BUFFERING 0x00000008

#define FILE_SYNCHRONOUS_IO_ALERT 0x00000010
#define FILE_SYNCHRONOUS_IO_NONALERT 0x00000020
#define FILE_NON_DIRECTORY_FILE 0x00000040
#define FILE_CREATE_TREE_CONNECTION 0x00000080

#define FILE_COMPLETE_IF_OPLOCKED 0x00000100
#define FILE_NO_EA_KNOWLEDGE 0x00000200
#define FILE_OPEN_FOR_RECOVERY 0x00000400
#define FILE_RANDOM_ACCESS 0x00000800

#define FILE_DELETE_ON_CLOSE 0x00001000
#define FILE_OPEN_BY_FILE_ID 0x00002000
#define FILE_OPEN_FOR_BACKUP_INTENT 0x00004000
#define FILE_NO_COMPRESSION 0x00008000
#if (PHNT_VERSION >= PHNT_WIN7)
#define FILE_OPEN_REQUIRING_OPLOCK 0x00010000
#define FILE_DISALLOW_EXCLUSIVE 0x00020000
#endif
#if (PHNT_VERSION >= PHNT_WIN8)
#define FILE_SESSION_AWARE 0x00040000
#endif

#define FILE_RESERVE_OPFILTER 0x00100000
#define FILE_OPEN_REPARSE_POINT 0x00200000
#define FILE_OPEN_NO_RECALL 0x00400000
#define FILE_OPEN_FOR_FREE_SPACE_QUERY 0x00800000

#define FILE_COPY_STRUCTURED_STORAGE 0x00000041
#define FILE_STRUCTURED_STORAGE 0x00000441

// I/O status information values for NtCreateFile/NtOpenFile

#define FILE_SUPERSEDED 0x00000000
#define FILE_OPENED 0x00000001
#define FILE_CREATED 0x00000002
#define FILE_OVERWRITTEN 0x00000003
#define FILE_EXISTS 0x00000004
#define FILE_DOES_NOT_EXIST 0x00000005

// Special ByteOffset parameters

#define FILE_WRITE_TO_END_OF_FILE 0xffffffff
#define FILE_USE_FILE_POINTER_POSITION 0xfffffffe

// Alignment requirement values

#define FILE_BYTE_ALIGNMENT 0x00000000
#define FILE_WORD_ALIGNMENT 0x00000001
#define FILE_LONG_ALIGNMENT 0x00000003
#define FILE_QUAD_ALIGNMENT 0x00000007
#define FILE_OCTA_ALIGNMENT 0x0000000f
#define FILE_32_BYTE_ALIGNMENT 0x0000001f
#define FILE_64_BYTE_ALIGNMENT 0x0000003f
#define FILE_128_BYTE_ALIGNMENT 0x0000007f
#define FILE_256_BYTE_ALIGNMENT 0x000000ff
#define FILE_512_BYTE_ALIGNMENT 0x000001ff

// Maximum length of a filename string

#define MAXIMUM_FILENAME_LENGTH 256

// Extended attributes

#define FILE_NEED_EA 0x00000080

#define FILE_EA_TYPE_BINARY 0xfffe
#define FILE_EA_TYPE_ASCII 0xfffd
#define FILE_EA_TYPE_BITMAP 0xfffb
#define FILE_EA_TYPE_METAFILE 0xfffa
#define FILE_EA_TYPE_ICON 0xfff9
#define FILE_EA_TYPE_EA 0xffee
#define FILE_EA_TYPE_MVMT 0xffdf
#define FILE_EA_TYPE_MVST 0xffde
#define FILE_EA_TYPE_ASN1 0xffdd
#define FILE_EA_TYPE_FAMILY_IDS 0xff01

// Device characteristics

#define FILE_REMOVABLE_MEDIA 0x00000001
#define FILE_READ_ONLY_DEVICE 0x00000002
#define FILE_FLOPPY_DISKETTE 0x00000004
#define FILE_WRITE_ONCE_MEDIA 0x00000008
#define FILE_REMOTE_DEVICE 0x00000010
#define FILE_DEVICE_IS_MOUNTED 0x00000020
#define FILE_VIRTUAL_VOLUME 0x00000040
#define FILE_AUTOGENERATED_DEVICE_NAME 0x00000080
#define FILE_DEVICE_SECURE_OPEN 0x00000100
#define FILE_CHARACTERISTIC_PNP_DEVICE 0x00000800
#define FILE_CHARACTERISTIC_TS_DEVICE 0x00001000
#define FILE_CHARACTERISTIC_WEBDAV_DEVICE 0x00002000
#define FILE_CHARACTERISTIC_CSV 0x00010000
#define FILE_DEVICE_ALLOW_APPCONTAINER_TRAVERSAL 0x00020000
#define FILE_PORTABLE_DEVICE 0x00040000

// Named pipe values

// NamedPipeType for NtCreateNamedPipeFile
#define FILE_PIPE_BYTE_STREAM_TYPE 0x00000000
#define FILE_PIPE_MESSAGE_TYPE 0x00000001
#define FILE_PIPE_ACCEPT_REMOTE_CLIENTS 0x00000000
#define FILE_PIPE_REJECT_REMOTE_CLIENTS 0x00000002
#define FILE_PIPE_TYPE_VALID_MASK 0x00000003

// CompletionMode for NtCreateNamedPipeFile
#define FILE_PIPE_QUEUE_OPERATION 0x00000000
#define FILE_PIPE_COMPLETE_OPERATION 0x00000001

// ReadMode for NtCreateNamedPipeFile
#define FILE_PIPE_BYTE_STREAM_MODE 0x00000000
#define FILE_PIPE_MESSAGE_MODE 0x00000001

// NamedPipeConfiguration for NtQueryInformationFile
#define FILE_PIPE_INBOUND 0x00000000
#define FILE_PIPE_OUTBOUND 0x00000001
#define FILE_PIPE_FULL_DUPLEX 0x00000002

// NamedPipeState for NtQueryInformationFile
#define FILE_PIPE_DISCONNECTED_STATE 0x00000001
#define FILE_PIPE_LISTENING_STATE 0x00000002
#define FILE_PIPE_CONNECTED_STATE 0x00000003
#define FILE_PIPE_CLOSING_STATE 0x00000004

// NamedPipeEnd for NtQueryInformationFile
#define FILE_PIPE_CLIENT_END 0x00000000
#define FILE_PIPE_SERVER_END 0x00000001

// Mailslot values

#define MAILSLOT_SIZE_AUTO 0

typedef struct _IO_STATUS_BLOCK
{
	union
	{
		NTSTATUS Status;
		PVOID Pointer;
	};
	ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

typedef VOID(NTAPI *PIO_APC_ROUTINE)(
	_In_ PVOID ApcContext,
	_In_ PIO_STATUS_BLOCK IoStatusBlock,
	_In_ ULONG Reserved
	);

// private
typedef struct _FILE_IO_COMPLETION_INFORMATION
{
	PVOID KeyContext;
	PVOID ApcContext;
	IO_STATUS_BLOCK IoStatusBlock;
} FILE_IO_COMPLETION_INFORMATION, *PFILE_IO_COMPLETION_INFORMATION;

typedef enum _FILE_INFORMATION_CLASS
{
	FileDirectoryInformation = 1,
	FileFullDirectoryInformation,
	FileBothDirectoryInformation,
	FileBasicInformation,
	FileStandardInformation,
	FileInternalInformation,
	FileEaInformation,
	FileAccessInformation,
	FileNameInformation,
	FileRenameInformation, // 10
	FileLinkInformation,
	FileNamesInformation,
	FileDispositionInformation,
	FilePositionInformation,
	FileFullEaInformation,
	FileModeInformation,
	FileAlignmentInformation,
	FileAllInformation,
	FileAllocationInformation,
	FileEndOfFileInformation, // 20
	FileAlternateNameInformation,
	FileStreamInformation,
	FilePipeInformation,
	FilePipeLocalInformation,
	FilePipeRemoteInformation,
	FileMailslotQueryInformation,
	FileMailslotSetInformation,
	FileCompressionInformation,
	FileObjectIdInformation,
	FileCompletionInformation, // 30
	FileMoveClusterInformation,
	FileQuotaInformation,
	FileReparsePointInformation,
	FileNetworkOpenInformation,
	FileAttributeTagInformation,
	FileTrackingInformation,
	FileIdBothDirectoryInformation,
	FileIdFullDirectoryInformation,
	FileValidDataLengthInformation,
	FileShortNameInformation, // 40
	FileIoCompletionNotificationInformation,
	FileIoStatusBlockRangeInformation,
	FileIoPriorityHintInformation,
	FileSfioReserveInformation,
	FileSfioVolumeInformation,
	FileHardLinkInformation,
	FileProcessIdsUsingFileInformation,
	FileNormalizedNameInformation,
	FileNetworkPhysicalNameInformation,
	FileIdGlobalTxDirectoryInformation, // 50
	FileIsRemoteDeviceInformation,
	FileUnusedInformation,
	FileNumaNodeInformation,
	FileStandardLinkInformation,
	FileRemoteProtocolInformation,
	FileRenameInformationBypassAccessCheck, // (kernel-mode only) // since WIN8
	FileLinkInformationBypassAccessCheck, // (kernel-mode only)
	FileIntegrityStreamInformation,
	FileVolumeNameInformation,
	FileIdInformation,
	FileIdExtdDirectoryInformation,
	FileReplaceCompletionInformation, // since WINBLUE
	FileHardLinkFullIdInformation,
	FileIdExtdBothDirectoryInformation, // since THRESHOLD
	FileMaximumInformation
} FILE_INFORMATION_CLASS, *PFILE_INFORMATION_CLASS;

// NtQueryInformationFile/NtSetInformationFile types

typedef struct _FILE_BASIC_INFORMATION
{
	LARGE_INTEGER CreationTime;
	LARGE_INTEGER LastAccessTime;
	LARGE_INTEGER LastWriteTime;
	LARGE_INTEGER ChangeTime;
	ULONG FileAttributes;
} FILE_BASIC_INFORMATION, *PFILE_BASIC_INFORMATION;

typedef struct _FILE_STANDARD_INFORMATION
{
	LARGE_INTEGER AllocationSize;
	LARGE_INTEGER EndOfFile;
	ULONG NumberOfLinks;
	BOOLEAN DeletePending;
	BOOLEAN Directory;
} FILE_STANDARD_INFORMATION, *PFILE_STANDARD_INFORMATION;

typedef struct _FILE_STANDARD_INFORMATION_EX
{
	LARGE_INTEGER AllocationSize;
	LARGE_INTEGER EndOfFile;
	ULONG NumberOfLinks;
	BOOLEAN DeletePending;
	BOOLEAN Directory;
	BOOLEAN AlternateStream;
	BOOLEAN MetadataAttribute;
} FILE_STANDARD_INFORMATION_EX, *PFILE_STANDARD_INFORMATION_EX;

typedef struct _FILE_INTERNAL_INFORMATION
{
	LARGE_INTEGER IndexNumber;
} FILE_INTERNAL_INFORMATION, *PFILE_INTERNAL_INFORMATION;

typedef struct _FILE_EA_INFORMATION
{
	ULONG EaSize;
} FILE_EA_INFORMATION, *PFILE_EA_INFORMATION;

typedef struct _FILE_ACCESS_INFORMATION
{
	ACCESS_MASK AccessFlags;
} FILE_ACCESS_INFORMATION, *PFILE_ACCESS_INFORMATION;

typedef struct _FILE_POSITION_INFORMATION
{
	LARGE_INTEGER CurrentByteOffset;
} FILE_POSITION_INFORMATION, *PFILE_POSITION_INFORMATION;

typedef struct _FILE_MODE_INFORMATION
{
	ULONG Mode;
} FILE_MODE_INFORMATION, *PFILE_MODE_INFORMATION;

typedef struct _FILE_ALIGNMENT_INFORMATION
{
	ULONG AlignmentRequirement;
} FILE_ALIGNMENT_INFORMATION, *PFILE_ALIGNMENT_INFORMATION;

typedef struct _FILE_NAME_INFORMATION
{
	ULONG FileNameLength;
	WCHAR FileName[1];
} FILE_NAME_INFORMATION, *PFILE_NAME_INFORMATION;

typedef struct _FILE_ALL_INFORMATION
{
	FILE_BASIC_INFORMATION BasicInformation;
	FILE_STANDARD_INFORMATION StandardInformation;
	FILE_INTERNAL_INFORMATION InternalInformation;
	FILE_EA_INFORMATION EaInformation;
	FILE_ACCESS_INFORMATION AccessInformation;
	FILE_POSITION_INFORMATION PositionInformation;
	FILE_MODE_INFORMATION ModeInformation;
	FILE_ALIGNMENT_INFORMATION AlignmentInformation;
	FILE_NAME_INFORMATION NameInformation;
} FILE_ALL_INFORMATION, *PFILE_ALL_INFORMATION;

typedef struct _FILE_NETWORK_OPEN_INFORMATION
{
	LARGE_INTEGER CreationTime;
	LARGE_INTEGER LastAccessTime;
	LARGE_INTEGER LastWriteTime;
	LARGE_INTEGER ChangeTime;
	LARGE_INTEGER AllocationSize;
	LARGE_INTEGER EndOfFile;
	ULONG FileAttributes;
} FILE_NETWORK_OPEN_INFORMATION, *PFILE_NETWORK_OPEN_INFORMATION;

typedef struct _FILE_ATTRIBUTE_TAG_INFORMATION
{
	ULONG FileAttributes;
	ULONG ReparseTag;
} FILE_ATTRIBUTE_TAG_INFORMATION, *PFILE_ATTRIBUTE_TAG_INFORMATION;

typedef struct _FILE_ALLOCATION_INFORMATION
{
	LARGE_INTEGER AllocationSize;
} FILE_ALLOCATION_INFORMATION, *PFILE_ALLOCATION_INFORMATION;

typedef struct _FILE_COMPRESSION_INFORMATION
{
	LARGE_INTEGER CompressedFileSize;
	USHORT CompressionFormat;
	UCHAR CompressionUnitShift;
	UCHAR ChunkShift;
	UCHAR ClusterShift;
	UCHAR Reserved[3];
} FILE_COMPRESSION_INFORMATION, *PFILE_COMPRESSION_INFORMATION;

typedef struct _FILE_DISPOSITION_INFORMATION
{
	BOOLEAN DeleteFile;
} FILE_DISPOSITION_INFORMATION, *PFILE_DISPOSITION_INFORMATION;

typedef struct _FILE_END_OF_FILE_INFORMATION
{
	LARGE_INTEGER EndOfFile;
} FILE_END_OF_FILE_INFORMATION, *PFILE_END_OF_FILE_INFORMATION;

typedef struct _FILE_VALID_DATA_LENGTH_INFORMATION
{
	LARGE_INTEGER ValidDataLength;
} FILE_VALID_DATA_LENGTH_INFORMATION, *PFILE_VALID_DATA_LENGTH_INFORMATION;

typedef struct _FILE_LINK_INFORMATION
{
	BOOLEAN ReplaceIfExists;
	HANDLE RootDirectory;
	ULONG FileNameLength;
	WCHAR FileName[1];
} FILE_LINK_INFORMATION, *PFILE_LINK_INFORMATION;

typedef struct _FILE_MOVE_CLUSTER_INFORMATION
{
	ULONG ClusterCount;
	HANDLE RootDirectory;
	ULONG FileNameLength;
	WCHAR FileName[1];
} FILE_MOVE_CLUSTER_INFORMATION, *PFILE_MOVE_CLUSTER_INFORMATION;

typedef struct _FILE_RENAME_INFORMATION
{
	BOOLEAN ReplaceIfExists;
	HANDLE RootDirectory;
	ULONG FileNameLength;
	WCHAR FileName[1];
} FILE_RENAME_INFORMATION, *PFILE_RENAME_INFORMATION;

typedef struct _FILE_STREAM_INFORMATION
{
	ULONG NextEntryOffset;
	ULONG StreamNameLength;
	LARGE_INTEGER StreamSize;
	LARGE_INTEGER StreamAllocationSize;
	WCHAR StreamName[1];
} FILE_STREAM_INFORMATION, *PFILE_STREAM_INFORMATION;

typedef struct _FILE_TRACKING_INFORMATION
{
	HANDLE DestinationFile;
	ULONG ObjectInformationLength;
	CHAR ObjectInformation[1];
} FILE_TRACKING_INFORMATION, *PFILE_TRACKING_INFORMATION;

typedef struct _FILE_COMPLETION_INFORMATION
{
	HANDLE Port;
	PVOID Key;
} FILE_COMPLETION_INFORMATION, *PFILE_COMPLETION_INFORMATION;

typedef struct _FILE_PIPE_INFORMATION
{
	ULONG ReadMode;
	ULONG CompletionMode;
} FILE_PIPE_INFORMATION, *PFILE_PIPE_INFORMATION;

typedef struct _FILE_PIPE_LOCAL_INFORMATION
{
	ULONG NamedPipeType;
	ULONG NamedPipeConfiguration;
	ULONG MaximumInstances;
	ULONG CurrentInstances;
	ULONG InboundQuota;
	ULONG ReadDataAvailable;
	ULONG OutboundQuota;
	ULONG WriteQuotaAvailable;
	ULONG NamedPipeState;
	ULONG NamedPipeEnd;
} FILE_PIPE_LOCAL_INFORMATION, *PFILE_PIPE_LOCAL_INFORMATION;

typedef struct _FILE_PIPE_REMOTE_INFORMATION
{
	LARGE_INTEGER CollectDataTime;
	ULONG MaximumCollectionCount;
} FILE_PIPE_REMOTE_INFORMATION, *PFILE_PIPE_REMOTE_INFORMATION;

typedef struct _FILE_MAILSLOT_QUERY_INFORMATION
{
	ULONG MaximumMessageSize;
	ULONG MailslotQuota;
	ULONG NextMessageSize;
	ULONG MessagesAvailable;
	LARGE_INTEGER ReadTimeout;
} FILE_MAILSLOT_QUERY_INFORMATION, *PFILE_MAILSLOT_QUERY_INFORMATION;

typedef struct _FILE_MAILSLOT_SET_INFORMATION
{
	PLARGE_INTEGER ReadTimeout;
} FILE_MAILSLOT_SET_INFORMATION, *PFILE_MAILSLOT_SET_INFORMATION;

typedef struct _FILE_REPARSE_POINT_INFORMATION
{
	LONGLONG FileReference;
	ULONG Tag;
} FILE_REPARSE_POINT_INFORMATION, *PFILE_REPARSE_POINT_INFORMATION;

typedef struct _FILE_LINK_ENTRY_INFORMATION
{
	ULONG NextEntryOffset;
	LONGLONG ParentFileId;
	ULONG FileNameLength;
	WCHAR FileName[1];
} FILE_LINK_ENTRY_INFORMATION, *PFILE_LINK_ENTRY_INFORMATION;

typedef struct _FILE_LINKS_INFORMATION
{
	ULONG BytesNeeded;
	ULONG EntriesReturned;
	FILE_LINK_ENTRY_INFORMATION Entry;
} FILE_LINKS_INFORMATION, *PFILE_LINKS_INFORMATION;

typedef struct _FILE_NETWORK_PHYSICAL_NAME_INFORMATION
{
	ULONG FileNameLength;
	WCHAR FileName[1];
} FILE_NETWORK_PHYSICAL_NAME_INFORMATION, *PFILE_NETWORK_PHYSICAL_NAME_INFORMATION;

typedef struct _FILE_STANDARD_LINK_INFORMATION
{
	ULONG NumberOfAccessibleLinks;
	ULONG TotalNumberOfLinks;
	BOOLEAN DeletePending;
	BOOLEAN Directory;
} FILE_STANDARD_LINK_INFORMATION, *PFILE_STANDARD_LINK_INFORMATION;

typedef struct _FILE_SFIO_RESERVE_INFORMATION
{
	ULONG RequestsPerPeriod;
	ULONG Period;
	BOOLEAN RetryFailures;
	BOOLEAN Discardable;
	ULONG RequestSize;
	ULONG NumOutstandingRequests;
} FILE_SFIO_RESERVE_INFORMATION, *PFILE_SFIO_RESERVE_INFORMATION;

typedef struct _FILE_SFIO_VOLUME_INFORMATION
{
	ULONG MaximumRequestsPerPeriod;
	ULONG MinimumPeriod;
	ULONG MinimumTransferSize;
} FILE_SFIO_VOLUME_INFORMATION, *PFILE_SFIO_VOLUME_INFORMATION;

typedef enum _IO_PRIORITY_HINT
{
	IoPriorityVeryLow = 0, // Defragging, content indexing and other background I/Os.
	IoPriorityLow, // Prefetching for applications.
	IoPriorityNormal, // Normal I/Os.
	IoPriorityHigh, // Used by filesystems for checkpoint I/O.
	IoPriorityCritical, // Used by memory manager. Not available for applications.
	MaxIoPriorityTypes
} IO_PRIORITY_HINT;

typedef struct _FILE_IO_PRIORITY_HINT_INFORMATION
{
	IO_PRIORITY_HINT PriorityHint;
} FILE_IO_PRIORITY_HINT_INFORMATION, *PFILE_IO_PRIORITY_HINT_INFORMATION;

typedef struct _FILE_IO_PRIORITY_HINT_INFORMATION_EX
{
	IO_PRIORITY_HINT PriorityHint;
	BOOLEAN BoostOutstanding;
} FILE_IO_PRIORITY_HINT_INFORMATION_EX, *PFILE_IO_PRIORITY_HINT_INFORMATION_EX;

#define FILE_SKIP_COMPLETION_PORT_ON_SUCCESS 0x1
#define FILE_SKIP_SET_EVENT_ON_HANDLE 0x2
#define FILE_SKIP_SET_USER_EVENT_ON_FAST_IO 0x4

typedef struct _FILE_IO_COMPLETION_NOTIFICATION_INFORMATION
{
	ULONG Flags;
} FILE_IO_COMPLETION_NOTIFICATION_INFORMATION, *PFILE_IO_COMPLETION_NOTIFICATION_INFORMATION;

typedef struct _FILE_PROCESS_IDS_USING_FILE_INFORMATION
{
	ULONG NumberOfProcessIdsInList;
	ULONG_PTR ProcessIdList[1];
} FILE_PROCESS_IDS_USING_FILE_INFORMATION, *PFILE_PROCESS_IDS_USING_FILE_INFORMATION;

typedef struct _FILE_IS_REMOTE_DEVICE_INFORMATION
{
	BOOLEAN IsRemote;
} FILE_IS_REMOTE_DEVICE_INFORMATION, *PFILE_IS_REMOTE_DEVICE_INFORMATION;

typedef struct _FILE_NUMA_NODE_INFORMATION
{
	USHORT NodeNumber;
} FILE_NUMA_NODE_INFORMATION, *PFILE_NUMA_NODE_INFORMATION;

typedef struct _FILE_IOSTATUSBLOCK_RANGE_INFORMATION
{
	PUCHAR IoStatusBlockRange;
	ULONG Length;
} FILE_IOSTATUSBLOCK_RANGE_INFORMATION, *PFILE_IOSTATUSBLOCK_RANGE_INFORMATION;

typedef struct _FILE_REMOTE_PROTOCOL_INFORMATION
{
	USHORT StructureVersion; // 1
	USHORT StructureSize;

	ULONG Protocol; // WNNC_NET_*

	USHORT ProtocolMajorVersion;
	USHORT ProtocolMinorVersion;
	USHORT ProtocolRevision;

	USHORT Reserved;

	// Generic information

	ULONG Flags;

	struct
	{
		ULONG Reserved[8];
	} GenericReserved;

	// Specific information

#if (PHNT_VERSION < PHNT_WIN8)
	struct
	{
		ULONG Reserved[16];
	} ProtocolSpecificReserved;
#else
	union
	{
		struct
		{
			struct
			{
				ULONG Capabilities;
			} Server;
			struct
			{
				ULONG Capabilities;
				ULONG CachingFlags;
			} Share;
		} Smb2;
		ULONG Reserved[16];
	} ProtocolSpecific;
#endif
} FILE_REMOTE_PROTOCOL_INFORMATION, *PFILE_REMOTE_PROTOCOL_INFORMATION;

#define CHECKSUM_ENFORCEMENT_OFF 0x00000001

typedef struct _FILE_INTEGRITY_STREAM_INFORMATION
{
	USHORT ChecksumAlgorithm;
	UCHAR ChecksumChunkShift;
	UCHAR ClusterShift;
	ULONG Flags;
} FILE_INTEGRITY_STREAM_INFORMATION, *PFILE_INTEGRITY_STREAM_INFORMATION;

// private
typedef struct _FILE_VOLUME_NAME_INFORMATION
{
	ULONG DeviceNameLength;
	WCHAR DeviceName[1];
} FILE_VOLUME_NAME_INFORMATION, *PFILE_VOLUME_NAME_INFORMATION;

// NtQueryDirectoryFile types

typedef struct _FILE_DIRECTORY_INFORMATION
{
	ULONG NextEntryOffset;
	ULONG FileIndex;
	LARGE_INTEGER CreationTime;
	LARGE_INTEGER LastAccessTime;
	LARGE_INTEGER LastWriteTime;
	LARGE_INTEGER ChangeTime;
	LARGE_INTEGER EndOfFile;
	LARGE_INTEGER AllocationSize;
	ULONG FileAttributes;
	ULONG FileNameLength;
	WCHAR FileName[1];
} FILE_DIRECTORY_INFORMATION, *PFILE_DIRECTORY_INFORMATION;

typedef struct _FILE_FULL_DIR_INFORMATION
{
	ULONG NextEntryOffset;
	ULONG FileIndex;
	LARGE_INTEGER CreationTime;
	LARGE_INTEGER LastAccessTime;
	LARGE_INTEGER LastWriteTime;
	LARGE_INTEGER ChangeTime;
	LARGE_INTEGER EndOfFile;
	LARGE_INTEGER AllocationSize;
	ULONG FileAttributes;
	ULONG FileNameLength;
	ULONG EaSize;
	WCHAR FileName[1];
} FILE_FULL_DIR_INFORMATION, *PFILE_FULL_DIR_INFORMATION;

typedef struct _FILE_ID_FULL_DIR_INFORMATION
{
	ULONG NextEntryOffset;
	ULONG FileIndex;
	LARGE_INTEGER CreationTime;
	LARGE_INTEGER LastAccessTime;
	LARGE_INTEGER LastWriteTime;
	LARGE_INTEGER ChangeTime;
	LARGE_INTEGER EndOfFile;
	LARGE_INTEGER AllocationSize;
	ULONG FileAttributes;
	ULONG FileNameLength;
	ULONG EaSize;
	LARGE_INTEGER FileId;
	WCHAR FileName[1];
} FILE_ID_FULL_DIR_INFORMATION, *PFILE_ID_FULL_DIR_INFORMATION;

typedef struct _FILE_BOTH_DIR_INFORMATION
{
	ULONG NextEntryOffset;
	ULONG FileIndex;
	LARGE_INTEGER CreationTime;
	LARGE_INTEGER LastAccessTime;
	LARGE_INTEGER LastWriteTime;
	LARGE_INTEGER ChangeTime;
	LARGE_INTEGER EndOfFile;
	LARGE_INTEGER AllocationSize;
	ULONG FileAttributes;
	ULONG FileNameLength;
	ULONG EaSize;
	CCHAR ShortNameLength;
	WCHAR ShortName[12];
	WCHAR FileName[1];
} FILE_BOTH_DIR_INFORMATION, *PFILE_BOTH_DIR_INFORMATION;

typedef struct _FILE_ID_BOTH_DIR_INFORMATION
{
	ULONG NextEntryOffset;
	ULONG FileIndex;
	LARGE_INTEGER CreationTime;
	LARGE_INTEGER LastAccessTime;
	LARGE_INTEGER LastWriteTime;
	LARGE_INTEGER ChangeTime;
	LARGE_INTEGER EndOfFile;
	LARGE_INTEGER AllocationSize;
	ULONG FileAttributes;
	ULONG FileNameLength;
	ULONG EaSize;
	CCHAR ShortNameLength;
	WCHAR ShortName[12];
	LARGE_INTEGER FileId;
	WCHAR FileName[1];
} FILE_ID_BOTH_DIR_INFORMATION, *PFILE_ID_BOTH_DIR_INFORMATION;

typedef struct _FILE_NAMES_INFORMATION
{
	ULONG NextEntryOffset;
	ULONG FileIndex;
	ULONG FileNameLength;
	WCHAR FileName[1];
} FILE_NAMES_INFORMATION, *PFILE_NAMES_INFORMATION;

typedef struct _FILE_ID_GLOBAL_TX_DIR_INFORMATION
{
	ULONG NextEntryOffset;
	ULONG FileIndex;
	LARGE_INTEGER CreationTime;
	LARGE_INTEGER LastAccessTime;
	LARGE_INTEGER LastWriteTime;
	LARGE_INTEGER ChangeTime;
	LARGE_INTEGER EndOfFile;
	LARGE_INTEGER AllocationSize;
	ULONG FileAttributes;
	ULONG FileNameLength;
	LARGE_INTEGER FileId;
	GUID LockingTransactionId;
	ULONG TxInfoFlags;
	WCHAR FileName[1];
} FILE_ID_GLOBAL_TX_DIR_INFORMATION, *PFILE_ID_GLOBAL_TX_DIR_INFORMATION;

#define FILE_ID_GLOBAL_TX_DIR_INFO_FLAG_WRITELOCKED 0x00000001
#define FILE_ID_GLOBAL_TX_DIR_INFO_FLAG_VISIBLE_TO_TX 0x00000002
#define FILE_ID_GLOBAL_TX_DIR_INFO_FLAG_VISIBLE_OUTSIDE_TX 0x00000004

typedef struct _FILE_OBJECTID_INFORMATION
{
	LONGLONG FileReference;
	UCHAR ObjectId[16];
	union
	{
		struct
		{
			UCHAR BirthVolumeId[16];
			UCHAR BirthObjectId[16];
			UCHAR DomainId[16];
		};
		UCHAR ExtendedInfo[48];
	};
} FILE_OBJECTID_INFORMATION, *PFILE_OBJECTID_INFORMATION;

// NtQueryEaFile/NtSetEaFile types

typedef struct _FILE_FULL_EA_INFORMATION
{
	ULONG NextEntryOffset;
	UCHAR Flags;
	UCHAR EaNameLength;
	USHORT EaValueLength;
	CHAR EaName[1];
} FILE_FULL_EA_INFORMATION, *PFILE_FULL_EA_INFORMATION;

typedef struct _FILE_GET_EA_INFORMATION
{
	ULONG NextEntryOffset;
	UCHAR EaNameLength;
	CHAR EaName[1];
} FILE_GET_EA_INFORMATION, *PFILE_GET_EA_INFORMATION;

// NtQueryQuotaInformationFile/NtSetQuotaInformationFile types

typedef struct _FILE_GET_QUOTA_INFORMATION
{
	ULONG NextEntryOffset;
	ULONG SidLength;
	SID Sid;
} FILE_GET_QUOTA_INFORMATION, *PFILE_GET_QUOTA_INFORMATION;

typedef struct _FILE_QUOTA_INFORMATION
{
	ULONG NextEntryOffset;
	ULONG SidLength;
	LARGE_INTEGER ChangeTime;
	LARGE_INTEGER QuotaUsed;
	LARGE_INTEGER QuotaThreshold;
	LARGE_INTEGER QuotaLimit;
	SID Sid;
} FILE_QUOTA_INFORMATION, *PFILE_QUOTA_INFORMATION;

typedef enum _FSINFOCLASS
{
	FileFsVolumeInformation = 1,
	FileFsLabelInformation,
	FileFsSizeInformation,
	FileFsDeviceInformation,
	FileFsAttributeInformation,
	FileFsControlInformation,
	FileFsFullSizeInformation,
	FileFsObjectIdInformation,
	FileFsDriverPathInformation,
	FileFsVolumeFlagsInformation,
	FileFsSectorSizeInformation, // since WIN8
	FileFsDataCopyInformation,
	FileFsMetadataSizeInformation, // since THRESHOLD
	FileFsMaximumInformation
} FSINFOCLASS, *PFSINFOCLASS;

// NtQueryVolumeInformation/NtSetVolumeInformation types

typedef struct _FILE_FS_LABEL_INFORMATION
{
	ULONG VolumeLabelLength;
	WCHAR VolumeLabel[1];
} FILE_FS_LABEL_INFORMATION, *PFILE_FS_LABEL_INFORMATION;

typedef struct _FILE_FS_VOLUME_INFORMATION
{
	LARGE_INTEGER VolumeCreationTime;
	ULONG VolumeSerialNumber;
	ULONG VolumeLabelLength;
	BOOLEAN SupportsObjects;
	WCHAR VolumeLabel[1];
} FILE_FS_VOLUME_INFORMATION, *PFILE_FS_VOLUME_INFORMATION;

typedef struct _FILE_FS_SIZE_INFORMATION
{
	LARGE_INTEGER TotalAllocationUnits;
	LARGE_INTEGER AvailableAllocationUnits;
	ULONG SectorsPerAllocationUnit;
	ULONG BytesPerSector;
} FILE_FS_SIZE_INFORMATION, *PFILE_FS_SIZE_INFORMATION;

typedef struct _FILE_FS_FULL_SIZE_INFORMATION
{
	LARGE_INTEGER TotalAllocationUnits;
	LARGE_INTEGER CallerAvailableAllocationUnits;
	LARGE_INTEGER ActualAvailableAllocationUnits;
	ULONG SectorsPerAllocationUnit;
	ULONG BytesPerSector;
} FILE_FS_FULL_SIZE_INFORMATION, *PFILE_FS_FULL_SIZE_INFORMATION;

typedef struct _FILE_FS_OBJECTID_INFORMATION
{
	UCHAR ObjectId[16];
	UCHAR ExtendedInfo[48];
} FILE_FS_OBJECTID_INFORMATION, *PFILE_FS_OBJECTID_INFORMATION;

typedef struct _FILE_FS_DEVICE_INFORMATION
{
	DEVICE_TYPE DeviceType;
	ULONG Characteristics;
} FILE_FS_DEVICE_INFORMATION, *PFILE_FS_DEVICE_INFORMATION;

typedef struct _FILE_FS_ATTRIBUTE_INFORMATION
{
	ULONG FileSystemAttributes;
	LONG MaximumComponentNameLength;
	ULONG FileSystemNameLength;
	WCHAR FileSystemName[1];
} FILE_FS_ATTRIBUTE_INFORMATION, *PFILE_FS_ATTRIBUTE_INFORMATION;

typedef struct _FILE_FS_DRIVER_PATH_INFORMATION
{
	BOOLEAN DriverInPath;
	ULONG DriverNameLength;
	WCHAR DriverName[1];
} FILE_FS_DRIVER_PATH_INFORMATION, *PFILE_FS_DRIVER_PATH_INFORMATION;

typedef struct _FILE_FS_VOLUME_FLAGS_INFORMATION
{
	ULONG Flags;
} FILE_FS_VOLUME_FLAGS_INFORMATION, *PFILE_FS_VOLUME_FLAGS_INFORMATION;

#define SSINFO_FLAGS_ALIGNED_DEVICE 0x00000001
#define SSINFO_FLAGS_PARTITION_ALIGNED_ON_DEVICE 0x00000002

// If set for Sector and Partition fields, alignment is not known.
#define SSINFO_OFFSET_UNKNOWN 0xffffffff

typedef struct _FILE_FS_SECTOR_SIZE_INFORMATION
{
	ULONG LogicalBytesPerSector;
	ULONG PhysicalBytesPerSectorForAtomicity;
	ULONG PhysicalBytesPerSectorForPerformance;
	ULONG FileSystemEffectivePhysicalBytesPerSectorForAtomicity;
	ULONG Flags;
	ULONG ByteOffsetForSectorAlignment;
	ULONG ByteOffsetForPartitionAlignment;
} FILE_FS_SECTOR_SIZE_INFORMATION, *PFILE_FS_SECTOR_SIZE_INFORMATION;

typedef struct _FILE_FS_METADATA_SIZE_INFORMATION
{
	LARGE_INTEGER TotalMetadataAllocationUnits;
	ULONG SectorsPerAllocationUnit;
	ULONG BytesPerSector;
} FILE_FS_METADATA_SIZE_INFORMATION, *PFILE_FS_METADATA_SIZE_INFORMATION;

#define FLUSH_FLAGS_FILE_DATA_ONLY 0x00000001
#define FLUSH_FLAGS_NO_SYNC 0x00000002

#pragma endregion

// 时间
#pragma region Time

typedef struct _TIME_FIELDS
{
	short Year; // 1601...
	short Month; // 1..12
	short Day; // 1..31
	short Hour; // 0..23
	short Minute; // 0..59
	short Second; // 0..59
	short Milliseconds; // 0..999
	short Weekday; // 0..6 = Sunday..Saturday
} TIME_FIELDS, *PTIME_FIELDS;

#pragma endregion

// 时区
#pragma region TimeZone

typedef struct _RTL_TIME_ZONE_INFORMATION
{
	LONG Bias;
	WCHAR StandardName[32];
	TIME_FIELDS StandardStart;
	LONG StandardBias;
	WCHAR DaylightName[32];
	TIME_FIELDS DaylightStart;
	LONG DaylightBias;
} RTL_TIME_ZONE_INFORMATION, *PRTL_TIME_ZONE_INFORMATION;

#pragma endregion

// 令牌
#pragma region Token

// Privileges

#define SE_MIN_WELL_KNOWN_PRIVILEGE (2L)
#define SE_CREATE_TOKEN_PRIVILEGE (2L)
#define SE_ASSIGNPRIMARYTOKEN_PRIVILEGE (3L)
#define SE_LOCK_MEMORY_PRIVILEGE (4L)
#define SE_INCREASE_QUOTA_PRIVILEGE (5L)

#define SE_MACHINE_ACCOUNT_PRIVILEGE (6L)
#define SE_TCB_PRIVILEGE (7L)
#define SE_SECURITY_PRIVILEGE (8L)
#define SE_TAKE_OWNERSHIP_PRIVILEGE (9L)
#define SE_LOAD_DRIVER_PRIVILEGE (10L)
#define SE_SYSTEM_PROFILE_PRIVILEGE (11L)
#define SE_SYSTEMTIME_PRIVILEGE (12L)
#define SE_PROF_SINGLE_PROCESS_PRIVILEGE (13L)
#define SE_INC_BASE_PRIORITY_PRIVILEGE (14L)
#define SE_CREATE_PAGEFILE_PRIVILEGE (15L)
#define SE_CREATE_PERMANENT_PRIVILEGE (16L)
#define SE_BACKUP_PRIVILEGE (17L)
#define SE_RESTORE_PRIVILEGE (18L)
#define SE_SHUTDOWN_PRIVILEGE (19L)
#define SE_DEBUG_PRIVILEGE (20L)
#define SE_AUDIT_PRIVILEGE (21L)
#define SE_SYSTEM_ENVIRONMENT_PRIVILEGE (22L)
#define SE_CHANGE_NOTIFY_PRIVILEGE (23L)
#define SE_REMOTE_SHUTDOWN_PRIVILEGE (24L)
#define SE_UNDOCK_PRIVILEGE (25L)
#define SE_SYNC_AGENT_PRIVILEGE (26L)
#define SE_ENABLE_DELEGATION_PRIVILEGE (27L)
#define SE_MANAGE_VOLUME_PRIVILEGE (28L)
#define SE_IMPERSONATE_PRIVILEGE (29L)
#define SE_CREATE_GLOBAL_PRIVILEGE (30L)
#define SE_TRUSTED_CREDMAN_ACCESS_PRIVILEGE (31L)
#define SE_RELABEL_PRIVILEGE (32L)
#define SE_INC_WORKING_SET_PRIVILEGE (33L)
#define SE_TIME_ZONE_PRIVILEGE (34L)
#define SE_CREATE_SYMBOLIC_LINK_PRIVILEGE (35L)
#define SE_MAX_WELL_KNOWN_PRIVILEGE SE_CREATE_SYMBOLIC_LINK_PRIVILEGE

// Authz

// begin_rev

// Types

#define TOKEN_SECURITY_ATTRIBUTE_TYPE_INVALID 0x00
#define TOKEN_SECURITY_ATTRIBUTE_TYPE_INT64 0x01
#define TOKEN_SECURITY_ATTRIBUTE_TYPE_UINT64 0x02
#define TOKEN_SECURITY_ATTRIBUTE_TYPE_STRING 0x03
#define TOKEN_SECURITY_ATTRIBUTE_TYPE_FQBN 0x04
#define TOKEN_SECURITY_ATTRIBUTE_TYPE_SID 0x05
#define TOKEN_SECURITY_ATTRIBUTE_TYPE_BOOLEAN 0x06
#define TOKEN_SECURITY_ATTRIBUTE_TYPE_OCTET_STRING 0x10

// Flags

#define TOKEN_SECURITY_ATTRIBUTE_NON_INHERITABLE 0x0001
#define TOKEN_SECURITY_ATTRIBUTE_VALUE_CASE_SENSITIVE 0x0002
#define TOKEN_SECURITY_ATTRIBUTE_USE_FOR_DENY_ONLY 0x0004
#define TOKEN_SECURITY_ATTRIBUTE_DISABLED_BY_DEFAULT 0x0008
#define TOKEN_SECURITY_ATTRIBUTE_DISABLED 0x0010
#define TOKEN_SECURITY_ATTRIBUTE_MANDATORY 0x0020

#define TOKEN_SECURITY_ATTRIBUTE_VALID_FLAGS ( \
    TOKEN_SECURITY_ATTRIBUTE_NON_INHERITABLE | \
    TOKEN_SECURITY_ATTRIBUTE_VALUE_CASE_SENSITIVE | \
    TOKEN_SECURITY_ATTRIBUTE_USE_FOR_DENY_ONLY | \
    TOKEN_SECURITY_ATTRIBUTE_DISABLED_BY_DEFAULT | \
    TOKEN_SECURITY_ATTRIBUTE_DISABLED | \
    TOKEN_SECURITY_ATTRIBUTE_MANDATORY)

#define TOKEN_SECURITY_ATTRIBUTE_CUSTOM_FLAGS 0xffff0000

// end_rev

// private
typedef struct _TOKEN_SECURITY_ATTRIBUTE_FQBN_VALUE
{
	ULONG64 Version;
	UNICODE_STRING Name;
} TOKEN_SECURITY_ATTRIBUTE_FQBN_VALUE, *PTOKEN_SECURITY_ATTRIBUTE_FQBN_VALUE;

// private
typedef struct _TOKEN_SECURITY_ATTRIBUTE_OCTET_STRING_VALUE
{
	PVOID pValue;
	ULONG ValueLength;
} TOKEN_SECURITY_ATTRIBUTE_OCTET_STRING_VALUE, *PTOKEN_SECURITY_ATTRIBUTE_OCTET_STRING_VALUE;

// private
typedef struct _TOKEN_SECURITY_ATTRIBUTE_V1
{
	UNICODE_STRING Name;
	USHORT ValueType;
	USHORT Reserved;
	ULONG Flags;
	ULONG ValueCount;
	union
	{
		PLONG64 pInt64;
		PULONG64 pUint64;
		PUNICODE_STRING pString;
		PTOKEN_SECURITY_ATTRIBUTE_FQBN_VALUE pFqbn;
		PTOKEN_SECURITY_ATTRIBUTE_OCTET_STRING_VALUE pOctetString;
	} Values;
} TOKEN_SECURITY_ATTRIBUTE_V1, *PTOKEN_SECURITY_ATTRIBUTE_V1;

// rev
#define TOKEN_SECURITY_ATTRIBUTES_INFORMATION_VERSION_V1 1
// rev
#define TOKEN_SECURITY_ATTRIBUTES_INFORMATION_VERSION TOKEN_SECURITY_ATTRIBUTES_INFORMATION_VERSION_V1

// private
typedef struct _TOKEN_SECURITY_ATTRIBUTES_INFORMATION
{
	USHORT Version;
	USHORT Reserved;
	ULONG AttributeCount;
	union
	{
		PTOKEN_SECURITY_ATTRIBUTE_V1 pAttributeV1;
	} Attribute;
} TOKEN_SECURITY_ATTRIBUTES_INFORMATION, *PTOKEN_SECURITY_ATTRIBUTES_INFORMATION;

#pragma endregion

// 进程
#pragma region Process

// source:http://www.microsoft.com/whdc/system/Sysinternals/MoreThan64proc.mspx

typedef enum _PROCESSINFOCLASS
{
	ProcessBasicInformation, // q: PROCESS_BASIC_INFORMATION, PROCESS_EXTENDED_BASIC_INFORMATION
	ProcessQuotaLimits, // qs: QUOTA_LIMITS, QUOTA_LIMITS_EX
	ProcessIoCounters, // q: IO_COUNTERS
	ProcessVmCounters, // q: VM_COUNTERS, VM_COUNTERS_EX, VM_COUNTERS_EX2
	ProcessTimes, // q: KERNEL_USER_TIMES
	ProcessBasePriority, // s: KPRIORITY
	ProcessRaisePriority, // s: ULONG
	ProcessDebugPort, // q: HANDLE
	ProcessExceptionPort, // s: HANDLE
	ProcessAccessToken, // s: PROCESS_ACCESS_TOKEN
	ProcessLdtInformation, // qs: PROCESS_LDT_INFORMATION // 10
	ProcessLdtSize, // s: PROCESS_LDT_SIZE
	ProcessDefaultHardErrorMode, // qs: ULONG
	ProcessIoPortHandlers, // (kernel-mode only)
	ProcessPooledUsageAndLimits, // q: POOLED_USAGE_AND_LIMITS
	ProcessWorkingSetWatch, // q: PROCESS_WS_WATCH_INFORMATION[]; s: void
	ProcessUserModeIOPL,
	ProcessEnableAlignmentFaultFixup, // s: BOOLEAN
	ProcessPriorityClass, // qs: PROCESS_PRIORITY_CLASS
	ProcessWx86Information,
	ProcessHandleCount, // q: ULONG, PROCESS_HANDLE_INFORMATION // 20
	ProcessAffinityMask, // s: KAFFINITY
	ProcessPriorityBoost, // qs: ULONG
	ProcessDeviceMap, // qs: PROCESS_DEVICEMAP_INFORMATION, PROCESS_DEVICEMAP_INFORMATION_EX
	ProcessSessionInformation, // q: PROCESS_SESSION_INFORMATION
	ProcessForegroundInformation, // s: PROCESS_FOREGROUND_BACKGROUND
	ProcessWow64Information, // q: ULONG_PTR
	ProcessImageFileName, // q: UNICODE_STRING
	ProcessLUIDDeviceMapsEnabled, // q: ULONG
	ProcessBreakOnTermination, // qs: ULONG
	ProcessDebugObjectHandle, // q: HANDLE // 30
	ProcessDebugFlags, // qs: ULONG
	ProcessHandleTracing, // q: PROCESS_HANDLE_TRACING_QUERY; s: size 0 disables, otherwise enables
	ProcessIoPriority, // qs: IO_PRIORITY_HINT
	ProcessExecuteFlags, // qs: ULONG
	ProcessResourceManagement,
	ProcessCookie, // q: ULONG
	ProcessImageInformation, // q: SECTION_IMAGE_INFORMATION
	ProcessCycleTime, // q: PROCESS_CYCLE_TIME_INFORMATION // since VISTA
	ProcessPagePriority, // q: ULONG
	ProcessInstrumentationCallback, // 40
	ProcessThreadStackAllocation, // s: PROCESS_STACK_ALLOCATION_INFORMATION, PROCESS_STACK_ALLOCATION_INFORMATION_EX
	ProcessWorkingSetWatchEx, // q: PROCESS_WS_WATCH_INFORMATION_EX[]
	ProcessImageFileNameWin32, // q: UNICODE_STRING
	ProcessImageFileMapping, // q: HANDLE (input)
	ProcessAffinityUpdateMode, // qs: PROCESS_AFFINITY_UPDATE_MODE
	ProcessMemoryAllocationMode, // qs: PROCESS_MEMORY_ALLOCATION_MODE
	ProcessGroupInformation, // q: USHORT[]
	ProcessTokenVirtualizationEnabled, // s: ULONG
	ProcessConsoleHostProcess, // q: ULONG_PTR
	ProcessWindowInformation, // q: PROCESS_WINDOW_INFORMATION // 50
	ProcessHandleInformation, // q: PROCESS_HANDLE_SNAPSHOT_INFORMATION // since WIN8
	ProcessMitigationPolicy, // s: PROCESS_MITIGATION_POLICY_INFORMATION
	ProcessDynamicFunctionTableInformation,
	ProcessHandleCheckingMode,
	ProcessKeepAliveCount, // q: PROCESS_KEEPALIVE_COUNT_INFORMATION
	ProcessRevokeFileHandles, // s: PROCESS_REVOKE_FILE_HANDLES_INFORMATION
	ProcessWorkingSetControl, // s: PROCESS_WORKING_SET_CONTROL
	ProcessHandleTable, // since WINBLUE
	ProcessCheckStackExtentsMode,
	ProcessCommandLineInformation, // q: UNICODE_STRING // 60
	ProcessProtectionInformation, // q: PS_PROTECTION
	ProcessMemoryExhaustion, // PROCESS_MEMORY_EXHAUSTION_INFO // since THRESHOLD
	ProcessFaultInformation, // PROCESS_FAULT_INFORMATION
	ProcessTelemetryIdInformation, // PROCESS_TELEMETRY_ID_INFORMATION
	ProcessCommitReleaseInformation, // PROCESS_COMMIT_RELEASE_INFORMATION
	ProcessDefaultCpuSetsInformation,
	ProcessAllowedCpuSetsInformation,
	ProcessReserved1Information,
	ProcessReserved2Information,
	ProcessSubsystemProcess, // 70
	ProcessJobMemoryInformation, // PROCESS_JOB_MEMORY_INFO
	ProcessInPrivate, // since THRESHOLD2
	ProcessRaiseUMExceptionOnInvalidHandleClose,
	MaxProcessInfoClass
} PROCESSINFOCLASS;

typedef enum _THREADINFOCLASS
{
	ThreadBasicInformation, // q: THREAD_BASIC_INFORMATION
	ThreadTimes, // q: KERNEL_USER_TIMES
	ThreadPriority, // s: KPRIORITY
	ThreadBasePriority, // s: LONG
	ThreadAffinityMask, // s: KAFFINITY
	ThreadImpersonationToken, // s: HANDLE
	ThreadDescriptorTableEntry, // q: DESCRIPTOR_TABLE_ENTRY (or WOW64_DESCRIPTOR_TABLE_ENTRY)
	ThreadEnableAlignmentFaultFixup, // s: BOOLEAN
	ThreadEventPair,
	ThreadQuerySetWin32StartAddress, // q: PVOID
	ThreadZeroTlsCell, // 10
	ThreadPerformanceCount, // q: LARGE_INTEGER
	ThreadAmILastThread, // q: ULONG
	ThreadIdealProcessor, // s: ULONG
	ThreadPriorityBoost, // qs: ULONG
	ThreadSetTlsArrayAddress,
	ThreadIsIoPending, // q: ULONG
	ThreadHideFromDebugger, // s: void
	ThreadBreakOnTermination, // qs: ULONG
	ThreadSwitchLegacyState,
	ThreadIsTerminated, // q: ULONG // 20
	ThreadLastSystemCall, // q: THREAD_LAST_SYSCALL_INFORMATION
	ThreadIoPriority, // qs: IO_PRIORITY_HINT
	ThreadCycleTime, // q: THREAD_CYCLE_TIME_INFORMATION
	ThreadPagePriority, // q: ULONG
	ThreadActualBasePriority,
	ThreadTebInformation, // q: THREAD_TEB_INFORMATION (requires THREAD_GET_CONTEXT + THREAD_SET_CONTEXT)
	ThreadCSwitchMon,
	ThreadCSwitchPmu,
	ThreadWow64Context, // q: WOW64_CONTEXT
	ThreadGroupInformation, // q: GROUP_AFFINITY // 30
	ThreadUmsInformation,
	ThreadCounterProfiling,
	ThreadIdealProcessorEx, // q: PROCESSOR_NUMBER
	ThreadCpuAccountingInformation, // since WIN8
	ThreadSuspendCount, // since WINBLUE
	ThreadHeterogeneousCpuPolicy, // q: KHETERO_CPU_POLICY // since THRESHOLD
	ThreadContainerId, // q: GUID
	ThreadNameInformation,
	ThreadSelectedCpuSets,
	ThreadSystemThreadInformation, // q: SYSTEM_THREAD_INFORMATION // 40
	ThreadActualGroupAffinity, // since THRESHOLD2
	MaxThreadInfoClass
} THREADINFOCLASS;

// Use with both ProcessPagePriority and ThreadPagePriority
typedef struct _PAGE_PRIORITY_INFORMATION
{
	ULONG PagePriority;
} PAGE_PRIORITY_INFORMATION, *PPAGE_PRIORITY_INFORMATION;

// Process information structures

typedef struct _PROCESS_BASIC_INFORMATION
{
	NTSTATUS ExitStatus;
	PPEB PebBaseAddress;
	ULONG_PTR AffinityMask;
	KPRIORITY BasePriority;
	HANDLE UniqueProcessId;
	HANDLE InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION, *PPROCESS_BASIC_INFORMATION;

typedef struct _PROCESS_EXTENDED_BASIC_INFORMATION
{
	SIZE_T Size; // set to sizeof structure on input
	PROCESS_BASIC_INFORMATION BasicInfo;
	union
	{
		ULONG Flags;
		struct
		{
			ULONG IsProtectedProcess : 1;
			ULONG IsWow64Process : 1;
			ULONG IsProcessDeleting : 1;
			ULONG IsCrossSessionCreate : 1;
			ULONG IsFrozen : 1;
			ULONG IsBackground : 1;
			ULONG IsStronglyNamed : 1;
			ULONG IsSecureProcess : 1;
			ULONG SpareBits : 24;
		};
	};
} PROCESS_EXTENDED_BASIC_INFORMATION, *PPROCESS_EXTENDED_BASIC_INFORMATION;

typedef struct _VM_COUNTERS
{
	SIZE_T PeakVirtualSize;
	SIZE_T VirtualSize;
	ULONG PageFaultCount;
	SIZE_T PeakWorkingSetSize;
	SIZE_T WorkingSetSize;
	SIZE_T QuotaPeakPagedPoolUsage;
	SIZE_T QuotaPagedPoolUsage;
	SIZE_T QuotaPeakNonPagedPoolUsage;
	SIZE_T QuotaNonPagedPoolUsage;
	SIZE_T PagefileUsage;
	SIZE_T PeakPagefileUsage;
} VM_COUNTERS, *PVM_COUNTERS;

typedef struct _VM_COUNTERS_EX
{
	SIZE_T PeakVirtualSize;
	SIZE_T VirtualSize;
	ULONG PageFaultCount;
	SIZE_T PeakWorkingSetSize;
	SIZE_T WorkingSetSize;
	SIZE_T QuotaPeakPagedPoolUsage;
	SIZE_T QuotaPagedPoolUsage;
	SIZE_T QuotaPeakNonPagedPoolUsage;
	SIZE_T QuotaNonPagedPoolUsage;
	SIZE_T PagefileUsage;
	SIZE_T PeakPagefileUsage;
	SIZE_T PrivateUsage;
} VM_COUNTERS_EX, *PVM_COUNTERS_EX;

// private
typedef struct _VM_COUNTERS_EX2
{
	VM_COUNTERS_EX CountersEx;
	SIZE_T PrivateWorkingSetSize;
	SIZE_T SharedCommitUsage;
} VM_COUNTERS_EX2, *PVM_COUNTERS_EX2;

typedef struct _KERNEL_USER_TIMES
{
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER ExitTime;
	LARGE_INTEGER KernelTime;
	LARGE_INTEGER UserTime;
} KERNEL_USER_TIMES, *PKERNEL_USER_TIMES;

typedef struct _POOLED_USAGE_AND_LIMITS
{
	SIZE_T PeakPagedPoolUsage;
	SIZE_T PagedPoolUsage;
	SIZE_T PagedPoolLimit;
	SIZE_T PeakNonPagedPoolUsage;
	SIZE_T NonPagedPoolUsage;
	SIZE_T NonPagedPoolLimit;
	SIZE_T PeakPagefileUsage;
	SIZE_T PagefileUsage;
	SIZE_T PagefileLimit;
} POOLED_USAGE_AND_LIMITS, *PPOOLED_USAGE_AND_LIMITS;

typedef struct _PROCESS_ACCESS_TOKEN
{
	HANDLE Token; // needs TOKEN_ASSIGN_PRIMARY access
	HANDLE Thread; // handle to initial/only thread; needs THREAD_QUERY_INFORMATION access
} PROCESS_ACCESS_TOKEN, *PPROCESS_ACCESS_TOKEN;

typedef struct _PROCESS_LDT_INFORMATION
{
	ULONG Start;
	ULONG Length;
	LDT_ENTRY LdtEntries[1];
} PROCESS_LDT_INFORMATION, *PPROCESS_LDT_INFORMATION;

typedef struct _PROCESS_LDT_SIZE
{
	ULONG Length;
} PROCESS_LDT_SIZE, *PPROCESS_LDT_SIZE;

typedef struct _PROCESS_WS_WATCH_INFORMATION
{
	PVOID FaultingPc;
	PVOID FaultingVa;
} PROCESS_WS_WATCH_INFORMATION, *PPROCESS_WS_WATCH_INFORMATION;

// psapi:PSAPI_WS_WATCH_INFORMATION_EX
typedef struct _PROCESS_WS_WATCH_INFORMATION_EX
{
	PROCESS_WS_WATCH_INFORMATION BasicInfo;
	ULONG_PTR FaultingThreadId;
	ULONG_PTR Flags;
} PROCESS_WS_WATCH_INFORMATION_EX, *PPROCESS_WS_WATCH_INFORMATION_EX;

#define PROCESS_PRIORITY_CLASS_UNKNOWN 0
#define PROCESS_PRIORITY_CLASS_IDLE 1
#define PROCESS_PRIORITY_CLASS_NORMAL 2
#define PROCESS_PRIORITY_CLASS_HIGH 3
#define PROCESS_PRIORITY_CLASS_REALTIME 4
#define PROCESS_PRIORITY_CLASS_BELOW_NORMAL 5
#define PROCESS_PRIORITY_CLASS_ABOVE_NORMAL 6

typedef struct _PROCESS_PRIORITY_CLASS
{
	BOOLEAN Foreground;
	UCHAR PriorityClass;
} PROCESS_PRIORITY_CLASS, *PPROCESS_PRIORITY_CLASS;

typedef struct _PROCESS_FOREGROUND_BACKGROUND
{
	BOOLEAN Foreground;
} PROCESS_FOREGROUND_BACKGROUND, *PPROCESS_FOREGROUND_BACKGROUND;

typedef struct _PROCESS_DEVICEMAP_INFORMATION
{
	union
	{
		struct
		{
			HANDLE DirectoryHandle;
		} Set;
		struct
		{
			ULONG DriveMap;
			UCHAR DriveType[32];
		} Query;
	};
} PROCESS_DEVICEMAP_INFORMATION, *PPROCESS_DEVICEMAP_INFORMATION;

#define PROCESS_LUID_DOSDEVICES_ONLY 0x00000001

typedef struct _PROCESS_DEVICEMAP_INFORMATION_EX
{
	union
	{
		struct
		{
			HANDLE DirectoryHandle;
		} Set;
		struct
		{
			ULONG DriveMap;
			UCHAR DriveType[32];
		} Query;
	};
	ULONG Flags; // PROCESS_LUID_DOSDEVICES_ONLY
} PROCESS_DEVICEMAP_INFORMATION_EX, *PPROCESS_DEVICEMAP_INFORMATION_EX;

typedef struct _PROCESS_SESSION_INFORMATION
{
	ULONG SessionId;
} PROCESS_SESSION_INFORMATION, *PPROCESS_SESSION_INFORMATION;

typedef struct _PROCESS_HANDLE_TRACING_ENABLE
{
	ULONG Flags; // 0 to disable, 1 to enable
} PROCESS_HANDLE_TRACING_ENABLE, *PPROCESS_HANDLE_TRACING_ENABLE;

typedef struct _PROCESS_HANDLE_TRACING_ENABLE_EX
{
	ULONG Flags; // 0 to disable, 1 to enable
	ULONG TotalSlots;
} PROCESS_HANDLE_TRACING_ENABLE_EX, *PPROCESS_HANDLE_TRACING_ENABLE_EX;

#define PROCESS_HANDLE_TRACING_MAX_STACKS 16
#define HANDLE_TRACE_DB_OPEN 1
#define HANDLE_TRACE_DB_CLOSE 2
#define HANDLE_TRACE_DB_BADREF 3

typedef struct _PROCESS_HANDLE_TRACING_ENTRY
{
	HANDLE Handle;
	CLIENT_ID ClientId;
	ULONG Type;
	PVOID Stacks[PROCESS_HANDLE_TRACING_MAX_STACKS];
} PROCESS_HANDLE_TRACING_ENTRY, *PPROCESS_HANDLE_TRACING_ENTRY;

typedef struct _PROCESS_HANDLE_TRACING_QUERY
{
	HANDLE Handle;
	ULONG TotalTraces;
	PROCESS_HANDLE_TRACING_ENTRY HandleTrace[1];
} PROCESS_HANDLE_TRACING_QUERY, *PPROCESS_HANDLE_TRACING_QUERY;

// private
typedef struct _PROCESS_STACK_ALLOCATION_INFORMATION
{
	SIZE_T ReserveSize;
	SIZE_T ZeroBits;
	PVOID StackBase;
} PROCESS_STACK_ALLOCATION_INFORMATION, *PPROCESS_STACK_ALLOCATION_INFORMATION;

// private
typedef struct _PROCESS_STACK_ALLOCATION_INFORMATION_EX
{
	ULONG PreferredNode;
	ULONG Reserved0;
	ULONG Reserved1;
	ULONG Reserved2;
	PROCESS_STACK_ALLOCATION_INFORMATION AllocInfo;
} PROCESS_STACK_ALLOCATION_INFORMATION_EX, *PPROCESS_STACK_ALLOCATION_INFORMATION_EX;

// private
typedef union _PROCESS_AFFINITY_UPDATE_MODE
{
	ULONG Flags;
	struct
	{
		ULONG EnableAutoUpdate : 1;
		ULONG Permanent : 1;
		ULONG Reserved : 30;
	};
} PROCESS_AFFINITY_UPDATE_MODE, *PPROCESS_AFFINITY_UPDATE_MODE;

// private
typedef union _PROCESS_MEMORY_ALLOCATION_MODE
{
	ULONG Flags;
	struct
	{
		ULONG TopDown : 1;
		ULONG Reserved : 31;
	};
} PROCESS_MEMORY_ALLOCATION_MODE, *PPROCESS_MEMORY_ALLOCATION_MODE;

// private
typedef struct _PROCESS_HANDLE_INFORMATION
{
	ULONG HandleCount;
	ULONG HandleCountHighWatermark;
} PROCESS_HANDLE_INFORMATION, *PPROCESS_HANDLE_INFORMATION;

// private
typedef struct _PROCESS_CYCLE_TIME_INFORMATION
{
	ULONGLONG AccumulatedCycles;
	ULONGLONG CurrentCycleCount;
} PROCESS_CYCLE_TIME_INFORMATION, *PPROCESS_CYCLE_TIME_INFORMATION;

// private
typedef struct _PROCESS_WINDOW_INFORMATION
{
	ULONG WindowFlags;
	USHORT WindowTitleLength;
	WCHAR WindowTitle[1];
} PROCESS_WINDOW_INFORMATION, *PPROCESS_WINDOW_INFORMATION;

// private
typedef struct _PROCESS_HANDLE_TABLE_ENTRY_INFO
{
	HANDLE HandleValue;
	ULONG_PTR HandleCount;
	ULONG_PTR PointerCount;
	ULONG GrantedAccess;
	ULONG ObjectTypeIndex;
	ULONG HandleAttributes;
	ULONG Reserved;
} PROCESS_HANDLE_TABLE_ENTRY_INFO, *PPROCESS_HANDLE_TABLE_ENTRY_INFO;

// private
typedef struct _PROCESS_HANDLE_SNAPSHOT_INFORMATION
{
	ULONG_PTR NumberOfHandles;
	ULONG_PTR Reserved;
	PROCESS_HANDLE_TABLE_ENTRY_INFO Handles[1];
} PROCESS_HANDLE_SNAPSHOT_INFORMATION, *PPROCESS_HANDLE_SNAPSHOT_INFORMATION;

// private
typedef struct _PROCESS_MITIGATION_POLICY_INFORMATION
{
	PROCESS_MITIGATION_POLICY Policy;
	union
	{
		PROCESS_MITIGATION_ASLR_POLICY ASLRPolicy;
		PROCESS_MITIGATION_STRICT_HANDLE_CHECK_POLICY StrictHandleCheckPolicy;
		PROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY SystemCallDisablePolicy;
		PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY ExtensionPointDisablePolicy;
		PROCESS_MITIGATION_DYNAMIC_CODE_POLICY DynamicCodePolicy;
		PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY ControlFlowGuardPolicy;
		PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY SignaturePolicy;
		PROCESS_MITIGATION_FONT_DISABLE_POLICY FontDisablePolicy;
		PROCESS_MITIGATION_IMAGE_LOAD_POLICY ImageLoadPolicy;
	};
} PROCESS_MITIGATION_POLICY_INFORMATION, *PPROCESS_MITIGATION_POLICY_INFORMATION;

typedef struct _PROCESS_KEEPALIVE_COUNT_INFORMATION
{
	ULONG WakeCount;
	ULONG NoWakeCount;
} PROCESS_KEEPALIVE_COUNT_INFORMATION, *PPROCESS_KEEPALIVE_COUNT_INFORMATION;

typedef struct _PROCESS_REVOKE_FILE_HANDLES_INFORMATION
{
	UNICODE_STRING TargetDevicePath;
} PROCESS_REVOKE_FILE_HANDLES_INFORMATION, *PPROCESS_REVOKE_FILE_HANDLES_INFORMATION;

// begin_private

typedef enum _PROCESS_WORKING_SET_OPERATION
{
	ProcessWorkingSetSwap,
	ProcessWorkingSetEmpty,
	ProcessWorkingSetOperationMax
} PROCESS_WORKING_SET_OPERATION;

typedef struct _PROCESS_WORKING_SET_CONTROL
{
	ULONG Version;
	PROCESS_WORKING_SET_OPERATION Operation;
	ULONG Flags;
} PROCESS_WORKING_SET_CONTROL, *PPROCESS_WORKING_SET_CONTROL;

typedef enum _PS_PROTECTED_TYPE
{
	PsProtectedTypeNone,
	PsProtectedTypeProtectedLight,
	PsProtectedTypeProtected,
	PsProtectedTypeMax
} PS_PROTECTED_TYPE;

typedef enum _PS_PROTECTED_SIGNER
{
	PsProtectedSignerNone,
	PsProtectedSignerAuthenticode,
	PsProtectedSignerCodeGen,
	PsProtectedSignerAntimalware,
	PsProtectedSignerLsa,
	PsProtectedSignerWindows,
	PsProtectedSignerWinTcb,
	PsProtectedSignerMax
} PS_PROTECTED_SIGNER;

typedef struct _PS_PROTECTION
{
	union
	{
		UCHAR Level;
		struct
		{
			UCHAR Type : 3;
			UCHAR Audit : 1;
			UCHAR Signer : 4;
		};
	};
} PS_PROTECTION, *PPS_PROTECTION;

typedef struct _PROCESS_FAULT_INFORMATION
{
	ULONG FaultFlags;
	ULONG AdditionalInfo;
} PROCESS_FAULT_INFORMATION, *PPROCESS_FAULT_INFORMATION;

typedef struct _PROCESS_TELEMETRY_ID_INFORMATION
{
	ULONG HeaderSize;
	ULONG ProcessId;
	ULONGLONG ProcessStartKey;
	ULONGLONG CreateTime;
	ULONGLONG CreateInterruptTime;
	ULONGLONG CreateUnbiasedInterruptTime;
	ULONGLONG ProcessSequenceNumber;
	ULONGLONG SessionCreateTime;
	ULONG SessionId;
	ULONG BootId;
	ULONG ImageChecksum;
	ULONG ImageTimeDateStamp;
	ULONG UserSidOffset;
	ULONG ImagePathOffset;
	ULONG PackageNameOffset;
	ULONG RelativeAppNameOffset;
	ULONG CommandLineOffset;
} PROCESS_TELEMETRY_ID_INFORMATION, *PPROCESS_TELEMETRY_ID_INFORMATION;

typedef struct _PROCESS_COMMIT_RELEASE_INFORMATION
{
	ULONG Version;
	struct
	{
		ULONG Eligible : 1;
		ULONG Spare : 31;
	};
	SIZE_T CommitDebt;
} PROCESS_COMMIT_RELEASE_INFORMATION, *PPROCESS_COMMIT_RELEASE_INFORMATION;

typedef struct _PROCESS_JOB_MEMORY_INFO
{
	ULONGLONG SharedCommitUsage;
	ULONGLONG PrivateCommitUsage;
	ULONGLONG PeakPrivateCommitUsage;
	ULONGLONG PrivateCommitLimit;
	ULONGLONG TotalCommitLimit;
} PROCESS_JOB_MEMORY_INFO, *PPROCESS_JOB_MEMORY_INFO;

// end_private

// Thread information structures

typedef struct _THREAD_BASIC_INFORMATION
{
	NTSTATUS ExitStatus;
	PTEB TebBaseAddress;
	CLIENT_ID ClientId;
	ULONG_PTR AffinityMask;
	KPRIORITY Priority;
	LONG BasePriority;
} THREAD_BASIC_INFORMATION, *PTHREAD_BASIC_INFORMATION;

// private
typedef struct _THREAD_LAST_SYSCALL_INFORMATION
{
	PVOID FirstArgument;
	USHORT SystemCallNumber;
} THREAD_LAST_SYSCALL_INFORMATION, *PTHREAD_LAST_SYSCALL_INFORMATION;

// private
typedef struct _THREAD_CYCLE_TIME_INFORMATION
{
	ULONGLONG AccumulatedCycles;
	ULONGLONG CurrentCycleCount;
} THREAD_CYCLE_TIME_INFORMATION, *PTHREAD_CYCLE_TIME_INFORMATION;

// private
typedef struct _THREAD_TEB_INFORMATION
{
	PVOID TebInformation; // buffer to place data in
	ULONG TebOffset; // offset in TEB to begin reading from
	ULONG BytesToRead; // number of bytes to read
} THREAD_TEB_INFORMATION, *PTHREAD_TEB_INFORMATION;

// symbols
typedef struct _COUNTER_READING
{
	HARDWARE_COUNTER_TYPE Type;
	ULONG Index;
	ULONG64 Start;
	ULONG64 Total;
} COUNTER_READING, *PCOUNTER_READING;

// symbols
typedef struct _THREAD_PERFORMANCE_DATA
{
	USHORT Size;
	USHORT Version;
	PROCESSOR_NUMBER ProcessorNumber;
	ULONG ContextSwitches;
	ULONG HwCountersCount;
	ULONG64 UpdateCount;
	ULONG64 WaitReasonBitMap;
	ULONG64 HardwareCounters;
	COUNTER_READING CycleTime;
	COUNTER_READING HwCounters[MAX_HW_COUNTERS];
} THREAD_PERFORMANCE_DATA, *PTHREAD_PERFORMANCE_DATA;

// private
typedef struct _THREAD_PROFILING_INFORMATION
{
	ULONG64 HardwareCounters;
	ULONG Flags;
	ULONG Enable;
	PTHREAD_PERFORMANCE_DATA PerformanceData;
} THREAD_PROFILING_INFORMATION, *PTHREAD_PROFILING_INFORMATION;

// Processes

#define PROCESS_CREATE_FLAGS_BREAKAWAY 0x00000001
#define PROCESS_CREATE_FLAGS_NO_DEBUG_INHERIT 0x00000002
#define PROCESS_CREATE_FLAGS_INHERIT_HANDLES 0x00000004
#define PROCESS_CREATE_FLAGS_OVERRIDE_ADDRESS_SPACE 0x00000008
#define PROCESS_CREATE_FLAGS_LARGE_PAGES 0x00000010

// Thread

typedef VOID(*PPS_APC_ROUTINE)(
	_In_opt_ PVOID ApcArgument1,
	_In_opt_ PVOID ApcArgument2,
	_In_opt_ PVOID ApcArgument3
	);

// User processes and threads

// Attributes

// begin_rev
#define PS_ATTRIBUTE_NUMBER_MASK 0x0000ffff
#define PS_ATTRIBUTE_THREAD 0x00010000 // can be used with threads
#define PS_ATTRIBUTE_INPUT 0x00020000 // input only
#define PS_ATTRIBUTE_UNKNOWN 0x00040000
// end_rev

// private
typedef enum _PS_ATTRIBUTE_NUM
{
	PsAttributeParentProcess, // in HANDLE
	PsAttributeDebugPort, // in HANDLE
	PsAttributeToken, // in HANDLE
	PsAttributeClientId, // out PCLIENT_ID
	PsAttributeTebAddress, // out PTEB *
	PsAttributeImageName, // in PWSTR
	PsAttributeImageInfo, // out PSECTION_IMAGE_INFORMATION
	PsAttributeMemoryReserve, // in PPS_MEMORY_RESERVE
	PsAttributePriorityClass, // in UCHAR
	PsAttributeErrorMode, // in ULONG
	PsAttributeStdHandleInfo, // 10, in PPS_STD_HANDLE_INFO
	PsAttributeHandleList, // in PHANDLE
	PsAttributeGroupAffinity, // in PGROUP_AFFINITY
	PsAttributePreferredNode, // in PUSHORT
	PsAttributeIdealProcessor, // in PPROCESSOR_NUMBER
	PsAttributeUmsThread, // ? in PUMS_CREATE_THREAD_ATTRIBUTES
	PsAttributeMitigationOptions, // in UCHAR
	PsAttributeProtectionLevel,
	PsAttributeSecureProcess, // since THRESHOLD
	PsAttributeJobList,
	PsAttributeChildProcessPolicy, // since THRESHOLD2
	PsAttributeMax
} PS_ATTRIBUTE_NUM;

// begin_rev

#define PsAttributeValue(Number, Thread, Input, Unknown) \
    (((Number) & PS_ATTRIBUTE_NUMBER_MASK) | \
    ((Thread) ? PS_ATTRIBUTE_THREAD : 0) | \
    ((Input) ? PS_ATTRIBUTE_INPUT : 0) | \
    ((Unknown) ? PS_ATTRIBUTE_UNKNOWN : 0))

#define PS_ATTRIBUTE_PARENT_PROCESS \
    PsAttributeValue(PsAttributeParentProcess, FALSE, TRUE, TRUE)
#define PS_ATTRIBUTE_DEBUG_PORT \
    PsAttributeValue(PsAttributeDebugPort, FALSE, TRUE, TRUE)
#define PS_ATTRIBUTE_TOKEN \
    PsAttributeValue(PsAttributeToken, FALSE, TRUE, TRUE)
#define PS_ATTRIBUTE_CLIENT_ID \
    PsAttributeValue(PsAttributeClientId, TRUE, FALSE, FALSE)
#define PS_ATTRIBUTE_TEB_ADDRESS \
    PsAttributeValue(PsAttributeTebAddress, TRUE, FALSE, FALSE)
#define PS_ATTRIBUTE_IMAGE_NAME \
    PsAttributeValue(PsAttributeImageName, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_IMAGE_INFO \
    PsAttributeValue(PsAttributeImageInfo, FALSE, FALSE, FALSE)
#define PS_ATTRIBUTE_MEMORY_RESERVE \
    PsAttributeValue(PsAttributeMemoryReserve, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_PRIORITY_CLASS \
    PsAttributeValue(PsAttributePriorityClass, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_ERROR_MODE \
    PsAttributeValue(PsAttributeErrorMode, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_STD_HANDLE_INFO \
    PsAttributeValue(PsAttributeStdHandleInfo, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_HANDLE_LIST \
    PsAttributeValue(PsAttributeHandleList, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_GROUP_AFFINITY \
    PsAttributeValue(PsAttributeGroupAffinity, TRUE, TRUE, FALSE)
#define PS_ATTRIBUTE_PREFERRED_NODE \
    PsAttributeValue(PsAttributePreferredNode, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_IDEAL_PROCESSOR \
    PsAttributeValue(PsAttributeIdealProcessor, TRUE, TRUE, FALSE)
#define PS_ATTRIBUTE_MITIGATION_OPTIONS \
    PsAttributeValue(PsAttributeMitigationOptions, FALSE, TRUE, TRUE)

// end_rev

// begin_private

typedef struct _PS_ATTRIBUTE
{
	ULONG Attribute;
	SIZE_T Size;
	union
	{
		ULONG Value;
		PVOID ValuePtr;
	};
	PSIZE_T ReturnLength;
} PS_ATTRIBUTE, *PPS_ATTRIBUTE;

typedef struct _PS_ATTRIBUTE_LIST
{
	SIZE_T TotalLength;
	PS_ATTRIBUTE Attributes[1];
} PS_ATTRIBUTE_LIST, *PPS_ATTRIBUTE_LIST;

typedef struct _PS_MEMORY_RESERVE
{
	PVOID ReserveAddress;
	SIZE_T ReserveSize;
} PS_MEMORY_RESERVE, *PPS_MEMORY_RESERVE;

typedef enum _PS_STD_HANDLE_STATE
{
	PsNeverDuplicate,
	PsRequestDuplicate, // duplicate standard handles specified by PseudoHandleMask, and only if StdHandleSubsystemType matches the image subsystem
	PsAlwaysDuplicate, // always duplicate standard handles
	PsMaxStdHandleStates
} PS_STD_HANDLE_STATE;

// begin_rev
#define PS_STD_INPUT_HANDLE 0x1
#define PS_STD_OUTPUT_HANDLE 0x2
#define PS_STD_ERROR_HANDLE 0x4
// end_rev

typedef struct _PS_STD_HANDLE_INFO
{
	union
	{
		ULONG Flags;
		struct
		{
			ULONG StdHandleState : 2; // PS_STD_HANDLE_STATE
			ULONG PseudoHandleMask : 3; // PS_STD_*
		};
	};
	ULONG StdHandleSubsystemType;
} PS_STD_HANDLE_INFO, *PPS_STD_HANDLE_INFO;

// windows-internals-book:"Chapter 5"
typedef enum _PS_CREATE_STATE
{
	PsCreateInitialState,
	PsCreateFailOnFileOpen,
	PsCreateFailOnSectionCreate,
	PsCreateFailExeFormat,
	PsCreateFailMachineMismatch,
	PsCreateFailExeName, // Debugger specified
	PsCreateSuccess,
	PsCreateMaximumStates
} PS_CREATE_STATE;

typedef struct _PS_CREATE_INFO
{
	SIZE_T Size;
	PS_CREATE_STATE State;
	union
	{
		// PsCreateInitialState
		struct
		{
			union
			{
				ULONG InitFlags;
				struct
				{
					UCHAR WriteOutputOnExit : 1;
					UCHAR DetectManifest : 1;
					UCHAR IFEOSkipDebugger : 1;
					UCHAR IFEODoNotPropagateKeyState : 1;
					UCHAR SpareBits1 : 4;
					UCHAR SpareBits2 : 8;
					USHORT ProhibitedImageCharacteristics : 16;
				};
			};
			ACCESS_MASK AdditionalFileAccess;
		} InitState;

		// PsCreateFailOnSectionCreate
		struct
		{
			HANDLE FileHandle;
		} FailSection;

		// PsCreateFailExeFormat
		struct
		{
			USHORT DllCharacteristics;
		} ExeFormat;

		// PsCreateFailExeName
		struct
		{
			HANDLE IFEOKey;
		} ExeName;

		// PsCreateSuccess
		struct
		{
			union
			{
				ULONG OutputFlags;
				struct
				{
					UCHAR ProtectedProcess : 1;
					UCHAR AddressSpaceOverride : 1;
					UCHAR DevOverrideEnabled : 1; // from Image File Execution Options
					UCHAR ManifestDetected : 1;
					UCHAR ProtectedProcessLight : 1;
					UCHAR SpareBits1 : 3;
					UCHAR SpareBits2 : 8;
					USHORT SpareBits3 : 16;
				};
			};
			HANDLE FileHandle;
			HANDLE SectionHandle;
			ULONGLONG UserProcessParametersNative;
			ULONG UserProcessParametersWow64;
			ULONG CurrentParameterFlags;
			ULONGLONG PebAddressNative;
			ULONG PebAddressWow64;
			ULONGLONG ManifestAddress;
			ULONG ManifestSize;
		} SuccessState;
	};
} PS_CREATE_INFO, *PPS_CREATE_INFO;

// end_private

// Extended PROCESS_CREATE_FLAGS_*
// begin_rev
#define PROCESS_CREATE_FLAGS_LARGE_PAGE_SYSTEM_DLL 0x00000020
#define PROCESS_CREATE_FLAGS_PROTECTED_PROCESS 0x00000040
#define PROCESS_CREATE_FLAGS_CREATE_SESSION 0x00000080 // ?
#define PROCESS_CREATE_FLAGS_INHERIT_FROM_PARENT 0x00000100
// end_rev

// begin_rev
#define THREAD_CREATE_FLAGS_CREATE_SUSPENDED 0x00000001
#define THREAD_CREATE_FLAGS_SKIP_THREAD_ATTACH 0x00000002 // ?
#define THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER 0x00000004
#define THREAD_CREATE_FLAGS_HAS_SECURITY_DESCRIPTOR 0x00000010 // ?
#define THREAD_CREATE_FLAGS_ACCESS_CHECK_IN_TARGET 0x00000020 // ?
#define THREAD_CREATE_FLAGS_INITIAL_THREAD 0x00000080
// end_rev

// Reserve objects

// private
typedef enum _MEMORY_RESERVE_TYPE
{
	MemoryReserveUserApc,
	MemoryReserveIoCompletion,
	MemoryReserveTypeMax
} MEMORY_RESERVE_TYPE;

// Process

#define DOS_MAX_COMPONENT_LENGTH 255
#define DOS_MAX_PATH_LENGTH (DOS_MAX_COMPONENT_LENGTH + 5)

typedef struct _CURDIR
{
	UNICODE_STRING DosPath;
	HANDLE Handle;
} CURDIR, *PCURDIR;

#define RTL_USER_PROC_CURDIR_CLOSE 0x00000002
#define RTL_USER_PROC_CURDIR_INHERIT 0x00000003

typedef struct _RTL_DRIVE_LETTER_CURDIR
{
	USHORT Flags;
	USHORT Length;
	ULONG TimeStamp;
	STRING DosPath;
} RTL_DRIVE_LETTER_CURDIR, *PRTL_DRIVE_LETTER_CURDIR;

#define RTL_MAX_DRIVE_LETTERS 32
#define RTL_DRIVE_LETTER_VALID (USHORT)0x0001

typedef struct _RTL_USER_PROCESS_PARAMETERS
{
	ULONG MaximumLength;
	ULONG Length;

	ULONG Flags;
	ULONG DebugFlags;

	HANDLE ConsoleHandle;
	ULONG ConsoleFlags;
	HANDLE StandardInput;
	HANDLE StandardOutput;
	HANDLE StandardError;

	CURDIR CurrentDirectory;
	UNICODE_STRING DllPath;
	UNICODE_STRING ImagePathName;
	UNICODE_STRING CommandLine;
	PVOID Environment;

	ULONG StartingX;
	ULONG StartingY;
	ULONG CountX;
	ULONG CountY;
	ULONG CountCharsX;
	ULONG CountCharsY;
	ULONG FillAttribute;

	ULONG WindowFlags;
	ULONG ShowWindowFlags;
	UNICODE_STRING WindowTitle;
	UNICODE_STRING DesktopInfo;
	UNICODE_STRING ShellInfo;
	UNICODE_STRING RuntimeData;
	RTL_DRIVE_LETTER_CURDIR CurrentDirectories[RTL_MAX_DRIVE_LETTERS];

	ULONG EnvironmentSize;
	ULONG EnvironmentVersion;
	PVOID PackageDependencyData;
	ULONG ProcessGroupId;
	ULONG LoaderThreads;
} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;

#define RTL_USER_PROC_PARAMS_NORMALIZED 0x00000001
#define RTL_USER_PROC_PROFILE_USER 0x00000002
#define RTL_USER_PROC_PROFILE_KERNEL 0x00000004
#define RTL_USER_PROC_PROFILE_SERVER 0x00000008
#define RTL_USER_PROC_RESERVE_1MB 0x00000020
#define RTL_USER_PROC_RESERVE_16MB 0x00000040
#define RTL_USER_PROC_CASE_SENSITIVE 0x00000080
#define RTL_USER_PROC_DISABLE_HEAP_DECOMMIT 0x00000100
#define RTL_USER_PROC_DLL_REDIRECTION_LOCAL 0x00001000
#define RTL_USER_PROC_APP_MANIFEST_PRESENT 0x00002000
#define RTL_USER_PROC_IMAGE_KEY_MISSING 0x00004000
#define RTL_USER_PROC_OPTIN_PROCESS 0x00020000

typedef struct _RTL_USER_PROCESS_INFORMATION
{
	ULONG Length;
	HANDLE Process;
	HANDLE Thread;
	CLIENT_ID ClientId;
	SECTION_IMAGE_INFORMATION ImageInformation;
} RTL_USER_PROCESS_INFORMATION, *PRTL_USER_PROCESS_INFORMATION;

#if (_WIN32_WINNT >= _WIN32_WINNT_VISTA)

// begin_rev
#define RTL_CLONE_PROCESS_FLAGS_CREATE_SUSPENDED 0x00000001
#define RTL_CLONE_PROCESS_FLAGS_INHERIT_HANDLES 0x00000002
#define RTL_CLONE_PROCESS_FLAGS_NO_SYNCHRONIZE 0x00000004 // don't update synchronization objects
// end_rev

// private
typedef struct _RTLP_PROCESS_REFLECTION_REFLECTION_INFORMATION
{
	HANDLE ReflectionProcessHandle;
	HANDLE ReflectionThreadHandle;
	CLIENT_ID ReflectionClientId;
} RTLP_PROCESS_REFLECTION_REFLECTION_INFORMATION, *PRTLP_PROCESS_REFLECTION_REFLECTION_INFORMATION;

#endif

NTSYSAPI
NTSTATUS
STDAPIVCALLTYPE
RtlSetProcessIsCritical(
	_In_ BOOLEAN NewValue,
	_Out_opt_ PBOOLEAN OldValue,
	_In_ BOOLEAN CheckFlag
);

NTSYSAPI
NTSTATUS
STDAPIVCALLTYPE
RtlSetThreadIsCritical(
	_In_ BOOLEAN NewValue,
	_Out_opt_ PBOOLEAN OldValue,
	_In_ BOOLEAN CheckFlag
);

// Threads

typedef NTSTATUS(NTAPI *PUSER_THREAD_START_ROUTINE)(
	_In_ PVOID ThreadParameter
	);

#pragma endregion

// Logical
#pragma region Logical

typedef ULONG LOGICAL;
typedef ULONG *PLOGICAL;

#pragma endregion

// 电源
#pragma region Power

typedef enum _SHUTDOWN_ACTION
{
	ShutdownNoReboot,
	ShutdownReboot,
	ShutdownPowerOff
} SHUTDOWN_ACTION;

typedef union _POWER_STATE
{
	SYSTEM_POWER_STATE SystemState;
	DEVICE_POWER_STATE DeviceState;
} POWER_STATE, *PPOWER_STATE;

typedef enum _POWER_STATE_TYPE
{
	SystemPowerState = 0,
	DevicePowerState
} POWER_STATE_TYPE, *PPOWER_STATE_TYPE;

#if (_WIN32_WINNT >= _WIN32_WINNT_VISTA)
// wdm
typedef struct _SYSTEM_POWER_STATE_CONTEXT
{
	union
	{
		struct
		{
			ULONG Reserved1 : 8;
			ULONG TargetSystemState : 4;
			ULONG EffectiveSystemState : 4;
			ULONG CurrentSystemState : 4;
			ULONG IgnoreHibernationPath : 1;
			ULONG PseudoTransition : 1;
			ULONG Reserved2 : 10;
		};
		ULONG ContextAsUlong;
	};
} SYSTEM_POWER_STATE_CONTEXT, *PSYSTEM_POWER_STATE_CONTEXT;
#endif

#if (_WIN32_WINNT >= _WIN32_WINNT_WIN7)
/** \cond NEVER */ // disable doxygen warning
				   // wdm
typedef struct _COUNTED_REASON_CONTEXT
{
	ULONG Version;
	ULONG Flags;
	union
	{
		struct
		{
			UNICODE_STRING ResourceFileName;
			USHORT ResourceReasonId;
			ULONG StringCount;
			PUNICODE_STRING _Field_size_(StringCount) ReasonStrings;
		};
		UNICODE_STRING SimpleString;
	};
} COUNTED_REASON_CONTEXT, *PCOUNTED_REASON_CONTEXT;
/** \endcond */
#endif

typedef enum
{
	PowerStateSleeping1 = 0,
	PowerStateSleeping2 = 1,
	PowerStateSleeping3 = 2,
	PowerStateSleeping4 = 3,
	PowerStateSleeping4Firmware = 4,
	PowerStateShutdownReset = 5,
	PowerStateShutdownOff = 6,
	PowerStateMaximum = 7
} POWER_STATE_HANDLER_TYPE, *PPOWER_STATE_HANDLER_TYPE;

typedef NTSTATUS(NTAPI *PENTER_STATE_SYSTEM_HANDLER)(
	_In_ PVOID SystemContext
	);

typedef NTSTATUS(NTAPI *PENTER_STATE_HANDLER)(
	_In_ PVOID Context,
	_In_opt_ PENTER_STATE_SYSTEM_HANDLER SystemHandler,
	_In_ PVOID SystemContext,
	_In_ LONG NumberProcessors,
	_In_ volatile PLONG Number
	);

typedef struct _POWER_STATE_HANDLER
{
	POWER_STATE_HANDLER_TYPE Type;
	BOOLEAN RtcWake;
	UCHAR Spare[3];
	PENTER_STATE_HANDLER Handler;
	PVOID Context;
} POWER_STATE_HANDLER, *PPOWER_STATE_HANDLER;

typedef NTSTATUS(NTAPI *PENTER_STATE_NOTIFY_HANDLER)(
	_In_ POWER_STATE_HANDLER_TYPE State,
	_In_ PVOID Context,
	_In_ BOOLEAN Entering
	);

typedef struct _POWER_STATE_NOTIFY_HANDLER
{
	PENTER_STATE_NOTIFY_HANDLER Handler;
	PVOID Context;
} POWER_STATE_NOTIFY_HANDLER, *PPOWER_STATE_NOTIFY_HANDLER;

typedef struct _PROCESSOR_POWER_INFORMATION
{
	ULONG Number;
	ULONG MaxMhz;
	ULONG CurrentMhz;
	ULONG MhzLimit;
	ULONG MaxIdleState;
	ULONG CurrentIdleState;
} PROCESSOR_POWER_INFORMATION, *PPROCESSOR_POWER_INFORMATION;

typedef struct _SYSTEM_POWER_INFORMATION
{
	ULONG MaxIdlenessAllowed;
	ULONG Idleness;
	ULONG TimeRemaining;
	UCHAR CoolingMode;
} SYSTEM_POWER_INFORMATION, *PSYSTEM_POWER_INFORMATION;

#pragma endregion

// 注册表
#pragma region Registry

// Boot condition flags (NtInitializeRegistry)

#define REG_INIT_BOOT_SM 0x0000
#define REG_INIT_BOOT_SETUP 0x0001
#define REG_INIT_BOOT_ACCEPTED_BASE 0x0002
#define REG_INIT_BOOT_ACCEPTED_MAX REG_INIT_BOOT_ACCEPTED_BASE + 999

#define REG_MAX_KEY_VALUE_NAME_LENGTH 32767
#define REG_MAX_KEY_NAME_LENGTH 512

typedef enum _KEY_INFORMATION_CLASS
{
	KeyBasicInformation,
	KeyNodeInformation,
	KeyFullInformation,
	KeyNameInformation,
	KeyCachedInformation,
	KeyFlagsInformation,
	KeyVirtualizationInformation,
	KeyHandleTagsInformation,
	KeyTrustInformation,
	MaxKeyInfoClass
} KEY_INFORMATION_CLASS;

typedef struct _KEY_BASIC_INFORMATION
{
	LARGE_INTEGER LastWriteTime;
	ULONG TitleIndex;
	ULONG NameLength;
	WCHAR Name[1];
} KEY_BASIC_INFORMATION, *PKEY_BASIC_INFORMATION;

typedef struct _KEY_NODE_INFORMATION
{
	LARGE_INTEGER LastWriteTime;
	ULONG TitleIndex;
	ULONG ClassOffset;
	ULONG ClassLength;
	ULONG NameLength;
	WCHAR Name[1];
	// ...
	// WCHAR Class[1];
} KEY_NODE_INFORMATION, *PKEY_NODE_INFORMATION;

typedef struct _KEY_FULL_INFORMATION
{
	LARGE_INTEGER LastWriteTime;
	ULONG TitleIndex;
	ULONG ClassOffset;
	ULONG ClassLength;
	ULONG SubKeys;
	ULONG MaxNameLen;
	ULONG MaxClassLen;
	ULONG Values;
	ULONG MaxValueNameLen;
	ULONG MaxValueDataLen;
	WCHAR Class[1];
} KEY_FULL_INFORMATION, *PKEY_FULL_INFORMATION;

typedef struct _KEY_NAME_INFORMATION
{
	ULONG NameLength;
	WCHAR Name[1];
} KEY_NAME_INFORMATION, *PKEY_NAME_INFORMATION;

typedef struct _KEY_CACHED_INFORMATION
{
	LARGE_INTEGER LastWriteTime;
	ULONG TitleIndex;
	ULONG SubKeys;
	ULONG MaxNameLen;
	ULONG Values;
	ULONG MaxValueNameLen;
	ULONG MaxValueDataLen;
	ULONG NameLength;
	WCHAR Name[1];
} KEY_CACHED_INFORMATION, *PKEY_CACHED_INFORMATION;

typedef struct _KEY_FLAGS_INFORMATION
{
	ULONG UserFlags;
} KEY_FLAGS_INFORMATION, *PKEY_FLAGS_INFORMATION;

typedef struct _KEY_VIRTUALIZATION_INFORMATION
{
	ULONG VirtualizationCandidate : 1; // Tells whether the key is part of the virtualization namespace scope (only HKLM\Software for now).
	ULONG VirtualizationEnabled : 1; // Tells whether virtualization is enabled on this key. Can be 1 only if above flag is 1.
	ULONG VirtualTarget : 1; // Tells if the key is a virtual key. Can be 1 only if above 2 are 0. Valid only on the virtual store key handles.
	ULONG VirtualStore : 1; // Tells if the key is a part of the virtual store path. Valid only on the virtual store key handles.
	ULONG VirtualSource : 1; // Tells if the key has ever been virtualized, can be 1 only if VirtualizationCandidate is 1.
	ULONG Reserved : 27;
} KEY_VIRTUALIZATION_INFORMATION, *PKEY_VIRTUALIZATION_INFORMATION;

// private
typedef struct _KEY_TRUST_INFORMATION
{
	ULONG TrustedKey : 1;
	ULONG Reserved : 31;
} KEY_TRUST_INFORMATION, *PKEY_TRUST_INFORMATION;

typedef enum _KEY_SET_INFORMATION_CLASS
{
	KeyWriteTimeInformation,
	KeyWow64FlagsInformation,
	KeyControlFlagsInformation,
	KeySetVirtualizationInformation,
	KeySetDebugInformation,
	KeySetHandleTagsInformation,
	MaxKeySetInfoClass
} KEY_SET_INFORMATION_CLASS;

typedef struct _KEY_WRITE_TIME_INFORMATION
{
	LARGE_INTEGER LastWriteTime;
} KEY_WRITE_TIME_INFORMATION, *PKEY_WRITE_TIME_INFORMATION;

typedef struct _KEY_WOW64_FLAGS_INFORMATION
{
	ULONG UserFlags;
} KEY_WOW64_FLAGS_INFORMATION, *PKEY_WOW64_FLAGS_INFORMATION;

typedef struct _KEY_HANDLE_TAGS_INFORMATION
{
	ULONG HandleTags;
} KEY_HANDLE_TAGS_INFORMATION, *PKEY_HANDLE_TAGS_INFORMATION;

typedef struct _KEY_CONTROL_FLAGS_INFORMATION
{
	ULONG ControlFlags;
} KEY_CONTROL_FLAGS_INFORMATION, *PKEY_CONTROL_FLAGS_INFORMATION;

typedef struct _KEY_SET_VIRTUALIZATION_INFORMATION
{
	ULONG VirtualTarget : 1;
	ULONG VirtualStore : 1;
	ULONG VirtualSource : 1; // true if key has been virtualized at least once
	ULONG Reserved : 29;
} KEY_SET_VIRTUALIZATION_INFORMATION, *PKEY_SET_VIRTUALIZATION_INFORMATION;

typedef enum _KEY_VALUE_INFORMATION_CLASS
{
	KeyValueBasicInformation,
	KeyValueFullInformation,
	KeyValuePartialInformation,
	KeyValueFullInformationAlign64,
	KeyValuePartialInformationAlign64,
	MaxKeyValueInfoClass
} KEY_VALUE_INFORMATION_CLASS;

typedef struct _KEY_VALUE_BASIC_INFORMATION
{
	ULONG TitleIndex;
	ULONG Type;
	ULONG NameLength;
	WCHAR Name[1];
} KEY_VALUE_BASIC_INFORMATION, *PKEY_VALUE_BASIC_INFORMATION;

typedef struct _KEY_VALUE_FULL_INFORMATION
{
	ULONG TitleIndex;
	ULONG Type;
	ULONG DataOffset;
	ULONG DataLength;
	ULONG NameLength;
	WCHAR Name[1];
	// ...
	// UCHAR Data[1];
} KEY_VALUE_FULL_INFORMATION, *PKEY_VALUE_FULL_INFORMATION;

typedef struct _KEY_VALUE_PARTIAL_INFORMATION
{
	ULONG TitleIndex;
	ULONG Type;
	ULONG DataLength;
	UCHAR Data[1];
} KEY_VALUE_PARTIAL_INFORMATION, *PKEY_VALUE_PARTIAL_INFORMATION;

typedef struct _KEY_VALUE_PARTIAL_INFORMATION_ALIGN64
{
	ULONG Type;
	ULONG DataLength;
	UCHAR Data[1];
} KEY_VALUE_PARTIAL_INFORMATION_ALIGN64, *PKEY_VALUE_PARTIAL_INFORMATION_ALIGN64;

typedef struct _KEY_VALUE_ENTRY
{
	PUNICODE_STRING ValueName;
	ULONG DataLength;
	ULONG DataOffset;
	ULONG Type;
} KEY_VALUE_ENTRY, *PKEY_VALUE_ENTRY;

typedef enum _REG_ACTION
{
	KeyAdded,
	KeyRemoved,
	KeyModified
} REG_ACTION;

typedef struct _REG_NOTIFY_INFORMATION
{
	ULONG NextEntryOffset;
	REG_ACTION Action;
	ULONG KeyLength;
	WCHAR Key[1];
} REG_NOTIFY_INFORMATION, *PREG_NOTIFY_INFORMATION;

typedef struct _KEY_PID_ARRAY
{
	HANDLE PID;
	UNICODE_STRING KeyName;
} KEY_PID_ARRAY, *PKEY_PID_ARRAY;

typedef struct _KEY_OPEN_SUBKEYS_INFORMATION
{
	ULONG Count;
	KEY_PID_ARRAY KeyArray[1];
} KEY_OPEN_SUBKEYS_INFORMATION, *PKEY_OPEN_SUBKEYS_INFORMATION;

#pragma endregion

#pragma endregion

// 本机API
#pragma region NativeCall

// 错误处理
extern "C"
{
	NTSYSAPI ULONG NTAPI RtlNtStatusToDosError(
		_In_ NTSTATUS Status
	);

	NTSYSAPI ULONG NTAPI RtlNtStatusToDosErrorNoTeb(
		_In_ NTSTATUS Status
	);

	NTSYSAPI NTSTATUS NTAPI RtlGetLastNtStatus(
		VOID
	);

	NTSYSAPI LONG NTAPI RtlGetLastWin32Error(
		VOID
	);

	NTSYSAPI VOID NTAPI RtlSetLastWin32ErrorAndNtStatusFromNtStatus(
		_In_ NTSTATUS Status
	);

	NTSYSAPI VOID NTAPI RtlSetLastWin32Error(
		_In_ LONG Win32Error
	);

	NTSYSAPI VOID NTAPI RtlRestoreLastWin32Error(
		_In_ LONG Win32Error
	);

	NTSYSAPI ULONG NTAPI RtlGetThreadErrorMode(
		VOID
	);

	NTSYSAPI NTSTATUS NTAPI RtlSetThreadErrorMode(
		_In_ ULONG NewMode,
		_Out_opt_ PULONG OldMode
	);
}

// 字符串
extern "C"
{
#if (_WIN32_WINNT >= _WIN32_WINNT_WIN10)
	NTSYSAPI NTSTATUS NTAPI RtlInitStringEx(
		_Out_ PSTRING DestinationString,
		_In_opt_z_ PCSTR SourceString
	);
#endif

#if (_WIN32_WINNT >= _WIN32_WINNT_WS03)
	NTSYSAPI NTSTATUS NTAPI RtlInitAnsiStringEx(
		_Out_ PANSI_STRING DestinationString,
		_In_opt_z_ PCSTR SourceString
	);
#endif

	NTSYSAPI VOID NTAPI RtlFreeAnsiString(
		_In_ PANSI_STRING AnsiString
	);

	NTSYSAPI VOID NTAPI RtlFreeOemString(
		_In_ POEM_STRING OemString
	);

	NTSYSAPI VOID NTAPI RtlCopyString(
		_In_ PSTRING DestinationString,
		_In_opt_ PSTRING SourceString
	);

	NTSYSAPI CHAR NTAPI RtlUpperChar(
		_In_ CHAR Character
	);

	_Must_inspect_result_ NTSYSAPI LONG NTAPI RtlCompareString(
		_In_ PSTRING String1,
		_In_ PSTRING String2,
		_In_ BOOLEAN CaseInSensitive
	);

	_Must_inspect_result_ NTSYSAPI BOOLEAN NTAPI RtlEqualString(
		_In_ PSTRING String1,
		_In_ PSTRING String2,
		_In_ BOOLEAN CaseInSensitive
	);

	_Must_inspect_result_ NTSYSAPI BOOLEAN NTAPI RtlPrefixString(
		_In_ PSTRING String1,
		_In_ PSTRING String2,
		_In_ BOOLEAN CaseInSensitive
	);

	NTSYSAPI NTSTATUS NTAPI RtlAppendStringToString(
		_In_ PSTRING Destination,
		_In_ PSTRING Source
	);

	NTSYSAPI NTSTATUS NTAPI RtlAppendAsciizToString(
		_In_ PSTRING Destination,
		_In_opt_ PSTR Source
	);

	NTSYSAPI VOID NTAPI RtlUpperString(
		_In_ PSTRING DestinationString,
		_In_ PSTRING SourceString
	);

	NTSYSAPI NTSTATUS NTAPI RtlInitUnicodeStringEx(
		_Out_ PUNICODE_STRING DestinationString,
		_In_opt_ PWSTR SourceString
	);

	NTSYSAPI BOOLEAN NTAPI RtlCreateUnicodeString(
		_Out_ PUNICODE_STRING DestinationString,
		_In_ PWSTR SourceString
	);

	NTSYSAPI BOOLEAN NTAPI RtlCreateUnicodeStringFromAsciiz(
		_Out_ PUNICODE_STRING DestinationString,
		_In_ PSTR SourceString
	);

	NTSYSAPI VOID NTAPI RtlFreeUnicodeString(
		_In_ PUNICODE_STRING UnicodeString
	);

	NTSYSAPI NTSTATUS NTAPI RtlDuplicateUnicodeString(
		_In_ ULONG Flags,
		_In_ PUNICODE_STRING StringIn,
		_Out_ PUNICODE_STRING StringOut
	);

	NTSYSAPI VOID NTAPI RtlCopyUnicodeString(
		_In_ PUNICODE_STRING DestinationString,
		_In_ PUNICODE_STRING SourceString
	);

	NTSYSAPI WCHAR NTAPI RtlUpcaseUnicodeChar(
		_In_ WCHAR SourceCharacter
	);

	NTSYSAPI WCHAR NTAPI RtlDowncaseUnicodeChar(
		_In_ WCHAR SourceCharacter
	);

	_Must_inspect_result_ NTSYSAPI LONG NTAPI RtlCompareUnicodeString(
		_In_ PUNICODE_STRING String1,
		_In_ PUNICODE_STRING String2,
		_In_ BOOLEAN CaseInSensitive
	);

#if (_WIN32_WINNT >= _WIN32_WINNT_VISTA)
	_Must_inspect_result_ NTSYSAPI LONG NTAPI RtlCompareUnicodeStrings(
		_In_reads_(String1Length) PWCH String1,
		_In_ SIZE_T String1Length,
		_In_reads_(String2Length) PWCH String2,
		_In_ SIZE_T String2Length,
		_In_ BOOLEAN CaseInSensitive
	);
#endif

	_Must_inspect_result_ NTSYSAPI BOOLEAN NTAPI RtlEqualUnicodeString(
		_In_ PUNICODE_STRING String1,
		_In_ PUNICODE_STRING String2,
		_In_ BOOLEAN CaseInSensitive
	);

	NTSYSAPI NTSTATUS NTAPI RtlHashUnicodeString(
		_In_ PUNICODE_STRING String,
		_In_ BOOLEAN CaseInSensitive,
		_In_ ULONG HashAlgorithm,
		_Out_ PULONG HashValue
	);

	NTSYSAPI NTSTATUS NTAPI RtlValidateUnicodeString(
		_In_ ULONG Flags,
		_In_ PUNICODE_STRING String
	);

	_Must_inspect_result_ NTSYSAPI BOOLEAN NTAPI RtlPrefixUnicodeString(
		_In_ PCUNICODE_STRING String1,
		_In_ PCUNICODE_STRING String2,
		_In_ BOOLEAN CaseInSensitive
	);

#if (_WIN32_WINNT >= _WIN32_WINNT_WIN10)
	_Must_inspect_result_ NTSYSAPI BOOLEAN NTAPI RtlSuffixUnicodeString(
		_In_ PCUNICODE_STRING String1,
		_In_ PCUNICODE_STRING String2,
		_In_ BOOLEAN CaseInSensitive
	);
#endif

	NTSYSAPI NTSTATUS NTAPI RtlFindCharInUnicodeString(
		_In_ ULONG Flags,
		_In_ PUNICODE_STRING StringToSearch,
		_In_ PUNICODE_STRING CharSet,
		_Out_ PUSHORT NonInclusivePrefixLength
	);

	NTSYSAPI NTSTATUS NTAPI RtlAppendUnicodeStringToString(
		_In_ PUNICODE_STRING Destination,
		_In_ PUNICODE_STRING Source
	);

	NTSYSAPI NTSTATUS NTAPI RtlAppendUnicodeToString(
		_In_ PUNICODE_STRING Destination,
		_In_opt_ PWSTR Source
	);

	NTSYSAPI NTSTATUS NTAPI RtlUpcaseUnicodeString(
		_Inout_ PUNICODE_STRING DestinationString,
		_In_ PUNICODE_STRING SourceString,
		_In_ BOOLEAN AllocateDestinationString
	);

	NTSYSAPI NTSTATUS NTAPI RtlDowncaseUnicodeString(
		_Inout_ PUNICODE_STRING DestinationString,
		_In_ PUNICODE_STRING SourceString,
		_In_ BOOLEAN AllocateDestinationString
	);

	NTSYSAPI VOID NTAPI RtlEraseUnicodeString(
		_Inout_ PUNICODE_STRING String
	);

	NTSYSAPI NTSTATUS NTAPI RtlAnsiStringToUnicodeString(
		_Inout_ PUNICODE_STRING DestinationString,
		_In_ PANSI_STRING SourceString,
		_In_ BOOLEAN AllocateDestinationString
	);

	NTSYSAPI NTSTATUS NTAPI RtlUnicodeStringToAnsiString(
		_Inout_ PANSI_STRING DestinationString,
		_In_ PUNICODE_STRING SourceString,
		_In_ BOOLEAN AllocateDestinationString
	);

	NTSYSAPI WCHAR NTAPI RtlAnsiCharToUnicodeChar(
		_Inout_ PUCHAR *SourceCharacter
	);

	NTSYSAPI NTSTATUS NTAPI RtlUpcaseUnicodeStringToAnsiString(
		_Inout_ PANSI_STRING DestinationString,
		_In_ PUNICODE_STRING SourceString,
		_In_ BOOLEAN AllocateDestinationString
	);

	NTSYSAPI NTSTATUS NTAPI RtlOemStringToUnicodeString(
		_Inout_ PUNICODE_STRING DestinationString,
		_In_ POEM_STRING SourceString,
		_In_ BOOLEAN AllocateDestinationString
	);

	NTSYSAPI NTSTATUS NTAPI RtlUnicodeStringToOemString(
		_Inout_ POEM_STRING DestinationString,
		_In_ PUNICODE_STRING SourceString,
		_In_ BOOLEAN AllocateDestinationString
	);

	NTSYSAPI NTSTATUS NTAPI RtlUpcaseUnicodeStringToOemString(
		_Inout_ POEM_STRING DestinationString,
		_In_ PUNICODE_STRING SourceString,
		_In_ BOOLEAN AllocateDestinationString
	);

	NTSYSAPI NTSTATUS NTAPI RtlUnicodeStringToCountedOemString(
		_Inout_ POEM_STRING DestinationString,
		_In_ PUNICODE_STRING SourceString,
		_In_ BOOLEAN AllocateDestinationString
	);

	NTSYSAPI NTSTATUS NTAPI RtlUpcaseUnicodeStringToCountedOemString(
		_Inout_ POEM_STRING DestinationString,
		_In_ PUNICODE_STRING SourceString,
		_In_ BOOLEAN AllocateDestinationString
	);

	NTSYSAPI NTSTATUS NTAPI RtlMultiByteToUnicodeN(
		_Out_writes_bytes_to_(MaxBytesInUnicodeString, *BytesInUnicodeString) PWCH UnicodeString,
		_In_ ULONG MaxBytesInUnicodeString,
		_Out_opt_ PULONG BytesInUnicodeString,
		_In_reads_bytes_(BytesInMultiByteString) PSTR MultiByteString,
		_In_ ULONG BytesInMultiByteString
	);

	NTSYSAPI NTSTATUS NTAPI RtlMultiByteToUnicodeSize(
		_Out_ PULONG BytesInUnicodeString,
		_In_reads_bytes_(BytesInMultiByteString) PSTR MultiByteString,
		_In_ ULONG BytesInMultiByteString
	);

	NTSYSAPI NTSTATUS NTAPI RtlUnicodeToMultiByteN(
		_Out_writes_bytes_to_(MaxBytesInMultiByteString, *BytesInMultiByteString) PCHAR MultiByteString,
		_In_ ULONG MaxBytesInMultiByteString,
		_Out_opt_ PULONG BytesInMultiByteString,
		_In_reads_bytes_(BytesInUnicodeString) PWCH UnicodeString,
		_In_ ULONG BytesInUnicodeString
	);

	NTSYSAPI NTSTATUS NTAPI RtlUnicodeToMultiByteSize(
		_Out_ PULONG BytesInMultiByteString,
		_In_reads_bytes_(BytesInUnicodeString) PWCH UnicodeString,
		_In_ ULONG BytesInUnicodeString
	);

	NTSYSAPI NTSTATUS NTAPI RtlUpcaseUnicodeToMultiByteN(
		_Out_writes_bytes_to_(MaxBytesInMultiByteString, *BytesInMultiByteString) PCHAR MultiByteString,
		_In_ ULONG MaxBytesInMultiByteString,
		_Out_opt_ PULONG BytesInMultiByteString,
		_In_reads_bytes_(BytesInUnicodeString) PWCH UnicodeString,
		_In_ ULONG BytesInUnicodeString
	);

	NTSYSAPI NTSTATUS NTAPI RtlOemToUnicodeN(
		_Out_writes_bytes_to_(MaxBytesInUnicodeString, *BytesInUnicodeString) PWSTR UnicodeString,
		_In_ ULONG MaxBytesInUnicodeString,
		_Out_opt_ PULONG BytesInUnicodeString,
		_In_reads_bytes_(BytesInOemString) PCH OemString,
		_In_ ULONG BytesInOemString
	);

	NTSYSAPI NTSTATUS NTAPI RtlUnicodeToOemN(
		_Out_writes_bytes_to_(MaxBytesInOemString, *BytesInOemString) PCHAR OemString,
		_In_ ULONG MaxBytesInOemString,
		_Out_opt_ PULONG BytesInOemString,
		_In_reads_bytes_(BytesInUnicodeString) PWCH UnicodeString,
		_In_ ULONG BytesInUnicodeString
	);

	NTSYSAPI NTSTATUS NTAPI RtlUpcaseUnicodeToOemN(
		_Out_writes_bytes_to_(MaxBytesInOemString, *BytesInOemString) PCHAR OemString,
		_In_ ULONG MaxBytesInOemString,
		_Out_opt_ PULONG BytesInOemString,
		_In_reads_bytes_(BytesInUnicodeString) PWCH UnicodeString,
		_In_ ULONG BytesInUnicodeString
	);

	NTSYSAPI NTSTATUS NTAPI RtlConsoleMultiByteToUnicodeN(
		_Out_writes_bytes_to_(MaxBytesInUnicodeString, *BytesInUnicodeString) PWCH UnicodeString,
		_In_ ULONG MaxBytesInUnicodeString,
		_Out_opt_ PULONG BytesInUnicodeString,
		_In_reads_bytes_(BytesInMultiByteString) PCH MultiByteString,
		_In_ ULONG BytesInMultiByteString,
		_Out_ PULONG pdwSpecialChar
	);

#if (_WIN32_WINNT >= _WIN32_WINNT_WIN7)
	NTSYSAPI NTSTATUS NTAPI RtlUTF8ToUnicodeN(
		_Out_writes_bytes_to_(UnicodeStringMaxByteCount, *UnicodeStringActualByteCount) PWSTR UnicodeStringDestination,
		_In_ ULONG UnicodeStringMaxByteCount,
		_Out_ PULONG UnicodeStringActualByteCount,
		_In_reads_bytes_(UTF8StringByteCount) PCH UTF8StringSource,
		_In_ ULONG UTF8StringByteCount
	);

	NTSYSAPI NTSTATUS NTAPI RtlUnicodeToUTF8N(
		_Out_writes_bytes_to_(UTF8StringMaxByteCount, *UTF8StringActualByteCount) PCHAR UTF8StringDestination,
		_In_ ULONG UTF8StringMaxByteCount,
		_Out_ PULONG UTF8StringActualByteCount,
		_In_reads_bytes_(UnicodeStringByteCount) PWCH UnicodeStringSource,
		_In_ ULONG UnicodeStringByteCount
	);
#endif

	NTSYSAPI NTSTATUS NTAPI RtlCustomCPToUnicodeN(
		_In_ PCPTABLEINFO CustomCP,
		_Out_writes_bytes_to_(MaxBytesInUnicodeString, *BytesInUnicodeString) PWCH UnicodeString,
		_In_ ULONG MaxBytesInUnicodeString,
		_Out_opt_ PULONG BytesInUnicodeString,
		_In_reads_bytes_(BytesInCustomCPString) PCH CustomCPString,
		_In_ ULONG BytesInCustomCPString
	);

	NTSYSAPI NTSTATUS NTAPI RtlUnicodeToCustomCPN(
		_In_ PCPTABLEINFO CustomCP,
		_Out_writes_bytes_to_(MaxBytesInCustomCPString, *BytesInCustomCPString) PCH CustomCPString,
		_In_ ULONG MaxBytesInCustomCPString,
		_Out_opt_ PULONG BytesInCustomCPString,
		_In_reads_bytes_(BytesInUnicodeString) PWCH UnicodeString,
		_In_ ULONG BytesInUnicodeString
	);

	NTSYSAPI NTSTATUS NTAPI RtlUpcaseUnicodeToCustomCPN(
		_In_ PCPTABLEINFO CustomCP,
		_Out_writes_bytes_to_(MaxBytesInCustomCPString, *BytesInCustomCPString) PCH CustomCPString,
		_In_ ULONG MaxBytesInCustomCPString,
		_Out_opt_ PULONG BytesInCustomCPString,
		_In_reads_bytes_(BytesInUnicodeString) PWCH UnicodeString,
		_In_ ULONG BytesInUnicodeString
	);

	NTSYSAPI VOID NTAPI RtlInitCodePageTable(
		_In_ PUSHORT TableBase,
		_Out_ PCPTABLEINFO CodePageTable
	);

	NTSYSAPI VOID NTAPI RtlInitNlsTables(
		_In_ PUSHORT AnsiNlsBase,
		_In_ PUSHORT OemNlsBase,
		_In_ PUSHORT LanguageNlsBase,
		_Out_ PNLSTABLEINFO TableInfo
	);

	NTSYSAPI VOID NTAPI RtlResetRtlTranslations(
		_In_ PNLSTABLEINFO TableInfo
	);

	NTSYSAPI BOOLEAN NTAPI RtlIsTextUnicode(
		_In_ PVOID Buffer,
		_In_ ULONG Size,
		_Inout_opt_ PULONG Result
	);

#if (_WIN32_WINNT >= _WIN32_WINNT_VISTA)
	NTSYSAPI NTSTATUS NTAPI RtlNormalizeString(
		_In_ ULONG NormForm, // RTL_NORM_FORM
		_In_ PCWSTR SourceString,
		_In_ LONG SourceStringLength,
		_Out_writes_to_(*DestinationStringLength, *DestinationStringLength) PWSTR DestinationString,
		_Inout_ PLONG DestinationStringLength
	);
#endif

#if (_WIN32_WINNT >= _WIN32_WINNT_VISTA)
	NTSYSAPI NTSTATUS NTAPI RtlIsNormalizedString(
		_In_ ULONG NormForm, // RTL_NORM_FORM
		_In_ PCWSTR SourceString,
		_In_ LONG SourceStringLength,
		_Out_ PBOOLEAN Normalized
	);
#endif

#if (_WIN32_WINNT >= _WIN32_WINNT_WIN7)
	// ntifs:FsRtlIsNameInExpression
	NTSYSAPI BOOLEAN NTAPI RtlIsNameInExpression(
		_In_ PUNICODE_STRING Expression,
		_In_ PUNICODE_STRING Name,
		_In_ BOOLEAN IgnoreCase,
		_In_opt_ PWCH UpcaseTable
	);
#endif

	NTSYSAPI BOOLEAN NTAPI RtlEqualDomainName(
		_In_ PUNICODE_STRING String1,
		_In_ PUNICODE_STRING String2
	);

	NTSYSAPI BOOLEAN NTAPI RtlEqualComputerName(
		_In_ PUNICODE_STRING String1,
		_In_ PUNICODE_STRING String2
	);

	NTSYSAPI NTSTATUS NTAPI RtlDnsHostNameToComputerName(
		_Out_ PUNICODE_STRING ComputerNameString,
		_In_ PCUNICODE_STRING DnsHostNameString,
		_In_ BOOLEAN AllocateComputerNameString
	);

	NTSYSAPI NTSTATUS NTAPI RtlStringFromGUID(
		_In_ LPGUID Guid,
		_Out_ PUNICODE_STRING GuidString
	);

	NTSYSAPI NTSTATUS NTAPI RtlGUIDFromString(
		_In_ PUNICODE_STRING GuidString,
		_Out_ LPGUID Guid
	);

#if (_WIN32_WINNT >= _WIN32_WINNT_VISTA)
	NTSYSAPI LONG NTAPI RtlCompareAltitudes(
		_In_ PUNICODE_STRING Altitude1,
		_In_ PUNICODE_STRING Altitude2
	);
#endif
}

// 对象
extern "C"
{
	// Object, Handle

	NTSYSAPI NTSTATUS NTAPI NtQueryObject(
		_In_ HANDLE Handle,
		_In_ OBJECT_INFORMATION_CLASS ObjectInformationClass,
		_Out_writes_bytes_opt_(ObjectInformationLength) PVOID ObjectInformation,
		_In_ ULONG ObjectInformationLength,
		_Out_opt_ PULONG ReturnLength
	);

	NTSYSAPI NTSTATUS NTAPI NtSetInformationObject(
		_In_ HANDLE Handle,
		_In_ OBJECT_INFORMATION_CLASS ObjectInformationClass,
		_In_reads_bytes_(ObjectInformationLength) PVOID ObjectInformation,
		_In_ ULONG ObjectInformationLength
	);

	NTSYSAPI NTSTATUS NTAPI NtDuplicateObject(
		_In_ HANDLE SourceProcessHandle,
		_In_ HANDLE SourceHandle,
		_In_opt_ HANDLE TargetProcessHandle,
		_Out_opt_ PHANDLE TargetHandle,
		_In_ ACCESS_MASK DesiredAccess,
		_In_ ULONG HandleAttributes,
		_In_ ULONG Options
	);

	NTSYSAPI NTSTATUS NTAPI NtMakeTemporaryObject(
		_In_ HANDLE Handle
	);

	NTSYSAPI NTSTATUS NTAPI NtMakePermanentObject(
		_In_ HANDLE Handle
	);

	NTSYSAPI NTSTATUS NTAPI NtSignalAndWaitForSingleObject(
		_In_ HANDLE SignalHandle,
		_In_ HANDLE WaitHandle,
		_In_ BOOLEAN Alertable,
		_In_opt_ PLARGE_INTEGER Timeout
	);

	NTSYSAPI NTSTATUS NTAPI NtWaitForSingleObject(
		_In_ HANDLE Handle,
		_In_ BOOLEAN Alertable,
		_In_opt_ PLARGE_INTEGER Timeout
	);

	NTSYSAPI NTSTATUS NTAPI NtWaitForMultipleObjects(
		_In_ ULONG Count,
		_In_reads_(Count) HANDLE Handles[],
		_In_ WAIT_TYPE WaitType,
		_In_ BOOLEAN Alertable,
		_In_opt_ PLARGE_INTEGER Timeout
	);

#if (_WIN32_WINNT >= _WIN32_WINNT_WS03)
	NTSYSAPI NTSTATUS NTAPI NtWaitForMultipleObjects32(
		_In_ ULONG Count,
		_In_reads_(Count) LONG Handles[],
		_In_ WAIT_TYPE WaitType,
		_In_ BOOLEAN Alertable,
		_In_opt_ PLARGE_INTEGER Timeout
	);
#endif

	NTSYSAPI NTSTATUS NTAPI NtSetSecurityObject(
		_In_ HANDLE Handle,
		_In_ SECURITY_INFORMATION SecurityInformation,
		_In_ PSECURITY_DESCRIPTOR SecurityDescriptor
	);

	NTSYSAPI NTSTATUS NTAPI NtQuerySecurityObject(
		_In_ HANDLE Handle,
		_In_ SECURITY_INFORMATION SecurityInformation,
		_Out_writes_bytes_opt_(Length) PSECURITY_DESCRIPTOR SecurityDescriptor,
		_In_ ULONG Length,
		_Out_ PULONG LengthNeeded
	);

	NTSYSAPI NTSTATUS NTAPI NtClose(
		_In_ HANDLE Handle
	);

#if (_WIN32_WINNT >= _WIN32_WINNT_WIN10)
	NTSYSAPI NTSTATUS NTAPI NtCompareObjects(
		_In_ HANDLE FirstObjectHandle,
		_In_ HANDLE SecondObjectHandle
	);
#endif

	// Directory Object

	NTSYSAPI NTSTATUS NTAPI NtCreateDirectoryObject(
		_Out_ PHANDLE DirectoryHandle,
		_In_ ACCESS_MASK DesiredAccess,
		_In_ POBJECT_ATTRIBUTES ObjectAttributes
	);

#if (_WIN32_WINNT >= _WIN32_WINNT_WIN8)
	NTSYSAPI NTSTATUS NTAPI NtCreateDirectoryObjectEx(
		_Out_ PHANDLE DirectoryHandle,
		_In_ ACCESS_MASK DesiredAccess,
		_In_ POBJECT_ATTRIBUTES ObjectAttributes,
		_In_ HANDLE ShadowDirectoryHandle,
		_In_ ULONG Flags
	);
#endif

	NTSYSAPI NTSTATUS NTAPI NtOpenDirectoryObject(
		_Out_ PHANDLE DirectoryHandle,
		_In_ ACCESS_MASK DesiredAccess,
		_In_ POBJECT_ATTRIBUTES ObjectAttributes
	);

	NTSYSAPI NTSTATUS NTAPI NtQueryDirectoryObject(
		_In_ HANDLE DirectoryHandle,
		_Out_writes_bytes_opt_(Length) PVOID Buffer,
		_In_ ULONG Length,
		_In_ BOOLEAN ReturnSingleEntry,
		_In_ BOOLEAN RestartScan,
		_Inout_ PULONG Context,
		_Out_opt_ PULONG ReturnLength
	);

	// Private namespaces

#if (_WIN32_WINNT >= _WIN32_WINNT_VISTA)

	NTSYSAPI NTSTATUS NTAPI NtCreatePrivateNamespace(
		_Out_ PHANDLE NamespaceHandle,
		_In_ ACCESS_MASK DesiredAccess,
		_In_ POBJECT_ATTRIBUTES ObjectAttributes,
		_In_ PVOID BoundaryDescriptor
	);

	NTSYSAPI NTSTATUS NTAPI NtOpenPrivateNamespace(
		_Out_ PHANDLE NamespaceHandle,
		_In_ ACCESS_MASK DesiredAccess,
		_In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
		_In_ PVOID BoundaryDescriptor
	);

	NTSYSAPI NTSTATUS NTAPI NtDeletePrivateNamespace(
		_In_ HANDLE NamespaceHandle
	);

#endif

	// Symbolic links

	NTSYSAPI NTSTATUS NTAPI NtCreateSymbolicLinkObject(
		_Out_ PHANDLE LinkHandle,
		_In_ ACCESS_MASK DesiredAccess,
		_In_ POBJECT_ATTRIBUTES ObjectAttributes,
		_In_ PUNICODE_STRING LinkTarget
	);

	NTSYSAPI NTSTATUS NTAPI NtOpenSymbolicLinkObject(
		_Out_ PHANDLE LinkHandle,
		_In_ ACCESS_MASK DesiredAccess,
		_In_ POBJECT_ATTRIBUTES ObjectAttributes
	);

	NTSYSAPI NTSTATUS NTAPI NtQuerySymbolicLinkObject(
		_In_ HANDLE LinkHandle,
		_Inout_ PUNICODE_STRING LinkTarget,
		_Out_opt_ PULONG ReturnedLength
	);
}

// 内存
extern "C"
{
	// Virtual memory

	NTSYSAPI NTSTATUS NTAPI NtAllocateVirtualMemory(
		_In_ HANDLE ProcessHandle,
		_Inout_ _At_(*BaseAddress, _Readable_bytes_(*RegionSize) _Writable_bytes_(*RegionSize) _Post_readable_byte_size_(*RegionSize)) PVOID *BaseAddress,
		_In_ ULONG_PTR ZeroBits,
		_Inout_ PSIZE_T RegionSize,
		_In_ ULONG AllocationType,
		_In_ ULONG Protect
	);

	NTSYSAPI NTSTATUS NTAPI NtFreeVirtualMemory(
		_In_ HANDLE ProcessHandle,
		_Inout_ PVOID *BaseAddress,
		_Inout_ PSIZE_T RegionSize,
		_In_ ULONG FreeType
	);

	NTSYSAPI NTSTATUS NTAPI NtReadVirtualMemory(
		_In_ HANDLE ProcessHandle,
		_In_opt_ PVOID BaseAddress,
		_Out_writes_bytes_(BufferSize) PVOID Buffer,
		_In_ SIZE_T BufferSize,
		_Out_opt_ PSIZE_T NumberOfBytesRead
	);

	NTSYSAPI NTSTATUS NTAPI NtWriteVirtualMemory(
		_In_ HANDLE ProcessHandle,
		_In_opt_ PVOID BaseAddress,
		_In_reads_bytes_(BufferSize) PVOID Buffer,
		_In_ SIZE_T BufferSize,
		_Out_opt_ PSIZE_T NumberOfBytesWritten
	);

	NTSYSAPI NTSTATUS NTAPI NtProtectVirtualMemory(
		_In_ HANDLE ProcessHandle,
		_Inout_ PVOID *BaseAddress,
		_Inout_ PSIZE_T RegionSize,
		_In_ ULONG NewProtect,
		_Out_ PULONG OldProtect
	);

	NTSYSAPI NTSTATUS NTAPI NtQueryVirtualMemory(
		_In_ HANDLE ProcessHandle,
		_In_ PVOID BaseAddress,
		_In_ MEMORY_INFORMATION_CLASS MemoryInformationClass,
		_Out_writes_bytes_(MemoryInformationLength) PVOID MemoryInformation,
		_In_ SIZE_T MemoryInformationLength,
		_Out_opt_ PSIZE_T ReturnLength
	);

#if (_WIN32_WINNT >= _WIN32_WINNT_WIN10)
	NTSYSAPI NTSTATUS NTAPI NtSetInformationVirtualMemory(
		_In_ HANDLE ProcessHandle,
		_In_ VIRTUAL_MEMORY_INFORMATION_CLASS VmInformationClass,
		_In_ ULONG_PTR NumberOfEntries,
		_In_reads_(NumberOfEntries) PMEMORY_RANGE_ENTRY VirtualAddresses,
		_In_reads_bytes_(VmInformationLength) PVOID VmInformation,
		_In_ ULONG VmInformationLength
	);
#endif

	NTSYSAPI NTSTATUS NTAPI NtLockVirtualMemory(
		_In_ HANDLE ProcessHandle,
		_Inout_ PVOID *BaseAddress,
		_Inout_ PSIZE_T RegionSize,
		_In_ ULONG MapType
	);

	NTSYSAPI NTSTATUS NTAPI NtUnlockVirtualMemory(
		_In_ HANDLE ProcessHandle,
		_Inout_ PVOID *BaseAddress,
		_Inout_ PSIZE_T RegionSize,
		_In_ ULONG MapType
	);

	// Sections

	NTSYSAPI NTSTATUS NTAPI NtCreateSection(
		_Out_ PHANDLE SectionHandle,
		_In_ ACCESS_MASK DesiredAccess,
		_In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
		_In_opt_ PLARGE_INTEGER MaximumSize,
		_In_ ULONG SectionPageProtection,
		_In_ ULONG AllocationAttributes,
		_In_opt_ HANDLE FileHandle
	);

	NTSYSAPI NTSTATUS NTAPI NtOpenSection(
		_Out_ PHANDLE SectionHandle,
		_In_ ACCESS_MASK DesiredAccess,
		_In_ POBJECT_ATTRIBUTES ObjectAttributes
	);

	NTSYSAPI NTSTATUS NTAPI NtMapViewOfSection(
		_In_ HANDLE SectionHandle,
		_In_ HANDLE ProcessHandle,
		_Inout_ _At_(*BaseAddress, _Readable_bytes_(*ViewSize) _Writable_bytes_(*ViewSize) _Post_readable_byte_size_(*ViewSize)) PVOID *BaseAddress,
		_In_ ULONG_PTR ZeroBits,
		_In_ SIZE_T CommitSize,
		_Inout_opt_ PLARGE_INTEGER SectionOffset,
		_Inout_ PSIZE_T ViewSize,
		_In_ SECTION_INHERIT InheritDisposition,
		_In_ ULONG AllocationType,
		_In_ ULONG Win32Protect
	);

	NTSYSAPI NTSTATUS NTAPI NtUnmapViewOfSection(
		_In_ HANDLE ProcessHandle,
		_In_opt_ PVOID BaseAddress
	);

#if (_WIN32_WINNT >= _WIN32_WINNT_WIN8)
	NTSYSAPI NTSTATUS NTAPI NtUnmapViewOfSectionEx(
		_In_ HANDLE ProcessHandle,
		_In_opt_ PVOID BaseAddress,
		_In_ ULONG Flags
	);
#endif

	NTSYSAPI NTSTATUS NTAPI NtExtendSection(
		_In_ HANDLE SectionHandle,
		_Inout_ PLARGE_INTEGER NewSectionSize
	);

	NTSYSAPI NTSTATUS NTAPI NtQuerySection(
		_In_ HANDLE SectionHandle,
		_In_ SECTION_INFORMATION_CLASS SectionInformationClass,
		_Out_writes_bytes_(SectionInformationLength) PVOID SectionInformation,
		_In_ SIZE_T SectionInformationLength,
		_Out_opt_ PSIZE_T ReturnLength
	);

	NTSYSAPI NTSTATUS NTAPI NtAreMappedFilesTheSame(
		_In_ PVOID File1MappedAsAnImage,
		_In_ PVOID File2MappedAsFile
	);

	// Partitions

#if (_WIN32_WINNT >= _WIN32_WINNT_WIN10)

	NTSYSAPI NTSTATUS NTAPI NtCreatePartition(
		_Out_ PHANDLE PartitionHandle,
		_In_ ACCESS_MASK DesiredAccess,
		_In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
		_In_ ULONG PreferredNode
	);

	NTSYSAPI NTSTATUS NTAPI NtOpenPartition(
		_Out_ PHANDLE PartitionHandle,
		_In_ ACCESS_MASK DesiredAccess,
		_In_ POBJECT_ATTRIBUTES ObjectAttributes
	);

	NTSYSAPI NTSTATUS NTAPI NtManagePartition(
		_In_ MEMORY_PARTITION_INFORMATION_CLASS PartitionInformationClass,
		_In_ PVOID PartitionInformation,
		_In_ ULONG PartitionInformationLength
	);

#endif

	// User physical pages

	NTSYSAPI NTSTATUS NTAPI NtMapUserPhysicalPages(
		_In_ PVOID VirtualAddress,
		_In_ ULONG_PTR NumberOfPages,
		_In_reads_opt_(NumberOfPages) PULONG_PTR UserPfnArray
	);

	NTSYSAPI NTSTATUS NTAPI NtMapUserPhysicalPagesScatter(
		_In_reads_(NumberOfPages) PVOID *VirtualAddresses,
		_In_ ULONG_PTR NumberOfPages,
		_In_reads_opt_(NumberOfPages) PULONG_PTR UserPfnArray
	);

	NTSYSAPI NTSTATUS NTAPI NtAllocateUserPhysicalPages(
		_In_ HANDLE ProcessHandle,
		_Inout_ PULONG_PTR NumberOfPages,
		_Out_writes_(*NumberOfPages) PULONG_PTR UserPfnArray
	);

	NTSYSAPI NTSTATUS NTAPI NtFreeUserPhysicalPages(
		_In_ HANDLE ProcessHandle,
		_Inout_ PULONG_PTR NumberOfPages,
		_In_reads_(*NumberOfPages) PULONG_PTR UserPfnArray
	);

	// Sessions

#if (_WIN32_WINNT >= _WIN32_WINNT_VISTA)
	NTSYSAPI NTSTATUS NTAPI NtOpenSession(
		_Out_ PHANDLE SessionHandle,
		_In_ ACCESS_MASK DesiredAccess,
		_In_ POBJECT_ATTRIBUTES ObjectAttributes
	);
#endif

	// Misc.

	NTSYSAPI NTSTATUS NTAPI NtGetWriteWatch(
		_In_ HANDLE ProcessHandle,
		_In_ ULONG Flags,
		_In_ PVOID BaseAddress,
		_In_ SIZE_T RegionSize,
		_Out_writes_(*EntriesInUserAddressArray) PVOID *UserAddressArray,
		_Inout_ PULONG_PTR EntriesInUserAddressArray,
		_Out_ PULONG Granularity
	);

	NTSYSAPI NTSTATUS NTAPI NtResetWriteWatch(
		_In_ HANDLE ProcessHandle,
		_In_ PVOID BaseAddress,
		_In_ SIZE_T RegionSize
	);

	NTSYSAPI NTSTATUS NTAPI NtCreatePagingFile(
		_In_ PUNICODE_STRING PageFileName,
		_In_ PLARGE_INTEGER MinimumSize,
		_In_ PLARGE_INTEGER MaximumSize,
		_In_ ULONG Priority
	);

	NTSYSAPI NTSTATUS NTAPI NtFlushInstructionCache(
		_In_ HANDLE ProcessHandle,
		_In_opt_ PVOID BaseAddress,
		_In_ SIZE_T Length
	);

	NTSYSAPI NTSTATUS NTAPI NtFlushWriteBuffer(
		VOID
	);
}

// 堆
extern "C"
{
	NTSYSAPI PVOID NTAPI RtlCreateHeap(
		_In_ ULONG Flags,
		_In_opt_ PVOID HeapBase,
		_In_opt_ SIZE_T ReserveSize,
		_In_opt_ SIZE_T CommitSize,
		_In_opt_ PVOID Lock,
		_In_opt_ PRTL_HEAP_PARAMETERS Parameters
	);

	NTSYSAPI PVOID NTAPI RtlDestroyHeap(
		_Frees_ptr_ PVOID HeapHandle
	);

	NTSYSAPI PVOID NTAPI RtlAllocateHeap(
		_In_ PVOID HeapHandle,
		_In_opt_ ULONG Flags,
		_In_ SIZE_T Size
	);

	NTSYSAPI BOOLEAN NTAPI RtlFreeHeap(
		_In_ PVOID HeapHandle,
		_In_opt_ ULONG Flags,
		_Frees_ptr_opt_ PVOID BaseAddress
	);

	NTSYSAPI SIZE_T NTAPI RtlSizeHeap(
		_In_ PVOID HeapHandle,
		_In_ ULONG Flags,
		_In_ PVOID BaseAddress
	);

	NTSYSAPI NTSTATUS NTAPI RtlZeroHeap(
		_In_ PVOID HeapHandle,
		_In_ ULONG Flags
	);

	NTSYSAPI VOID NTAPI RtlProtectHeap(
		_In_ PVOID HeapHandle,
		_In_ BOOLEAN MakeReadOnly
	);

	NTSYSAPI BOOLEAN NTAPI RtlLockHeap(
		_In_ PVOID HeapHandle
	);

	NTSYSAPI BOOLEAN NTAPI RtlUnlockHeap(
		_In_ PVOID HeapHandle
	);

	NTSYSAPI PVOID NTAPI RtlReAllocateHeap(
		_In_ PVOID HeapHandle,
		_In_ ULONG Flags,
		_Frees_ptr_opt_ PVOID BaseAddress,
		_In_ SIZE_T Size
	);

	NTSYSAPI BOOLEAN NTAPI RtlGetUserInfoHeap(
		_In_ PVOID HeapHandle,
		_In_ ULONG Flags,
		_In_ PVOID BaseAddress,
		_Out_opt_ PVOID *UserValue,
		_Out_opt_ PULONG UserFlags
	);

	NTSYSAPI BOOLEAN NTAPI RtlSetUserValueHeap(
		_In_ PVOID HeapHandle,
		_In_ ULONG Flags,
		_In_ PVOID BaseAddress,
		_In_ PVOID UserValue
	);

	NTSYSAPI BOOLEAN NTAPI RtlSetUserFlagsHeap(
		_In_ PVOID HeapHandle,
		_In_ ULONG Flags,
		_In_ PVOID BaseAddress,
		_In_ ULONG UserFlagsReset,
		_In_ ULONG UserFlagsSet
	);

	NTSYSAPI ULONG NTAPI RtlCreateTagHeap(
		_In_ PVOID HeapHandle,
		_In_ ULONG Flags,
		_In_opt_ PWSTR TagPrefix,
		_In_ PWSTR TagNames
	);

	NTSYSAPI PWSTR NTAPI RtlQueryTagHeap(
		_In_ PVOID HeapHandle,
		_In_ ULONG Flags,
		_In_ USHORT TagIndex,
		_In_ BOOLEAN ResetCounters,
		_Out_opt_ PRTL_HEAP_TAG_INFO TagInfo
	);

	NTSYSAPI NTSTATUS NTAPI RtlExtendHeap(
		_In_ PVOID HeapHandle,
		_In_ ULONG Flags,
		_In_ PVOID Base,
		_In_ SIZE_T Size
	);

	NTSYSAPI SIZE_T NTAPI RtlCompactHeap(
		_In_ PVOID HeapHandle,
		_In_ ULONG Flags
	);

	NTSYSAPI BOOLEAN NTAPI RtlValidateHeap(
		_In_ PVOID HeapHandle,
		_In_ ULONG Flags,
		_In_ PVOID BaseAddress
	);

	NTSYSAPI BOOLEAN NTAPI RtlValidateProcessHeaps(
		VOID
	);

	NTSYSAPI ULONG NTAPI RtlGetProcessHeaps(
		_In_ ULONG NumberOfHeaps,
		_Out_ PVOID *ProcessHeaps
	);

	NTSYSAPI NTSTATUS NTAPI RtlEnumProcessHeaps(
		_In_ PRTL_ENUM_HEAPS_ROUTINE EnumRoutine,
		_In_ PVOID Parameter
	);

	NTSYSAPI NTSTATUS NTAPI RtlUsageHeap(
		_In_ PVOID HeapHandle,
		_In_ ULONG Flags,
		_Inout_ PRTL_HEAP_USAGE Usage
	);

	NTSYSAPI NTSTATUS NTAPI RtlWalkHeap(
		_In_ PVOID HeapHandle,
		_Inout_ PRTL_HEAP_WALK_ENTRY Entry
	);

	NTSYSAPI NTSTATUS NTAPI RtlQueryHeapInformation(
		_In_ PVOID HeapHandle,
		_In_ HEAP_INFORMATION_CLASS HeapInformationClass,
		_Out_opt_ PVOID HeapInformation,
		_In_opt_ SIZE_T HeapInformationLength,
		_Out_opt_ PSIZE_T ReturnLength
	);

	NTSYSAPI NTSTATUS NTAPI RtlSetHeapInformation(
		_In_ PVOID HeapHandle,
		_In_ HEAP_INFORMATION_CLASS HeapInformationClass,
		_In_opt_ PVOID HeapInformation,
		_In_opt_ SIZE_T HeapInformationLength
	);

	NTSYSAPI ULONG NTAPI RtlMultipleAllocateHeap(
		_In_ PVOID HeapHandle,
		_In_ ULONG Flags,
		_In_ SIZE_T Size,
		_In_ ULONG Count,
		_Out_ PVOID *Array
	);

	NTSYSAPI ULONG NTAPI RtlMultipleFreeHeap(
		_In_ PVOID HeapHandle,
		_In_ ULONG Flags,
		_In_ ULONG Count,
		_In_ PVOID *Array
	);

#if (_WIN32_WINNT >= _WIN32_WINNT_WIN7)
	NTSYSAPI VOID NTAPI RtlDetectHeapLeaks(
		VOID
	);
#endif
}

// 系统信息
extern "C"
{
	NTSYSAPI NTSTATUS NTAPI NtQuerySystemInformation(
		_In_ SYSTEM_INFORMATION_CLASS SystemInformationClass,
		_Out_writes_bytes_opt_(SystemInformationLength) PVOID SystemInformation,
		_In_ ULONG SystemInformationLength,
		_Out_opt_ PULONG ReturnLength
	);

#if (_WIN32_WINNT >= _WIN32_WINNT_WIN7)
	NTSYSAPI NTSTATUS NTAPI NtQuerySystemInformationEx(
		_In_ SYSTEM_INFORMATION_CLASS SystemInformationClass,
		_In_reads_bytes_(InputBufferLength) PVOID InputBuffer,
		_In_ ULONG InputBufferLength,
		_Out_writes_bytes_opt_(SystemInformationLength) PVOID SystemInformation,
		_In_ ULONG SystemInformationLength,
		_Out_opt_ PULONG ReturnLength
	);
#endif

	NTSYSAPI NTSTATUS NTAPI NtSetSystemInformation(
		_In_ SYSTEM_INFORMATION_CLASS SystemInformationClass,
		_In_reads_bytes_opt_(SystemInformationLength) PVOID SystemInformation,
		_In_ ULONG SystemInformationLength
	);
}

// IO (文件)
extern "C"
{
	NTSYSAPI NTSTATUS NTAPI NtCreateFile(
		_Out_ PHANDLE FileHandle,
		_In_ ACCESS_MASK DesiredAccess,
		_In_ POBJECT_ATTRIBUTES ObjectAttributes,
		_Out_ PIO_STATUS_BLOCK IoStatusBlock,
		_In_opt_ PLARGE_INTEGER AllocationSize,
		_In_ ULONG FileAttributes,
		_In_ ULONG ShareAccess,
		_In_ ULONG CreateDisposition,
		_In_ ULONG CreateOptions,
		_In_reads_bytes_opt_(EaLength) PVOID EaBuffer,
		_In_ ULONG EaLength
	);

	NTSYSAPI NTSTATUS NTAPI NtCreateNamedPipeFile(
		_Out_ PHANDLE FileHandle,
		_In_ ULONG DesiredAccess,
		_In_ POBJECT_ATTRIBUTES ObjectAttributes,
		_Out_ PIO_STATUS_BLOCK IoStatusBlock,
		_In_ ULONG ShareAccess,
		_In_ ULONG CreateDisposition,
		_In_ ULONG CreateOptions,
		_In_ ULONG NamedPipeType,
		_In_ ULONG ReadMode,
		_In_ ULONG CompletionMode,
		_In_ ULONG MaximumInstances,
		_In_ ULONG InboundQuota,
		_In_ ULONG OutboundQuota,
		_In_opt_ PLARGE_INTEGER DefaultTimeout
	);

	NTSYSAPI NTSTATUS NTAPI NtCreateMailslotFile(
		_Out_ PHANDLE FileHandle,
		_In_ ULONG DesiredAccess,
		_In_ POBJECT_ATTRIBUTES ObjectAttributes,
		_Out_ PIO_STATUS_BLOCK IoStatusBlock,
		_In_ ULONG CreateOptions,
		_In_ ULONG MailslotQuota,
		_In_ ULONG MaximumMessageSize,
		_In_ PLARGE_INTEGER ReadTimeout
	);

	NTSYSAPI NTSTATUS NTAPI NtOpenFile(
		_Out_ PHANDLE FileHandle,
		_In_ ACCESS_MASK DesiredAccess,
		_In_ POBJECT_ATTRIBUTES ObjectAttributes,
		_Out_ PIO_STATUS_BLOCK IoStatusBlock,
		_In_ ULONG ShareAccess,
		_In_ ULONG OpenOptions
	);

	NTSYSAPI NTSTATUS NTAPI NtDeleteFile(
		_In_ POBJECT_ATTRIBUTES ObjectAttributes
	);

	NTSYSAPI NTSTATUS NTAPI NtFlushBuffersFile(
		_In_ HANDLE FileHandle,
		_Out_ PIO_STATUS_BLOCK IoStatusBlock
	);

#if (_WIN32_WINNT >= _WIN32_WINNT_WIN8)
	NTSYSAPI NTSTATUS NTAPI NtFlushBuffersFileEx(
		_In_ HANDLE FileHandle,
		_In_ ULONG Flags,
		_In_reads_bytes_(ParametersSize) PVOID Parameters,
		_In_ ULONG ParametersSize,
		_Out_ PIO_STATUS_BLOCK IoStatusBlock
	);
#endif

	NTSYSAPI NTSTATUS NTAPI NtQueryInformationFile(
		_In_ HANDLE FileHandle,
		_Out_ PIO_STATUS_BLOCK IoStatusBlock,
		_Out_writes_bytes_(Length) PVOID FileInformation,
		_In_ ULONG Length,
		_In_ FILE_INFORMATION_CLASS FileInformationClass
	);

	NTSYSAPI NTSTATUS NTAPI NtSetInformationFile(
		_In_ HANDLE FileHandle,
		_Out_ PIO_STATUS_BLOCK IoStatusBlock,
		_In_reads_bytes_(Length) PVOID FileInformation,
		_In_ ULONG Length,
		_In_ FILE_INFORMATION_CLASS FileInformationClass
	);

	NTSYSAPI NTSTATUS NTAPI NtQueryDirectoryFile(
		_In_ HANDLE FileHandle,
		_In_opt_ HANDLE Event,
		_In_opt_ PIO_APC_ROUTINE ApcRoutine,
		_In_opt_ PVOID ApcContext,
		_Out_ PIO_STATUS_BLOCK IoStatusBlock,
		_Out_writes_bytes_(Length) PVOID FileInformation,
		_In_ ULONG Length,
		_In_ FILE_INFORMATION_CLASS FileInformationClass,
		_In_ BOOLEAN ReturnSingleEntry,
		_In_opt_ PUNICODE_STRING FileName,
		_In_ BOOLEAN RestartScan
	);

	NTSYSAPI NTSTATUS NTAPI NtQueryEaFile(
		_In_ HANDLE FileHandle,
		_Out_ PIO_STATUS_BLOCK IoStatusBlock,
		_Out_writes_bytes_(Length) PVOID Buffer,
		_In_ ULONG Length,
		_In_ BOOLEAN ReturnSingleEntry,
		_In_reads_bytes_opt_(EaListLength) PVOID EaList,
		_In_ ULONG EaListLength,
		_In_opt_ PULONG EaIndex,
		_In_ BOOLEAN RestartScan
	);

	NTSYSAPI NTSTATUS NTAPI NtSetEaFile(
		_In_ HANDLE FileHandle,
		_Out_ PIO_STATUS_BLOCK IoStatusBlock,
		_In_reads_bytes_(Length) PVOID Buffer,
		_In_ ULONG Length
	);

	NTSYSAPI NTSTATUS NTAPI NtQueryQuotaInformationFile(
		_In_ HANDLE FileHandle,
		_Out_ PIO_STATUS_BLOCK IoStatusBlock,
		_Out_writes_bytes_(Length) PVOID Buffer,
		_In_ ULONG Length,
		_In_ BOOLEAN ReturnSingleEntry,
		_In_reads_bytes_opt_(SidListLength) PVOID SidList,
		_In_ ULONG SidListLength,
		_In_opt_ PSID StartSid,
		_In_ BOOLEAN RestartScan
	);

	NTSYSAPI NTSTATUS NTAPI NtSetQuotaInformationFile(
		_In_ HANDLE FileHandle,
		_Out_ PIO_STATUS_BLOCK IoStatusBlock,
		_In_reads_bytes_(Length) PVOID Buffer,
		_In_ ULONG Length
	);

	NTSYSAPI NTSTATUS NTAPI NtQueryVolumeInformationFile(
		_In_ HANDLE FileHandle,
		_Out_ PIO_STATUS_BLOCK IoStatusBlock,
		_Out_writes_bytes_(Length) PVOID FsInformation,
		_In_ ULONG Length,
		_In_ FSINFOCLASS FsInformationClass
	);

	NTSYSAPI NTSTATUS NTAPI NtSetVolumeInformationFile(
		_In_ HANDLE FileHandle,
		_Out_ PIO_STATUS_BLOCK IoStatusBlock,
		_In_reads_bytes_(Length) PVOID FsInformation,
		_In_ ULONG Length,
		_In_ FSINFOCLASS FsInformationClass
	);

	NTSYSAPI NTSTATUS NTAPI NtCancelIoFile(
		_In_ HANDLE FileHandle,
		_Out_ PIO_STATUS_BLOCK IoStatusBlock
	);

#if (_WIN32_WINNT >= _WIN32_WINNT_VISTA)
	NTSYSAPI NTSTATUS NTAPI NtCancelIoFileEx(
		_In_ HANDLE FileHandle,
		_In_opt_ PIO_STATUS_BLOCK IoRequestToCancel,
		_Out_ PIO_STATUS_BLOCK IoStatusBlock
	);

	NTSYSAPI NTSTATUS NTAPI NtCancelSynchronousIoFile(
		_In_ HANDLE ThreadHandle,
		_In_opt_ PIO_STATUS_BLOCK IoRequestToCancel,
		_Out_ PIO_STATUS_BLOCK IoStatusBlock
	);
#endif

	NTSYSAPI NTSTATUS NTAPI NtDeviceIoControlFile(
		_In_ HANDLE FileHandle,
		_In_opt_ HANDLE Event,
		_In_opt_ PIO_APC_ROUTINE ApcRoutine,
		_In_opt_ PVOID ApcContext,
		_Out_ PIO_STATUS_BLOCK IoStatusBlock,
		_In_ ULONG IoControlCode,
		_In_reads_bytes_opt_(InputBufferLength) PVOID InputBuffer,
		_In_ ULONG InputBufferLength,
		_Out_writes_bytes_opt_(OutputBufferLength) PVOID OutputBuffer,
		_In_ ULONG OutputBufferLength
	);

	NTSYSAPI NTSTATUS NTAPI NtFsControlFile(
		_In_ HANDLE FileHandle,
		_In_opt_ HANDLE Event,
		_In_opt_ PIO_APC_ROUTINE ApcRoutine,
		_In_opt_ PVOID ApcContext,
		_Out_ PIO_STATUS_BLOCK IoStatusBlock,
		_In_ ULONG FsControlCode,
		_In_reads_bytes_opt_(InputBufferLength) PVOID InputBuffer,
		_In_ ULONG InputBufferLength,
		_Out_writes_bytes_opt_(OutputBufferLength) PVOID OutputBuffer,
		_In_ ULONG OutputBufferLength
	);

	NTSYSAPI NTSTATUS NTAPI NtReadFile(
		_In_ HANDLE FileHandle,
		_In_opt_ HANDLE Event,
		_In_opt_ PIO_APC_ROUTINE ApcRoutine,
		_In_opt_ PVOID ApcContext,
		_Out_ PIO_STATUS_BLOCK IoStatusBlock,
		_Out_writes_bytes_(Length) PVOID Buffer,
		_In_ ULONG Length,
		_In_opt_ PLARGE_INTEGER ByteOffset,
		_In_opt_ PULONG Key
	);

	NTSYSAPI NTSTATUS NTAPI NtWriteFile(
		_In_ HANDLE FileHandle,
		_In_opt_ HANDLE Event,
		_In_opt_ PIO_APC_ROUTINE ApcRoutine,
		_In_opt_ PVOID ApcContext,
		_Out_ PIO_STATUS_BLOCK IoStatusBlock,
		_In_reads_bytes_(Length) PVOID Buffer,
		_In_ ULONG Length,
		_In_opt_ PLARGE_INTEGER ByteOffset,
		_In_opt_ PULONG Key
	);

	NTSYSAPI NTSTATUS NTAPI NtReadFileScatter(
		_In_ HANDLE FileHandle,
		_In_opt_ HANDLE Event,
		_In_opt_ PIO_APC_ROUTINE ApcRoutine,
		_In_opt_ PVOID ApcContext,
		_Out_ PIO_STATUS_BLOCK IoStatusBlock,
		_In_ PFILE_SEGMENT_ELEMENT SegmentArray,
		_In_ ULONG Length,
		_In_opt_ PLARGE_INTEGER ByteOffset,
		_In_opt_ PULONG Key
	);

	NTSYSAPI NTSTATUS NTAPI NtWriteFileGather(
		_In_ HANDLE FileHandle,
		_In_opt_ HANDLE Event,
		_In_opt_ PIO_APC_ROUTINE ApcRoutine,
		_In_opt_ PVOID ApcContext,
		_Out_ PIO_STATUS_BLOCK IoStatusBlock,
		_In_ PFILE_SEGMENT_ELEMENT SegmentArray,
		_In_ ULONG Length,
		_In_opt_ PLARGE_INTEGER ByteOffset,
		_In_opt_ PULONG Key
	);

	NTSYSAPI NTSTATUS NTAPI NtLockFile(
		_In_ HANDLE FileHandle,
		_In_opt_ HANDLE Event,
		_In_opt_ PIO_APC_ROUTINE ApcRoutine,
		_In_opt_ PVOID ApcContext,
		_Out_ PIO_STATUS_BLOCK IoStatusBlock,
		_In_ PLARGE_INTEGER ByteOffset,
		_In_ PLARGE_INTEGER Length,
		_In_ ULONG Key,
		_In_ BOOLEAN FailImmediately,
		_In_ BOOLEAN ExclusiveLock
	);

	NTSYSAPI NTSTATUS NTAPI NtUnlockFile(
		_In_ HANDLE FileHandle,
		_Out_ PIO_STATUS_BLOCK IoStatusBlock,
		_In_ PLARGE_INTEGER ByteOffset,
		_In_ PLARGE_INTEGER Length,
		_In_ ULONG Key
	);

	NTSYSAPI NTSTATUS NTAPI NtQueryAttributesFile(
		_In_ POBJECT_ATTRIBUTES ObjectAttributes,
		_Out_ PFILE_BASIC_INFORMATION FileInformation
	);

	NTSYSAPI NTSTATUS NTAPI NtQueryFullAttributesFile(
		_In_ POBJECT_ATTRIBUTES ObjectAttributes,
		_Out_ PFILE_NETWORK_OPEN_INFORMATION FileInformation
	);

	NTSYSAPI NTSTATUS NTAPI NtNotifyChangeDirectoryFile(
		_In_ HANDLE FileHandle,
		_In_opt_ HANDLE Event,
		_In_opt_ PIO_APC_ROUTINE ApcRoutine,
		_In_opt_ PVOID ApcContext,
		_Out_ PIO_STATUS_BLOCK IoStatusBlock,
		_Out_writes_bytes_(Length) PVOID Buffer, // FILE_NOTIFY_INFORMATION
		_In_ ULONG Length,
		_In_ ULONG CompletionFilter,
		_In_ BOOLEAN WatchTree
	);
}

// 时间
extern "C"
{
	NTSYSAPI BOOLEAN NTAPI RtlCutoverTimeToSystemTime(
		_In_ PTIME_FIELDS CutoverTime,
		_Out_ PLARGE_INTEGER SystemTime,
		_In_ PLARGE_INTEGER CurrentSystemTime,
		_In_ BOOLEAN ThisYear
	);

	NTSYSAPI NTSTATUS NTAPI RtlSystemTimeToLocalTime(
		_In_ PLARGE_INTEGER SystemTime,
		_Out_ PLARGE_INTEGER LocalTime
	);

	NTSYSAPI NTSTATUS NTAPI RtlLocalTimeToSystemTime(
		_In_ PLARGE_INTEGER LocalTime,
		_Out_ PLARGE_INTEGER SystemTime
	);

	NTSYSAPI VOID NTAPI RtlTimeToElapsedTimeFields(
		_In_ PLARGE_INTEGER Time,
		_Out_ PTIME_FIELDS TimeFields
	);

	NTSYSAPI VOID NTAPI RtlTimeToTimeFields(
		_In_ PLARGE_INTEGER Time,
		_Out_ PTIME_FIELDS TimeFields
	);

	NTSYSAPI BOOLEAN NTAPI RtlTimeFieldsToTime(
		_In_ PTIME_FIELDS TimeFields, // Weekday is ignored
		_Out_ PLARGE_INTEGER Time
	);

	NTSYSAPI BOOLEAN NTAPI RtlTimeToSecondsSince1980(
		_In_ PLARGE_INTEGER Time,
		_Out_ PULONG ElapsedSeconds
	);

	NTSYSAPI VOID NTAPI RtlSecondsSince1980ToTime(
		_In_ ULONG ElapsedSeconds,
		_Out_ PLARGE_INTEGER Time
	);

	NTSYSAPI BOOLEAN NTAPI RtlTimeToSecondsSince1970(
		_In_ PLARGE_INTEGER Time,
		_Out_ PULONG ElapsedSeconds
	);

	NTSYSAPI VOID NTAPI RtlSecondsSince1970ToTime(
		_In_ ULONG ElapsedSeconds,
		_Out_ PLARGE_INTEGER Time
	);
}

// 时区
extern "C"
{
	NTSYSAPI NTSTATUS NTAPI RtlQueryTimeZoneInformation(
		_Out_ PRTL_TIME_ZONE_INFORMATION TimeZoneInformation
	);

	NTSYSAPI NTSTATUS NTAPI RtlSetTimeZoneInformation(
		_In_ PRTL_TIME_ZONE_INFORMATION TimeZoneInformation
	);
}

// 随机
extern "C"
{
	NTSYSAPI ULONG NTAPI RtlUniform(
		_Inout_ PULONG Seed
	);

	NTSYSAPI ULONG NTAPI RtlRandom(
		_Inout_ PULONG Seed
	);

	NTSYSAPI ULONG NTAPI RtlRandomEx(
		_Inout_ PULONG Seed
	);

	NTSYSAPI NTSTATUS NTAPI RtlComputeImportTableHash(
		_In_ HANDLE hFile,
		_Out_writes_bytes_(16) PCHAR Hash,
		_In_ ULONG ImportTableHashRevision // must be 1
	);
}

// 性能计数
extern "C"
{
	NTSYSAPI NTSTATUS NTAPI NtQueryPerformanceCounter(
		_Out_ PLARGE_INTEGER PerformanceCounter,
		_Out_opt_ PLARGE_INTEGER PerformanceFrequency
	);
}

// 驱动加载
extern "C"
{
	NTSYSAPI NTSTATUS NTAPI NtLoadDriver(
		_In_ PUNICODE_STRING DriverServiceName
	);

	NTSYSAPI NTSTATUS NTAPI NtUnloadDriver(
		_In_ PUNICODE_STRING DriverServiceName
	);
}

// 令牌
extern "C"
{
	NTSYSAPI NTSTATUS NTAPI NtCreateToken(
		_Out_ PHANDLE TokenHandle,
		_In_ ACCESS_MASK DesiredAccess,
		_In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
		_In_ TOKEN_TYPE TokenType,
		_In_ PLUID AuthenticationId,
		_In_ PLARGE_INTEGER ExpirationTime,
		_In_ PTOKEN_USER User,
		_In_ PTOKEN_GROUPS Groups,
		_In_ PTOKEN_PRIVILEGES Privileges,
		_In_opt_ PTOKEN_OWNER Owner,
		_In_ PTOKEN_PRIMARY_GROUP PrimaryGroup,
		_In_opt_ PTOKEN_DEFAULT_DACL DefaultDacl,
		_In_ PTOKEN_SOURCE TokenSource
	);

#if (_WIN32_WINNT >= _WIN32_WINNT_WIN8)
	NTSYSAPI NTSTATUS NTAPI NtCreateLowBoxToken(
		_Out_ PHANDLE TokenHandle,
		_In_ HANDLE ExistingTokenHandle,
		_In_ ACCESS_MASK DesiredAccess,
		_In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
		_In_ PSID PackageSid,
		_In_ ULONG CapabilityCount,
		_In_reads_opt_(CapabilityCount) PSID_AND_ATTRIBUTES Capabilities,
		_In_ ULONG HandleCount,
		_In_reads_opt_(HandleCount) HANDLE *Handles
	);

	NTSYSAPI NTSTATUS NTAPI NtCreateTokenEx(
		_Out_ PHANDLE TokenHandle,
		_In_ ACCESS_MASK DesiredAccess,
		_In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
		_In_ TOKEN_TYPE TokenType,
		_In_ PLUID AuthenticationId,
		_In_ PLARGE_INTEGER ExpirationTime,
		_In_ PTOKEN_USER User,
		_In_ PTOKEN_GROUPS Groups,
		_In_ PTOKEN_PRIVILEGES Privileges,
		_In_opt_ PTOKEN_SECURITY_ATTRIBUTES_INFORMATION UserAttributes,
		_In_opt_ PTOKEN_SECURITY_ATTRIBUTES_INFORMATION DeviceAttributes,
		_In_opt_ PTOKEN_GROUPS DeviceGroups,
		_In_opt_ PTOKEN_MANDATORY_POLICY TokenMandatoryPolicy,
		_In_opt_ PTOKEN_OWNER Owner,
		_In_ PTOKEN_PRIMARY_GROUP PrimaryGroup,
		_In_opt_ PTOKEN_DEFAULT_DACL DefaultDacl,
		_In_ PTOKEN_SOURCE TokenSource
	);
#endif

	NTSYSAPI NTSTATUS NTAPI NtOpenProcessToken(
		_In_ HANDLE ProcessHandle,
		_In_ ACCESS_MASK DesiredAccess,
		_Out_ PHANDLE TokenHandle
	);

	NTSYSAPI NTSTATUS NTAPI NtOpenProcessTokenEx(
		_In_ HANDLE ProcessHandle,
		_In_ ACCESS_MASK DesiredAccess,
		_In_ ULONG HandleAttributes,
		_Out_ PHANDLE TokenHandle
	);

	NTSYSAPI NTSTATUS NTAPI NtOpenThreadToken(
		_In_ HANDLE ThreadHandle,
		_In_ ACCESS_MASK DesiredAccess,
		_In_ BOOLEAN OpenAsSelf,
		_Out_ PHANDLE TokenHandle
	);

	NTSYSAPI NTSTATUS NTAPI NtOpenThreadTokenEx(
		_In_ HANDLE ThreadHandle,
		_In_ ACCESS_MASK DesiredAccess,
		_In_ BOOLEAN OpenAsSelf,
		_In_ ULONG HandleAttributes,
		_Out_ PHANDLE TokenHandle
	);

	NTSYSAPI NTSTATUS NTAPI NtDuplicateToken(
		_In_ HANDLE ExistingTokenHandle,
		_In_ ACCESS_MASK DesiredAccess,
		_In_ POBJECT_ATTRIBUTES ObjectAttributes,
		_In_ BOOLEAN EffectiveOnly,
		_In_ TOKEN_TYPE TokenType,
		_Out_ PHANDLE NewTokenHandle
	);

	NTSYSAPI NTSTATUS NTAPI NtQueryInformationToken(
		_In_ HANDLE TokenHandle,
		_In_ TOKEN_INFORMATION_CLASS TokenInformationClass,
		_Out_writes_bytes_(TokenInformationLength) PVOID TokenInformation,
		_In_ ULONG TokenInformationLength,
		_Out_ PULONG ReturnLength
	);

	NTSYSAPI NTSTATUS NTAPI NtSetInformationToken(
		_In_ HANDLE TokenHandle,
		_In_ TOKEN_INFORMATION_CLASS TokenInformationClass,
		_In_reads_bytes_(TokenInformationLength) PVOID TokenInformation,
		_In_ ULONG TokenInformationLength
	);

	NTSYSAPI NTSTATUS NTAPI NtAdjustPrivilegesToken(
		_In_ HANDLE TokenHandle,
		_In_ BOOLEAN DisableAllPrivileges,
		_In_opt_ PTOKEN_PRIVILEGES NewState,
		_In_ ULONG BufferLength,
		_Out_writes_bytes_to_opt_(BufferLength, *ReturnLength) PTOKEN_PRIVILEGES PreviousState,
		_Out_ _When_(PreviousState == NULL, _Out_opt_) PULONG ReturnLength
	);

	NTSYSAPI NTSTATUS NTAPI NtAdjustGroupsToken(
		_In_ HANDLE TokenHandle,
		_In_ BOOLEAN ResetToDefault,
		_In_opt_ PTOKEN_GROUPS NewState,
		_In_opt_ ULONG BufferLength,
		_Out_writes_bytes_to_opt_(BufferLength, *ReturnLength) PTOKEN_GROUPS PreviousState,
		_Out_ PULONG ReturnLength
	);

#if (_WIN32_WINNT >= _WIN32_WINNT_WIN8)
	NTSYSAPI NTSTATUS NTAPI NtAdjustTokenClaimsAndDeviceGroups(
		_In_ HANDLE TokenHandle,
		_In_ BOOLEAN UserResetToDefault,
		_In_ BOOLEAN DeviceResetToDefault,
		_In_ BOOLEAN DeviceGroupsResetToDefault,
		_In_opt_ PTOKEN_SECURITY_ATTRIBUTES_INFORMATION NewUserState,
		_In_opt_ PTOKEN_SECURITY_ATTRIBUTES_INFORMATION NewDeviceState,
		_In_opt_ PTOKEN_GROUPS NewDeviceGroupsState,
		_In_ ULONG UserBufferLength,
		_Out_writes_bytes_to_opt_(UserBufferLength, *UserReturnLength) PTOKEN_SECURITY_ATTRIBUTES_INFORMATION PreviousUserState,
		_In_ ULONG DeviceBufferLength,
		_Out_writes_bytes_to_opt_(DeviceBufferLength, *DeviceReturnLength) PTOKEN_SECURITY_ATTRIBUTES_INFORMATION PreviousDeviceState,
		_In_ ULONG DeviceGroupsBufferLength,
		_Out_writes_bytes_to_opt_(DeviceGroupsBufferLength, *DeviceGroupsReturnBufferLength) PTOKEN_GROUPS PreviousDeviceGroups,
		_Out_opt_ PULONG UserReturnLength,
		_Out_opt_ PULONG DeviceReturnLength,
		_Out_opt_ PULONG DeviceGroupsReturnBufferLength
	);
#endif

	NTSYSAPI NTSTATUS NTAPI NtFilterToken(
		_In_ HANDLE ExistingTokenHandle,
		_In_ ULONG Flags,
		_In_opt_ PTOKEN_GROUPS SidsToDisable,
		_In_opt_ PTOKEN_PRIVILEGES PrivilegesToDelete,
		_In_opt_ PTOKEN_GROUPS RestrictedSids,
		_Out_ PHANDLE NewTokenHandle
	);

#if (_WIN32_WINNT >= _WIN32_WINNT_WIN8)
	NTSYSAPI NTSTATUS NTAPI NtFilterTokenEx(
		_In_ HANDLE ExistingTokenHandle,
		_In_ ULONG Flags,
		_In_opt_ PTOKEN_GROUPS SidsToDisable,
		_In_opt_ PTOKEN_PRIVILEGES PrivilegesToDelete,
		_In_opt_ PTOKEN_GROUPS RestrictedSids,
		_In_ ULONG DisableUserClaimsCount,
		_In_opt_ PUNICODE_STRING UserClaimsToDisable,
		_In_ ULONG DisableDeviceClaimsCount,
		_In_opt_ PUNICODE_STRING DeviceClaimsToDisable,
		_In_opt_ PTOKEN_GROUPS DeviceGroupsToDisable,
		_In_opt_ PTOKEN_SECURITY_ATTRIBUTES_INFORMATION RestrictedUserAttributes,
		_In_opt_ PTOKEN_SECURITY_ATTRIBUTES_INFORMATION RestrictedDeviceAttributes,
		_In_opt_ PTOKEN_GROUPS RestrictedDeviceGroups,
		_Out_ PHANDLE NewTokenHandle
	);
#endif

	NTSYSAPI NTSTATUS NTAPI NtCompareTokens(
		_In_ HANDLE FirstTokenHandle,
		_In_ HANDLE SecondTokenHandle,
		_Out_ PBOOLEAN Equal
	);

	NTSYSAPI NTSTATUS NTAPI NtPrivilegeCheck(
		_In_ HANDLE ClientToken,
		_Inout_ PPRIVILEGE_SET RequiredPrivileges,
		_Out_ PBOOLEAN Result
	);

	NTSYSAPI NTSTATUS NTAPI NtImpersonateAnonymousToken(
		_In_ HANDLE ThreadHandle
	);

#if (_WIN32_WINNT >= _WIN32_WINNT_WIN7)
	// rev
	NTSYSAPI NTSTATUS NTAPI NtQuerySecurityAttributesToken(
		_In_ HANDLE TokenHandle,
		_In_reads_opt_(NumberOfAttributes) PUNICODE_STRING Attributes,
		_In_ ULONG NumberOfAttributes,
		_Out_writes_bytes_(Length) PVOID Buffer, // PTOKEN_SECURITY_ATTRIBUTES_INFORMATION
		_In_ ULONG Length,
		_Out_ PULONG ReturnLength
	);
#endif

}

// 进程
extern "C"
{
	// Processes

	NTSYSAPI NTSTATUS NTAPI NtCreateProcess(
		_Out_ PHANDLE ProcessHandle,
		_In_ ACCESS_MASK DesiredAccess,
		_In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
		_In_ HANDLE ParentProcess,
		_In_ BOOLEAN InheritObjectTable,
		_In_opt_ HANDLE SectionHandle,
		_In_opt_ HANDLE DebugPort,
		_In_opt_ HANDLE ExceptionPort
	);

	NTSYSAPI NTSTATUS NTAPI NtCreateProcessEx(
		_Out_ PHANDLE ProcessHandle,
		_In_ ACCESS_MASK DesiredAccess,
		_In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
		_In_ HANDLE ParentProcess,
		_In_ ULONG Flags,
		_In_opt_ HANDLE SectionHandle,
		_In_opt_ HANDLE DebugPort,
		_In_opt_ HANDLE ExceptionPort,
		_In_ ULONG JobMemberLevel
	);

	NTSYSAPI NTSTATUS NTAPI NtOpenProcess(
		_Out_ PHANDLE ProcessHandle,
		_In_ ACCESS_MASK DesiredAccess,
		_In_ POBJECT_ATTRIBUTES ObjectAttributes,
		_In_opt_ PCLIENT_ID ClientId
	);

	NTSYSAPI NTSTATUS NTAPI NtTerminateProcess(
		_In_opt_ HANDLE ProcessHandle,
		_In_ NTSTATUS ExitStatus
	);

	NTSYSAPI NTSTATUS NTAPI NtSuspendProcess(
		_In_ HANDLE ProcessHandle
	);

	NTSYSAPI NTSTATUS NTAPI NtResumeProcess(
		_In_ HANDLE ProcessHandle
	);

	NTSYSAPI NTSTATUS NTAPI NtQueryInformationProcess(
		_In_ HANDLE ProcessHandle,
		_In_ PROCESSINFOCLASS ProcessInformationClass,
		_Out_writes_bytes_(ProcessInformationLength) PVOID ProcessInformation,
		_In_ ULONG ProcessInformationLength,
		_Out_opt_ PULONG ReturnLength
	);

#if (PHNT_VERSION >= PHNT_WS03)
	NTSYSAPI NTSTATUS NTAPI NtGetNextProcess(
		_In_ HANDLE ProcessHandle,
		_In_ ACCESS_MASK DesiredAccess,
		_In_ ULONG HandleAttributes,
		_In_ ULONG Flags,
		_Out_ PHANDLE NewProcessHandle
	);
#endif

#if (_WIN32_WINNT >= _WIN32_WINNT_WS03)
	NTSYSAPI NTSTATUS NTAPI NtGetNextThread(
		_In_ HANDLE ProcessHandle,
		_In_ HANDLE ThreadHandle,
		_In_ ACCESS_MASK DesiredAccess,
		_In_ ULONG HandleAttributes,
		_In_ ULONG Flags,
		_Out_ PHANDLE NewThreadHandle
	);
#endif

	NTSYSAPI NTSTATUS NTAPI NtSetInformationProcess(
		_In_ HANDLE ProcessHandle,
		_In_ PROCESSINFOCLASS ProcessInformationClass,
		_In_reads_bytes_(ProcessInformationLength) PVOID ProcessInformation,
		_In_ ULONG ProcessInformationLength
	);

	NTSYSAPI NTSTATUS NTAPI NtQueryPortInformationProcess(
		VOID
	);

	// Threads

	NTSYSAPI NTSTATUS NTAPI NtCreateThread(
		_Out_ PHANDLE ThreadHandle,
		_In_ ACCESS_MASK DesiredAccess,
		_In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
		_In_ HANDLE ProcessHandle,
		_Out_ PCLIENT_ID ClientId,
		_In_ PCONTEXT ThreadContext,
		_In_ PINITIAL_TEB InitialTeb,
		_In_ BOOLEAN CreateSuspended
	);

	NTSYSAPI NTSTATUS NTAPI NtOpenThread(
		_Out_ PHANDLE ThreadHandle,
		_In_ ACCESS_MASK DesiredAccess,
		_In_ POBJECT_ATTRIBUTES ObjectAttributes,
		_In_opt_ PCLIENT_ID ClientId
	);

	NTSYSAPI NTSTATUS NTAPI NtTerminateThread(
		_In_opt_ HANDLE ThreadHandle,
		_In_ NTSTATUS ExitStatus
	);

	NTSYSAPI NTSTATUS NTAPI NtSuspendThread(
		_In_ HANDLE ThreadHandle,
		_Out_opt_ PULONG PreviousSuspendCount
	);

	NTSYSAPI NTSTATUS NTAPI NtResumeThread(
		_In_ HANDLE ThreadHandle,
		_Out_opt_ PULONG PreviousSuspendCount
	);

	NTSYSAPI ULONG NTAPI NtGetCurrentProcessorNumber(
		VOID
	);

	NTSYSAPI NTSTATUS NTAPI NtGetContextThread(
		_In_ HANDLE ThreadHandle,
		_Inout_ PCONTEXT ThreadContext
	);

	NTSYSAPI NTSTATUS NTAPI NtSetContextThread(
		_In_ HANDLE ThreadHandle,
		_In_ PCONTEXT ThreadContext
	);

	NTSYSAPI NTSTATUS NTAPI NtQueryInformationThread(
		_In_ HANDLE ThreadHandle,
		_In_ THREADINFOCLASS ThreadInformationClass,
		_Out_writes_bytes_(ThreadInformationLength) PVOID ThreadInformation,
		_In_ ULONG ThreadInformationLength,
		_Out_opt_ PULONG ReturnLength
	);

	NTSYSAPI NTSTATUS NTAPI NtSetInformationThread(
		_In_ HANDLE ThreadHandle,
		_In_ THREADINFOCLASS ThreadInformationClass,
		_In_reads_bytes_(ThreadInformationLength) PVOID ThreadInformation,
		_In_ ULONG ThreadInformationLength
	);

	NTSYSAPI NTSTATUS NTAPI NtAlertThread(
		_In_ HANDLE ThreadHandle
	);

	NTSYSAPI NTSTATUS NTAPI NtAlertResumeThread(
		_In_ HANDLE ThreadHandle,
		_Out_opt_ PULONG PreviousSuspendCount
	);

	NTSYSAPI NTSTATUS NTAPI NtTestAlert(
		VOID
	);

	NTSYSAPI NTSTATUS NTAPI NtImpersonateThread(
		_In_ HANDLE ServerThreadHandle,
		_In_ HANDLE ClientThreadHandle,
		_In_ PSECURITY_QUALITY_OF_SERVICE SecurityQos
	);

	NTSYSAPI NTSTATUS NTAPI NtRegisterThreadTerminatePort(
		_In_ HANDLE PortHandle
	);

	NTSYSAPI NTSTATUS NTAPI NtSetLdtEntries(
		_In_ ULONG Selector0,
		_In_ ULONG Entry0Low,
		_In_ ULONG Entry0Hi,
		_In_ ULONG Selector1,
		_In_ ULONG Entry1Low,
		_In_ ULONG Entry1Hi
	);


	NTSYSAPI NTSTATUS NTAPI NtQueueApcThread(
		_In_ HANDLE ThreadHandle,
		_In_ PPS_APC_ROUTINE ApcRoutine,
		_In_opt_ PVOID ApcArgument1,
		_In_opt_ PVOID ApcArgument2,
		_In_opt_ PVOID ApcArgument3
	);

#if (_WIN32_WINNT >= _WIN32_WINNT_WIN7)
	NTSYSAPI NTSTATUS NTAPI NtQueueApcThreadEx(
		_In_ HANDLE ThreadHandle,
		_In_opt_ HANDLE UserApcReserveHandle,
		_In_ PPS_APC_ROUTINE ApcRoutine,
		_In_opt_ PVOID ApcArgument1,
		_In_opt_ PVOID ApcArgument2,
		_In_opt_ PVOID ApcArgument3
	);
#endif

#if (_WIN32_WINNT >= _WIN32_WINNT_WIN8)

	// rev
	NTSYSAPI NTSTATUS NTAPI NtAlertThreadByThreadId(
		_In_ HANDLE ThreadId
	);

	// rev
	NTSYSAPI NTSTATUS NTAPI NtWaitForAlertByThreadId(
		_In_ PVOID Address,
		_In_opt_ PLARGE_INTEGER Timeout
	);

#endif

	// User processes and threads

#if (_WIN32_WINNT >= _WIN32_WINNT_VISTA)
	NTSYSAPI NTSTATUS NTAPI NtCreateUserProcess(
		_Out_ PHANDLE ProcessHandle,
		_Out_ PHANDLE ThreadHandle,
		_In_ ACCESS_MASK ProcessDesiredAccess,
		_In_ ACCESS_MASK ThreadDesiredAccess,
		_In_opt_ POBJECT_ATTRIBUTES ProcessObjectAttributes,
		_In_opt_ POBJECT_ATTRIBUTES ThreadObjectAttributes,
		_In_ ULONG ProcessFlags, // PROCESS_CREATE_FLAGS_*
		_In_ ULONG ThreadFlags, // THREAD_CREATE_FLAGS_*
		_In_opt_ PVOID ProcessParameters, // PRTL_USER_PROCESS_PARAMETERS
		_Inout_ PPS_CREATE_INFO CreateInfo,
		_In_opt_ PPS_ATTRIBUTE_LIST AttributeList
	);

	NTSYSAPI NTSTATUS NTAPI NtCreateThreadEx(
		_Out_ PHANDLE ThreadHandle,
		_In_ ACCESS_MASK DesiredAccess,
		_In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
		_In_ HANDLE ProcessHandle,
		_In_ PVOID StartRoutine, // PUSER_THREAD_START_ROUTINE
		_In_opt_ PVOID Argument,
		_In_ ULONG CreateFlags, // THREAD_CREATE_FLAGS_*
		_In_ SIZE_T ZeroBits,
		_In_ SIZE_T StackSize,
		_In_ SIZE_T MaximumStackSize,
		_In_opt_ PPS_ATTRIBUTE_LIST AttributeList
	);
#endif

	// Job objects

	NTSYSAPI NTSTATUS NTAPI NtCreateJobObject(
		_Out_ PHANDLE JobHandle,
		_In_ ACCESS_MASK DesiredAccess,
		_In_opt_ POBJECT_ATTRIBUTES ObjectAttributes
	);

	NTSYSAPI NTSTATUS NTAPI NtOpenJobObject(
		_Out_ PHANDLE JobHandle,
		_In_ ACCESS_MASK DesiredAccess,
		_In_ POBJECT_ATTRIBUTES ObjectAttributes
	);

	NTSYSAPI NTSTATUS NTAPI NtAssignProcessToJobObject(
		_In_ HANDLE JobHandle,
		_In_ HANDLE ProcessHandle
	);

	NTSYSAPI NTSTATUS NTAPI NtTerminateJobObject(
		_In_ HANDLE JobHandle,
		_In_ NTSTATUS ExitStatus
	);

	NTSYSAPI NTSTATUS NTAPI NtIsProcessInJob(
		_In_ HANDLE ProcessHandle,
		_In_opt_ HANDLE JobHandle
	);

	NTSYSAPI NTSTATUS NTAPI NtQueryInformationJobObject(
		_In_opt_ HANDLE JobHandle,
		_In_ JOBOBJECTINFOCLASS JobObjectInformationClass,
		_Out_writes_bytes_(JobObjectInformationLength) PVOID JobObjectInformation,
		_In_ ULONG JobObjectInformationLength,
		_Out_opt_ PULONG ReturnLength
	);

	NTSYSAPI NTSTATUS NTAPI NtSetInformationJobObject(
		_In_ HANDLE JobHandle,
		_In_ JOBOBJECTINFOCLASS JobObjectInformationClass,
		_In_reads_bytes_(JobObjectInformationLength) PVOID JobObjectInformation,
		_In_ ULONG JobObjectInformationLength
	);

	NTSYSAPI NTSTATUS NTAPI NtCreateJobSet(
		_In_ ULONG NumJob,
		_In_reads_(NumJob) PJOB_SET_ARRAY UserJobSet,
		_In_ ULONG Flags
	);

#if (_WIN32_WINNT >= _WIN32_WINNT_WIN10)
	NTSYSAPI NTSTATUS NTAPI NtRevertContainerImpersonation(
		VOID
	);
#endif

	// Reserve objects

#if (_WIN32_WINNT >= _WIN32_WINNT_WIN7)
	NTSYSAPI NTSTATUS NTAPI NtAllocateReserveObject(
		_Out_ PHANDLE MemoryReserveHandle,
		_In_ POBJECT_ATTRIBUTES ObjectAttributes,
		_In_ MEMORY_RESERVE_TYPE Type
	);
#endif

	// Process

	NTSYSAPI NTSTATUS NTAPI RtlCreateProcessParameters(
		_Out_ PRTL_USER_PROCESS_PARAMETERS *pProcessParameters,
		_In_ PUNICODE_STRING ImagePathName,
		_In_opt_ PUNICODE_STRING DllPath,
		_In_opt_ PUNICODE_STRING CurrentDirectory,
		_In_opt_ PUNICODE_STRING CommandLine,
		_In_opt_ PVOID Environment,
		_In_opt_ PUNICODE_STRING WindowTitle,
		_In_opt_ PUNICODE_STRING DesktopInfo,
		_In_opt_ PUNICODE_STRING ShellInfo,
		_In_opt_ PUNICODE_STRING RuntimeData
	);

#if (_WIN32_WINNT >= _WIN32_WINNT_VISTA)
	// private
	NTSYSAPI NTSTATUS NTAPI RtlCreateProcessParametersEx(
		_Out_ PRTL_USER_PROCESS_PARAMETERS *pProcessParameters,
		_In_ PUNICODE_STRING ImagePathName,
		_In_opt_ PUNICODE_STRING DllPath,
		_In_opt_ PUNICODE_STRING CurrentDirectory,
		_In_opt_ PUNICODE_STRING CommandLine,
		_In_opt_ PVOID Environment,
		_In_opt_ PUNICODE_STRING WindowTitle,
		_In_opt_ PUNICODE_STRING DesktopInfo,
		_In_opt_ PUNICODE_STRING ShellInfo,
		_In_opt_ PUNICODE_STRING RuntimeData,
		_In_ ULONG Flags // pass RTL_USER_PROC_PARAMS_NORMALIZED to keep parameters normalized
	);
#endif

	NTSYSAPI NTSTATUS NTAPI RtlDestroyProcessParameters(
		_In_ _Post_invalid_ PRTL_USER_PROCESS_PARAMETERS ProcessParameters
	);

	NTSYSAPI PRTL_USER_PROCESS_PARAMETERS NTAPI RtlNormalizeProcessParams(
		_Inout_ PRTL_USER_PROCESS_PARAMETERS ProcessParameters
	);

	NTSYSAPI PRTL_USER_PROCESS_PARAMETERS NTAPI RtlDeNormalizeProcessParams(
		_Inout_ PRTL_USER_PROCESS_PARAMETERS ProcessParameters
	);

	// private
	NTSYSAPI NTSTATUS NTAPI RtlCreateUserProcess(
		_In_ PUNICODE_STRING NtImagePathName,
		_In_ ULONG AttributesDeprecated,
		_In_ PRTL_USER_PROCESS_PARAMETERS ProcessParameters,
		_In_opt_ PSECURITY_DESCRIPTOR ProcessSecurityDescriptor,
		_In_opt_ PSECURITY_DESCRIPTOR ThreadSecurityDescriptor,
		_In_opt_ HANDLE ParentProcess,
		_In_ BOOLEAN InheritHandles,
		_In_opt_ HANDLE DebugPort,
		_In_opt_ HANDLE TokenHandle, // used to be ExceptionPort
		_Out_ PRTL_USER_PROCESS_INFORMATION ProcessInformation
	);

#if (_WIN32_WINNT >= _WIN32_WINNT_VISTA)
	DECLSPEC_NORETURN NTSYSAPI VOID NTAPI RtlExitUserProcess(
		_In_ NTSTATUS ExitStatus
	);
#endif

#if (_WIN32_WINNT >= _WIN32_WINNT_VISTA)

	// private
	NTSYSAPI NTSTATUS NTAPI RtlCloneUserProcess(
		_In_ ULONG ProcessFlags,
		_In_opt_ PSECURITY_DESCRIPTOR ProcessSecurityDescriptor,
		_In_opt_ PSECURITY_DESCRIPTOR ThreadSecurityDescriptor,
		_In_opt_ HANDLE DebugPort,
		_Out_ PRTL_USER_PROCESS_INFORMATION ProcessInformation
	);

	// private
	NTSYSAPI VOID NTAPI RtlUpdateClonedCriticalSection(
		_Inout_ PRTL_CRITICAL_SECTION CriticalSection
	);

	// private
	NTSYSAPI VOID NTAPI RtlUpdateClonedSRWLock(
		_Inout_ PRTL_SRWLOCK SRWLock,
		_In_ LOGICAL Shared // TRUE to set to shared acquire
	);

#endif

#if (_WIN32_WINNT >= _WIN32_WINNT_WIN7)
	// rev
	NTSYSAPI NTSTATUS NTAPI RtlCreateProcessReflection(
		_In_ HANDLE ProcessHandle,
		_In_ ULONG Flags,
		_In_opt_ PVOID StartRoutine,
		_In_opt_ PVOID StartContext,
		_In_opt_ HANDLE EventHandle,
		_Out_opt_ PRTLP_PROCESS_REFLECTION_REFLECTION_INFORMATION ReflectionInformation
	);
#endif

	// Threads

	NTSYSAPI NTSTATUS NTAPI RtlCreateUserThread(
		_In_ HANDLE Process,
		_In_opt_ PSECURITY_DESCRIPTOR ThreadSecurityDescriptor,
		_In_ BOOLEAN CreateSuspended,
		_In_opt_ ULONG ZeroBits,
		_In_opt_ SIZE_T MaximumStackSize,
		_In_opt_ SIZE_T CommittedStackSize,
		_In_ PUSER_THREAD_START_ROUTINE StartAddress,
		_In_opt_ PVOID Parameter,
		_Out_opt_ PHANDLE Thread,
		_Out_opt_ PCLIENT_ID ClientId
	);

#if (_WIN32_WINNT >= _WIN32_WINNT_VISTA) // should be _WIN32_WINNT_WINXP, but is _WIN32_WINNT_VISTA for consistency with RtlExitUserProcess
	DECLSPEC_NORETURN NTSYSAPI VOID NTAPI RtlExitUserThread(
		_In_ NTSTATUS ExitStatus
	);
#endif

#if (_WIN32_WINNT >= _WIN32_WINNT_VISTA)

	// private
	NTSYSAPI NTSTATUS NTAPI RtlCreateUserStack(
		_In_opt_ SIZE_T CommittedStackSize,
		_In_opt_ SIZE_T MaximumStackSize,
		_In_opt_ ULONG_PTR ZeroBits,
		_In_ SIZE_T PageSize,
		_In_ ULONG_PTR ReserveAlignment,
		_Out_ PINITIAL_TEB InitialTeb
	);

	// private
	NTSYSAPI NTSTATUS NTAPI RtlFreeUserStack(
		_In_ PVOID AllocationBase
	);

#endif

	NTSYSAPI VOID NTAPI RtlInitializeContext(
		_In_ HANDLE Process,
		_Out_ PCONTEXT Context,
		_In_opt_ PVOID Parameter,
		_In_opt_ PVOID InitialPc,
		_In_opt_ PVOID InitialSp
	);

	NTSYSAPI NTSTATUS NTAPI RtlRemoteCall(
		_In_ HANDLE Process,
		_In_ HANDLE Thread,
		_In_ PVOID CallSite,
		_In_ ULONG ArgumentCount,
		_In_opt_ PULONG_PTR Arguments,
		_In_ BOOLEAN PassContext,
		_In_ BOOLEAN AlreadySuspended
	);

#ifdef _WIN64
	// rev
	NTSYSAPI NTSTATUS NTAPI RtlWow64GetThreadContext(
		_In_ HANDLE ThreadHandle,
		_Inout_ PWOW64_CONTEXT ThreadContext
	);
#endif

#ifdef _WIN64
	// rev
	NTSYSAPI NTSTATUS NTAPI RtlWow64SetThreadContext(
		_In_ HANDLE ThreadHandle,
		_In_ PWOW64_CONTEXT ThreadContext
	);
#endif

}

// SID, SD, Access masks, ACL, ACE
extern "C"
{
	// SIDs

	_Check_return_ NTSYSAPI BOOLEAN NTAPI RtlValidSid(
		_In_ PSID Sid
	);

	_Check_return_ NTSYSAPI BOOLEAN NTAPI RtlEqualSid(
		_In_ PSID Sid1,
		_In_ PSID Sid2
	);

	NTSYSAPI ULONG NTAPI RtlLengthRequiredSid(
		_In_ ULONG SubAuthorityCount
	);

	NTSYSAPI PVOID NTAPI RtlFreeSid(
		_In_ _Post_invalid_ PSID Sid
	);

	_Check_return_ NTSYSAPI NTSTATUS NTAPI RtlAllocateAndInitializeSid(
		_In_ PSID_IDENTIFIER_AUTHORITY IdentifierAuthority,
		_In_ UCHAR SubAuthorityCount,
		_In_ ULONG SubAuthority0,
		_In_ ULONG SubAuthority1,
		_In_ ULONG SubAuthority2,
		_In_ ULONG SubAuthority3,
		_In_ ULONG SubAuthority4,
		_In_ ULONG SubAuthority5,
		_In_ ULONG SubAuthority6,
		_In_ ULONG SubAuthority7,
		_Outptr_ PSID *Sid
	);

	NTSYSAPI NTSTATUS NTAPI RtlInitializeSid(
		_Out_ PSID Sid,
		_In_ PSID_IDENTIFIER_AUTHORITY IdentifierAuthority,
		_In_ UCHAR SubAuthorityCount
	);

#if (_WIN32_WINNT >= _WIN32_WINNT_WIN10)
	NTSYSAPI NTSTATUS NTAPI RtlInitializeSidEx(
		_Out_writes_bytes_(SECURITY_SID_SIZE(SubAuthorityCount)) PSID Sid,
		_In_ PSID_IDENTIFIER_AUTHORITY IdentifierAuthority,
		_In_ UCHAR SubAuthorityCount,
		...
	);
#endif

	NTSYSAPI PSID_IDENTIFIER_AUTHORITY NTAPI RtlIdentifierAuthoritySid(
		_In_ PSID Sid
	);

	NTSYSAPI PULONG NTAPI RtlSubAuthoritySid(
		_In_ PSID Sid,
		_In_ ULONG SubAuthority
	);

	NTSYSAPI PUCHAR NTAPI RtlSubAuthorityCountSid(
		_In_ PSID Sid
	);

	NTSYSAPI ULONG NTAPI RtlLengthSid(
		_In_ PSID Sid
	);

	NTSYSAPI NTSTATUS NTAPI RtlCopySid(
		_In_ ULONG DestinationSidLength,
		_In_reads_bytes_(DestinationSidLength) PSID DestinationSid,
		_In_ PSID SourceSid
	);

#if (_WIN32_WINNT >= _WIN32_WINNT_VISTA)
	NTSYSAPI NTSTATUS NTAPI RtlCreateServiceSid(
		_In_ PUNICODE_STRING ServiceName,
		_Out_writes_bytes_opt_(*ServiceSidLength) PSID ServiceSid,
		_Inout_ PULONG ServiceSidLength
	);

	// private
	NTSYSAPI NTSTATUS NTAPI RtlSidDominates(
		_In_ PSID Sid1,
		_In_ PSID Sid2,
		_Out_ PBOOLEAN pbDominate
	);

	// private
	NTSYSAPI NTSTATUS NTAPI RtlSidEqualLevel(
		_In_ PSID Sid1,
		_In_ PSID Sid2,
		_Out_ PBOOLEAN pbEqual
	);

	// private
	NTSYSAPI NTSTATUS NTAPI RtlSidIsHigherLevel(
		_In_ PSID Sid1,
		_In_ PSID Sid2,
		_Out_ PBOOLEAN pbHigher
	);
#endif

#if (_WIN32_WINNT >= _WIN32_WINNT_WIN7)
	NTSYSAPI NTSTATUS NTAPI RtlCreateVirtualAccountSid(
		_In_ PUNICODE_STRING Name,
		_In_ ULONG BaseSubAuthority,
		_Out_writes_bytes_(*SidLength) PSID Sid,
		_Inout_ PULONG SidLength
	);

	NTSYSAPI NTSTATUS NTAPI RtlReplaceSidInSd(
		_Inout_ PSECURITY_DESCRIPTOR SecurityDescriptor,
		_In_ PSID OldSid,
		_In_ PSID NewSid,
		_Out_ ULONG *NumChanges
	);
#endif

	NTSYSAPI NTSTATUS NTAPI RtlConvertSidToUnicodeString(
		_Inout_ PUNICODE_STRING UnicodeString,
		_In_ PSID Sid,
		_In_ BOOLEAN AllocateDestinationString
	);

#if (_WIN32_WINNT >= _WIN32_WINNT_VISTA)
	// private
	NTSYSAPI NTSTATUS NTAPI RtlSidHashInitialize(
		_In_reads_(SidCount) PSID_AND_ATTRIBUTES SidAttr,
		_In_ ULONG SidCount,
		_Out_ PSID_AND_ATTRIBUTES_HASH SidAttrHash
	);

	// private
	NTSYSAPI PSID_AND_ATTRIBUTES NTAPI RtlSidHashLookup(
		_In_ PSID_AND_ATTRIBUTES_HASH SidAttrHash,
		_In_ PSID Sid
	);
#endif

	// Security Descriptors

	NTSYSAPI NTSTATUS NTAPI RtlCreateSecurityDescriptor(
		_Out_ PSECURITY_DESCRIPTOR SecurityDescriptor,
		_In_ ULONG Revision
	);

	_Check_return_ NTSYSAPI BOOLEAN NTAPI RtlValidSecurityDescriptor(
		_In_ PSECURITY_DESCRIPTOR SecurityDescriptor
	);

	NTSYSAPI ULONG NTAPI RtlLengthSecurityDescriptor(
		_In_ PSECURITY_DESCRIPTOR SecurityDescriptor
	);

	_Check_return_ NTSYSAPI BOOLEAN NTAPI RtlValidRelativeSecurityDescriptor(
		_In_reads_bytes_(SecurityDescriptorLength) PSECURITY_DESCRIPTOR SecurityDescriptorInput,
		_In_ ULONG SecurityDescriptorLength,
		_In_ SECURITY_INFORMATION RequiredInformation
	);

	NTSYSAPI NTSTATUS NTAPI RtlGetControlSecurityDescriptor(
		_In_ PSECURITY_DESCRIPTOR SecurityDescriptor,
		_Out_ PSECURITY_DESCRIPTOR_CONTROL Control,
		_Out_ PULONG Revision
	);

	NTSYSAPI NTSTATUS NTAPI RtlSetControlSecurityDescriptor(
		_Inout_ PSECURITY_DESCRIPTOR SecurityDescriptor,
		_In_ SECURITY_DESCRIPTOR_CONTROL ControlBitsOfInterest,
		_In_ SECURITY_DESCRIPTOR_CONTROL ControlBitsToSet
	);

	NTSYSAPI NTSTATUS NTAPI RtlSetAttributesSecurityDescriptor(
		_Inout_ PSECURITY_DESCRIPTOR SecurityDescriptor,
		_In_ SECURITY_DESCRIPTOR_CONTROL Control,
		_Out_ PULONG Revision
	);

	NTSYSAPI BOOLEAN NTAPI RtlGetSecurityDescriptorRMControl(
		_In_ PSECURITY_DESCRIPTOR SecurityDescriptor,
		_Out_ PUCHAR RMControl
	);

	NTSYSAPI VOID NTAPI RtlSetSecurityDescriptorRMControl(
		_Inout_ PSECURITY_DESCRIPTOR SecurityDescriptor,
		_In_opt_ PUCHAR RMControl
	);

	NTSYSAPI NTSTATUS NTAPI RtlSetDaclSecurityDescriptor(
		_Inout_ PSECURITY_DESCRIPTOR SecurityDescriptor,
		_In_ BOOLEAN DaclPresent,
		_In_opt_ PACL Dacl,
		_In_opt_ BOOLEAN DaclDefaulted
	);

	NTSYSAPI NTSTATUS NTAPI RtlGetDaclSecurityDescriptor(
		_In_ PSECURITY_DESCRIPTOR SecurityDescriptor,
		_Out_ PBOOLEAN DaclPresent,
		_Out_ PACL *Dacl,
		_Out_ PBOOLEAN DaclDefaulted
	);

	NTSYSAPI NTSTATUS NTAPI RtlSetSaclSecurityDescriptor(
		_Inout_ PSECURITY_DESCRIPTOR SecurityDescriptor,
		_In_ BOOLEAN SaclPresent,
		_In_opt_ PACL Sacl,
		_In_opt_ BOOLEAN SaclDefaulted
	);

	NTSYSAPI NTSTATUS NTAPI RtlGetSaclSecurityDescriptor(
		_In_ PSECURITY_DESCRIPTOR SecurityDescriptor,
		_Out_ PBOOLEAN SaclPresent,
		_Out_ PACL *Sacl,
		_Out_ PBOOLEAN SaclDefaulted
	);

	NTSYSAPI NTSTATUS NTAPI RtlGetSaclSecurityDescriptor(
		_In_ PSECURITY_DESCRIPTOR SecurityDescriptor,
		_Out_ PBOOLEAN SaclPresent,
		_Out_ PACL *Sacl,
		_Out_ PBOOLEAN SaclDefaulted
	);

	NTSYSAPI NTSTATUS NTAPI RtlSetOwnerSecurityDescriptor(
		_Inout_ PSECURITY_DESCRIPTOR SecurityDescriptor,
		_In_opt_ PSID Owner,
		_In_opt_ BOOLEAN OwnerDefaulted
	);

	NTSYSAPI NTSTATUS NTAPI RtlGetOwnerSecurityDescriptor(
		_In_ PSECURITY_DESCRIPTOR SecurityDescriptor,
		_Out_ PSID *Owner,
		_Out_ PBOOLEAN OwnerDefaulted
	);

	NTSYSAPI NTSTATUS NTAPI RtlSetGroupSecurityDescriptor(
		_Inout_ PSECURITY_DESCRIPTOR SecurityDescriptor,
		_In_opt_ PSID Group,
		_In_opt_ BOOLEAN GroupDefaulted
	);

	NTSYSAPI NTSTATUS NTAPI RtlGetGroupSecurityDescriptor(
		_In_ PSECURITY_DESCRIPTOR SecurityDescriptor,
		_Out_ PSID *Group,
		_Out_ PBOOLEAN GroupDefaulted
	);

	NTSYSAPI NTSTATUS NTAPI RtlMakeSelfRelativeSD(
		_In_ PSECURITY_DESCRIPTOR AbsoluteSecurityDescriptor,
		_Out_writes_bytes_(*BufferLength) PSECURITY_DESCRIPTOR SelfRelativeSecurityDescriptor,
		_Inout_ PULONG BufferLength
	);

	NTSYSAPI NTSTATUS NTAPI RtlAbsoluteToSelfRelativeSD(
		_In_ PSECURITY_DESCRIPTOR AbsoluteSecurityDescriptor,
		_Out_writes_bytes_to_opt_(*BufferLength, *BufferLength) PSECURITY_DESCRIPTOR SelfRelativeSecurityDescriptor,
		_Inout_ PULONG BufferLength
	);

	NTSYSAPI NTSTATUS NTAPI RtlSelfRelativeToAbsoluteSD(
		_In_ PSECURITY_DESCRIPTOR SelfRelativeSecurityDescriptor,
		_Out_writes_bytes_to_opt_(*AbsoluteSecurityDescriptorSize, *AbsoluteSecurityDescriptorSize) PSECURITY_DESCRIPTOR AbsoluteSecurityDescriptor,
		_Inout_ PULONG AbsoluteSecurityDescriptorSize,
		_Out_writes_bytes_to_opt_(*DaclSize, *DaclSize) PACL Dacl,
		_Inout_ PULONG DaclSize,
		_Out_writes_bytes_to_opt_(*SaclSize, *SaclSize) PACL Sacl,
		_Inout_ PULONG SaclSize,
		_Out_writes_bytes_to_opt_(*OwnerSize, *OwnerSize) PSID Owner,
		_Inout_ PULONG OwnerSize,
		_Out_writes_bytes_to_opt_(*PrimaryGroupSize, *PrimaryGroupSize) PSID PrimaryGroup,
		_Inout_ PULONG PrimaryGroupSize
	);

	// private
	NTSYSAPI NTSTATUS NTAPI RtlSelfRelativeToAbsoluteSD2(
		_Inout_ PSECURITY_DESCRIPTOR pSelfRelativeSecurityDescriptor,
		_Inout_ PULONG pBufferSize
	);

	// Access masks

	NTSYSAPI BOOLEAN NTAPI RtlAreAllAccessesGranted(
		_In_ ACCESS_MASK GrantedAccess,
		_In_ ACCESS_MASK DesiredAccess
	);

	NTSYSAPI BOOLEAN NTAPI RtlAreAnyAccessesGranted(
		_In_ ACCESS_MASK GrantedAccess,
		_In_ ACCESS_MASK DesiredAccess
	);

	NTSYSAPI VOID NTAPI RtlMapGenericMask(
		_Inout_ PACCESS_MASK AccessMask,
		_In_ PGENERIC_MAPPING GenericMapping
	);

	// ACLs

	NTSYSAPI NTSTATUS NTAPI RtlCreateAcl(
		_Out_writes_bytes_(AclLength) PACL Acl,
		_In_ ULONG AclLength,
		_In_ ULONG AclRevision
	);

	NTSYSAPI BOOLEAN NTAPI RtlValidAcl(
		_In_ PACL Acl
	);

	NTSYSAPI NTSTATUS NTAPI RtlQueryInformationAcl(
		_In_ PACL Acl,
		_Out_writes_bytes_(AclInformationLength) PVOID AclInformation,
		_In_ ULONG AclInformationLength,
		_In_ ACL_INFORMATION_CLASS AclInformationClass
	);

	NTSYSAPI NTSTATUS NTAPI RtlSetInformationAcl(
		_Inout_ PACL Acl,
		_In_reads_bytes_(AclInformationLength) PVOID AclInformation,
		_In_ ULONG AclInformationLength,
		_In_ ACL_INFORMATION_CLASS AclInformationClass
	);

	NTSYSAPI NTSTATUS NTAPI RtlAddAce(
		_Inout_ PACL Acl,
		_In_ ULONG AceRevision,
		_In_ ULONG StartingAceIndex,
		_In_reads_bytes_(AceListLength) PVOID AceList,
		_In_ ULONG AceListLength
	);

	NTSYSAPI NTSTATUS NTAPI RtlDeleteAce(
		_Inout_ PACL Acl,
		_In_ ULONG AceIndex
	);

	NTSYSAPI NTSTATUS NTAPI RtlGetAce(
		_In_ PACL Acl,
		_In_ ULONG AceIndex,
		_Outptr_ PVOID *Ace
	);

	NTSYSAPI BOOLEAN NTAPI RtlFirstFreeAce(
		_In_ PACL Acl,
		_Out_ PVOID *FirstFree
	);

#if (_WIN32_WINNT >= _WIN32_WINNT_VISTA)
	// private
	NTSYSAPI PVOID NTAPI RtlFindAceByType(
		_In_ PACL pAcl,
		_In_ UCHAR AceType,
		_Out_opt_ PULONG pIndex
	);

	// private
	NTSYSAPI BOOLEAN NTAPI RtlOwnerAcesPresent(
		_In_ PACL pAcl
	);
#endif

	NTSYSAPI NTSTATUS NTAPI RtlAddAccessAllowedAce(
		_Inout_ PACL Acl,
		_In_ ULONG AceRevision,
		_In_ ACCESS_MASK AccessMask,
		_In_ PSID Sid
	);

	NTSYSAPI NTSTATUS NTAPI RtlAddAccessAllowedAceEx(
		_Inout_ PACL Acl,
		_In_ ULONG AceRevision,
		_In_ ULONG AceFlags,
		_In_ ACCESS_MASK AccessMask,
		_In_ PSID Sid
	);

	NTSYSAPI NTSTATUS NTAPI RtlAddAccessDeniedAce(
		_Inout_ PACL Acl,
		_In_ ULONG AceRevision,
		_In_ ACCESS_MASK AccessMask,
		_In_ PSID Sid
	);

	NTSYSAPI NTSTATUS NTAPI RtlAddAccessDeniedAceEx(
		_Inout_ PACL Acl,
		_In_ ULONG AceRevision,
		_In_ ULONG AceFlags,
		_In_ ACCESS_MASK AccessMask,
		_In_ PSID Sid
	);

	NTSYSAPI NTSTATUS NTAPI RtlAddAuditAccessAce(
		_Inout_ PACL Acl,
		_In_ ULONG AceRevision,
		_In_ ACCESS_MASK AccessMask,
		_In_ PSID Sid,
		_In_ BOOLEAN AuditSuccess,
		_In_ BOOLEAN AuditFailure
	);

	NTSYSAPI NTSTATUS NTAPI RtlAddAuditAccessAceEx(
		_Inout_ PACL Acl,
		_In_ ULONG AceRevision,
		_In_ ULONG AceFlags,
		_In_ ACCESS_MASK AccessMask,
		_In_ PSID Sid,
		_In_ BOOLEAN AuditSuccess,
		_In_ BOOLEAN AuditFailure
	);

	NTSYSAPI NTSTATUS NTAPI RtlAddAccessAllowedObjectAce(
		_Inout_ PACL Acl,
		_In_ ULONG AceRevision,
		_In_ ULONG AceFlags,
		_In_ ACCESS_MASK AccessMask,
		_In_opt_ LPGUID ObjectTypeGuid,
		_In_opt_ LPGUID InheritedObjectTypeGuid,
		_In_ PSID Sid
	);

	NTSYSAPI NTSTATUS NTAPI RtlAddAccessDeniedObjectAce(
		_Inout_ PACL Acl,
		_In_ ULONG AceRevision,
		_In_ ULONG AceFlags,
		_In_ ACCESS_MASK AccessMask,
		_In_opt_ LPGUID ObjectTypeGuid,
		_In_opt_ LPGUID InheritedObjectTypeGuid,
		_In_ PSID Sid
	);

	NTSYSAPI NTSTATUS NTAPI RtlAddAuditAccessObjectAce(
		_Inout_ PACL Acl,
		_In_ ULONG AceRevision,
		_In_ ULONG AceFlags,
		_In_ ACCESS_MASK AccessMask,
		_In_opt_ LPGUID ObjectTypeGuid,
		_In_opt_ LPGUID InheritedObjectTypeGuid,
		_In_ PSID Sid,
		_In_ BOOLEAN AuditSuccess,
		_In_ BOOLEAN AuditFailure
	);

	NTSYSAPI NTSTATUS NTAPI RtlAddCompoundAce(
		_Inout_ PACL Acl,
		_In_ ULONG AceRevision,
		_In_ UCHAR AceType,
		_In_ ACCESS_MASK AccessMask,
		_In_ PSID ServerSid,
		_In_ PSID ClientSid
	);

#if (_WIN32_WINNT >= _WIN32_WINNT_VISTA)
	// private
	NTSYSAPI NTSTATUS NTAPI RtlAddMandatoryAce(
		_Inout_ PACL Acl,
		_In_ ULONG AceRevision,
		_In_ ULONG AceFlags,
		_In_ PSID Sid,
		_In_ UCHAR AceType,
		_In_ ACCESS_MASK AccessMask
	);
#endif
}

// 电源
extern "C"
{
	NTSYSAPI NTSTATUS NTAPI NtShutdownSystem(
		_In_ SHUTDOWN_ACTION Action
	);

	NTSYSAPI NTSTATUS NTAPI NtPowerInformation(
		_In_ POWER_INFORMATION_LEVEL InformationLevel,
		_In_reads_bytes_opt_(InputBufferLength) PVOID InputBuffer,
		_In_ ULONG InputBufferLength,
		_Out_writes_bytes_opt_(OutputBufferLength) PVOID OutputBuffer,
		_In_ ULONG OutputBufferLength
	);

	NTSYSAPI NTSTATUS NTAPI NtSetThreadExecutionState(
		_In_ EXECUTION_STATE NewFlags, // ES_* flags
		_Out_ EXECUTION_STATE *PreviousFlags
	);

	NTSYSAPI NTSTATUS NTAPI NtRequestWakeupLatency(
		_In_ LATENCY_TIME latency
	);

	NTSYSAPI NTSTATUS NTAPI NtInitiatePowerAction(
		_In_ POWER_ACTION SystemAction,
		_In_ SYSTEM_POWER_STATE LightestSystemState,
		_In_ ULONG Flags, // POWER_ACTION_* flags
		_In_ BOOLEAN Asynchronous
	);

	NTSYSAPI NTSTATUS NTAPI NtSetSystemPowerState(
		_In_ POWER_ACTION SystemAction,
		_In_ SYSTEM_POWER_STATE LightestSystemState,
		_In_ ULONG Flags // POWER_ACTION_* flags
	);

	NTSYSAPI NTSTATUS NTAPI NtGetDevicePowerState(
		_In_ HANDLE Device,
		_Out_ PDEVICE_POWER_STATE State
	);

	NTSYSAPI BOOLEAN NTAPI NtIsSystemResumeAutomatic(
		VOID
	);
}

// 注册表
extern "C"
{
	NTSYSAPI NTSTATUS NTAPI NtCreateKey(
		_Out_ PHANDLE KeyHandle,
		_In_ ACCESS_MASK DesiredAccess,
		_In_ POBJECT_ATTRIBUTES ObjectAttributes,
		_Reserved_ ULONG TitleIndex,
		_In_opt_ PUNICODE_STRING Class,
		_In_ ULONG CreateOptions,
		_Out_opt_ PULONG Disposition
	);

#if (_WIN32_WINNT >= _WIN32_WINNT_VISTA)
	NTSYSAPI NTSTATUS NTAPI NtCreateKeyTransacted(
		_Out_ PHANDLE KeyHandle,
		_In_ ACCESS_MASK DesiredAccess,
		_In_ POBJECT_ATTRIBUTES ObjectAttributes,
		_Reserved_ ULONG TitleIndex,
		_In_opt_ PUNICODE_STRING Class,
		_In_ ULONG CreateOptions,
		_In_ HANDLE TransactionHandle,
		_Out_opt_ PULONG Disposition
	);
#endif

	NTSYSAPI NTSTATUS NTAPI NtOpenKey(
		_Out_ PHANDLE KeyHandle,
		_In_ ACCESS_MASK DesiredAccess,
		_In_ POBJECT_ATTRIBUTES ObjectAttributes
	);

#if (_WIN32_WINNT >= _WIN32_WINNT_VISTA)
	NTSYSAPI NTSTATUS NTAPI NtOpenKeyTransacted(
		_Out_ PHANDLE KeyHandle,
		_In_ ACCESS_MASK DesiredAccess,
		_In_ POBJECT_ATTRIBUTES ObjectAttributes,
		_In_ HANDLE TransactionHandle
	);
#endif

#if (_WIN32_WINNT >= _WIN32_WINNT_WIN7)
	NTSYSAPI NTSTATUS NTAPI NtOpenKeyEx(
		_Out_ PHANDLE KeyHandle,
		_In_ ACCESS_MASK DesiredAccess,
		_In_ POBJECT_ATTRIBUTES ObjectAttributes,
		_In_ ULONG OpenOptions
	);

	NTSYSAPI NTSTATUS NTAPI NtOpenKeyTransactedEx(
		_Out_ PHANDLE KeyHandle,
		_In_ ACCESS_MASK DesiredAccess,
		_In_ POBJECT_ATTRIBUTES ObjectAttributes,
		_In_ ULONG OpenOptions,
		_In_ HANDLE TransactionHandle
	);
#endif

	NTSYSAPI NTSTATUS NTAPI NtDeleteKey(
		_In_ HANDLE KeyHandle
	);

	NTSYSAPI NTSTATUS NTAPI NtRenameKey(
		_In_ HANDLE KeyHandle,
		_In_ PUNICODE_STRING NewName
	);

	NTSYSAPI NTSTATUS NTAPI NtDeleteValueKey(
		_In_ HANDLE KeyHandle,
		_In_ PUNICODE_STRING ValueName
	);

	NTSYSAPI NTSTATUS NTAPI NtQueryKey(
		_In_ HANDLE KeyHandle,
		_In_ KEY_INFORMATION_CLASS KeyInformationClass,
		_Out_writes_bytes_opt_(Length) PVOID KeyInformation,
		_In_ ULONG Length,
		_Out_ PULONG ResultLength
	);

	NTSYSAPI NTSTATUS NTAPI NtSetInformationKey(
		_In_ HANDLE KeyHandle,
		_In_ KEY_SET_INFORMATION_CLASS KeySetInformationClass,
		_In_reads_bytes_(KeySetInformationLength) PVOID KeySetInformation,
		_In_ ULONG KeySetInformationLength
	);

	NTSYSAPI NTSTATUS NTAPI NtQueryValueKey(
		_In_ HANDLE KeyHandle,
		_In_ PUNICODE_STRING ValueName,
		_In_ KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
		_Out_writes_bytes_opt_(Length) PVOID KeyValueInformation,
		_In_ ULONG Length,
		_Out_ PULONG ResultLength
	);

	NTSYSAPI NTSTATUS NTAPI NtSetValueKey(
		_In_ HANDLE KeyHandle,
		_In_ PUNICODE_STRING ValueName,
		_In_opt_ ULONG TitleIndex,
		_In_ ULONG Type,
		_In_reads_bytes_opt_(DataSize) PVOID Data,
		_In_ ULONG DataSize
	);

	NTSYSAPI NTSTATUS NTAPI NtQueryMultipleValueKey(
		_In_ HANDLE KeyHandle,
		_Inout_updates_(EntryCount) PKEY_VALUE_ENTRY ValueEntries,
		_In_ ULONG EntryCount,
		_Out_writes_bytes_(*BufferLength) PVOID ValueBuffer,
		_Inout_ PULONG BufferLength,
		_Out_opt_ PULONG RequiredBufferLength
	);

	NTSYSAPI NTSTATUS NTAPI NtEnumerateKey(
		_In_ HANDLE KeyHandle,
		_In_ ULONG Index,
		_In_ KEY_INFORMATION_CLASS KeyInformationClass,
		_Out_writes_bytes_opt_(Length) PVOID KeyInformation,
		_In_ ULONG Length,
		_Out_ PULONG ResultLength
	);

	NTSYSAPI NTSTATUS NTAPI NtEnumerateValueKey(
		_In_ HANDLE KeyHandle,
		_In_ ULONG Index,
		_In_ KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
		_Out_writes_bytes_opt_(Length) PVOID KeyValueInformation,
		_In_ ULONG Length,
		_Out_ PULONG ResultLength
	);

	NTSYSAPI NTSTATUS NTAPI NtFlushKey(
		_In_ HANDLE KeyHandle
	);

	NTSYSAPI NTSTATUS NTAPI NtCompactKeys(
		_In_ ULONG Count,
		_In_reads_(Count) HANDLE KeyArray[]
	);

	NTSYSAPI NTSTATUS NTAPI NtCompressKey(
		_In_ HANDLE Key
	);

	NTSYSAPI NTSTATUS NTAPI NtLoadKey(
		_In_ POBJECT_ATTRIBUTES TargetKey,
		_In_ POBJECT_ATTRIBUTES SourceFile
	);

	NTSYSAPI NTSTATUS NTAPI NtLoadKey2(
		_In_ POBJECT_ATTRIBUTES TargetKey,
		_In_ POBJECT_ATTRIBUTES SourceFile,
		_In_ ULONG Flags
	);

	NTSYSAPI NTSTATUS NTAPI NtLoadKeyEx(
		_In_ POBJECT_ATTRIBUTES TargetKey,
		_In_ POBJECT_ATTRIBUTES SourceFile,
		_In_ ULONG Flags,
		_In_opt_ HANDLE TrustClassKey,
		_In_opt_ HANDLE Event,
		_In_opt_ ACCESS_MASK DesiredAccess,
		_Out_opt_ PHANDLE RootHandle,
		_Out_opt_ PIO_STATUS_BLOCK IoStatus
	);

	NTSYSAPI NTSTATUS NTAPI NtReplaceKey(
		_In_ POBJECT_ATTRIBUTES NewFile,
		_In_ HANDLE TargetHandle,
		_In_ POBJECT_ATTRIBUTES OldFile
	);

	NTSYSAPI NTSTATUS NTAPI NtSaveKey(
		_In_ HANDLE KeyHandle,
		_In_ HANDLE FileHandle
	);

	NTSYSAPI NTSTATUS NTAPI NtSaveKeyEx(
		_In_ HANDLE KeyHandle,
		_In_ HANDLE FileHandle,
		_In_ ULONG Format
	);

	NTSYSAPI NTSTATUS NTAPI NtSaveMergedKeys(
		_In_ HANDLE HighPrecedenceKeyHandle,
		_In_ HANDLE LowPrecedenceKeyHandle,
		_In_ HANDLE FileHandle
	);

	NTSYSAPI NTSTATUS NTAPI NtRestoreKey(
		_In_ HANDLE KeyHandle,
		_In_ HANDLE FileHandle,
		_In_ ULONG Flags
	);

	NTSYSAPI NTSTATUS NTAPI NtUnloadKey(
		_In_ POBJECT_ATTRIBUTES TargetKey
	);

	NTSYSAPI NTSTATUS NTAPI NtUnloadKey2(
		_In_ POBJECT_ATTRIBUTES TargetKey,
		_In_ ULONG Flags
	);

	NTSYSAPI NTSTATUS NTAPI NtUnloadKeyEx(
		_In_ POBJECT_ATTRIBUTES TargetKey,
		_In_opt_ HANDLE Event
	);

	NTSYSAPI NTSTATUS NTAPI NtNotifyChangeKey(
		_In_ HANDLE KeyHandle,
		_In_opt_ HANDLE Event,
		_In_opt_ PIO_APC_ROUTINE ApcRoutine,
		_In_opt_ PVOID ApcContext,
		_Out_ PIO_STATUS_BLOCK IoStatusBlock,
		_In_ ULONG CompletionFilter,
		_In_ BOOLEAN WatchTree,
		_Out_writes_bytes_opt_(BufferSize) PVOID Buffer,
		_In_ ULONG BufferSize,
		_In_ BOOLEAN Asynchronous
	);

	NTSYSAPI NTSTATUS NTAPI NtNotifyChangeMultipleKeys(
		_In_ HANDLE MasterKeyHandle,
		_In_opt_ ULONG Count,
		_In_reads_opt_(Count) OBJECT_ATTRIBUTES SubordinateObjects[],
		_In_opt_ HANDLE Event,
		_In_opt_ PIO_APC_ROUTINE ApcRoutine,
		_In_opt_ PVOID ApcContext,
		_Out_ PIO_STATUS_BLOCK IoStatusBlock,
		_In_ ULONG CompletionFilter,
		_In_ BOOLEAN WatchTree,
		_Out_writes_bytes_opt_(BufferSize) PVOID Buffer,
		_In_ ULONG BufferSize,
		_In_ BOOLEAN Asynchronous
	);

	NTSYSAPI NTSTATUS NTAPI NtQueryOpenSubKeys(
		_In_ POBJECT_ATTRIBUTES TargetKey,
		_Out_ PULONG HandleCount
	);

	NTSYSAPI NTSTATUS NTAPI NtQueryOpenSubKeysEx(
		_In_ POBJECT_ATTRIBUTES TargetKey,
		_In_ ULONG BufferLength,
		_Out_writes_bytes_(BufferLength) PVOID Buffer,
		_Out_ PULONG RequiredSize
	);

	NTSYSAPI NTSTATUS NTAPI NtInitializeRegistry(
		_In_ USHORT BootCondition
	);

	NTSYSAPI NTSTATUS NTAPI NtLockRegistryKey(
		_In_ HANDLE KeyHandle
	);

	NTSYSAPI NTSTATUS NTAPI NtLockProductActivationKeys(
		_Inout_opt_ ULONG *pPrivateVer,
		_Out_opt_ ULONG *pSafeMode
	);

#if (_WIN32_WINNT >= _WIN32_WINNT_VISTA)
	// private
	NTSYSAPI NTSTATUS NTAPI NtFreezeRegistry(
		_In_ ULONG TimeOutInSeconds
	);

	// private
	NTSYSAPI NTSTATUS NTAPI NtThawRegistry(
		VOID
	);
#endif
}

#pragma endregion

// 内联调用
#pragma region InlineCall

//进程
#pragma region Process

// 获取当前进程句柄
inline HANDLE NtCurrentProcess()
{
	return (HANDLE)(LONG_PTR)-1;
}

// 获取当前进程句柄
inline HANDLE ZwCurrentProcess()
{
	return NtCurrentProcess();
}

// 获取当前线程句柄
inline HANDLE NtCurrentThread()
{
	return (HANDLE)(LONG_PTR)-2;
}

// 获取当前线程句柄
inline HANDLE ZwCurrentThread()
{
	return NtCurrentThread();
}

// 获取当前进程环境块
inline PPEB NtCurrentPeb()
{
	return NtCurrentTeb()->ProcessEnvironmentBlock;
}

#pragma endregion

// 内存
#pragma region Memory

// 获取当前会话
inline HANDLE NtCurrentSession()
{
	return (HANDLE)(LONG_PTR)-3;
}

// 获取当前会话
inline HANDLE ZwCurrentSession()
{
	return NtCurrentSession();
}

#pragma endregion

// 堆
#pragma region Heap

// 获取当前进程堆句柄
inline HANDLE RtlProcessHeap()
{
	return NtCurrentPeb()->ProcessHeap;
}

#pragma endregion

// 字符串
#pragma region String

// 初始化STRING结构
__forceinline void RtlInitString(
	_Out_ PSTRING DestinationString,
	_In_opt_ PSTR SourceString)
{
	if (SourceString)
	{
		DestinationString->Length = (USHORT)strlen(SourceString);
		DestinationString->MaximumLength = DestinationString->Length + 1;
	}
	else
	{
		DestinationString->Length = 0;
		DestinationString->MaximumLength = 0;
	}

	DestinationString->Buffer = SourceString;
}

// 初始化ANSI_STRING结构
__forceinline void RtlInitAnsiString(
	_Out_ PANSI_STRING DestinationString,
	_In_opt_ PSTR SourceString)
{
	RtlInitString(DestinationString, SourceString);
}

// 初始化UNICODE_STRING结构
__forceinline void RtlInitUnicodeString(
	_Out_ PUNICODE_STRING DestinationString,
	_In_opt_ PWSTR SourceString)
{
	if (SourceString)
	{
		DestinationString->Length = (USHORT)(wcslen(SourceString) * sizeof(WCHAR));
		DestinationString->MaximumLength = DestinationString->Length + sizeof(WCHAR);
	}
	else
	{
		DestinationString->Length = 0;
		DestinationString->MaximumLength = 0;
	}

	DestinationString->Buffer = SourceString;
}

#pragma endregion

#pragma endregion

#endif