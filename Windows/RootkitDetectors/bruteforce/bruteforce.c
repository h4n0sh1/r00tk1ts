#include <stdio.h>
#include <stdlib.h>
#include <Windows.h>
#include <tlhelp32.h>
#include "uthash.h"
#include <winbase.h>
/* Build options > Linker > C:/Program Files/Code Blocks/MinGW/lib/libpsapi.a */
#include <psapi.h>

void SetDebugPrivilege()
{
    TOKEN_PRIVILEGES privilege;
    LUID Luid;
    HANDLE handle1;
    HANDLE handle2;

    // Get Handle on cur. process
    handle1 = OpenProcess(PROCESS_ALL_ACCESS, FALSE, GetCurrentProcessId());

    // Get privileged token
    OpenProcessToken(handle1, TOKEN_ALL_ACCESS, &handle2);

    // Activate SE_DEBUG_NAME priv. (disabled by default - even 4 admin)
    LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &Luid);
    privilege.PrivilegeCount = 1;
    privilege.Privileges[0].Luid = Luid;
    privilege.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    AdjustTokenPrivileges(handle2, FALSE, &privilege, sizeof(privilege), NULL, NULL);
    CloseHandle(handle2);
    CloseHandle(handle1);
}

struct PROCESSTABLE{
        int pid;
        char name[256];
        UT_hash_handle hh;
};

struct PROCESSTABLE *processTable = NULL;
struct PROCESSTABLE *hiddenTable = NULL;

void add_process(struct PROCESSTABLE **processTable, int pid, char *name){
    struct PROCESSTABLE *pt;
    HASH_FIND_INT(*processTable, &pid, pt); /* pid already used ? */
    if( pt == NULL){
        pt = malloc(sizeof(struct PROCESSTABLE));
        pt->pid = pid;
        strcpy(pt->name, name);
        HASH_ADD_INT(*processTable, pid, pt);
    }
}

void print_all_process(struct PROCESSTABLE **processTable){
    struct PROCESSTABLE *pt;
    printf( "\n PID \t | Name \n");
    printf( "\n --- \t | ----- \n");
    for(pt=*processTable; pt != NULL; pt=pt->hh.next){
        printf("%i \t | %s  \n", pt->pid, pt->name);
    }
}

void find_rootkit(){
    HANDLE process;
    char name[256];
    struct PROCESSTABLE *pt;
    int i;
    for(i=0; i < 65000; i++)
    {
        process = OpenProcess( PROCESS_QUERY_INFORMATION |
                                PROCESS_VM_READ,
                                FALSE, i );
        if(process != NULL && i%4 == 0)
        {
            HASH_FIND_INT(processTable, &i, pt);
            if(pt == NULL){
                pt = malloc(sizeof(struct PROCESSTABLE));
                GetModuleBaseNameW(process, NULL, name, 256);
                pt->pid = i;
                strcpy(pt->name, name);
                HASH_ADD_INT(hiddenTable, pid, pt);
            }
        }
        CloseHandle(process);
    }
}

int main()
{

    HANDLE process;
    BOOL enumProcess;
    PROCESSENTRY32 processEntry;

    processEntry.dwSize = sizeof(PROCESSENTRY32);

    process = CreateToolhelp32Snapshot(
                TH32CS_SNAPPROCESS,
                0
                );

    if( process == INVALID_HANDLE_VALUE)
        return -2;

    enumProcess = Process32First(process,&processEntry);

    if (enumProcess == FALSE)
        return -3;

    while(Process32Next(process, &processEntry)){
        //printf( "\n Process: %s", processEntry.szExeFile );
        add_process(&processTable, processEntry.th32ProcessID,processEntry.szExeFile);
    }

    printf("Process Enumerated: %u \n", HASH_COUNT(processTable));
    print_all_process(&processTable);

    SetDebugPrivilege();
    find_rootkit();

    printf("\n Rootkit Enumerated: %u \n", HASH_COUNT(hiddenTable));
    print_all_process(&hiddenTable);

    system("pause");

    CloseHandle(process);

    return 0;
}

