include masm32rt.inc
include shlwapi.inc
include msvcrt.inc
includelib msvcrt.lib
includelib shlwapi.lib


PROCESSENTRY32W STRUCT
    dwSize              DWORD ?
    cntUsage            DWORD ?
    th32ProcessID       DWORD ?
    th32DefaultHeapID   DWORD ?
    th32ModuleID        DWORD ?
    cntThreads          DWORD ?
    th32ParentProcessID DWORD ?
    pcPriClassBase      DWORD ?
    dwFlags             DWORD ?
    szExeFile           dw MAX_PATH dup(?)
PROCESSENTRY32W ENDS

.data
   process_name dw 'm','s','g','b','o','x','.','e','x','e',0
   process_id dw ?

.data?
    pe32W PROCESSENTRY32W <>
    hProcessSnap HANDLE ?

.code
    start:
        take_process_snap:
        push 0
        push TH32CS_SNAPPROCESS
        call CreateToolhelp32Snapshot
        
        mov hProcessSnap, eax
        
        find_first_process:
            mov pe32W.dwSize, sizeof pe32W
            push offset pe32W
            push hProcessSnap
            call Process32FirstW
        
        find_next_process:
            push offset pe32W
            push hProcessSnap
            call Process32NextW
            
            inc eax
            
            push OFFSET process_name
            push OFFSET pe32W.szExeFile
            call StrCmpW
            cmp eax, FALSE
            je show_pid_and_name
            jmp find_next_process
            
        show_pid_and_name:
            push offset pe32W.szExeFile
            call StdOutW
            
            printf("\n")
            
            push offset process_id
            push pe32W.th32ProcessID
            call dwtoa
            
            push offset process_id
            call StdOut     

end start
