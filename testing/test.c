#include <stdio.h>
#include <windows.h>
#include <string.h>
#include "peb_structs.h"

// 
// Macro to convert a character to lowercase
//
#define TO_LOWER(c) ( (c >= 'A' && c <= 'Z') ? (c + 'a' - 'A') : c )


//
// Function prototypes for module lookup and function lookup
// 
inline LPVOID get_module_by_name( wchar_t* module_name );
inline LPVOID get_func_by_name( LPVOID module, char* function_name );

int main( void )
{
    wchar_t kernel32dll[] = { 'k', 'e', 'r', 'n', 'e', 'l', '3', '2', '.', 'd', 'l', 'l', '\0' };
    LPVOID kernel32dll_base = get_module_by_name( kernel32dll );

    if( NULL == kernel32dll_base )
    {
        // printf( "[!] Could not find kernel32.dll!\n" );
        return 1;
    }

    // printf( "[+] Successfully found kernel32.dll!\n" );



    // 
    // Get GetProcAddress
    // 
    char get_proc_addr[] = { 'G', 'e', 't', 'P', 'r', 'o', 'c', 'A', 'd', 'd', 'r', 'e', 's', 's', '\0' }; 

    LPVOID getprocaddress_addr = get_func_by_name( kernel32dll_base, get_proc_addr );
    if( NULL == getprocaddress_addr )
    {
        // printf( "[!] Could not find function! Exiting!\n" );
        return 1;
    }
    // printf( "[+] Found GetProcAddress!\n" );



    // 
    // Get LoadLibraryA
    //    
    char load_library[] = { 'L', 'o', 'a', 'd', 'L', 'i', 'b', 'r', 'a', 'r', 'y', 'A', '\0' };    
    LPVOID loadlibrarya_addr = get_func_by_name( kernel32dll_base, load_library );
    if( loadlibrarya_addr == NULL )
    {
        // printf( "[!] Could not find function! Exiting!\n" );
        return 1;
    }
    // printf( "[+] Found LoadLibraryA!\n" );



    //
    // Dynamically resolve LoadLibraryA/GetProcAddress
    //
    HMODULE( WINAPI * _LoadLibraryA )( LPCSTR lpLibFileName )                = ( HMODULE(WINAPI*)(LPCSTR))loadlibrarya_addr;
    FARPROC( WINAPI * _GetProcAddress)( HMODULE hModule, LPCSTR lpProcName ) = ( FARPROC (WINAPI*)(HMODULE, LPCSTR))getprocaddress_addr;

    if( NULL == _LoadLibraryA && NULL == _GetProcAddress)
    {
        // printf( "[!] LoadLibraryA or GetProcAddress could not be resolved!\n" );
        return 1;
    }

    //
    // Dynamically resolve CreateProcess() from kernel32.dll
    // 
    char createprocessa[] = { 'C', 'r', 'e', 'a', 't', 'e', 'P', 'r', 'o', 'c', 'e', 's', 's', 'A', '\0' }; 
    BOOL ( WINAPI * _CreateProcessA )
    (
        LPCSTR                lpApplicationName,
        LPSTR                 lpCommandLine,
        LPSECURITY_ATTRIBUTES lpProcessAttributes,
        LPSECURITY_ATTRIBUTES lpThreadAttributes,
        BOOL                  bInheritHandles,
        DWORD                 dwCreationFlags,
        LPVOID                lpEnvironment,
        LPCSTR                lpCurrentDirectory,
        LPSTARTUPINFOA        lpStartupInfo,
        LPPROCESS_INFORMATION lpProcessInformation
    );

    _CreateProcessA = ( BOOL(WINAPI*)
    (
        LPCSTR                lpApplicationName,
        LPSTR                 lpCommandLine,
        LPSECURITY_ATTRIBUTES lpProcessAttributes,
        LPSECURITY_ATTRIBUTES lpThreadAttributes,
        BOOL                  bInheritHandles,
        DWORD                 dwCreationFlags,
        LPVOID                lpEnvironment,
        LPCSTR                lpCurrentDirectory,
        LPSTARTUPINFOA        lpStartupInfo,
        LPPROCESS_INFORMATION lpProcessInformation
    )) _GetProcAddress( (HMODULE)kernel32dll_base, createprocessa );

    if( NULL == _CreateProcessA )
    {
        // printf( "[!] Could not dynamically resolve CreateProcess()!\n" );
        return 1;
    }

    STARTUPINFOA si;              // Structure that defines how to start the program
    PROCESS_INFORMATION pi;       // Structure that receives information about the new process

    char msvcrtdll[] = { 'm', 's', 'v', 'c', 'r', 't', '.', 'd', 'l', 'l', '\0' };
    LPVOID msvcrtdll_base = _LoadLibraryA( msvcrtdll );

    if( NULL == msvcrtdll_base )
    {
        // printf( "[!] Could not find msvcrt.dll!\n" );
        return 1;
    }

    void * (WINAPI * _memset)
    (
        void *dest,
        int c,
        size_t count
    );

    char memset_str[] = { 'm', 'e', 'm', 's', 'e', 't', '\0' }; 
    _memset = ( void *(WINAPI*)
    (
        void *dest,
        int c,
        size_t count
    )) _GetProcAddress( (HMODULE)msvcrtdll_base, memset_str );

    if( NULL == _memset)
    {
        // printf( "[!] Could not resolve memset()\n" );
        return 1;
    }

    _memset(&si, 0, sizeof(si));  // Initialize the STARTUPINFO structure with zero
    si.cb = sizeof(si);           // Set the size of the structure
    _memset(&pi, 0, sizeof(pi));  // Initialize the PROCESS_INFORMATION structure with zero

    // Command to execute
    char command[] = {'c', 'm', 'd', '.', 'e', 'x', 'e', ' ', '/', 'C', ' ', 'c', 'a', 'l', 'c', '.', 'e', 'x', 'e', '\0' };

    // Create the process
    BOOL result = _CreateProcessA
    (
        NULL,        // Application name - use command line for specifying the app
        command,     // Command line - application name and parameters
        NULL,        // Process handle not inheritable
        NULL,        // Thread handle not inheritable
        FALSE,       // Set handle inheritance to FALSE
        0,           // No creation flags
        NULL,        // Use parent's environment block
        NULL,        // Use parent's starting directory
        &si,         // Pointer to STARTUPINFO structure
        &pi          // Pointer to PROCESS_INFORMATION structure
    );


    // printf( "[+] Exiting with status 0!\n" );
    return 0;
}

//
// This function gets the base address of the module being searched
// 
inline LPVOID get_module_by_name( wchar_t* module_name )
{
    // wprintf( L"[*] Finding address of module: %ls\n", module_name );
    //
    // Access the PEB from GS register offset x60
    // 
    PPEB peb = NULL;
    peb = ( PPEB )__readgsqword( 0x60 ); 

    //
    // Get the Ldr to find the module list
    // 
    // printf( "[*] Found address of peb->Ldr: %p\n", peb->Ldr );
    PPEB_LDR_DATA ldr = peb->Ldr;
    LIST_ENTRY module_list = ldr->InLoadOrderModuleList;

    PLDR_DATA_TABLE_ENTRY front_link = *( (PLDR_DATA_TABLE_ENTRY*)(&module_list) );
    PLDR_DATA_TABLE_ENTRY current_link = front_link;
    
    LPVOID return_module = NULL;

    // 
    // Go through the doubly linked list
    // 
    wchar_t current_module[1032];

    while( current_link != NULL && current_link->DllBase != NULL ) 
    {
        USHORT buffer_len = current_link->BaseDllName.Length / sizeof( WCHAR );
        USHORT i = 0;

        //
        // Reset the current_module string
        //
        for( i = 0; i < 1032; i++ )
        {
            current_module[i] = '\0';
        }
        
        // printf( "[*] Found BaseDllName: " );
        
        for( i = 0; i < buffer_len; i++ )
        {
            current_module[i] = TO_LOWER( current_link->BaseDllName.Buffer[i] );
        }

        // wprintf( L"current_module: %ls\n", current_module );
         
        for( i = 0; i < buffer_len && module_name[i] != '\0'; i++ )
        {
            if( TO_LOWER( current_link->BaseDllName.Buffer[i] ) != module_name[i] )
            {
                break;
            }

            //
            // If i == buffer_len - 1 and hasn't broken out of the loop - it's the module we're looking for!
            // 
            if( i == buffer_len - 1 )
            {
                // printf("[*] Found a matching module name!\n");
                return_module = current_link->DllBase;
                return return_module;
            }
        }

        //
        // Check to make sure the next does not equal NULL
        // Might be redundant with while loop condition...
        //
        if( (PLDR_DATA_TABLE_ENTRY)current_link->InLoadOrderLinks.Flink == NULL )
        {
            break;
        }
        
        //
        // Go to next item on the linked list
        // 
        current_link = ( PLDR_DATA_TABLE_ENTRY )current_link->InLoadOrderLinks.Flink;
    }

    return return_module;
}

//
// This function gets the function address from the module
// 
inline LPVOID get_func_by_name( LPVOID module, char* function_name )
{
    LPVOID return_address = NULL;
    
    // printf( "[*] Getting address of function: %s\n", function_name );

    // 
    // Check if magic bytes are correct ("MZ")
    // 
    IMAGE_DOS_HEADER* dos_header = ( IMAGE_DOS_HEADER* )module;
    if( dos_header->e_magic != IMAGE_DOS_SIGNATURE)
    {
        return NULL;
    }

    // printf( "[*] Magic bytes are \"MZ\"\n" );

    //
    // Get address of the PE Header (e_lfanew)
    // PE Header contains data directories, which are pointers to important data in the executable, such as the import and export tables
    //
    IMAGE_NT_HEADERS* nt_headers = (IMAGE_NT_HEADERS*)((BYTE*)module + dos_header->e_lfanew);

    // 
    // Get the exports directory - contains functions exported by the module
    // The export directory is in the 0th index of the DataDirectory
    // 
    IMAGE_DATA_DIRECTORY* exports_directory = &(nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);
    if (exports_directory->VirtualAddress == NULL) 
    {
        return NULL;
    }

    // printf( "[*] Found the exports directory\n" );

    //
    // Get the relative virtual address of the export table
    //
    DWORD export_table_rva = exports_directory->VirtualAddress;

    //
    // Calculate the absolute address of the export directory by adding the VirtualAddress to the base address of the module
    //
    IMAGE_EXPORT_DIRECTORY* export_table_aa = ( IMAGE_EXPORT_DIRECTORY* )( export_table_rva + (ULONG_PTR)module );
    SIZE_T namesCount = export_table_aa->NumberOfNames;

    //
    // Retrieves the number of function names
    // Also gets RVAs of lists of function addresses, function names, and name ordinals
    // 
    DWORD function_list_rva = export_table_aa->AddressOfFunctions;
    DWORD function_names_rva = export_table_aa->AddressOfNames;
    DWORD ordinal_names_rva = export_table_aa->AddressOfNameOrdinals;

    //
    // Loop through names of functions exported by module
    // Attempts to find function whose name matches the func_name parameter
    // 
    for( SIZE_T i = 0; i < namesCount; i++ )
    {
        //
        // Calculate the virtual address of the FUNCTION NAME at the i-th position in the exported names table
        //
        DWORD* name_va  = ( DWORD* )( function_names_rva + (BYTE*)module + i * sizeof(DWORD));
        
        //
        // Calculate the virtual address of the ORDINAL NUMBER of the function name at the i-th position in the exported names table
        //
        WORD* index = ( WORD* )( ordinal_names_rva + (BYTE*)module + i * sizeof(WORD));
        
        //
        // Calculate the virtual address of the FUNCTION'S ADDRESS corresponding to the i-th function name in the exported names table
        //
        DWORD* function_address_va = ( DWORD* )( function_list_rva + (BYTE*)module + (*index) * sizeof(DWORD) );

        //
        // Calculate the function name's (name_va) absolute address
        //
        LPSTR current_name = ( LPSTR )( *name_va + (BYTE*)module);
        
        //
        // Compare the characters and return if function is the module found
        //
        size_t j = 0;
        /*
        printf( "[*] Found function: " );
        
        for( j = 0; function_name[j] != '\0' && current_name[j] != 0; j++ )
        {
            printf( "%c", current_name[j] );
        }
        printf( "\n" );
        */ 
        //
        // Compare the target function name to current function name
        // 
        for( j = 0; function_name[j] != '\0' && current_name[j] != 0; j++ )
        {
            if( TO_LOWER(function_name[j]) != TO_LOWER(current_name[j]) )
            {
                break;
            }

            //
            // If j = the length of both and we haven't broken out of loop, we have a matching function!
            // Return the absoluste address of the function
            //
            if( function_name[j + 1] == '\0' && current_name[j + 1] == 0 )
            {
                return_address = (BYTE*)module + (*function_address_va);
                return return_address;
            }
        }
    }

    return return_address;
}
