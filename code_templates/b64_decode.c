//
// You'll need these 3 header files
//
#include <stdio.h>
#include <wincrypt.h>
#include <windows.h>

//
// Need to link Crypt32.lib
//
#pragma comment( lib, "Crypt32.lib" )

//
// Example Usage:
//
//  const char *payload = "Base64 encoded payload  here";
//  unsigned char *decoded_shellcode;
//  DWORD decoded_length;
//  decode_base64( payload, &decoded_shellcode, &decoded_length );

//
// Base64 Decoding Function
// 
int decode_base64( const char *encoded_data, unsigned char **decoded_data, DWORD *decoded_length ) 
{	
	//
	// Calculate the required size for the output buffer where the decoded binary data should be stored
	// 
    if ( !CryptStringToBinaryA(encoded_data, 0, CRYPT_STRING_BASE64, NULL, decoded_length, NULL, NULL) ) 
	{
        fprintf( stderr, "Failed to calculate the buffer size needed for decoding.\n" );
        return 0;
    }

	// 
	// Allocate memory
	// 
    *decoded_data = ( unsigned char * )malloc( *decoded_length );
    if( *decoded_data == NULL ) 
	{
        fprintf(stderr, "Memory allocation failed.\n");
        return 0;
    }

	//
	// Decode the base64 encoded shellcode
	//
    if( !CryptStringToBinaryA( encoded_data, 0, CRYPT_STRING_BASE64, *decoded_data, decoded_length, NULL, NULL) ) 
	{
        fprintf( stderr, "Base64 decoding failed.\n" );
        free( *decoded_data );
        return 0;
    }

	//
	// Return 1 for success
	// 
    return 1; 
}