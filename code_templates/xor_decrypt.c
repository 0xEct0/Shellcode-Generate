//
// XOR Decryption Function
//
void xor_decrypt( unsigned char *data, int data_len )
{
    unsigned char key = 0x00;

	for( int i = 0; i < data_len; i++ )
	{
		data[i] ^= key;
	}
}