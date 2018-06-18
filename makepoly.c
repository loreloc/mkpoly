
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

extern int poly_engine(char* exe_data, size_t enc_beg_offset, size_t enc_size, size_t dec_offset);

int main(int argc, char* argv[])
{
	if(argc < 5)
	{
		printf("Usage: ");
		printf("makepoly <in-file> <enc-beg-offset> <enc-end-offset> <dec-offset>\n");
		printf("\t<in-file>        the executable file to make polymorphic\n");
		printf("\t<enc-beg-offset> the begin offset of the section to encrypt\n");
		printf("\t<enc-end-offset> the end offset of the section to encrypt\n");
		printf("\t<dec-offset>     the offset of the section in which to place the decrypt function\n");
		return -1;
	}

	// get the program arguments
	const char* exe_filename    = argv[1];
	const size_t enc_beg_offset = strtol(argv[2], NULL, 16);
	const size_t enc_end_offset = strtol(argv[3], NULL, 16);
	const size_t dec_offset     = strtol(argv[4], NULL, 16);

	// open the executable file
	FILE* exe_file = fopen(exe_filename, "rb");
	if(!exe_file)
	{
		printf("ERROR: failed to open %s\n", exe_filename);
		return 1;
	}

	// get the size of the executable file
	size_t exe_size;
	fseek(exe_file, 0, SEEK_END);
	exe_size = ftell(exe_file);
	rewind(exe_file);

	// allocate the data
	char* exe_data = malloc(exe_size);
	if(!exe_data)
	{
		fclose(exe_file);
		printf("ERROR: data allocation failed\n");
		return 2;
	}

	// read the entire executable file
	if(!fread(exe_data, exe_size, 1, exe_file))
	{
		fclose(exe_file);
		free(exe_data);
		printf("ERROR: executable file read failed\n");
		return 3;
	}

	// close the file
	fclose(exe_file);

	// check the offsets of the section to encrypt
	if(enc_end_offset <= enc_beg_offset || enc_beg_offset >= exe_size || enc_end_offset >= exe_size)
	{
		free(exe_data);
		printf("ERROR: invalid offsets of the section to encrypt\n");
		return 4;
	}

	// calculate the size of the section to encrypt
	size_t enc_size = enc_end_offset - enc_beg_offset;

	// check the size of the section to encrypt
	if(enc_size == 0 || (enc_size & 0x0F) != 0)
	{
		free(exe_data);
		printf("ERROR: the section to encrypt size must be a multiple of 16\n");
		return 5;
	}

	// check the offset of the section in which to place the decryption function
	if(dec_offset >= exe_size)
	{
		free(exe_data);
		printf("ERROR: decryption function offset overflow\n");
		return 6;
	}

	// call the polymorphic engine
	if(poly_engine(exe_data, enc_beg_offset, enc_size, dec_offset) != 0)
	{
		free(exe_data);
		printf("ERROR: an error occured in the polymorphic engine\n");
		return 7;
	}

	// initialize the output filename
	char out_filename[FILENAME_MAX];
	snprintf(out_filename, FILENAME_MAX, "%s.poly", exe_filename);

	// open the output file
	FILE* out_file = fopen(out_filename, "wb");
	if(!out_file)
	{
		free(exe_data);
		printf("ERROR: failed to open %s\n", out_filename);
		return 8;
	}

	// write the modified executable data
	if(!fwrite(exe_data, exe_size, 1, out_file))
	{
		free(exe_data);
		printf("ERROR: failed to write into %s\n", out_filename);
		return 9;
	}

	free(exe_data);

	return 0;
}

