
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>

extern int poly_engine(char* exe_data, size_t enc_beg_offset, size_t enc_size, size_t dec_offset);

int main(int argc, char* argv[])
{
	if(argc < 5)
	{
		printf("Usage: ");
		printf("makepoly <exe-filename> <enc-offset> <enc-size> <dec-offset>\n");
		printf("\n");
		printf("<exe-filename> the filename of the executable to make polymorphic\n");
		printf("<enc-offset>   the offset of the section to encrypt\n");
		printf("<enc-size>     the size of the section to encrypt\n");
		printf("<dec-offset>   the offset in which to place the decrypt function\n");
		printf("\n");
		return -1;
	}

	// seed the random number generator
	srand(time(NULL));

	// get the arguments
	const char* exe_filename = argv[1];
	const size_t enc_offset  = strtol(argv[2], NULL, 16);
	const size_t enc_size    = strtol(argv[3], NULL, 16);
	const size_t dec_offset  = strtol(argv[4], NULL, 16);

	// open the executable file
	FILE* exe_file = fopen(exe_filename, "rb");
	if(!exe_file)
	{
		printf("Failed to open %s\n", exe_filename);
		return -1;
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
		printf("Executable data allocation failed\n");
		return 1;
	}

	// read the entire executable file
	if(!fread(exe_data, exe_size, 1, exe_file))
	{
		fclose(exe_file);
		printf("Executable file read failed\n");
		goto quit;
	}

	// close the file
	fclose(exe_file);

	// check the input parameters
	if(enc_offset >= exe_size)
	{
		printf("The offset of the section to encrypt is invalid\n");
		goto quit;
	}

	if(dec_offset >= exe_size)
	{
		printf("The offset in which to place the decrypt function is invalid\n");
		goto quit;
	}

	if(enc_size == 0 || (enc_size & 0x0F) != 0)
	{
		printf("The section to encrypt size must be a multiple of 16\n");
		goto quit;
	}

	// call the polymorphic engine
	if(poly_engine(exe_data, enc_offset, enc_size, dec_offset) != 0)
	{
		printf("An error occured in the polymorphic engine\n");
		goto quit;
	}

	// initialize the output filename
	char out_filename[FILENAME_MAX];
	snprintf(out_filename, FILENAME_MAX, "%s.poly", exe_filename);

	// open the output file
	FILE* out_file = fopen(out_filename, "wb");
	if(!out_file)
	{
		printf("failed to open %s\n", out_filename);
		goto quit;
	}

	// write the modified executable data
	if(!fwrite(exe_data, exe_size, 1, out_file))
	{
		printf("failed to write into %s\n", out_filename);
	}

quit:
	free(exe_data);
	return 0;
}

