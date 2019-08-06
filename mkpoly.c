
#include "mkpoly.h"

int main(int argc, char* argv[])
{
	if (argc < 5)
	{
		help();
		return 1;
	}

	FILE* source = fopen(argv[1], "rb");

	if (!source)
	{
		fprintf(stderr, "failed to open %s\n", argv[1]);
		return 2;
	}

	size_t size;
	fseek(source, 0, SEEK_END);
	size = ftell(source);
	fseek(source, 0, SEEK_SET);

	uint8_t *bin = malloc(size);

	if (!bin)
	{
		fprintf(stderr, "failed to allocate binary data");
		fclose(source);
		return 3;
	}

	if (!fread(bin, size, 1, source))
	{
		fprintf(stderr, "binary file reading failed\n");
		fclose(source);
		free(bin);
		return 4;
	}

	fclose(source);

	size_t coff  = strtol(argv[2], NULL, 16);
	size_t csize = strtol(argv[3], NULL, 16);
	size_t eoff  = strtol(argv[4], NULL, 16);

	if (polyeng(bin, coff, csize, eoff))
	{
		fprintf(stderr, "polymorphic engine error\n");
		free(bin);
		return 5;
	}

	char filename[FILENAME_MAX];
	snprintf(filename, FILENAME_MAX, "%s.crypt", argv[1]);

	FILE *dest = fopen(filename, "wb");

	if (!dest)
	{
		fprintf(stderr, "failed to open %s\n", filename);
		free(bin);
		return 6;
	}

	if (!fwrite(bin, size, 1, dest))
	{
		fprintf(stderr, "failed to write polymorphic code into %s\n", filename);
		free(bin);
		return 7;
	}

	free(bin);

	return 0;
}

void help()
{
	printf("usage: mkpoly ");
	printf("<source> <crypt-off> <crypt-size> <engine-off>\n");
	printf("<source>     the filename of the binary file\n");
	printf("<crypt-off>  the offset of the section to crypt\n");
	printf("<crypt-size> the size of the section to crypt\n");
	printf("<engine-off> the offset where to place the decryptor\n");
}

