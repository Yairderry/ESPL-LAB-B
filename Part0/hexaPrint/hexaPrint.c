#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void printHex(char *buffer, int length);

int main(int argc, char **argv)
{
    char *binaryFileName = argv[1];
    FILE *inputFile = fopen(binaryFileName, "r");
    char buffer[256];

    if (inputFile)
    {
        /* Loop will continue until an end of file is reached i.e. fread returns 0 elements read */
        while (fread(buffer, 4, 1, inputFile) == 1)
            printHex(buffer, 4);
        fclose(inputFile);
    }
    return 0;
}

void printHex(char *buffer, int length)
{
    for (int i = 0; i < length; i++)
        printf("%02X ", (unsigned char)buffer[i]);
}
