#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct virus
{
    unsigned short SigSize;
    char virusName[16];
    unsigned char *sig;
} virus;

virus *readVirus(FILE *filename);
void printVirus(virus *virus, FILE *output);
void printHex(unsigned char *buffer, int length, FILE *output);

int main(int argc, char **argv)
{
    FILE *inputFile = fopen("signatures-L", "r");
    FILE *outputFile = fopen("test", "w");
    char buffer[5];
    char *line;
    virus *currVirus;

    if ((line = fgets(buffer, 5, inputFile)) != NULL)
    {
        if (strncmp(line, "VISL", 4) != 0)
        {
            fprintf(stderr, "not little endian");
            fclose(inputFile);
            exit(0);
        }
    }

    while ((currVirus = readVirus(inputFile)) != NULL)
    {
        printVirus(currVirus, outputFile);
        free(currVirus->sig);
        free(currVirus);
    }

    fclose(inputFile);
    fclose(outputFile);
    return 0;
}

virus *readVirus(FILE *filename)
{
    virus *currVirus = malloc(sizeof(virus));

    if (fread(currVirus, 18, 1, filename) != 0)
    {
        currVirus->sig = malloc(currVirus->SigSize);
        if (fread(currVirus->sig, currVirus->SigSize, 1, filename) != 0)
            return currVirus;
    }

    free(currVirus);
    return NULL;
}

void printVirus(virus *virus, FILE *output)
{
    fprintf(output, "Virus name: %s\n", virus->virusName);
    fprintf(output, "Virus size: %d\n", virus->SigSize);
    fprintf(output, "signature:\n");
    printHex(virus->sig, virus->SigSize, output);
}

void printHex(unsigned char *buffer, int length, FILE *output)
{
    for (int i = 0; i < length; i++)
        fprintf(output, "%02hhX ", buffer[i]);

    fprintf(output, "\n\n");
}