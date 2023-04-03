#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct virus
{
    unsigned short SigSize;
    char virusName[16];
    unsigned char *sig;
} virus;

typedef struct link link;
struct link
{
    link *nextVirus;
    virus *vir;
};

struct fun_desc
{
    char *name;
    link *(*fun)(link *, char *);
};

virus *readVirus(FILE *filename);
void printVirus(virus *virus, FILE *output);
void printHex(unsigned char *buffer, int length, FILE *output);
void list_print(link *virus_list, FILE *output);
link *list_append(link *virus_list, virus *data);
void list_free(link *virus_list);
void virus_free(virus *virus);
void printOptions(struct fun_desc *menu);

link *load_signatures(link *list, char *fileName);
link *print_signatures(link *list, char *fileName);
link *detect_viruses(link *list, char *fileName);
link *fix_file(link *list, char *fileName);
link *quit(link *list, char *fileName);
int detect_virus(virus *virus, int size, char *buffer, int isDetection, char *fileName);
int get_file_size(FILE *file);
void neutralize_virus(char *fileName, int signatureOffset);

int main(int argc, char **argv)
{
    link *list = NULL;
    char *fileName = "";
    char lineBuffer[256];
    char *line;
    struct fun_desc menu[] = {{"Load signatures", load_signatures}, {"Print signatures", print_signatures}, {"Detect viruses", detect_viruses}, {"Fix file", fix_file}, {"Quit", quit}, {NULL, NULL}};

    if (argc > 1)
        fileName = argv[1];

    printOptions(menu);

    while ((line = fgets(lineBuffer, 256, stdin)) != NULL)
    {
        printf("\n");
        int prompt = line[0] - 48;
        if (1 <= prompt && prompt <= 5)
            list = menu[prompt - 1].fun(list, fileName);
        else
        {
            printf("Not within bounds\n");
            quit(list, fileName);
        }

        printOptions(menu);
    }

    quit(list, fileName);
    return 0;
}

void list_print(link *virus_list, FILE *output)
{
    if (virus_list == NULL)
        return;

    printVirus(virus_list->vir, output);
    fprintf(output, "\n\n");
    list_print(virus_list->nextVirus, output);
}

link *list_append(link *virus_list, virus *data)
{
    link *newLink = malloc(sizeof(link));
    newLink->nextVirus = virus_list;
    newLink->vir = data;

    return newLink;
}

void list_free(link *virus_list)
{
    if (virus_list == NULL)
        return;

    list_free(virus_list->nextVirus);
    virus_free(virus_list->vir);
    free(virus_list);
}

void virus_free(virus *virus)
{
    free(virus->sig);
    free(virus);
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
}

void printOptions(struct fun_desc *menu)
{
    printf("Please choose a function (ctrl^D for exit):\n");
    for (int i = 1; i <= 5; i++)
        printf("%d)  %s\n", i, menu[i - 1].name);
    printf("Option: ");
}

link *quit(link *list, char *fileName)
{
    list_free(list);
    exit(0);
}

link *load_signatures(link *list, char *fileName)
{
    char filename[256];
    char beggingBuffer[5];
    char *line;
    virus *currVirus;
    FILE *inputFile;

    if (fgets(filename, 256, stdin) == NULL)
    {
        fprintf(stderr, "couldn't read line");
        exit(0);
    }

    filename[strlen(filename) - 1] = '\0';
    if ((inputFile = fopen(filename, "r")) == NULL)
    {
        fprintf(stderr, "couldn't read file");
        exit(0);
    }

    if ((line = fgets(beggingBuffer, 5, inputFile)) != NULL)
    {
        if (strncmp(line, "VISL", 4) != 0)
        {
            fprintf(stderr, "not little endian");
            fclose(inputFile);
            exit(0);
        }
    }

    while ((currVirus = readVirus(inputFile)) != NULL)
        list = list_append(list, currVirus);

    fclose(inputFile);

    return list;
}

link *print_signatures(link *list, char *fileName)
{
    list_print(list, stdout);

    return list;
}

link *detect_viruses(link *list, char *fileName)
{
    char suspectedFileBuffer[10000];
    FILE *suspectedFile = fopen(fileName, "rb");

    if (suspectedFile == NULL)
        return list;

    fread(suspectedFileBuffer, sizeof(suspectedFileBuffer), 1, suspectedFile);
    int size = get_file_size(suspectedFile);

    link *currLink = list;
    while (currLink != NULL)
    {
        printf(detect_virus(currLink->vir, size, suspectedFileBuffer, 1, fileName) == 1 && currLink->nextVirus != NULL ? "\n" : "");
        currLink = currLink->nextVirus;
    }

    return list;
}

int detect_virus(virus *virus, int size, char *buffer, int isDetetion, char *fileName)
{
    for (int i = 0; i <= size - virus->SigSize; i++)
    {
        if (memcmp(virus->sig, buffer + i, virus->SigSize) == 0)
        {
            if (isDetetion)
                printf("The starting byte location in the suspected file: %d\nThe virus name: %s\nThe size of the virus signature: %d\n", i, virus->virusName, virus->SigSize);
            else
                neutralize_virus(fileName, i);
            return 1;
        }
    }

    return 0;
}

int get_file_size(FILE *file)
{
    fseek(file, 0L, SEEK_END);
    int file_size = ftell(file);
    rewind(file);
    return file_size;
}

link *fix_file(link *list, char *fileName)
{
    char suspectedFileBuffer[10000];
    FILE *suspectedFile = fopen(fileName, "rb");

    if (suspectedFile == NULL)
        return list;

    fread(suspectedFileBuffer, sizeof(suspectedFileBuffer), 1, suspectedFile);
    int size = get_file_size(suspectedFile);

    link *currLink = list;
    while (currLink != NULL)
    {
        detect_virus(currLink->vir, size, suspectedFileBuffer, 0, fileName);
        currLink = currLink->nextVirus;
    }

    return list;
}

void neutralize_virus(char *fileName, int signatureOffset)
{
    FILE *file = fopen(fileName, "r+b");
    fseek(file, signatureOffset, SEEK_SET);
    char ret = 0xc3;
    fwrite(&ret, 1, 1, file);
    fclose(file);
}