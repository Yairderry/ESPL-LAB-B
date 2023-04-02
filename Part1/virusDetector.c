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
    link *(*fun)(link *);
};

virus *readVirus(FILE *filename);
void printVirus(virus *virus, FILE *output);
void printHex(unsigned char *buffer, int length, FILE *output);
void list_print(link *virus_list, FILE *output);
link *list_append(link *virus_list, virus *data);
void list_free(link *virus_list);
void virus_free(virus *virus);
void printOptions(struct fun_desc *menu);

link *loadSignatures(link *list);
link *printSignatures(link *list);
link *detectViruses(link *list);
link *fixFile(link *list);
link *quit(link *list);

int main(int argc, char **argv)
{
    link *list = NULL;

    struct fun_desc menu[] = {{"Load signatures", loadSignatures}, {"Print signatures", printSignatures}, {"Detect viruses", detectViruses}, {"Fix file", fixFile}, {"Quit", quit}, {NULL, NULL}};

    printOptions(menu);

    char buffer[256];
    char *line;

    while ((line = fgets(buffer, 256, stdin)) != NULL)
    {
        printf("\n");
        int prompt = line[0] - 48;
        if (1 <= prompt && prompt <= 5)
        {
            list = menu[prompt - 1].fun(list);
        }
        else
        {
            printf("Not within bounds\n");
            quit(list);
        }

        printOptions(menu);
    }

    quit(list);
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

link *quit(link *list)
{
    list_free(list);
    exit(0);
}

link *loadSignatures(link *list)
{
    char filename[256];
    char buffer[5];
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
        list = list_append(list, currVirus);

    fclose(inputFile);

    return list;
}

link *printSignatures(link *list)
{
    list_print(list, stdout);

    return list;
}

link *detectViruses(link *list)
{
    printf("Not implemented\n");

    return list;
}

link *fixFile(link *list)
{
    printf("Not implemented\n");

    return list;
}
