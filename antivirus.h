#ifndef ANTIVIRUS_H_
#define ANTIVIRUS_H_

/*
   This is the antivirus header file.
   It contains the constants and functions used to execute
   antivirus-related logic.
*/

#define SIZE 100
#define SLASH "/"
#define TWENTY_PERCENT 0.2
#define EIGHTY_PERCENT 0.8
#define THREE 3
#define DIR_INDEX 1
#define SIG_INDEX 2

#define FALSE 0
#define TRUE !FALSE

typedef struct log
{
    char dir[SIZE];
    char sig[SIZE];
    char option[SIZE];
    char results[SIZE][SIZE];
} log;

void welcomeMsg(char *dirPath, char *sigPath);
void createLog();
int getPaths(char **argv, char *dirPath, char *sigPath);
int checkDir(char *dirPath);
void sortResults();
void printResults();
char *getSignature(char *sigPath);
void scanFiles(char *sig, char *dirPath);
int scanFile(char *currentFilePath, char *sig, int mode);
int findSignature(char *file, char *sig, int fileSize, int start, int end);
void cleanBuffer(char *buff, int size);

int sigSize = 0;
int results = 0;
log programLog = {0};

/*
This function prints the welcome message
    input: 	
            dirPath - the path to the directory to be scanned
            sigPath - the path to the signature
    output:	none
*/
void welcomeMsg(char *dirPath, char *sigPath)
{
    printf("Virus Scanner\n\n");

    printf("Folder to scan: %s\nVirus signature: %s\n\n", dirPath, sigPath);
}

/*
This function sorts the logged results in alphabetical order
    input:  none
    output:	none
*/
void sortResults()
{
    int i = 0, j = 0;
    char temp[SIZE] = {0};

    for (i = 0; i < results - 1; i++)
    {
        for (j = 0; j < results - i - 1; j++)
        {
            if (strcasecmp(programLog.results[j], programLog.results[j + 1]) > 0)
            {
                strcpy(temp, programLog.results[j]);
                strcpy(programLog.results[j], programLog.results[j + 1]);
                strcpy(programLog.results[j + 1], temp);
            }
        }
    }
}

void printResults()
{
    int i = 0;

    for (i = 0; i < results; i++)
    {
        printf("%s\n", programLog.results[i]);
    }

    printf("\nScan completed.\nSee log path for results: %s/log.txt\n", programLog.dir);
}

/*
A function to compose and write logs to a log file
    input:  none
    output: none
*/
void createLog()
{
    FILE *logFile = 0;
    char logPath[SIZE] = {0}, temp[SIZE] = {0};
    int i = 0, j = 0;

    strcpy(logPath, programLog.dir);
    strcat(logPath, "/log.txt");

    logFile = fopen(logPath, "w+");

    fprintf(logFile, "Anti-virus log\n\nFolder to scan: %s\nVirus signature: %s\n\nScanning option: %s\n\nResults:\n", programLog.dir, programLog.sig, programLog.option);

    for (i = 0; i < results; i++)
    {
        fprintf(logFile, "%s\n", programLog.results[i]);
    }

    fclose(logFile);
}

/*
A function to get the path of the directory to scan and the path of the file containing the virus signature
    input:
            argv - array of command line arguments
            dirPath - a pointer to write the directory path to
            sigPath - a pointer to write the signature path to
    output:
            0 - invalid params
            1 - valid params
*/
int getPaths(char **argv, char *dirPath, char *sigPath)
{
    int success = TRUE;

    strcpy(dirPath, argv[DIR_INDEX]);
    strcpy(sigPath, argv[SIG_INDEX]);

    if (!checkDir(dirPath) || !fopen(sigPath, "rb"))
    {
        success = FALSE;
    }

    strcpy(programLog.dir, dirPath);
    strcpy(programLog.sig, sigPath);

    return success;
}

/*
This function will check if the dir has any files
    input:
            dirPath - the path to the directory to be scanned
    output:
            0 - invalid dir
            1 - valid dir
*/
int checkDir(char *dirPath)
{
    int valid = FALSE;
    DIR *dir = opendir(dirPath);

    if (dir != NULL)
    {
        readdir(dir);
        readdir(dir);
        if (readdir(dir) != NULL)
        {
            valid = TRUE;
        }

        closedir(dir);
    }

    return valid;
}

/*
A function to get the virus signature
    input:
            sigPath - a string containing the path of the signature file
    output:
            a string containing the signature
*/
char *getSignature(char *sigPath)
{
    FILE *sigFile = fopen(sigPath, "rb");
    char *signature = 0;
    long size = 0;

    fseek(sigFile, 0, SEEK_END);
    sigSize = ftell(sigFile) - 1; // getting the size of the signature by checking end location
    fseek(sigFile, 0, SEEK_SET);

    signature = (char *)malloc(sigSize); // allocating a buffer for the signature and saving it
    fread(signature, 1, sigSize, sigFile);

    return signature;
}

/*
This function lets the user choose the mode and iterates over the files in the directory
    input:
            sig - the signature
            dirPath - the path to the directory to be scanned
    output: none
*/
void scanFiles(char *sig, char *dirPath)
{
    struct dirent *dp;
    DIR *dir = opendir(dirPath);
    char currentFile[SIZE] = {0};
    int mode = 0;

    printf("Press 0 for a normal scan or any other key for a quick scan: ");
    scanf("%d", &mode);
    getchar();
    strcpy(programLog.option, !mode ? "Normal scan" : "Quick scan");

    mode = !mode ? 0 : 1; // if the mode is 0 it is kept 0, if something else it is set to 1 to simplify other expressions

    printf("\nScanning:\n");
    while ((dp = readdir(dir)) != NULL)
    {
        if ((strcmp(dp->d_name, ".") == 0) || (strcmp(dp->d_name, "..") == 0)) {
            continue;
        }

        strcpy(currentFile, dirPath);    // resetting the current file string
        strcat(currentFile, SLASH);      // to contain '<dir>/'
        strcat(currentFile, dp->d_name); // and adding the current file name '<dir>/<file>

        switch (scanFile(currentFile, sig, mode))
        {
            case 0:
                strcpy(programLog.results[results], currentFile);
                strcat(programLog.results[results], " - Clean");
                results++;
                break;
            case 1:
                strcpy(programLog.results[results], currentFile);
                strcat(programLog.results[results], " - Infected! (first 20%)");
                results++;
                break;
            case 2:
                strcpy(programLog.results[results], currentFile);
                strcat(programLog.results[results], " - Infected! (last 20%)");
                results++;
                break;
            case 3:
                strcpy(programLog.results[results], currentFile);
                strcat(programLog.results[results], " - Infected!");
                results++;
                break;
        }
    }
    closedir(dir);
}

/*
This function will scan the file with the selected mode
    input:
            currentFilePath - the path to the file that is currently being scanned
            sig - the signature
            mode - the scan mode
    output:
            0 - not found
            1 - found in 1st 20%
            2 - found in last 20%
            3 - found in file
*/
int scanFile(char *currentFilePath, char *sig, int mode)
{
    FILE *currFile = fopen(currentFilePath, "rb");
    int i = !mode ? 2 : 0; // if the mode is normal the first 2 scans (first and last 20%) are skipped
    int fileSize = 0, found = FALSE, location = 0;
    char *buff = 0;

    fseek(currFile, 0, SEEK_END); // resetting position of the current file in case it's not at the beginning
    fileSize = ftell(currFile);   // allocating a string with the size of the current file
    fseek(currFile, 0, SEEK_SET);
    buff = (char *)malloc(fileSize);

    for (i; i < THREE && !found; i++)
    {
        cleanBuffer(buff, fileSize);        // restting the buffer
        fread(buff, 1, fileSize, currFile); // and reading the first byte
        fseek(currFile, 0, SEEK_SET);

        switch (i) // switch for every scan(1 - 1st 20%, 2nd - last 20%, 3rd - full)
        {
            case 0:
                if (findSignature(buff, sig, fileSize, 0, fileSize * TWENTY_PERCENT))
                {
                    location = 1;
                    found = TRUE;
                }
                break;
            case 1:
                if (findSignature(buff, sig, fileSize, fileSize * EIGHTY_PERCENT, fileSize))
                {
                    location = 2;
                    found = TRUE;
                }
                break;
            case 2:
                if (!mode && findSignature(buff, sig, fileSize, 0, fileSize))
                {
                    location = 3;
                    found = TRUE;
                }
                break;
            default:
                printf("err");
                break;
        }
    }

    free(buff);

    return location;
}

/*
Function that checks if the signature appears in a byte sequence
    input:
            file - file contents
            sig - the signature
            fileSize - the file's size (in bytes)
            start - start of scan range
            end - end of scan range
    output:
            0 - not found
            1 - found
*/
int findSignature(char *file, char *sig, int fileSize, int start, int end)
{
    int i = 0, j = 0, count = 0;

    for (i = start; i < end && count != sigSize; i++)
    {
        if (file[i] == sig[count])
        {
            count++;
        }
        else
        {
            count = 0;
        }
    }

    return count == sigSize ? 1 : 0;
}

/*
A function to clear a buffer(fill with NULL's)
    input: 
            buff - a buffer to be cleared
            size - the amount of bytes to reset to NULL
    output: none
*/
void cleanBuffer(char *buff, int size)
{
    int i = 0;

    for (i = 0; i < size; i++)
    {
        buff[i] = 0;
    }
}

#endif
