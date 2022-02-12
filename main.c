
#pragma warning(disable : 4996)

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <dirent.h>

#include "antivirus.h"

void myFgets(char *str);

/*
The main function. Returns 0 upon successful execution.
*/
int main(int argc, char **argv)
{
	char dirPath[SIZE] = {0};
	char sigPath[SIZE] = {0};
	char *signature = 0;

	if (argc == 3 && getPaths(argv, dirPath, sigPath)) // only starting if all params are valid
	{
		welcomeMsg(dirPath, sigPath);
		signature = getSignature(sigPath);
		scanFiles(signature, dirPath);
		sortResults();
		printResults();
		createLog();
	}
	else
	{
		printf("Invalid parameters!\n");
		printf("Usage: ./antivirus path/to/dir path/to/signature\n");

		return 1;
	}

	return 0;
}

/*
Simple function for shortening fgets
	input:
			str - the string to read input into
	output: none
*/
void myFgets(char *str)
{
	fgets(str, SIZE, stdin);
	str[strcspn(str, "\n")] = 0;
}
