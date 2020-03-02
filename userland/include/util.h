#ifndef _UTIL_H
#define _UTIL_H

//#include "config.h"

#define ERROR -1
#define RL_BUFSIZE 2048
#define TOK_BUFSIZE 64
#define TOK_DELIM " \t\r\n\a"

extern char *optarg;
// extern int optind;

char good[] = "\e[01;34m[*]\e[00m";
char awesome[] = "\e[01;32m[+]\e[00m";
char bad[] = "\e[01;31m[-]\e[00m";
char warn[] = "\e[01;33m[!]\e[00m";

void p_error(char *message)
{
	char error_message[129];

	strcpy(error_message, bad);
	strcat(error_message, " Error ");
	strncat(error_message, message, 93);
	perror(error_message);
	printf("\n\n");
}

void fatal(char *message)
{
	p_error(message);
	exit(ERROR);
}

void banner(void)
{
	fprintf(stdout, "\e[01;31m\n"
	"\t  █████▒▄▄▄     ▄▄▄█████▓ ▄▄▄       ██▓     ██▓▄▄▄█████▓▓██   ██▓\n"
	"\t▓██   ▒▒████▄   ▓  ██▒ ▓▒▒████▄    ▓██▒    ▓██▒▓  ██▒ ▓▒ ▒██  ██▒\n"
	"\t▒████ ░▒██  ▀█▄ ▒ ▓██░ ▒░▒██  ▀█▄  ▒██░    ▒██▒▒ ▓██░ ▒░  ▒██ ██░\n"
	"\t░▓█▒  ░░██▄▄▄▄██░ ▓██▓ ░ ░██▄▄▄▄██ ▒██░    ░██░░ ▓██▓ ░   ░ ▐██▓░\n"
	"\t░▒█░    ▓█   ▓██▒ ▒██▒ ░  ▓█   ▓██▒░██████▒░██░  ▒██▒ ░   ░ ██▒▓░\n"
	"\t ▒ ░    ▒▒   ▓▒█░ ▒ ░░    ▒▒   ▓▒█░░ ▒░▓  ░░▓    ▒ ░░      ██▒▒▒ \n"
	"\t ░       ▒   ▒▒ ░   ░      ▒   ▒▒ ░░ ░ ▒  ░ ▒ ░    ░     ▓██ ░▒░ \n"
	"\t ░ ░     ░   ▒    ░        ░   ▒     ░ ░    ▒ ░  ░       ▒ ▒ ░░  \n"
	"\t             ░  ░              ░  ░    ░  ░ ░            ░ ░     \n"
	"\t                                                         ░ ░     \n");
	fprintf(stdout, "\n\e[01;32m\t\t\t\t  Reptile Wins\n");
	fprintf(stdout, "\e[00m\t\t\t\tFlawless Victory\n\n");
}

void banner2(void)
{
	fprintf(stdout, "\e[01;31m\n\n"
    "███████ ██ ███    ██ ██ ███████ ██   ██    ██   ██ ██ ███    ███     ██ ██\n"
	"██      ██ ████   ██ ██ ██      ██   ██    ██   ██ ██ ████  ████     ██ ██\n"
	"█████   ██ ██ ██  ██ ██ ███████ ███████    ███████ ██ ██ ████ ██     ██ ██\n"
	"██      ██ ██  ██ ██ ██      ██ ██   ██    ██   ██ ██ ██  ██  ██          \n"
	"██      ██ ██   ████ ██ ███████ ██   ██    ██   ██ ██ ██      ██     ██ ██\n"
	"\n");
}

#endif
