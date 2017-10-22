#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char *argv[])
{
	uid_t id;
	char bash[] = "/bin/bash\x00";
	char *envp[1] = { NULL };
	char *arg[3] = {"/bin/bash", NULL};

    	setreuid(1337, 1337);
    	id = geteuid();

	if(id == 0){
		printf("\e[01;36mYou got super powers!\e[00m\n\n");
		execve(bash, arg, envp);
	} else {
		printf("\e[00;31mYou have no power here! :( \e[00m\n");
		printf("EUID: %d\n\n", id);
	}
    	return 0;
}
