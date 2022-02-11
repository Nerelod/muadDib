#ifdef PTREGS_SYSCALL_STUBS
static asmlinkage long (*og_accept)(const struct pt_regs *);

/* We can only modify our own privileges, and not that of another
 * process. Just have to wait for signal 64 (normally unused)
 * and then call the set_root() function. */
asmlinkage int muaddib_accept(const struct pt_regs *regs){

    printk("accept hooked :)");
    return og_accept(regs);

}
#else
/* This is the old way of declaring a syscall hook */
static asmlinkage long (*og_accept)(int sockfd, struct sockaddr *restrict addr, socklen_t *restrict addrlen);

static asmlinkage int muaddib_accept(int sockfd, struct sockaddr *restrict addr, socklen_t *restrict addrlen){
    printk("accept hooked :)");
    return og_accept(sockfd, addr, addrlen);
}
#endif
