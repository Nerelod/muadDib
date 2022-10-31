#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

static struct nf_hook_ops nf_accept_tcp_hook_options;

static unsigned int nf_accept_tcp(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
	struct iphdr *iph;
	if(!skb)
		return NF_ACCEPT;
	iph = ip_hdr(skb);
	if (iph->protocol == IPPROTO_TCP) {
		return NF_ACCEPT;
	}
	return NF_ACCEPT;
}

int reg_nf_hook(void){
    int err;
    nf_accept_tcp_hook_options.hook = nf_accept_tcp;
    nf_accept_tcp_hook_options.pf = PF_INET;
    nf_accept_tcp_hook_options.hooknum = NF_INET_PRE_ROUTING;
    nf_accept_tcp_hook_options.priority = NF_IP_PRI_FIRST;
    #if LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0)
        err = nf_register_net_hook(&init_net, &nf_accept_tcp_hook_options);
    #else
        err = nf_register_hook(&nf_accept_tcp_hook_options);
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


void unreg_nf_hook(void){
    #if LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0)
    nf_unregister_net_hook(&init_net, &nf_accept_tcp_hook_options);
    #else
    nf_unregister_hook(&nf_accept_tcp_hook_options);
    #endif
    #ifdef DEBUGMSG
    printk(KERN_INFO "muaddib: Unregistered nethook");
    #endif

}
