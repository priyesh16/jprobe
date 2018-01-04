#include<linux/module.h>
#include<linux/version.h>
#include<linux/kernel.h>
#include<linux/init.h>
#include<linux/kprobes.h>
#include<linux/netlink.h>
#include<linux/filter.h>
#include<net/ip.h>

//int my_handler(struct sock *sk, struct sk_buff *skb, u32 portid, unsigned int group, int report, gfp_t flags) {
//static unsigned int my_handler(void *ctx, const struct bpf_insn *insn) {
int filter_handler(struct sock *sk, struct sk_buff *skb, unsigned int cap) {
    struct nlmsghdr *nlh;
    struct ifinfomsg *ifm;
    struct sk_filter *filter;
    struct sock_filter inst[15];
    int i = 0;
    rcu_read_lock();
    filter = rcu_dereference(sk->sk_filter);
    if (filter == NULL)
        jprobe_return();
    rcu_read_unlock();
    nlh = (struct nlmsghdr *)skb->data;
    if (nlh->nlmsg_type != 16)
        jprobe_return();
    ifm = nlmsg_data(nlh);
    printk("filter1_notify: \n");
    printk("sock : %p: \n", sk);
    printk("skb : %p: \n", skb);
    printk("skb->data : %p: \n", skb->data);
    printk("skb->protocol : %d: \n", skb->protocol);
    printk("nlh->nlmsg_type : %d: \n", nlh->nlmsg_type);
    printk("nlh->nlmsg_pid : %d: \n", nlh->nlmsg_pid);
    printk("ifm->ifi_type : %d: \n", ifm->ifi_type);
    printk("ifm->ifi_index : %d: \n", ifm->ifi_index);
    printk("skb->data[20] : %d: \n", skb->data[20]);
    printk("filter : %p: \n", filter);
    printk("orig_program : %p: \n", filter);
    for (i = 0; i < 1; i++) {
        inst[i] = filter->prog->orig_prog->filter[i];
        printk("inst%d : %x %x %x %x: \n",i , inst[i].code, inst[i].jt, inst[i].jf, inst[i].k);
    }
/*
    //printk("filter->prog : %p: \n", filter->prog);
    //printk("filter->prog->len : %d: \n", filter->prog->len);
    printk("final_program : %p: \n", filter);
    for (i = 0; i < 5; i++) {
        inst[i] = filter->prog->insns[i];
        printk("inst%d : %x %x %x %x: \n",i , inst[i].code, inst[i].jt, inst[i].jf, inst[i].k);
    }
*/
    jprobe_return();
    return -1;
}

int attach_handler(struct sock_fprog *fprog, struct sock *sk) {
    //struct sk_filter *filter;
    struct sock_filter *filter;
    struct sock_filter inst[15];
    int i = 0;
    filter = fprog->filter;
    inst[0] = *filter;
    printk("attach_notify: \n");
    printk("sock: %p\n", sk);
    printk("filter: %p\n", filter);
    printk("inst%d : %x %x %x %x: \n",i , inst[i].code, inst[i].jt, inst[i].jf, inst[i].k);
    
/*
    printk("filter : %p: \n", filter);
    printk("filter->prog : %p: \n", filter->prog);
    printk("filter->prog->len : %d: \n", filter->prog->len);
    for (i = 0; i < 8; i++) {
        inst[i] = filter->prog->insns[i];
        printk("inst%d : %x %x %x %x: \n",i , inst[i].code, inst[i].jt, inst[i].jf, inst[i].k);
    }
*/
    jprobe_return();
    return -1;
}

int hit = 0;
unsigned int filter_func(void *ctx, const struct bpf_insn *insn) {
    struct nlmsghdr *nlh;
    struct ifinfomsg *ifm;
    struct sk_buff *skb;
    int i = 0;
    int offsetdata;
    skb = (struct sk_buff *)ctx;
    nlh = (struct nlmsghdr *)skb->data;
    if (nlh->nlmsg_type != 16)
        jprobe_return();
    ifm = nlmsg_data(nlh);
    hit = 1;
    printk("filter_notify: \n");
    printk("skb : %p: \n", skb);
    printk("skb->data : %p: \n", skb->data);
    printk("address of skb->data : %p: \n", &(skb->data));
    printk("skb->data : %p: \n", *(&(skb->data)));
    printk("skb->protocol : %d: \n", skb->protocol);
    printk("nlh->nlmsg_type : %d: \n", nlh->nlmsg_type);
    printk("ifm->ifi_index : %d: \n", ifm->ifi_index);
    printk("skb->data[39] : %d: \n", skb->data[39]);
    for (i = 0; i < 50; i=i+5) {
        printk("skb->data%d : %d %d %d %d %d: \t", i, skb->data[i], skb->data[i+1], skb->data[i+2],skb->data[i+3],skb->data[i+4]);
        i = i + 5;
        printk("skb->data%d : %d %d %d %d %d: \t", i, skb->data[i], skb->data[i+1], skb->data[i+2],skb->data[i+3],skb->data[i+4]);
        i = i + 5;
        printk("skb->data%d : %d %d %d %d %d: \t", i, skb->data[i], skb->data[i+1], skb->data[i+2],skb->data[i+3],skb->data[i+4]);
        printk("\n");
    }
    offsetdata = offsetof(struct sk_buff, data);
    printk("offsetdata : %d: \n", offsetdata);
    printk("address of skb->data[offset] : %p: \n", ((char *)skb + offsetdata));
/*
    uintptr_t skbdataptr;
    skbdataptr = *(uintptr_t *)((char *)skb + offsetdata);
    printk("skb->data[offset] : %p: \n", skbdataptr);
    printk("skb->ifindex[offset] : %d: \n", *(int *)(skbdataptr + 20));
    for (i = 0; i < 15; i++) {
        printk("inst%d : %x %x %x %x %x: \n",i , insn[i].code, insn[i].dst_reg, insn[i].src_reg, insn[i].off, insn[i].imm);
    }
    i = 5;
    printk("inst%d : %x %x %x %x %x: \n",i , insn[i].code, insn[i].dst_reg, insn[i].src_reg, insn[i].off, insn[i].imm);
    printk("inst%d : protocol is  %d: \n",i , insn[i].imm);
    i = 7;
    printk("inst%d : %x %x %x %x %x: \n",i , insn[i].code, insn[i].dst_reg, insn[i].src_reg, insn[i].off, insn[i].imm);
    printk("inst%d : nlmsg_type is  %d: \n",i , insn[i].imm);
    i = 10;
    printk("inst%d : %x %x %x %x %x: \n",i , insn[i].code, insn[i].dst_reg, insn[i].src_reg, insn[i].off, insn[i].imm);
    printk("inst%d : ifIndex is  %d: \n",i , insn[i].imm);
    printk("offsetproto : %ld: \n", offsetof(struct sk_buff, protocol));
    printk("skb->proto[offset] : %d: \n", ((char *)skb)[offsetof(struct sk_buff, protocol)]);
    printk("skb->ifindex[offset] : %d: \n", (int)*((char *)skb + offsetof(struct sk_buff, data) + 20));
    for (i = 0; i < 25; i++)
        printk("skb->data[offset] : %d: \n", (int)*((char *)skb + offsetof(struct sk_buff, data) + i));
*/
    jprobe_return();
    return -1;

}


static struct jprobe filter1_probe;
static struct jprobe filter2_probe;
static struct jprobe attach_probe;

static int mprotect_ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
   int retval;
   if (hit == 1) {
       printk("Original return address: 0x%lx\n", (unsigned long)ri->ret_addr);
       retval  = regs_return_value(regs);
       printk(KERN_INFO "returned %d \n", retval);
    }
   hit = 0;
   return 0;
}
static struct kretprobe filter2_retprobe =
{
   .handler = mprotect_ret_handler, // return probe handler
   .maxactive = NR_CPUS // max number of kretprobe instances
};

int myinit(void)
{
//    filter1_probe.kp.addr = (kprobe_opcode_t *)0xffffffffac5cdc10;
    filter1_probe.kp.addr = (kprobe_opcode_t *)kallsyms_lookup_name("sk_filter_trim_cap");
    filter1_probe.entry = (kprobe_opcode_t *)filter_handler;
    register_jprobe(&filter1_probe);
    //filter2_probe.kp.addr = (kprobe_opcode_t *)0xffffffffabf8ad20;
    filter2_probe.kp.addr = (kprobe_opcode_t *)kallsyms_lookup_name("__bpf_prog_run");
    filter2_probe.entry = (kprobe_opcode_t *)filter_func;
    register_jprobe(&filter2_probe);
    filter2_retprobe.kp.addr = (kprobe_opcode_t *)kallsyms_lookup_name("__bpf_prog_run");
    register_kretprobe(&filter2_retprobe);
    attach_probe.kp.addr = (kprobe_opcode_t *)kallsyms_lookup_name("sk_attach_filter");
    attach_probe.entry = (kprobe_opcode_t *)attach_handler;
    register_jprobe(&attach_probe);
    return 0;
}

void myexit(void)
{
    unregister_jprobe(&filter1_probe);
    unregister_jprobe(&filter2_probe);
    unregister_jprobe(&attach_probe);
    unregister_kretprobe(&filter2_retprobe);

    printk("module removed\n ");
}

module_init(myinit);
module_exit(myexit);

/*Kernel module Comments*/
MODULE_AUTHOR("Manoj");
MODULE_DESCRIPTION("SIMPLE MODULE");
MODULE_LICENSE("GPL");
//MODULE_LICENSE("GPL v2");
