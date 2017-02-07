
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/ktime.h>
#include <linux/limits.h>
#include <linux/sched.h>
#include <asm/uaccess.h>

#include "dbg.h"
#include "proc.h"
#include "hook_def.h"
#include "hook_config.h"

//module_param(target_pid, uint, 0);
MODULE_PARM_DESC(func, "Hook hijack; this module will replace given syscall");


typedef int (*hook_init_func_t)(void);
typedef void (*hook_exit_func_t)(void);

typedef struct hook_entry {
  hook_init_func_t entry;
  hook_exit_func_t exit;
} hook_entry_t;

static hook_entry_t hook_entry_list [] = {
  {hook_send_init, hook_send_exit},
  {hook_recv_init, hook_recv_exit},
  {NULL, NULL}
};

static int __init hook_init(void)
{
  int i = 0;
  /* create /proc entry */
  if(hook_init_proc()){
    hook_debug("hook_init_proc error!\n");
    return -1;
  }
  if(hook_config_init()){
    hook_debug("hook_config_init error!\n");
    return -1;
  }
  while(hook_entry_list[i].entry) {
    if(hook_entry_list[i].entry()){
      return -1;
    }
    ++i;
  }
  hook_debug("Module init ok!\n");
  return 0;
}

static void __exit hook_exit(void)
{
  int i = 0;
  while(hook_entry_list[i].exit) {
    hook_entry_list[i].exit();
    ++i;
  }
  hook_config_exit();
  hook_release_proc();
  hook_debug("Module exit ok!\n");
}

module_init(hook_init)
module_exit(hook_exit)
MODULE_LICENSE("GPL");

