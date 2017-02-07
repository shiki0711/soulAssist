#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/limits.h>
#include <linux/sched.h>
#include <asm/uaccess.h>
#include <linux/time.h>
#include <linux/slab.h>

#include "dbg.h"
#include "hook_def.h"
#include "hook_config.h"
#include "encrypt.h"

static char func_name[NAME_MAX] = "sys_recvfrom";

/* per-instance private data */
struct recv_param {
  char __user *buff;  /* in ARM_r1  */
  size_t size;  /* in ARM_r2  */
  char *work;
};

static int get_usp_buff(char *to, const char __user *from, size_t size) {
  unsigned long n = 0;
  n = copy_from_user(to, from, size);
  return (n == 0);
}

static int filter_chat_packet_type(packet_info_t *info){
  static int types[] = {50014, 50054, 0};
  int i = 0;
  
  while(types[i]){
    if(types[i] == info->type){
      return 1;
    }
    ++i;
  }
  return 0;
}

/* entry of sys_sendto */
static int entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
  struct recv_param *data;
  
  data = (struct recv_param *)ri->data;
  data->buff = (char __user *)(regs->ARM_r1);
  data->size = (size_t)(regs->ARM_r2);
  data->work = NULL;
  return 0;
}

/*
 * Return-probe handler: change the return value of a given pid.
 */
static int ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
  struct recv_param *data;
  pid_t target_pid = 0;
  packet_info_t info = {0};
  int debug_dump_packet = 0;
  int ret;
  long recv_size = 0;
  struct timeval tv;

  data = (struct recv_param *)ri->data;
  recv_size = (long)(regs->ARM_r0);
  //hook_debug("sys_recvfrom buffer size=%d\n", data->size);
  //hook_debug("sys_recvfrom return size=%ld\n", recv_size);
  
  if(hook_config_int("target_pid", &target_pid)){
    //hook_debug("sys_send no target_pid!\n");
    return 0;
  }
  hook_config_int("debug_dump_packet", &debug_dump_packet);
  if(target_pid && target_pid==current->tgid){
    if(!debug_dump_packet){
      return 0;
    }
    
    data->work = kcalloc(1, recv_size + 1, GFP_KERNEL);
    if(!data->work){
      hook_debug("sys_resvfrom alloc working buff error! size=%ld\n", recv_size);
      return 0;
    }
    if(!get_usp_buff(data->work, data->buff, recv_size)){
      hook_debug("sys_recvfrom copy packet from userspace faild!\n");
      kfree(data->work);
      data->work = NULL;
      return 0;
    }
    
    //hook_debug("sys_send matched: pid=%d data=%s\n", current->pid, &data->work[12]);
    ret = filter_chat_packet(data->work, recv_size, &info);
    //hook_debug("filter return: %d\n", ret);
    if(ret){
      /* decrypt packet */
      decrypt_packet(&info);
      if(filter_chat_packet_type(&info)){
        do_gettimeofday(&tv);
        hook_debug("[%ld:%09ld]]sys_recvfrom original data:\n", tv.tv_sec, tv.tv_usec);
        show_packet_info(&info);
      }

      put_packet(&info);
    }
    kfree(data->work);
    data->work = NULL;
  }
  return 0;
}

static struct kretprobe hook_kretprobe = {
  .handler = ret_handler,
  .entry_handler = entry_handler,
  .data_size = sizeof(struct recv_param),
  /* Probe up to 20 instances concurrently. */
  .maxactive = 20,
};

int hook_recv_init(void)
{
  int ret;

  hook_kretprobe.kp.symbol_name = func_name;
  ret = register_kretprobe(&hook_kretprobe);
  if (ret < 0) {
    hook_debug("register_kretprobe failed, returned %d\n", ret);
    return -1;
  }
  hook_debug("Planted return probe at %s: %p\n",
             hook_kretprobe.kp.symbol_name, hook_kretprobe.kp.addr);
  return 0;
}

void hook_recv_exit(void)
{
  unregister_kretprobe(&hook_kretprobe);
  hook_debug("kretprobe at %p unregistered\n", hook_kretprobe.kp.addr);

  /* nmissed > 0 suggests that maxactive was set too low. */
  hook_debug("Missed probing %d instances of %s\n",
             hook_kretprobe.nmissed, hook_kretprobe.kp.symbol_name);
}

