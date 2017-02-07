#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/limits.h>
#include <linux/sched.h>
#include <asm/uaccess.h>
#include <linux/scatterlist.h>
#include <linux/crypto.h>

#include "dbg.h"
#include "hook_def.h"
#include "hook_config.h"
#include "encrypt.h"

static char func_name[NAME_MAX] = "sys_sendto";

/* per-instance private data */
struct send_param {
  char __user *buff;  /* in ARM_r1  */
  size_t size;  /* in ARM_r2  */
  char *work;
};

/* TODO(yanfeng): json decoder */
static int hijack_packet_end_dungeon(packet_info_t *info) {
  int ret = 0;  /* if packet changed then return 1 */
  char *p1 = NULL;
  char *p2 = NULL;
  int property_value_int;
  int rc;
  char buf[16] = {0};
  
  rc = hook_config_int("dungeon_clrtime", &property_value_int);
  if(rc){
    /* none dungeon_clrtime config */
    return ret;
  }
  if(property_value_int <= 10 || property_value_int >= 100){
    /* we simply surpport value of range[10-99] only */
    return ret;
  }
  sprintf(buf, "%d", property_value_int);
  p1 = strstr(info->dec_data, "\"clrtimesecs\":");
  if(!p1){
    hook_debug("sys_sendto hijack_packet error when try to match finish dungeon(type=102) packet\n");
    return ret;
  }
  p1 += strlen("\"clrtimesecs\":");
  p2 = strstr(p1, ",");
  if(!p2){
    hook_debug("sys_sendto hijack_packet error while packet may broken\n");
    return ret;
  }
  /* now p1 point to the head of original value and p2 point to the tail */
  if((p2 - p1) < 2){
    /* no need to change clrtimesecs, return */
    return ret;
  }
  *p1 = buf[0];
  p1++;
  *p1 = buf[1];
  p1++;
  while(p1 != p2){
    /* fill gaps with spaces */
    *p1 = ' ';
    ++p1;
  }
  ret = 1;
   
  return ret;
}

static int hijack_packet_end_tower_rush(packet_info_t *info) {
  int ret = 0;  /* if packet changed then return 1 */
  char *p1 = NULL;
  char *p2 = NULL;
  int property_value_int;
  int rc;
  
  rc = hook_config_int("tower_rush_win", &property_value_int);
  if(rc){
    /* none tower_rush_win config */
    return ret;
  }
  if(property_value_int != 1){
    /* must be 1, which means win the game forcing */
    return ret;
  }
  p1 = strstr(info->dec_data, "\"bWin\":");
  if(!p1){
    hook_debug("sys_sendto hijack_packet error when try to match finish TR(type=816205) packet\n");
    return ret;
  }
  p1 += strlen("\"bWin\":");
  p2 = strstr(p1, ",");
  if(!p2){
    hook_debug("sys_sendto hijack_packet error: no [\"bWin\":] found\n");
    return ret;
  }
  /* now p1 point to the head of original value and p2 point to the tail */
  if(strncmp(p1, "true", strlen("true")) == 0){
    /* we already win the game, no need to change anymore, return */
    return ret;
  }
  if(strncmp(p1, "false", strlen("false")) != 0){
    hook_debug("sys_sendto hijack_packet error: [\"bWin\":] is neither true or false\n");
    return ret;
  }
  *p1 = 't';
  p1++;
  *p1 = 'r';
  p1++;
  *p1 = 'u';
  p1++;
  *p1 = 'e';
  p1++;
  /* fill gaps with spaces */
  *p1 = ' ';
  p1++;
  ret = 1;

  return ret;
}

typedef struct packet_handler {
  int type;
  int(*handler)(packet_info_t*);
} packet_handler_t;

static packet_handler_t hijack_packet_table[] = {
  {.type = 102, .handler = hijack_packet_end_dungeon},
  {.type = 816205, .handler = hijack_packet_end_tower_rush},
  {.type = 0, .handler = NULL}  /* sentinel */
};

/* try to match and perform packet handler */
static int hijack_packet(packet_info_t *info) {
  int i = 0;

  while(hijack_packet_table[i].type){
    if(hijack_packet_table[i].type == info->type){
      return hijack_packet_table[i].handler(info);
    }
    ++i;
  }
  return 0;
}

static int packet_handler_matched(int type){
  int i = 0;

  while(hijack_packet_table[i].type){
    if(hijack_packet_table[i].type == type){
      return 1;
    }
    ++i;
  }
  return 0;
}

static int get_usp_buff(char *to, const char __user *from, size_t size) {
  unsigned long n = 0;
  n = copy_from_user(to, from, size);
  return (n == 0);
}
static int set_usp_buff(char __user *to, char *from, size_t size){
  unsigned long n = 0;
  n = copy_to_user(to, from, size);
  return (n == 0);
}

/* entry of sys_sendto */
static int entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
  struct send_param *data;
  pid_t target_pid = 0;
  packet_info_t info = {0};
  char buffer[8] = {0};  /* header buffer */
  int debug_dump_packet = 0;
  int ret;
  
  data = (struct send_param *)ri->data;
  data->buff = (char __user *)(regs->ARM_r1);
  data->size = (size_t)(regs->ARM_r2);
  data->work = NULL;

  if(hook_config_int("target_pid", &target_pid)){
    //hook_debug("sys_send no target_pid!\n");
    return 0;
  }
  hook_config_int("debug_dump_packet", &debug_dump_packet);
  if(target_pid && target_pid==current->tgid){
    if(!debug_dump_packet){
      /* try to match packet type */
      if(!get_usp_buff(buffer, data->buff, 8)){
        hook_debug("sys_send copy header from userspace faild!\n");
        return 0;
      }
      info.pktlen = *(u32 *)(buffer);
      info.type = *(u32 *)(buffer+4);
      if(!packet_handler_matched(info.type)){
        /* packet type not matched */
        return 0;
      }
    }
    
    data->work = kcalloc(1, data->size + 1, GFP_KERNEL);
    if(!data->work){
      hook_debug("sys_sendto alloc working buff error!\n");
      return 0;
    }
    if(!get_usp_buff(data->work, data->buff, data->size)){
      hook_debug("sys_send copy packet from userspace faild!\n");
      kfree(data->work);
      data->work = NULL;
      return 0;
    }
    
    //hook_debug("sys_send matched: pid=%d data=%s\n", current->pid, &data->work[12]);
    ret = filter_packet(data->work, data->size, &info);
    //hook_debug("filter return: %d\n", ret);
    if(ret){
      //hook_debug("sys_sendto dump original data:\n");
      //hook_hexdump(info.pkt, info.pktlen);

      /* decrypt packet */
      decrypt_packet(&info);

      hook_debug("sys_sendto original data:\n");
      show_packet_info(&info);

      /* try to hijack given packet */
      if(hijack_packet(&info)){
        hook_debug("sys_sendto modified data:\n");
        show_packet_info(&info);

        /* re-encrypt packet */
        info.real_pkt_len = info.pktlen + 128;
        re_encrypt_packet(&info);
          
        //hook_debug("sys_sendto dump modified data:\n");
        //hook_hexdump(info.real_pkt, info.real_pkt_len);

        /* copy our new packet back to usr space
         * note: our packet length must equal or less than original packet
         *       if our packet length less than original, we must also
         *       change the packet length param of sys_sendto which is in ARM_r2 register. 
         */
        if(!set_usp_buff(data->buff, info.real_pkt, info.real_pkt_len)){
          hook_debug("sys_send copy packet to userspace faild!\n"); 
        }
      }
      put_packet(&info);
    }
    kfree(data->work);
    data->work = NULL;
  }
  return 0;
}

/*
 * Return-probe handler: change the return value of a given pid.
 */
static int ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
  return 0;
}

static struct kretprobe hook_kretprobe = {
  .handler = ret_handler,
  .entry_handler = entry_handler,
  .data_size = sizeof(struct send_param),
  /* Probe up to 20 instances concurrently. */
  .maxactive = 20,
};

int hook_send_init(void)
{
  int ret;

  if(init_super_key()){
    hook_debug("init_super_key error\n");
    return -1;
  }
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

void hook_send_exit(void)
{
  unregister_kretprobe(&hook_kretprobe);
  hook_debug("kretprobe at %p unregistered\n", hook_kretprobe.kp.addr);

  /* nmissed > 0 suggests that maxactive was set too low. */
  hook_debug("Missed probing %d instances of %s\n",
             hook_kretprobe.nmissed, hook_kretprobe.kp.symbol_name);
}

