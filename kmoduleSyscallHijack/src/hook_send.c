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
#include "base64.h"

static char func_name[NAME_MAX] = "sys_sendto";

/* per-instance private data */
struct send_param {
  char __user *buff;  /* in ARM_r1  */
  size_t size;  /* in ARM_r2  */
  char *work;
};

/* super key */
const char *super_key_base64 = "k5pp9f90NBFSt0nesS7tgUSi4pdaLhFGoqk9CTLgtJ4=";
const char *super_iv_base64 = "brOjEMCP2MbjVfs7KT0UnQ==";
char super_key[32] = {0};
char super_iv[16] = {0};

static int init_super_key(void) {
  char buff[64] = {0};
  int len = 0;

  /* decode base64 super key/iv */
  len = base64_decode(super_key_base64, strlen(super_key_base64), buff);
  if(len <= 0){
    return -1;
  }
  memcpy(super_key, buff, len);
  hook_debug("init super key:\n");
  hook_hexdump(super_key, len);
  
  len = base64_decode(super_iv_base64, strlen(super_iv_base64), buff);
  if(len <= 0){
    return -1;
  }
  memcpy(super_iv, buff, len);
  hook_debug("init super iv:\n");
  hook_hexdump(super_iv, len);
  
  return 0;
}

typedef struct packet_info {
  /* original packet info */
  char *pkt;
  int pktlen;
  int type;
  int keylen;
  char *key_base64;
  int ivlen;
  char *iv_base64;
  int datalen;
  char *data_base64;
  int sum;

  /* working info */
  char *enc_data;
  int enc_data_len;
  char *dec_data;
  int dec_data_len;
  char key[48];
  char iv[32];
  char real_key_base64[48];
  char real_iv_base64[32];
  char real_key[32];
  char real_iv[16];

  /* new pkt */
  char *real_pkt;
  int real_pkt_len;
} packet_info_t;

static void put_packet(packet_info_t *info){
  /* free alloced memory */
  if(info->enc_data){
    kfree(info->enc_data);
    info->enc_data = NULL;
  }if(info->dec_data){
    kfree(info->dec_data);
    info->dec_data = NULL;
  }if(info->real_pkt){
    kfree(info->real_pkt);
    info->real_pkt = NULL;
  }
}

/*
 * filter packet which matched format:
 * ------------------------------------------------------------
 * |TCP/IP header|L   |T   |KEYL|KEY |IVL |IV  |DATL|DAT |SUM |
 * ------------------------------------------------------------
 * len:           4    4    4    64   4    44   4    var  4 
 */
static int filter_packet(char *buff, size_t len, packet_info_t *info) {
  int offset = 0;
  int size = 0;

  info->pkt = buff;
  if(len < 16){
    return 0;
  }
  /* L */
  info->pktlen = *((int *)(buff+offset));
  if(info->pktlen != len){
    return 0;
  }
  offset += 4;
  
  /* T */
  info->type = *((int *)(buff+offset));
  offset += 4;

  /* KEYL and KEY */
  info->keylen = *((int *)(buff+offset));
  if(info->keylen != 64){
    return 0;
  }
  offset += 4;

  if(info->keylen + offset >= len){
    return 0;
  }
  info->key_base64 = buff + offset;
  size = base64_decode(info->key_base64, info->keylen, info->key);
  if(size != sizeof(info->key)){
    return -1;
  }
  offset += info->keylen;

  /* IVL and IV */
  info->ivlen = *((int *)(buff+offset));
  if(info->ivlen != 44){
    return 0;
  }
  offset += 4;

  if(info->ivlen + offset >= len){
    return 0;
  }
  info->iv_base64 = buff + offset;
  size = base64_decode(info->iv_base64, info->ivlen, info->iv);
  if(size != sizeof(info->iv)){
    return -1;
  }
  offset += info->ivlen;

  /* DATL and DAT */
  info->datalen = *((int *)(buff+offset));
  offset += 4;
  
  if(info->datalen + offset >= len){
    return 0;
  }
  info->data_base64 = buff + offset;
  //base64_decode(info->data_base64, info->datalen, );
  offset += info->datalen;

  /* SUM */
  info->sum = *((int *)(buff+offset));
  offset += 4;
  if(offset != len){
    return 0;
  }
  return 1;
}

static void show_packet_info(packet_info_t *info){
  hook_debug("pktlen=%d type=%d\n", info->pktlen, info->type);
  if(info->dec_data){
    hook_debug("decoded data: %s\b", info->dec_data);
  }
  //hook_debug("type=%d\n", info->type);
  //hook_debug("keylen=%d\n", info->keylen);
  //hook_debug("key_base64=%s\n", info->key_base64);
  //hook_debug("ivlen=%d\n", info->ivlen);
  //hook_debug("iv_base64:\n");
  //hook_debug("datalen=%d\n", info->datalen);
  //hook_debug("data_base64=%s\n", info->data_base64);
  //hook_debug("sum=%d\n", info->sum);
}

static int encrypt_data(int enc_flag, char* key, int lkey,
                        char* iv, int liv,
                        char *enc, int lenc,
                        char *dec, int ldec){
  struct crypto_blkcipher *key_tfm = NULL;
  struct blkcipher_desc desc;
  struct scatterlist sg_enc, sg_dec;
  int rc;
  int ret = 0;

  /* alloc cipher */
  key_tfm = crypto_alloc_blkcipher("cbc(aes)", 0, CRYPTO_ALG_TYPE_BLKCIPHER);
  if (IS_ERR(key_tfm)) {
    hook_debug("sys_sendto crypto_alloc_blkcipher error!\n");
    return -1;
  }
  rc = crypto_blkcipher_setkey(key_tfm, key, lkey);
  if(rc){
    hook_debug("sys_sendto crypto_blkcipher_setkey error!\n");
    ret = -1;
    goto out;
  }
  crypto_blkcipher_set_iv(key_tfm, iv, liv);

  /* en(de)crypt*/
  desc.tfm = key_tfm;
  desc.info = iv;
  desc.flags = 0;
  sg_init_one(&sg_enc, enc, lenc);
  sg_init_one(&sg_dec, dec, ldec);
  if(enc_flag){
    rc = crypto_blkcipher_encrypt(&desc, &sg_dec, &sg_enc, lenc);
  }else{
    rc = crypto_blkcipher_decrypt(&desc, &sg_dec, &sg_enc, lenc);
  }
  if(rc){
    hook_debug("sys_sendto crypto_blkcipher_en(de)crypt key error!\n");
    ret = -1;
    goto out;
  }

 out:
  crypto_free_blkcipher(key_tfm);
  return ret;
}

static int decrypt_packet(packet_info_t *info){
  int rc;

  /* decrypt real key/iv which is used to decrypt data */
  rc = encrypt_data(0, super_key, 32, super_iv, 16,
                    info->key, sizeof(info->key),
                    info->real_key_base64, sizeof(info->real_key_base64));
  if(rc){
    hook_debug("sys_sendto crypto_blkcipher_decrypt key error!\n");
    return -1;
  }
  rc = encrypt_data(0, super_key, 32, super_iv, 16,
                    info->iv, sizeof(info->iv),
                    info->real_iv_base64, sizeof(info->real_iv_base64));
  if(rc){
    hook_debug("sys_sendto crypto_blkcipher_decrypt iv error!\n");
    return -1;
  }
  
  /* base64 decode real key/iv */
  rc = base64_decode(info->real_key_base64, 44, info->real_key);
  if(rc <= 0){
    hook_debug("sys_sendto base64_decode real key error!\n");
    return -1;
  }
  rc = base64_decode(info->real_iv_base64, 24, info->real_iv);
  if(rc <= 0){
    hook_debug("sys_sendto base64_decode real iv error!\n");
    return -1;
  }

  /* decrypt data */
  info->enc_data = kcalloc(1, info->pktlen, GFP_KERNEL);
  if(!info->enc_data){
    hook_debug("sys_sendto kmalloc error!\n");
    return -1;
  }
  rc = base64_decode(info->data_base64, info->datalen, info->enc_data);
  if(rc <= 0){
    hook_debug("sys_sendto base64_decode data error!\n");
    return -1;
  }
  info->enc_data_len = rc;
  info->dec_data = kcalloc(1, info->pktlen, GFP_KERNEL);
  if(!info->dec_data){
    hook_debug("sys_sendto kmalloc error!\n");
    return -1;
  }
  rc = encrypt_data(0, info->real_key, 32, info->real_iv, 16,
                    info->enc_data, info->enc_data_len,
                    info->dec_data, info->enc_data_len);
  if(rc){
    hook_debug("sys_sendto crypto_blkcipher_decrypt iv error!\n");
    return -1;
  }
  info->dec_data_len = strlen(info->dec_data);
  hook_debug("sys_sendto packet data: %s\n", info->dec_data);
  return 0;
}

static int re_encrypt_packet(packet_info_t *info){
  int offset = 0;
  int *working = NULL;
  int *new_pktlen = NULL;
  int rc;
  int len;
  char *buff = NULL;
  
  info->real_pkt = kcalloc(1, info->real_pkt_len, GFP_KERNEL);
  if(!info->real_pkt){
    hook_debug("sys_sendto kmalloc error!\n");
    return -1;
  }

  /* re-compose packet: */
  
  /* pktlen */
  new_pktlen = (int*)(info->real_pkt + offset);
  offset += 4;

  /* type */
  working = (int*)(info->real_pkt + offset);
  *working = info->type;
  offset += 4;

  /* keylen */
  working = (int*)(info->real_pkt + offset);
  *working = 64;
  offset += 4;

  /* key */
  working = (int*)(info->real_pkt + offset);
  memcpy((char*)working, info->key_base64, 64);
  offset += 64;

  /* ivlen */
  working = (int*)(info->real_pkt + offset);
  *working = 44;
  offset += 4;

  /* iv */
  working = (int*)(info->real_pkt + offset);
  memcpy((char*)working, info->iv_base64, 44);
  offset += 44;

  /* encrypt and base64_encode data */
  if(info->dec_data_len % 16){
    len = (info->dec_data_len/16 + 1) * 16;
  }else{
    len = info->dec_data_len;
  }
  buff = kcalloc(1, len, GFP_KERNEL);
  if(!buff){
    hook_debug("sys_sendto kmalloc error!\n");
    return -1;
  }
  rc = encrypt_data(1, info->real_key, 32, info->real_iv, 16,
                    info->dec_data, info->dec_data_len,
                    buff, len);
  if(rc){
    hook_debug("sys_sendto crypto_blkcipher_(re)encrypt data error!\n");
    kfree(buff);
    return -1;
  }
  rc = base64_encode(buff, len, info->real_pkt + offset + 4);  /* skip datelen field */
  kfree(buff);
  if(rc <= 0){
    hook_debug("sys_sento base64_encode data error \n");
    return -1;
  }
  
  /* datalen */
  working = (int*)(info->real_pkt + offset);
  *working = rc;
  offset += 4;
  offset += rc;  /* skip data field */

  /* set new packet len */
  *new_pktlen = 4 + /* pktlen */
    4 + /* type */
    4 + 64 + /* key */
    4 + 44 + /* iv */
    4 + rc + /* data */
    4; /* sum */
  info->real_pkt_len = *new_pktlen;
  
  /* calculate sum */
  working = (int*)(info->real_pkt + offset);
  len = 0;
  for(; offset>=0; offset--){
    len += *(info->real_pkt + offset);
  }
  *working = len;
  return 0;
}

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
      info.pktlen = *(int *)(buffer);
      info.type = *(int *)(buffer+4);
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

