#include <linux/kernel.h>
#include <asm/uaccess.h>
#include <linux/scatterlist.h>
#include <linux/crypto.h>
#include <linux/kprobes.h>

#include "dbg.h"
#include "encrypt.h"
#include "hook_config.h"
#include "base64.h"

/* super key */
const char *super_key_base64 = "k5pp9f90NBFSt0nesS7tgUSi4pdaLhFGoqk9CTLgtJ4=";
const char *super_iv_base64 = "brOjEMCP2MbjVfs7KT0UnQ==";
char super_key[32] = {0};
char super_iv[16] = {0};

int init_super_key(void) {
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

void put_packet(packet_info_t *info){
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
int filter_packet(char *buff, size_t len, packet_info_t *info) {
  int offset = 0;
  int size = 0;

  info->pkt = buff;
  if(len < 16){
    return 0;
  }
  /* L */
  info->pktlen = *((u32 *)(buff+offset));
  if(info->pktlen != len){
    return 0;
  }
  offset += 4;
  
  /* T */
  info->type = *((u32 *)(buff+offset));
  offset += 4;

  /* KEYL and KEY */
  info->keylen = *((u32 *)(buff+offset));
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
  info->ivlen = *((u32 *)(buff+offset));
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
  info->datalen = *((u32 *)(buff+offset));
  offset += 4;
  
  if(info->datalen + offset >= len){
    return 0;
  }
  info->data_base64 = buff + offset;
  //base64_decode(info->data_base64, info->datalen, );
  offset += info->datalen;

  /* SUM */
  info->sum = *((u32 *)(buff+offset));
  offset += 4;
  if(offset != len){
    return 0;
  }
  return 1;
}

static void compress_chat_msg(char *msg, size_t len) {
  int i = 0;
  for(i=0; i<len/2; ++i){
    msg[i] = msg[i*2];
  }
}

/*
 * filter chat message packet which matched format:
 * -----------------------------------------------------------------
 * |TCP/IP header|L   |T   |KEYL|KEY |IVL |IV  |PAD |DATL|DAT |SUM |
 * -----------------------------------------------------------------
 * len:           4    4    4    128  4    88   4    4    var  4 
 */
int filter_chat_packet(char *buff, size_t len, packet_info_t *info) {
  int offset = 0;
  int size = 0;

  info->pkt = buff;
  if(len < 16){
    return 0;
  }
  /* L */
  info->pktlen = *((u32 *)(buff+offset));
  if(info->pktlen != len){
    return 0;
  }
  offset += 4;
  
  /* T */
  info->type = *((u32 *)(buff+offset));
  offset += 4;

  /* KEYL and KEY */
  info->keylen = *((u32 *)(buff+offset));
  if(info->keylen != 128){
    return 0;
  }
  offset += 4;

  if(info->keylen + offset >= len){
    return 0;
  }
  
  info->key_base64 = buff + offset;
  compress_chat_msg(info->key_base64, info->keylen);
  size = base64_decode(info->key_base64, info->keylen/2, info->key);
  //recover_chat_msg(info->key_base64, info->keylen);
  if(size != sizeof(info->key)){
    return 0;
  }
  offset += info->keylen;
  info->keylen /= 2;

  /* IVL and IV */
  info->ivlen = *((u32 *)(buff+offset));
  if(info->ivlen != 88){
    return 0;
  }
  offset += 4;

  if(info->ivlen + offset >= len){
    return 0;
  }
  info->iv_base64 = buff + offset;
  compress_chat_msg(info->iv_base64, info->ivlen);
  size = base64_decode(info->iv_base64, info->ivlen/2, info->iv);
  //recover_chat_msg(info->iv_base64, info->ivlen);
  if(size != sizeof(info->iv)){
    return 0;
  }
  offset += info->ivlen;
  info->ivlen /= 2;

  /* PAD */
  offset += 4;
  
  /* DATL and DAT */
  info->datalen = *((u32 *)(buff+offset));
  offset += 4;
  
  if(info->datalen + offset >= len){
    return 0;
  }
  info->data_base64 = buff + offset;
  compress_chat_msg(info->data_base64, info->datalen);
  offset += info->datalen;
  info->datalen /= 2;

  /* SUM */
  info->sum = *((u32 *)(buff+offset));
  offset += 4;
  if(offset != len){
    return 0;
  }
  
  return 1;
}

void show_packet_info(packet_info_t *info){
  hook_debug("pktlen=%u type=%u\n", info->pktlen, info->type);
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

static int encrypt_data(int enc_flag, char* key, unsigned int lkey,
                        char* iv, unsigned int liv,
                        char *enc, unsigned int lenc,
                        char *dec, unsigned int ldec){
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

int decrypt_packet(packet_info_t *info){
  int rc;

  /* decrypt real key/iv which is used to decrypt data */
  rc = encrypt_data(0, super_key, 32, super_iv, 16,
                    info->key, sizeof(info->key),
                    info->real_key_base64, sizeof(info->real_key_base64));
  if(rc){
    hook_debug("decrypt crypto_blkcipher_decrypt key error!\n");
    return -1;
  }
  rc = encrypt_data(0, super_key, 32, super_iv, 16,
                    info->iv, sizeof(info->iv),
                    info->real_iv_base64, sizeof(info->real_iv_base64));
  if(rc){
    hook_debug("decrypt crypto_blkcipher_decrypt iv error!\n");
    return -1;
  }
  
  /* base64 decode real key/iv */
  rc = base64_decode(info->real_key_base64, 44, info->real_key);
  if(rc <= 0){
    hook_debug("decrypt base64_decode real key error!\n");
    return -1;
  }
  rc = base64_decode(info->real_iv_base64, 24, info->real_iv);
  if(rc <= 0){
    hook_debug("decrypt base64_decode real iv error!\n");
    return -1;
  }

  /* decrypt data */
  info->enc_data = kcalloc(1, info->pktlen, GFP_KERNEL);
  if(!info->enc_data){
    hook_debug("decrypt kmalloc error!\n");
    return -1;
  }
  rc = base64_decode(info->data_base64, info->datalen, info->enc_data);
  if(rc <= 0){
    hook_debug("decrypt base64_decode data error! datalen=%d\n", info->datalen);
    hook_hexdump(info->data_base64, info->datalen);
    return -1;
  }
  info->enc_data_len = rc;
  info->dec_data = kcalloc(1, info->pktlen, GFP_KERNEL);
  if(!info->dec_data){
    hook_debug("decrypt kmalloc error!\n");
    return -1;
  }
  rc = encrypt_data(0, info->real_key, 32, info->real_iv, 16,
                    info->enc_data, info->enc_data_len,
                    info->dec_data, info->enc_data_len);
  if(rc){
    hook_debug("decrypt crypto_blkcipher_decrypt iv error!\n");
    return -1;
  }
  info->dec_data_len = strlen(info->dec_data);
  //hook_debug("decrypt packet data: %s\n", info->dec_data);
  return 0;
}

int re_encrypt_packet(packet_info_t *info){
  int offset = 0;
  u32 *working = NULL;
  u32 *new_pktlen = NULL;
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
  new_pktlen = (u32*)(info->real_pkt + offset);
  offset += 4;

  /* type */
  working = (u32*)(info->real_pkt + offset);
  *working = info->type;
  offset += 4;

  /* keylen */
  working = (u32*)(info->real_pkt + offset);
  *working = 64;
  offset += 4;

  /* key */
  working = (u32*)(info->real_pkt + offset);
  memcpy((char*)working, info->key_base64, 64);
  offset += 64;

  /* ivlen */
  working = (u32*)(info->real_pkt + offset);
  *working = 44;
  offset += 4;

  /* iv */
  working = (u32*)(info->real_pkt + offset);
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
  working = (u32*)(info->real_pkt + offset);
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
  working = (u32*)(info->real_pkt + offset);
  len = 0;
  for(; offset>=0; offset--){
    len += *(info->real_pkt + offset);
  }
  *working = len;
  return 0;
}


