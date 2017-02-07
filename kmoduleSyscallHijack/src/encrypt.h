
#ifndef __ENCRYPT_H__
#define __ENCRYPT_H__

typedef struct packet_info {
  /* original packet info */
  char *pkt;
  u32 pktlen;
  u32 type;
  u32 keylen;
  char *key_base64;
  u32 ivlen;
  char *iv_base64;
  u32 datalen;
  char *data_base64;
  u32 sum;

  /* working info */
  char *enc_data;
  u32 enc_data_len;
  char *dec_data;
  u32 dec_data_len;
  char key[48];
  char iv[32];
  char real_key_base64[48];
  char real_iv_base64[32];
  char real_key[32];
  char real_iv[16];

  /* new pkt */
  char *real_pkt;
  u32 real_pkt_len;
} packet_info_t;

extern int init_super_key(void);
extern void put_packet(packet_info_t *info);
extern int filter_packet(char *buff, size_t len, packet_info_t *info);
extern int filter_chat_packet(char *buff, size_t len, packet_info_t *info);
extern int decrypt_packet(packet_info_t *info);
extern int re_encrypt_packet(packet_info_t *info);
extern void show_packet_info(packet_info_t *info);

#endif
