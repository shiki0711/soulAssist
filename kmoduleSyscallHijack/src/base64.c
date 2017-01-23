
#ifdef __UT__
#include <stdio.h>
#include <string.h>
#else
#include <linux/kernel.h>
#endif

#include "base64.h"

const char *base64char = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static char rvBase64Char(char c) {
  int i = 0;
  for(i=0; i<64; ++i) {
    if(c == base64char[i]){
      return i;
    }
  }
  return 64;
}

int base64_encode(const char *in, int len, char *out){
  char work;
  char remain = 0;
  int offset = 0;
  int ret = 0;
  int c;
    
  while(len--){
    work = in[offset];
    switch(offset%3){
    case 0:
      c = ((work & 0xfc) >> 2);
      out[ret++] = base64char[c];
      remain = (work & 0x03);
      break;
    case 1:
      c = (remain << 4) | ((work & 0xf0) >> 4);
      out[ret++] = base64char[c];
      remain = (work & 0x0f);
      break;
    case 2:
      c = (remain << 2) | ((work & 0xc0) >> 6);
      out[ret++] = base64char[c];
      c = (work & 0x3f);
      out[ret++] = base64char[c];
      remain = 0;
      break;
    default:
      break;
    }
    ++offset;
  }
  switch(ret%4){
  case 1:
    c = (remain << 4);
    out[ret++] = base64char[c];
    out[ret++] = '=';
    out[ret++] = '=';
    break;
  case 2:
    c = (remain << 2);
    out[ret++] = base64char[c];
    out[ret++] = '=';
    break;
  case 3:
    c = remain;
    out[ret++] = base64char[c];
    break;
  default:
    break;
  }
  return ret;
}

int base64_decode(const char *in, int len, char *out){
  char work;
  char remain = 0;
  int offset = 0;
  int ret = 0;

  while(len--){
    work = in[offset];
    if(work == '=') {
      break;
    }
    work = rvBase64Char(work);
    if(work >= 64){
      return -1;
    }
    switch(offset%4){
    case 0:
      remain = (work << 2);
      break;
    case 1:
      out[ret++] = (remain | ((work & 0x30) >> 4) );
      remain = ((work & 0x0f) << 4);
      break;
    case 2:
      out[ret++] = (remain | ((work & 0x3c) >> 2) );
      remain = ((work & 0x03) << 6);
      break;
    case 3:
      out[ret++] = (remain | work);
      remain = 0;
      break;
    default:
      break;
    }
    ++offset;
  }
  
  return ret;
}

#ifdef __UT__
int main(int argc, const char *argv[]){
  const char* in = argv[1];
  char out[128] = {0};
  char org[128] = {0};
  
  int i = base64_encode(in, strlen(in), out);
  printf("encode data: %s return: %d\n", out, i);
  i = base64_decode(out, i, org);
  printf("decode data: %s return: %d\n", org, i);
  return 0;
}
#endif

