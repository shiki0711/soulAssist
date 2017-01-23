
#include <linux/string.h>
#include <linux/kernel.h>
#include "dbg.h"

void hook_hexdump(const char *hex, int len) {
  char buf[64] = {0};
  int i = 0;
  char *p = buf;
  
  for(i=0; i<len; ++i){
    sprintf(p, "%02X ", hex[i]);
    p += 3;
    if(i%16 == 7){
      sprintf(p++, " ");
    }
    if(i%16 == 15){
      hook_debug("%s\n", buf);
      p = buf;
      memset(p, 0, 64);
    }
  }
  if(p != buf){
    hook_debug("%s\n", buf);
  }
}


