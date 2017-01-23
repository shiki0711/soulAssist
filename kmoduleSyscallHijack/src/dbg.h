#ifndef __DBG_H__
#define __DBG_H_

#define hook_debug(...)  printk(KERN_CRIT "[hook hijack]:"__VA_ARGS__)

extern void hook_hexdump(const char *hex, int len);

#endif



