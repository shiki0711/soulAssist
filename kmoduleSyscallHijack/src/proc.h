
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/ktime.h>
#include <linux/limits.h>
#include <linux/sched.h>
#include <asm/uaccess.h>

#ifndef __PROC_H__
#define __PROC_H__

#define PROC_BUFF_LEN  (32)

typedef struct property {
  char *filename;
  char buf[PROC_BUFF_LEN+1];
  unsigned char motified;
} property_t;

extern int hook_init_proc(void);
extern void hook_release_proc(void);
extern int hook_create_proc_entry(property_t *);
//extern char* hook_read_proc(property_t *);
extern void hook_remove_proc_entry(property_t *);


#endif
