
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/ktime.h>
#include <linux/limits.h>
#include <linux/sched.h>
#include <asm/uaccess.h>

#ifndef __HOOK_DEF_H__
#define __HOOK_DEF_H__

extern int hook_open_init(void);
extern void hook_open_exit(void);
extern int hook_clock_gettime_init(void);
extern void hook_clock_gettime_exit(void);
extern int hook_send_init(void);
extern void hook_send_exit(void);


#endif
