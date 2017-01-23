#ifndef __HOOK_CONFIG_H__
#define __HOOK_CONFIG_H__

extern int hook_config(const char *name, char **value);
extern int hook_config_int(const char *name, int* value);
#define hook_config_string hook_config

extern int hook_config_init(void);
extern void hook_config_exit(void);

#endif
