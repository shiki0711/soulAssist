
#include <linux/kernel.h>
#include <linux/limits.h>
#include <linux/sched.h>
#include <asm/uaccess.h>

#include "dbg.h"
#include "proc.h"
#include "hook_config.h"


static property_t target_pid_property = {
  .filename = "target_pid",
  .buf = {0},
  .motified = 0,
};

static property_t dungeon_clrtime_property = {
  .filename = "dungeon_clrtime",
  .buf = {0},
  .motified = 0,
};

static property_t tower_rush_win_property = {
  .filename = "tower_rush_win",
  .buf = {0},
  .motified = 0,
};

static property_t debug_dump_packet_property = {
  .filename = "debug_dump_packet",
  .buf = {0},
  .motified = 0,
};

static property_t nil_property = {
  .filename = NULL,
  .buf = {0},
  .motified = 0,
};

static property_t *configs[] = {
  &target_pid_property,
  &dungeon_clrtime_property,
  &tower_rush_win_property,
  &debug_dump_packet_property,
  &nil_property  /* sentinel */
};

int hook_config(const char *name, char **value)
{
  int i = 0;
  const char *filename = NULL;

  *value = NULL;
  while((filename = configs[i]->filename) != NULL) {
    if(strncmp(filename, name, strlen(filename)) == 0){
      if(configs[i]->motified == 0){
        return -2;
      }else{
        *value = configs[i]->buf;
        return 0;
      }
    }
    ++i;
  }
  return -1;
}

int hook_config_int(const char *name, int *value)
{
  int rc;
  char *value_str = NULL;

  rc = hook_config(name, &value_str);
  if(!rc){
    if(!value_str){
      return -1;
    }
    *value = simple_strtoul(value_str, NULL, 0);
  }
  return rc;
}

int hook_config_init(void)
{
  int i = 0;

  while(configs[i]->filename != NULL) {
    if(hook_create_proc_entry(configs[i])){
      return -1;
    }
    ++i;
  }
  return 0;
}

void hook_config_exit(void)
{
  int i = 0;

  while(configs[i]->filename != NULL) {
    hook_remove_proc_entry(configs[i]);
    ++i;
  }
  return;
}


