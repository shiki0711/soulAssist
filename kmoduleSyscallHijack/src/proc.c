/*
 * Read message from /proc/soulseeker_hook
*/
#include <linux/kernel.h>
#include <asm/uaccess.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>

#include "dbg.h"
#include "proc.h"

static const char *proc_entry_name = "soulseeker_hook";

static struct proc_dir_entry *soulseeker_hook_dir = NULL;

static int hook_proc_show(struct seq_file *m, void *v) {
  property_t *p = v;
  seq_printf(m, "Open proc %s file!\n", p->filename);
  return 0;
}
static int hook_proc_open(struct inode *inode, struct  file *file) {
  property_t *p = NULL;
  p = (property_t *)(PDE(file->f_path.dentry->d_inode)->data);
  //hook_debug("p=%p\n", p);
  return single_open(file, hook_proc_show, p);
}

static int hook_mod_write( struct file *filp, const char __user *buff,
                          size_t len, loff_t *data )
{
  int n;
  char tmp[PROC_BUFF_LEN] = {0};
  int l = 0;

  property_t *p = (property_t *)(PDE(filp->f_path.dentry->d_inode)->data);
  //hook_debug("p=%p\n", p);
  l = strlen_user(buff);
  if(!l){
    return 0;
  }
  n = copy_from_user(tmp, buff, l);
  if(n){
    hook_debug("Read proc %s error. %d byte left.!\n", p->filename, n);
  }else{
    if(tmp[0]){
      /* skip blank line */
      memcpy(p->buf, &tmp, PROC_BUFF_LEN);
      p->motified ++;
      hook_debug("Read %s ok, value:%s\n", p->filename, p->buf);
    }
  }
  return l;
}


static const struct file_operations hook_proc_fops = {
  .owner = THIS_MODULE,
  .open  = hook_proc_open,
  .read  = seq_read,
  .write  = hook_mod_write,
  .llseek  = seq_lseek,
  .release = single_release,
};

int hook_init_proc(void) {
  soulseeker_hook_dir = proc_mkdir_mode(proc_entry_name, 0777, NULL);
  return (soulseeker_hook_dir == NULL);
}

void hook_release_proc(void) {
  remove_proc_entry(proc_entry_name, NULL);
  soulseeker_hook_dir = NULL;
}

int hook_create_proc_entry(property_t *p) {
  struct proc_dir_entry *hook_proc_entry;

  if(p->filename == NULL) {
    hook_debug("Create proc entry error, filename is nil!\n");
    return 1;
  }
  hook_proc_entry = proc_create_data(p->filename, 0777, soulseeker_hook_dir, &hook_proc_fops, p);
  if(!hook_proc_entry){
    hook_debug("Create proc entry %s error!\n", p->filename);
    return 1;
  }
  hook_debug("Create proc entry %s ok p=%p!\n", p->filename, p);
  return 0;
}

/*
char* hook_read_proc(property_t *p) {
  if(p->motified){
    if(p->motified != (unsigned char)-1) {
      p->motified += 1;
    }
    return p->buf;
  }else{
    return NULL;
  }
}
*/

void hook_remove_proc_entry(property_t *p) {
  if(p->filename == NULL) {
    hook_debug("Create proc entry error, filename is nil!\n");
    return;
  }
  remove_proc_entry( p->filename, NULL );
  printk(KERN_CRIT "Remove proc entry %s ok!\n", p->filename);
}

