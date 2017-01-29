#include <linux/module.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

MODULE_INFO(vermagic, VERMAGIC_STRING);

struct module __this_module
__attribute__((section(".gnu.linkonce.this_module"))) = {
 .name = KBUILD_MODNAME,
 .init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
 .exit = cleanup_module,
#endif
 .arch = MODULE_ARCH_INIT,
};

static const struct modversion_info ____versions[]
__used
__attribute__((section("__versions"))) = {
	{ 0x121260f, "module_layout" },
	{ 0xe914e41e, "strcpy" },
	{ 0xc23d315a, "unregister_kretprobe" },
	{ 0xd4f305a3, "register_kretprobe" },
	{ 0x9d669763, "memcpy" },
	{ 0x67c2fa54, "__copy_to_user" },
	{ 0x37a0cba, "kfree" },
	{ 0x12da5bb2, "__kmalloc" },
	{ 0xac1ad522, "crypto_destroy_tfm" },
	{ 0xefdd2345, "sg_init_one" },
	{ 0xb59d8ca8, "crypto_alloc_base" },
	{ 0x349cba85, "strchr" },
	{ 0x1e6d26a8, "strstr" },
	{ 0x91715312, "sprintf" },
	{ 0x20000329, "simple_strtoul" },
	{ 0x84b183ae, "strncmp" },
	{ 0x97255bdf, "strlen" },
	{ 0x4b23bb56, "single_release" },
	{ 0x7f1c7969, "seq_read" },
	{ 0x930280ee, "seq_lseek" },
	{ 0x191e8be6, "proc_create_data" },
	{ 0xf2de56a8, "remove_proc_entry" },
	{ 0x455d9c9e, "proc_mkdir_mode" },
	{ 0x8f678b07, "__stack_chk_guard" },
	{ 0xf0fdf6cb, "__stack_chk_fail" },
	{ 0xfa2a45e, "__memzero" },
	{ 0xfbc74f64, "__copy_from_user" },
	{ 0x6cef247f, "__strnlen_user" },
	{ 0x5f754e5a, "memset" },
	{ 0x2e5810c6, "__aeabi_unwind_cpp_pr1" },
	{ 0xd67319, "seq_printf" },
	{ 0xf358ac1a, "single_open" },
	{ 0xefd6cf06, "__aeabi_unwind_cpp_pr0" },
	{ 0x27e1a049, "printk" },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=";

