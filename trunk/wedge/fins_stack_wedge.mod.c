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
	{ 0x9e770581, "module_layout" },
	{ 0xf0fdf6cb, "__stack_chk_fail" },
	{ 0x362ef408, "_copy_from_user" },
	{ 0x2f287f0d, "copy_to_user" },
	{ 0x12da5bb2, "__kmalloc" },
	{ 0xbd09c7fa, "release_sock" },
	{ 0xbbfb8953, "lock_sock_nested" },
	{ 0xad91e2fc, "current_task" },
	{ 0xe45f60d8, "__wake_up" },
	{ 0xf9a482f9, "msleep" },
	{ 0x37a0cba, "kfree" },
	{ 0x1dd8093a, "kmem_cache_alloc_trace" },
	{ 0x552137ab, "kmalloc_caches" },
	{ 0xaab516a9, "netlink_unicast" },
	{ 0x2e60bace, "memcpy" },
	{ 0x2bc95bd4, "memset" },
	{ 0x23cf8d1, "skb_put" },
	{ 0xabe3b815, "__alloc_skb" },
	{ 0x90bb893d, "sock_init_data" },
	{ 0xa8d20bfc, "sk_alloc" },
	{ 0x27195660, "sk_free" },
	{ 0xc596a86f, "skb_queue_purge" },
	{ 0x1844bf9e, "netlink_kernel_create" },
	{ 0xb050dc66, "init_net" },
	{ 0xa5a4e078, "sock_register" },
	{ 0xc69b1636, "proto_register" },
	{ 0xc4554217, "up" },
	{ 0x4792c572, "down_interruptible" },
	{ 0x36884386, "proto_unregister" },
	{ 0x62737e1d, "sock_unregister" },
	{ 0xfc4e97b0, "sock_release" },
	{ 0x50eedeb8, "printk" },
	{ 0xb4390f9a, "mcount" },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=";


MODULE_INFO(srcversion, "5FF4B836CAF1DF7DEAF0712");
