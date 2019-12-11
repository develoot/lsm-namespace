#include <linux/debugfs.h>
#include <linux/fs.h>
#include <linux/rwlock_types.h>
#include <linux/string.h>
#include <linux/kernel.h>
#include <linux/module.h>

int print_debugfs(const char *msg, ...);
