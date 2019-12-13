#ifndef LSM_DEBUG_H
#define LSM_DEBUG_H

#include <stdarg.h>
#include <linux/debugfs.h>
#include <linux/fs.h>
#include <linux/rwlock_types.h>
#include <linux/string.h>
#include <linux/kernel.h>

int print_debugfs(const char *msg, ...);
void flush_plist(void);
int print_plist(const char* msg);

#endif
