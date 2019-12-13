#include <linux/fs.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/parser.h>
#include <linux/rwlock.h>
#include <linux/lsm_namespace.h>

#define LEN 1024

static const enum {
	Lsmns_selinux,
	Lsmns_apparmor,
	Lsmns_tomoyo,
	Lsmns_err
};

const match_table_t tokens = {
	{Lsmns_selinux, "selinux"},
	{Lsmns_apparmor, "apparmor"},
	{Lsmns_tomoyo, "tomoyo"},
	{Lsmns_err, NULL}
};

struct proc_dir_entry *proc_lsm;
static char lsm_buff[LEN];
static rwlock_t buff_lock;

int parse_lsmns_procfs(void)
{
	int types = 0;
	substring_t args[MAX_OPT_ARGS];
	int token;
	int str_len;
	char *str;
	char *p;
	int i;


	read_lock(&buff_lock);
	str_len = strlen(lsm_buff);
	read_unlock(&buff_lock);
	if(str_len == 0)
		return types;
	str = kmalloc(str_len, GFP_KERNEL);
	read_lock(&buff_lock);
	strlcpy(str, lsm_buff, str_len);
	read_unlock(&buff_lock);

	for(i = 0; i < str_len; i++){
		if(str[i] == ' ' || str[i] =='.' || str[i] == '\n' || str[i] == '\r')
			str[i] = ',';
	}

	str = &str[0];
        while((p = strsep(&str, ",")) != NULL){
                if (!*p)
                        continue;
                token = match_token(p, tokens, args);
                switch (token) {
                case Lsmns_selinux:
                        types |= LSMNS_SELINUX;
                        break;
                case Lsmns_apparmor:
                        types |= LSMNS_APPARMOR;
                        break;
                case Lsmns_tomoyo:
                        types |= LSMNS_TOMOYO;
                        break;
                }
        }
	return types;
}

static ssize_t lsmns_read(struct file* fp, char __user *user_buff,
               size_t count, loff_t *position)
{
	ssize_t size;
	read_lock(&buff_lock);
        size = simple_read_from_buffer(user_buff, count, position, lsm_buff, LEN);
	read_unlock(&buff_lock);
	return size;
}

static ssize_t lsmns_write(struct file* fp, const char __user *user_buff,
                size_t count, loff_t *position)
{
	ssize_t size = 0;
	if(count > LEN)
                return -EINVAL;
	write_lock(&buff_lock);
        memset(lsm_buff, 0, LEN);
	size = simple_write_to_buffer(lsm_buff, LEN, position, user_buff, count);
	write_unlock(&buff_lock);
	return size;
}

struct file_operations proc_fops = {
        .read = lsmns_read,
        .write = lsmns_write,
};

static int __init proc_lsmns_init(void)
{
	rwlock_init(&buff_lock);
	proc_create_data("lsmns", 0664, NULL, &proc_fops, "lsmns");
	return 0;
}

fs_initcall(proc_lsmns_init);
