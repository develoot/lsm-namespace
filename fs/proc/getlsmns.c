#include <linux/fs.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/parser.h>
#include <linux/rwlock.h>
#include <linux/lsm_namespace.h>
#include <linux/nsproxy.h>
#include <linux/lsm_hooks.h>

#define LEN 1024

static char buff[LEN];
static int cursor;
static rwlock_t buff_lock;

static int get_current_lsmns(void){
        struct task_struct *tsk = current;
        struct nsproxy *nsproxy;
        struct lsm_namespace *ns;
        int types;
        task_lock(tsk);
        nsproxy = tsk->nsproxy;
        if(!nsproxy)
               return -1;
        ns = nsproxy -> lsm_ns;
        if(!ns)
               return -2;
        types = ns->types;
        task_unlock(tsk);
        return types;
}

void static flush_buff(void){
	write_lock(&buff_lock);
	memset(buff, 0, LEN);
	cursor = 0;
	write_unlock(&buff_lock);
}

void static write_buff(const char* msg){
	int len = strlen(msg);
	write_lock(&buff_lock);
	if(len == strlcpy(buff + cursor, msg, len)){
		cursor += len;
		cursor ++;
		buff[cursor++] = '\n';
	}
	write_unlock(&buff_lock);
	return 0;
}

static ssize_t lsmns_read(struct file* fp, char __user *user_buff,
		size_t count, loff_t* pos)
{
	flush_buff();
	ssize_t size = 0;
	int types = get_current_lsmns();
	if(types < 0){
		write_buff("nsproxy or lsmns is NULL\n");
	}
	else{
		if(types & LSMNS_SELINUX)
			write_buff("selinux\n");
		if(types & LSMNS_APPARMOR)
			write_buff("apparmor\n");
		if(types & LSMNS_TOMOYO)
			write_buff("tomoyo\n");
	}
	write_lock(&buff_lock);
	size = simple_read_from_buffer(user_buff, count, pos, buff, LEN);
	write_unlock(&buff_lock);
	return size;
}

static const struct file_operations proc_fops = {
        .read = lsmns_read,
};

static int __init get_lsmns_init(void)
{
	rwlock_init(&buff_lock);
	cursor = 0;
	proc_create_data("getlsmns", 0666, NULL, &proc_fops, "getlsmns");
	return 0;
}


fs_initcall(get_lsmns_init);
