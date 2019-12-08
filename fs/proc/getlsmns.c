#include <linux/fs.h>
#include <linux/init.h>
#include <linux/lsm_hooks.h>
#include <linux/lsm_namespace.h>
#include <linux/nsproxy.h>
#include <linux/parser.h>
#include <linux/proc_fs.h>
#include <linux/rwlock.h>
#include <linux/slab.h>
#include <linux/string.h>

#define BUFF_SIZE	1024
#define ERR_NSPROXY	-1
#define ERR_LSMNS	-2

static char buff[BUFF_SIZE];
static int cursor;
static rwlock_t buff_lock;

static int get_current_lsmns(void)
{
	int type;
	struct lsm_namespace *ns;
	struct nsproxy *nsproxy;
	struct task_struct *tsk = current;

	task_lock(tsk);
	nsproxy = tsk->nsproxy;
	if (!nsproxy)
		return ERR_NSPROXY;

	ns = nsproxy->lsm_ns;
	if (!ns)
		return ERR_LSMNS;

	type = ns->type;
	task_unlock(tsk);

	return type;
}

static void flush_buff(void)
{
	write_lock(&buff_lock);
	memset(buff, 0, BUFF_SIZE);
	cursor = 0;
	write_unlock(&buff_lock);
}

static void write_buff(const char *msg)
{
	int len = strlen(msg);

	write_lock(&buff_lock);
	if (len == strlcpy(buff + cursor, msg, len)) {
		cursor += len;
		cursor++;
		buff[cursor++] = '\n';
	}
	write_unlock(&buff_lock);

	return 0;
}

static ssize_t lsmns_read(struct file *fp, char __user *user_buff, size_t count, loff_t *pos)
{
	int type;
	ssize_t size;

	flush_buff();

	size = 0;

	type = get_current_lsmns();
	if (type == ERR_NSPROXY) {
		write_buff("nsproxy is NULL\n");
		goto ERR;
	} else if (type == ERR_LSMNS) {
		write_buff("lsmns is NULL\n");
		goto ERR;
	}

	if (type & LSMNS_SELINUX)
		write_buff("selinux\n");
	if (type & LSMNS_APPARMOR)
		write_buff("apparmor\n");
	if (type & LSMNS_TOMOYO)
		write_buff("tomoyo\n");
	if (type & LSMNS_OTHER)
		write_buff("other\n");

	write_lock(&buff_lock);
	size = simple_read_from_buffer(user_buff, count, pos, buff, BUFF_SIZE);
	write_unlock(&buff_lock);

	return size;

ERR:
	return 0;
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
