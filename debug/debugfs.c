#include <debug/debugfs.h>

#define MAX_BUFF_SIZE 4096

static struct dentry *root;
static struct dentry *log;
static char buff[MAX_BUFF_SIZE];
static int cursor;
static rwlock_t buff_lock;

static ssize_t read(struct file *file, char __user *user_buff,
		size_t count, loff_t *pos)
{
	return simple_read_from_buffer(user_buff, count, pos,
			buff, MAX_BUFF_SIZE);
}

static const struct file_operations fops = {
	.read = read,
};

static int __init lsmns_debugfs_init(void)
{
	root = debugfs_create_dir("lsmns", NULL);
	log = debugfs_create_file("log", 0644, root, NULL, &fops);
	cursor = 0;

	DEFINE_RWLOCK(buff_lock);

	return 0;
}
__initcall(lsmns_debugfs_init);

int print_debugfs(const char *msg)
{
	int len = strlen(msg);

	if (MAX_BUFF_SIZE < cursor + len + 1) {
		write_lock(&buff_lock);
		cursor = 0;
		memset(buff, 0, MAX_BUFF_SIZE);
		write_unlock(&buff_lock);
	}

	write_lock(&buff_lock);
	if (len == strlcpy(buff + cursor, msg, len)) {
		cursor += len;
		cursor ++;
		buff[cursor++] = '\n';
		write_unlock(&buff_lock);

		return 1;
	}
	write_unlock(&buff_lock);

	return 0;
}
