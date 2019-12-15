#include <debug/debugfs.h>

#define MAX_BUFF_SIZE 4096

static struct dentry *root;
static struct dentry *log;
static struct dentry *plist;
static char buff[MAX_BUFF_SIZE];
static char plist_buff[MAX_BUFF_SIZE];
static int cursor;
static int plist_cursor;
static rwlock_t buff_lock;

static ssize_t read(struct file *file, char __user *user_buff,
		size_t count, loff_t *pos)
{
	return simple_read_from_buffer(user_buff, count, pos,
			buff, MAX_BUFF_SIZE);
}

static const struct file_operations fops_log = {
	.read = read,
};

static ssize_t plist_read(struct file *file, char __user *user_buff,
                size_t count, loff_t *pos)
{
        return simple_read_from_buffer(user_buff, count, pos, plist_buff, MAX_BUFF_SIZE);
}

extern int print_hooklist(long index);
static ssize_t plist_write(struct file *file, const char __user *user_buff,
                size_t count, loff_t *pos)
{
        char tmp[MAX_BUFF_SIZE];
        memset(tmp, 0, MAX_BUFF_SIZE);
        long arg;
        ssize_t sz;
        sz = simple_write_to_buffer(tmp, MAX_BUFF_SIZE, pos, user_buff, count);
        kstrtol(tmp, 10, &arg);
        print_hooklist(arg);
        return sz;
}

static const struct file_operations fops_plist = {
        .read = plist_read,
        .write = plist_write,
};

void flush_plist(void)
{
        memset(plist_buff, 0, MAX_BUFF_SIZE);
        plist_cursor = 0;
}

int print_plist(const char* msg)
{
        int len = strlen(msg);
        if(len + plist_cursor > MAX_BUFF_SIZE)
                flush_plist();
        if(len == strlcpy(plist_buff + plist_cursor, msg, len)){
                plist_cursor += len;
                plist_cursor++;
                plist_buff[plist_cursor++] = '\n';
        }
        return 1;
}

int print_debugfs(const char *msg, ...)
{
	va_list ap;
	char tmp[MAX_BUFF_SIZE];
	va_start(ap, msg);
	vsnprintf(tmp, MAX_BUFF_SIZE, msg, ap);
	va_end(ap);

	int len = strlen(tmp);
	if (MAX_BUFF_SIZE < cursor + len + 1) {
		write_lock(&buff_lock);
		cursor = 0;
		memset(buff, 0, MAX_BUFF_SIZE);
		write_unlock(&buff_lock);
	}

	write_lock(&buff_lock);
	if (len == strlcpy(buff + cursor, tmp, len)) {
		cursor += len;
		cursor ++;
		buff[cursor++] = '\n';
		write_unlock(&buff_lock);

		return 1;
	}
	write_unlock(&buff_lock);

	return 0;
}

static int __init lsmns_debugfs_init(void)
{
        root = debugfs_create_dir("lsmns", NULL);
        log = debugfs_create_file("log", 0666, root, NULL, &fops_log);
        plist = debugfs_create_file("plist", 0666, root, NULL, &fops_plist);
        cursor = 0;
        plist_cursor = 0;
        DEFINE_RWLOCK(buff_lock);

        return 0;
}
__initcall(lsmns_debugfs_init);
