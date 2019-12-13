#ifndef _LINUX_LSM_NS_H
#define _LINUX_LSM_NS_H

#include <linux/cred.h>
#include <linux/kref.h>
#include <linux/ns_common.h>
#include <linux/nsproxy.h>
#include <linux/proc_ns.h>
#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/user_namespace.h>

#define LSMNS_SELINUX		1
#define LSMNS_APPARMOR		2
#define LSMNS_TOMOYO		4

struct security_hook_ptrs {
	struct hlist_node *binder_set_context_mgr;
	struct hlist_node *binder_transaction;
	struct hlist_node *binder_transfer_binder;
	struct hlist_node *binder_transfer_file;
	struct hlist_node *ptrace_access_check;
	struct hlist_node *ptrace_traceme;
	struct hlist_node *capget;
	struct hlist_node *capset;
	struct hlist_node *capable;
	struct hlist_node *quotactl;
	struct hlist_node *quota_on;
	struct hlist_node *syslog;
	struct hlist_node *settime;
	struct hlist_node *vm_enough_memory;
	struct hlist_node *bprm_set_creds;
	struct hlist_node *bprm_check_security;
	struct hlist_node *bprm_committing_creds;
	struct hlist_node *bprm_committed_creds;
	struct hlist_node *fs_context_dup;
	struct hlist_node *fs_context_parse_param;
	struct hlist_node *sb_alloc_security;
	struct hlist_node *sb_free_security;
	struct hlist_node *sb_free_mnt_opts;
	struct hlist_node *sb_eat_lsm_opts;
	struct hlist_node *sb_remount;
	struct hlist_node *sb_kern_mount;
	struct hlist_node *sb_show_options;
	struct hlist_node *sb_statfs;
	struct hlist_node *sb_mount;
	struct hlist_node *sb_umount;
	struct hlist_node *sb_pivotroot;
	struct hlist_node *sb_set_mnt_opts;
	struct hlist_node *sb_clone_mnt_opts;
	struct hlist_node *sb_add_mnt_opt;
	struct hlist_node *move_mount;
	struct hlist_node *dentry_init_security;
	struct hlist_node *dentry_create_files_as;
#ifdef CONFIG_SECURITY_PATH
	struct hlist_node *path_unlink;
	struct hlist_node *path_mkdir;
	struct hlist_node *path_rmdir;
	struct hlist_node *path_mknod;
	struct hlist_node *path_truncate;
	struct hlist_node *path_symlink;
	struct hlist_node *path_link;
	struct hlist_node *path_rename;
	struct hlist_node *path_chmod;
	struct hlist_node *path_chown;
	struct hlist_node *path_chroot;
#endif
	/* Needed for inode based modules as well */
	struct hlist_node *path_notify;
	struct hlist_node *inode_alloc_security;
	struct hlist_node *inode_free_security;
	struct hlist_node *inode_init_security;
	struct hlist_node *inode_create;
	struct hlist_node *inode_link;
	struct hlist_node *inode_unlink;
	struct hlist_node *inode_symlink;
	struct hlist_node *inode_mkdir;
	struct hlist_node *inode_rmdir;
	struct hlist_node *inode_mknod;
	struct hlist_node *inode_rename;
	struct hlist_node *inode_readlink;
	struct hlist_node *inode_follow_link;
	struct hlist_node *inode_permission;
	struct hlist_node *inode_setattr;
	struct hlist_node *inode_getattr;
	struct hlist_node *inode_setxattr;
	struct hlist_node *inode_post_setxattr;
	struct hlist_node *inode_getxattr;
	struct hlist_node *inode_listxattr;
	struct hlist_node *inode_removexattr;
	struct hlist_node *inode_need_killpriv;
	struct hlist_node *inode_killpriv;
	struct hlist_node *inode_getsecurity;
	struct hlist_node *inode_setsecurity;
	struct hlist_node *inode_listsecurity;
	struct hlist_node *inode_getsecid;
	struct hlist_node *inode_copy_up;
	struct hlist_node *inode_copy_up_xattr;
	struct hlist_node *kernfs_init_security;
	struct hlist_node *file_permission;
	struct hlist_node *file_alloc_security;
	struct hlist_node *file_free_security;
	struct hlist_node *file_ioctl;
	struct hlist_node *mmap_addr;
	struct hlist_node *mmap_file;
	struct hlist_node *file_mprotect;
	struct hlist_node *file_lock;
	struct hlist_node *file_fcntl;
	struct hlist_node *file_set_fowner;
	struct hlist_node *file_send_sigiotask;
	struct hlist_node *file_receive;
	struct hlist_node *file_open;
	struct hlist_node *task_alloc;
	struct hlist_node *task_free;
	struct hlist_node *cred_alloc_blank;
	struct hlist_node *cred_free;
	struct hlist_node *cred_prepare;
	struct hlist_node *cred_transfer;
	struct hlist_node *cred_getsecid;
	struct hlist_node *kernel_act_as;
	struct hlist_node *kernel_create_files_as;
	struct hlist_node *kernel_load_data;
	struct hlist_node *kernel_read_file;
	struct hlist_node *kernel_post_read_file;
	struct hlist_node *kernel_module_request;
	struct hlist_node *task_fix_setuid;
	struct hlist_node *task_setpgid;
	struct hlist_node *task_getpgid;
	struct hlist_node *task_getsid;
	struct hlist_node *task_getsecid;
	struct hlist_node *task_setnice;
	struct hlist_node *task_setioprio;
	struct hlist_node *task_getioprio;
	struct hlist_node *task_prlimit;
	struct hlist_node *task_setrlimit;
	struct hlist_node *task_setscheduler;
	struct hlist_node *task_getscheduler;
	struct hlist_node *task_movememory;
	struct hlist_node *task_kill;
	struct hlist_node *task_prctl;
	struct hlist_node *task_to_inode;
	struct hlist_node *ipc_permission;
	struct hlist_node *ipc_getsecid;
	struct hlist_node *msg_msg_alloc_security;
	struct hlist_node *msg_msg_free_security;
	struct hlist_node *msg_queue_alloc_security;
	struct hlist_node *msg_queue_free_security;
	struct hlist_node *msg_queue_associate;
	struct hlist_node *msg_queue_msgctl;
	struct hlist_node *msg_queue_msgsnd;
	struct hlist_node *msg_queue_msgrcv;
	struct hlist_node *shm_alloc_security;
	struct hlist_node *shm_free_security;
	struct hlist_node *shm_associate;
	struct hlist_node *shm_shmctl;
	struct hlist_node *shm_shmat;
	struct hlist_node *sem_alloc_security;
	struct hlist_node *sem_free_security;
	struct hlist_node *sem_associate;
	struct hlist_node *sem_semctl;
	struct hlist_node *sem_semop;
	struct hlist_node *netlink_send;
	struct hlist_node *d_instantiate;
	struct hlist_node *getprocattr;
	struct hlist_node *setprocattr;
	struct hlist_node *ismaclabel;
	struct hlist_node *secid_to_secctx;
	struct hlist_node *secctx_to_secid;
	struct hlist_node *release_secctx;
	struct hlist_node *inode_invalidate_secctx;
	struct hlist_node *inode_notifysecctx;
	struct hlist_node *inode_setsecctx;
	struct hlist_node *inode_getsecctx;
#ifdef CONFIG_SECURITY_NETWORK
	struct hlist_node *unix_stream_connect;
	struct hlist_node *unix_may_send;
	struct hlist_node *socket_create;
	struct hlist_node *socket_post_create;
	struct hlist_node *socket_socketpair;
	struct hlist_node *socket_bind;
	struct hlist_node *socket_connect;
	struct hlist_node *socket_listen;
	struct hlist_node *socket_accept;
	struct hlist_node *socket_sendmsg;
	struct hlist_node *socket_recvmsg;
	struct hlist_node *socket_getsockname;
	struct hlist_node *socket_getpeername;
	struct hlist_node *socket_getsockopt;
	struct hlist_node *socket_setsockopt;
	struct hlist_node *socket_shutdown;
	struct hlist_node *socket_sock_rcv_skb;
	struct hlist_node *socket_getpeersec_stream;
	struct hlist_node *socket_getpeersec_dgram;
	struct hlist_node *sk_alloc_security;
	struct hlist_node *sk_free_security;
	struct hlist_node *sk_clone_security;
	struct hlist_node *sk_getsecid;
	struct hlist_node *sock_graft;
	struct hlist_node *inet_conn_request;
	struct hlist_node *inet_csk_clone;
	struct hlist_node *inet_conn_established;
	struct hlist_node *secmark_relabel_packet;
	struct hlist_node *secmark_refcount_inc;
	struct hlist_node *secmark_refcount_dec;
	struct hlist_node *req_classify_flow;
	struct hlist_node *tun_dev_alloc_security;
	struct hlist_node *tun_dev_free_security;
	struct hlist_node *tun_dev_create;
	struct hlist_node *tun_dev_attach_queue;
	struct hlist_node *tun_dev_attach;
	struct hlist_node *tun_dev_open;
	struct hlist_node *sctp_assoc_request;
	struct hlist_node *sctp_bind_connect;
	struct hlist_node *sctp_sk_clone;
#endif	/* CONFIG_SECURITY_NETWORK */
#ifdef CONFIG_SECURITY_INFINIBAND
	struct hlist_node *ib_pkey_access;
	struct hlist_node *ib_endport_manage_subnet;
	struct hlist_node *ib_alloc_security;
	struct hlist_node *ib_free_security;
#endif	/* CONFIG_SECURITY_INFINIBAND */
#ifdef CONFIG_SECURITY_NETWORK_XFRM
	struct hlist_node *xfrm_policy_alloc_security;
	struct hlist_node *xfrm_policy_clone_security;
	struct hlist_node *xfrm_policy_free_security;
	struct hlist_node *xfrm_policy_delete_security;
	struct hlist_node *xfrm_state_alloc;
	struct hlist_node *xfrm_state_alloc_acquire;
	struct hlist_node *xfrm_state_free_security;
	struct hlist_node *xfrm_state_delete_security;
	struct hlist_node *xfrm_policy_lookup;
	struct hlist_node *xfrm_state_pol_flow_match;
	struct hlist_node *xfrm_decode_session;
#endif	/* CONFIG_SECURITY_NETWORK_XFRM */
#ifdef CONFIG_KEYS
	struct hlist_node *key_alloc;
	struct hlist_node *key_free;
	struct hlist_node *key_permission;
	struct hlist_node *key_getsecurity;
#endif	/* CONFIG_KEYS */
#ifdef CONFIG_AUDIT
	struct hlist_node *audit_rule_init;
	struct hlist_node *audit_rule_known;
	struct hlist_node *audit_rule_match;
	struct hlist_node *audit_rule_free;
#endif /* CONFIG_AUDIT */
#ifdef CONFIG_BPF_SYSCALL
	struct hlist_node *bpf;
	struct hlist_node *bpf_map;
	struct hlist_node *bpf_prog;
	struct hlist_node *bpf_map_alloc_security;
	struct hlist_node *bpf_map_free_security;
	struct hlist_node *bpf_prog_alloc_security;
	struct hlist_node *bpf_prog_free_security;
#endif /* CONFIG_BPF_SYSCALL */
	struct hlist_node *locked_down;
};

struct lsm_namespace {
	struct kref kref;
	struct ns_common ns;
	struct user_namespace *user_ns;
	struct ucounts *ucounts;
	int types;
} __randomize_layout;

static inline struct lsm_namespace *get_lsm_ns(struct lsm_namespace *ns)
{
	kref_get(&ns->kref);
	return ns;
}

extern void free_lsm_ns(struct kref *kref);

static inline struct lsm_namespace *put_lsm_ns(struct lsm_namespace *ns)
{
	kref_put(&ns->kref, free_lsm_ns);
	return ns;
}

static inline struct lsm_namespace *to_lsm_ns(struct ns_common *ns)
{
	return container_of(ns, struct lsm_namespace, ns);
}

void __init lsmns_init(void);
struct lsm_namespace *copy_lsm_ns(unsigned long flags,
				struct user_namespace *user_ns, struct lsm_namespace *old_ns);
extern struct lsm_namespace init_lsm_ns;

#endif /* _LINUX_LSM_NS_H */
