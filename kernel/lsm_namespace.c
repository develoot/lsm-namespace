#include <linux/capability.h>
#include <linux/err.h>
#include <linux/lsm_namespace.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/user_namespace.h>

static struct kmem_cache *lsm_ns_cachep;

const struct proc_ns_operations lsmns_operations = {
        .name = "lsm",
        .type = CLONE_NEWLSM,
        .get = lsmns_get,
        .put = lsmns_put,
        .install = lsmns_install,
        .owner = lsmns_owner
};

struct lsm_namespace init_lsm_ns = {
	.kref = KREF_INIT(1),
	.ns.ops = &lsmns_operations,
	.ns.inum = PROC_LSM_INIT_INO,
	.user_ns = &init_user_ns
};

static struct ucounts *inc_lsm_namespaces(struct user_namespace *ns)
{
	return inc_ucount(ns, current_euid(), UCOUNT_LSM_NAMESPACES);
}

static void dec_lsm_namespaces(struct ucounts *ucounts)
{
	dec_ucount(ucounts, UCOUNT_LSM_NAMESPACES);
}

static struct lsm_namespace *alloc_lsm_ns(struct user_namespace *user_ns)
{
	struct lsm_namespace *new_ns;
	struct ucounts *ucounts;
	int err;

	err = -ENOMEM;
	new_ns = kmem_cache_zalloc(lsm_ns_cachep, GFP_KERNEL);
	if (new_ns == NULL)
		goto fail;

	ucounts = inc_lsm_namespaces(user_ns);
	if (!ucounts)
		goto fail_free;
	new_ns->ucounts = ucounts;

	err = ns_alloc_inum(&new_ns->ns);
	if (err) {
		dec_lsm_namespaces(user_ns->ucounts);
		goto fail_free;
	}
	new_ns->ns.ops = &lsmns_operations;
	new_ns->user_ns = get_user_ns(user_ns);

	kref_init(&new_ns->kref);

	// need to add hooking func

	return new_ns;

fail_free:
	kmem_cache_free(lsm_ns_cachep, new_ns);
fail:
	return ERR_PTR(err);
}

void free_lsm_ns(struct kref *kref)
{
        struct lsm_namespace *ns;

	ns = container_of(kref, struct lsm_namespace, kref);
        dec_lsm_namespaces(ns->ucounts);
        put_user_ns(ns->user_ns);
        ns_free_inum(&ns->ns);
        kmem_cache_free(lsm_ns_cachep, ns);
        //need to free hooking functions
}

struct lsm_namespace *copy_lsm_ns(unsigned long flags,
		struct user_namespace *user_ns, struct lsm_namespace *old_ns)
{
	if (!(flags & CLONE_NEWLSM)) {
		return get_lsm_ns(old_ns);
	}
	return alloc_lsm_ns(user_ns);
}

static struct ns_common *lsmns_get(struct task_struct *task)
{
        struct ns_common *ns = NULL;
        struct nsproxy *nsproxy;

        task_lock(task);
	nsproxy = task->nsproxy;
	if(nsproxy) {
                ns = &nsproxy->lsm_ns->ns;
                get_lsm_ns(to_lsm_ns(ns));
        }
        task_unlock(task);

        return ns;
}

static void lsmns_put(struct ns_common *ns)
{
        put_lsm_ns(to_lsm_ns(ns));
}

static int lsmns_install(struct nsproxy *nsproxy, struct ns_common *new)
{
        struct lsm_namespace *ns = to_lsm_ns(new);

        if (!ns_capable(ns->user_ns, CAP_SYS_ADMIN) ||
           !ns_capable(current_user_ns(), CAP_SYS_ADMIN))
                return -EPERM;

        get_lsm_ns(ns);
	put_lsm_ns(nsproxy->lsm_ns);
        nsproxy->lsm_ns = ns;

        return 0;
}

static struct user_namespace *lsmns_owner(struct ns_common *ns)
{
        return to_lsm_ns(ns)->user_ns;
}

static __init int lsm_namespaces_init(void)
{
	lsm_ns_cachep = KMEM_CACHE(lsm_namespace, SLAB_PANIC);

	return 0;
}
__initcall(lsm_namespaces_init);

extern struct security_hook_heads security_hook_heads;

#define LSMNS_PTR_INIT(FUNC)						       \
	do {								       \
		struct hlist_node *first = security_hook_heads.FUNC->first;    \
		struct hlist_node *pos;					       \
									       \
		init_lsm_ns.start.FUNC = first;				       \
									       \
		if (first == NULL)					       \
			init_lsm_ns.end.FUNC = NULL;			       \
		else {							       \
			for (pos = first; pos->next; pos = pos->next);	       \
			init_lsm_ns.end.FUNC = pos;			       \
		}							       \
	} while (0)

void __init lsmns_init(void)
{
	LSMNS_PTR_INIT(binder_set_context_mgr);
	LSMNS_PTR_INIT(binder_transaction);
	LSMNS_PTR_INIT(binder_transfer_binder);
	LSMNS_PTR_INIT(binder_transfer_file);
	LSMNS_PTR_INIT(ptrace_access_check);
	LSMNS_PTR_INIT(ptrace_traceme);
	LSMNS_PTR_INIT(capget);
	LSMNS_PTR_INIT(capset);
	LSMNS_PTR_INIT(capable);
	LSMNS_PTR_INIT(quotactl);
	LSMNS_PTR_INIT(quota_on);
	LSMNS_PTR_INIT(syslog);
	LSMNS_PTR_INIT(settime);
	LSMNS_PTR_INIT(vm_enough_memory);
	LSMNS_PTR_INIT(bprm_set_creds);
	LSMNS_PTR_INIT(bprm_check_security);
	LSMNS_PTR_INIT(bprm_committing_creds);
	LSMNS_PTR_INIT(bprm_committed_creds);
	LSMNS_PTR_INIT(fs_context_dup);
	LSMNS_PTR_INIT(fs_context_parse_param);
	LSMNS_PTR_INIT(sb_alloc_security);
	LSMNS_PTR_INIT(sb_free_security);
	LSMNS_PTR_INIT(sb_free_mnt_opts);
	LSMNS_PTR_INIT(sb_eat_lsm_opts);
	LSMNS_PTR_INIT(sb_remount);
	LSMNS_PTR_INIT(sb_kern_mount);
	LSMNS_PTR_INIT(sb_show_options);
	LSMNS_PTR_INIT(sb_statfs);
	LSMNS_PTR_INIT(sb_mount);
	LSMNS_PTR_INIT(sb_umount);
	LSMNS_PTR_INIT(sb_pivotroot);
	LSMNS_PTR_INIT(sb_set_mnt_opts);
	LSMNS_PTR_INIT(sb_clone_mnt_opts);
	LSMNS_PTR_INIT(sb_add_mnt_opt);
	LSMNS_PTR_INIT(move_mount);
	LSMNS_PTR_INIT(dentry_init_security);
	LSMNS_PTR_INIT(dentry_create_files_as);
#ifdef CONFIG_SECURITY_PATH
	LSMNS_PTR_INIT(path_unlink);
	LSMNS_PTR_INIT(path_mkdir);
	LSMNS_PTR_INIT(path_rmdir);
	LSMNS_PTR_INIT(path_mknod);
	LSMNS_PTR_INIT(path_truncate);
	LSMNS_PTR_INIT(path_symlink);
	LSMNS_PTR_INIT(path_link);
	LSMNS_PTR_INIT(path_rename);
	LSMNS_PTR_INIT(path_chmod);
	LSMNS_PTR_INIT(path_chown);
	LSMNS_PTR_INIT(path_chroot);
#endif
	/* Needed for inode based modules as well */
	LSMNS_PTR_INIT(path_notify);
	LSMNS_PTR_INIT(inode_alloc_security);
	LSMNS_PTR_INIT(inode_free_security);
	LSMNS_PTR_INIT(inode_init_security);
	LSMNS_PTR_INIT(inode_create);
	LSMNS_PTR_INIT(inode_link);
	LSMNS_PTR_INIT(inode_unlink);
	LSMNS_PTR_INIT(inode_symlink);
	LSMNS_PTR_INIT(inode_mkdir);
	LSMNS_PTR_INIT(inode_rmdir);
	LSMNS_PTR_INIT(inode_mknod);
	LSMNS_PTR_INIT(inode_rename);
	LSMNS_PTR_INIT(inode_readlink);
	LSMNS_PTR_INIT(inode_follow_link);
	LSMNS_PTR_INIT(inode_permission);
	LSMNS_PTR_INIT(inode_setattr);
	LSMNS_PTR_INIT(inode_getattr);
	LSMNS_PTR_INIT(inode_setxattr);
	LSMNS_PTR_INIT(inode_post_setxattr);
	LSMNS_PTR_INIT(inode_getxattr);
	LSMNS_PTR_INIT(inode_listxattr);
	LSMNS_PTR_INIT(inode_removexattr);
	LSMNS_PTR_INIT(inode_need_killpriv);
	LSMNS_PTR_INIT(inode_killpriv);
	LSMNS_PTR_INIT(inode_getsecurity);
	LSMNS_PTR_INIT(inode_setsecurity);
	LSMNS_PTR_INIT(inode_listsecurity);
	LSMNS_PTR_INIT(inode_getsecid);
	LSMNS_PTR_INIT(inode_copy_up);
	LSMNS_PTR_INIT(inode_copy_up_xattr);
	LSMNS_PTR_INIT(kernfs_init_security);
	LSMNS_PTR_INIT(file_permission);
	LSMNS_PTR_INIT(file_alloc_security);
	LSMNS_PTR_INIT(file_free_security);
	LSMNS_PTR_INIT(file_ioctl);
	LSMNS_PTR_INIT(mmap_addr);
	LSMNS_PTR_INIT(mmap_file);
	LSMNS_PTR_INIT(file_mprotect);
	LSMNS_PTR_INIT(file_lock);
	LSMNS_PTR_INIT(file_fcntl);
	LSMNS_PTR_INIT(file_set_fowner);
	LSMNS_PTR_INIT(file_send_sigiotask);
	LSMNS_PTR_INIT(file_receive);
	LSMNS_PTR_INIT(file_open);
	LSMNS_PTR_INIT(task_alloc);
	LSMNS_PTR_INIT(task_free);
	LSMNS_PTR_INIT(cred_alloc_blank);
	LSMNS_PTR_INIT(cred_free);
	LSMNS_PTR_INIT(cred_prepare);
	LSMNS_PTR_INIT(cred_transfer);
	LSMNS_PTR_INIT(cred_getsecid);
	LSMNS_PTR_INIT(kernel_act_as);
	LSMNS_PTR_INIT(kernel_create_files_as);
	LSMNS_PTR_INIT(kernel_load_data);
	LSMNS_PTR_INIT(kernel_read_file);
	LSMNS_PTR_INIT(kernel_post_read_file);
	LSMNS_PTR_INIT(kernel_module_request);
	LSMNS_PTR_INIT(task_fix_setuid);
	LSMNS_PTR_INIT(task_setpgid);
	LSMNS_PTR_INIT(task_getpgid);
	LSMNS_PTR_INIT(task_getsid);
	LSMNS_PTR_INIT(task_getsecid);
	LSMNS_PTR_INIT(task_setnice);
	LSMNS_PTR_INIT(task_setioprio);
	LSMNS_PTR_INIT(task_getioprio);
	LSMNS_PTR_INIT(task_prlimit);
	LSMNS_PTR_INIT(task_setrlimit);
	LSMNS_PTR_INIT(task_setscheduler);
	LSMNS_PTR_INIT(task_getscheduler);
	LSMNS_PTR_INIT(task_movememory);
	LSMNS_PTR_INIT(task_kill);
	LSMNS_PTR_INIT(task_prctl);
	LSMNS_PTR_INIT(task_to_inode);
	LSMNS_PTR_INIT(ipc_permission);
	LSMNS_PTR_INIT(ipc_getsecid);
	LSMNS_PTR_INIT(msg_msg_alloc_security);
	LSMNS_PTR_INIT(msg_msg_free_security);
	LSMNS_PTR_INIT(msg_queue_alloc_security);
	LSMNS_PTR_INIT(msg_queue_free_security);
	LSMNS_PTR_INIT(msg_queue_associate);
	LSMNS_PTR_INIT(msg_queue_msgctl);
	LSMNS_PTR_INIT(msg_queue_msgsnd);
	LSMNS_PTR_INIT(msg_queue_msgrcv);
	LSMNS_PTR_INIT(shm_alloc_security);
	LSMNS_PTR_INIT(shm_free_security);
	LSMNS_PTR_INIT(shm_associate);
	LSMNS_PTR_INIT(shm_shmctl);
	LSMNS_PTR_INIT(shm_shmat);
	LSMNS_PTR_INIT(sem_alloc_security);
	LSMNS_PTR_INIT(sem_free_security);
	LSMNS_PTR_INIT(sem_associate);
	LSMNS_PTR_INIT(sem_semctl);
	LSMNS_PTR_INIT(sem_semop);
	LSMNS_PTR_INIT(netlink_send);
	LSMNS_PTR_INIT(d_instantiate);
	LSMNS_PTR_INIT(getprocattr);
	LSMNS_PTR_INIT(setprocattr);
	LSMNS_PTR_INIT(ismaclabel);
	LSMNS_PTR_INIT(secid_to_secctx);
	LSMNS_PTR_INIT(secctx_to_secid);
	LSMNS_PTR_INIT(release_secctx);
	LSMNS_PTR_INIT(inode_invalidate_secctx);
	LSMNS_PTR_INIT(inode_notifysecctx);
	LSMNS_PTR_INIT(inode_setsecctx);
	LSMNS_PTR_INIT(inode_getsecctx);
#ifdef CONFIG_SECURITY_NETWORK
	LSMNS_PTR_INIT(unix_stream_connect);
	LSMNS_PTR_INIT(unix_may_send);
	LSMNS_PTR_INIT(socket_create);
	LSMNS_PTR_INIT(socket_post_create);
	LSMNS_PTR_INIT(socket_socketpair);
	LSMNS_PTR_INIT(socket_bind);
	LSMNS_PTR_INIT(socket_connect);
	LSMNS_PTR_INIT(socket_listen);
	LSMNS_PTR_INIT(socket_accept);
	LSMNS_PTR_INIT(socket_sendmsg);
	LSMNS_PTR_INIT(socket_recvmsg);
	LSMNS_PTR_INIT(socket_getsockname);
	LSMNS_PTR_INIT(socket_getpeername);
	LSMNS_PTR_INIT(socket_getsockopt);
	LSMNS_PTR_INIT(socket_setsockopt);
	LSMNS_PTR_INIT(socket_shutdown);
	LSMNS_PTR_INIT(socket_sock_rcv_skb);
	LSMNS_PTR_INIT(socket_getpeersec_stream);
	LSMNS_PTR_INIT(socket_getpeersec_dgram);
	LSMNS_PTR_INIT(sk_alloc_security);
	LSMNS_PTR_INIT(sk_free_security);
	LSMNS_PTR_INIT(sk_clone_security);
	LSMNS_PTR_INIT(sk_getsecid);
	LSMNS_PTR_INIT(sock_graft);
	LSMNS_PTR_INIT(inet_conn_request);
	LSMNS_PTR_INIT(inet_csk_clone);
	LSMNS_PTR_INIT(inet_conn_established);
	LSMNS_PTR_INIT(secmark_relabel_packet);
	LSMNS_PTR_INIT(secmark_refcount_inc);
	LSMNS_PTR_INIT(secmark_refcount_dec);
	LSMNS_PTR_INIT(req_classify_flow);
	LSMNS_PTR_INIT(tun_dev_alloc_security);
	LSMNS_PTR_INIT(tun_dev_free_security);
	LSMNS_PTR_INIT(tun_dev_create);
	LSMNS_PTR_INIT(tun_dev_attach_queue);
	LSMNS_PTR_INIT(tun_dev_attach);
	LSMNS_PTR_INIT(tun_dev_open);
	LSMNS_PTR_INIT(sctp_assoc_request);
	LSMNS_PTR_INIT(sctp_bind_connect);
	LSMNS_PTR_INIT(sctp_sk_clone);
/* CONFIG_SECURITY_NETWORK */
#ifdef CONFIG_SECURITY_INFINIBAND
	LSMNS_PTR_INIT(ib_pkey_access);
	LSMNS_PTR_INIT(ib_endport_manage_subnet);
	LSMNS_PTR_INIT(ib_alloc_security);
	LSMNS_PTR_INIT(ib_free_security);
#endif	/* CONFIG_SECURITY_INFINIBAND */
#ifdef CONFIG_SECURITY_NETWORK_XFRM
	LSMNS_PTR_INIT(xfrm_policy_alloc_security);
	LSMNS_PTR_INIT(xfrm_policy_clone_security);
	LSMNS_PTR_INIT(xfrm_policy_free_security);
	LSMNS_PTR_INIT(xfrm_policy_delete_security);
	LSMNS_PTR_INIT(xfrm_state_alloc);
	LSMNS_PTR_INIT(xfrm_state_alloc_acquire);
	LSMNS_PTR_INIT(xfrm_state_free_security);
	LSMNS_PTR_INIT(xfrm_state_delete_security);
	LSMNS_PTR_INIT(xfrm_policy_lookup);
	LSMNS_PTR_INIT(xfrm_state_pol_flow_match);
	LSMNS_PTR_INIT(xfrm_decode_session);
#endif	/* CONFIG_SECURITY_NETWORK_XFRM */
#ifdef CONFIG_KEYS
	LSMNS_PTR_INIT(key_alloc);
	LSMNS_PTR_INIT(key_free);
	LSMNS_PTR_INIT(key_permission);
	LSMNS_PTR_INIT(key_getsecurity);
#endif	/* CONFIG_KEYS */
#ifdef CONFIG_AUDIT
	LSMNS_PTR_INIT(audit_rule_init);
	LSMNS_PTR_INIT(audit_rule_known);
	LSMNS_PTR_INIT(audit_rule_match);
	LSMNS_PTR_INIT(audit_rule_free);
#endif /* CONFIG_AUDIT */
#ifdef CONFIG_BPF_SYSCALL
	LSMNS_PTR_INIT(bpf);
	LSMNS_PTR_INIT(bpf_map);
	LSMNS_PTR_INIT(bpf_prog);
	LSMNS_PTR_INIT(bpf_map_alloc_security);
	LSMNS_PTR_INIT(bpf_map_free_security);
	LSMNS_PTR_INIT(bpf_prog_alloc_security);
	LSMNS_PTR_INIT(bpf_prog_free_security);
#endif /* CONFIG_BPF_SYSCALL */
	LSMNS_PTR_INIT(locked_down);
}
