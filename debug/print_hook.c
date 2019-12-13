#include <linux/unistd.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <debug/debugfs.h>
#include <linux/lsm_hooks.h>
#include <linux/list.h>

extern struct security_hook_heads security_hook_heads;


#define print_hook_list(FUNC)							\
	do {									\
		print_plist("[FUNC] "#FUNC);					\
		struct security_hook_list *P;					\
		hlist_for_each_entry(P, &security_hook_heads.FUNC, list)	\
			print_plist(P->lsm);					\
	} while(0)								\


static void plist_binder_set_context_mgr(void){print_hook_list(binder_set_context_mgr);}
static void plist_binder_transaction(void){print_hook_list(binder_transaction);}
static void plist_binder_transfer_binder(void){print_hook_list(binder_transfer_binder);}
static void plist_binder_transfer_file(void){print_hook_list(binder_transfer_file);}
static void plist_ptrace_access_check(void){print_hook_list(ptrace_access_check);}
static void plist_ptrace_traceme(void){print_hook_list(ptrace_traceme);}
static void plist_capget(void){print_hook_list(capget);}
static void plist_capset(void){print_hook_list(capset);}
static void plist_capable(void){print_hook_list(capable);}
static void plist_quotactl(void){print_hook_list(quotactl);}
static void plist_quota_on(void){print_hook_list(quota_on);}
static void plist_syslog(void){print_hook_list(syslog);}
static void plist_settime(void){print_hook_list(settime);}
static void plist_vm_enough_memory(void){print_hook_list(vm_enough_memory);}
static void plist_bprm_set_creds(void){print_hook_list(bprm_set_creds);}
static void plist_bprm_check_security(void){print_hook_list(bprm_check_security);}
static void plist_bprm_committing_creds(void){print_hook_list(bprm_committing_creds);}
static void plist_bprm_committed_creds(void){print_hook_list(bprm_committed_creds);}
static void plist_fs_context_dup(void){print_hook_list(fs_context_dup);}
static void plist_fs_context_parse_param(void){print_hook_list(fs_context_parse_param);}
static void plist_sb_alloc_security(void){print_hook_list(sb_alloc_security);}
static void plist_sb_free_security(void){print_hook_list(sb_free_security);}
static void plist_sb_free_mnt_opts(void){print_hook_list(sb_free_mnt_opts);}
static void plist_sb_eat_lsm_opts(void){print_hook_list(sb_eat_lsm_opts);}
static void plist_sb_remount(void){print_hook_list(sb_remount);}
static void plist_sb_kern_mount(void){print_hook_list(sb_kern_mount);}
static void plist_sb_show_options(void){print_hook_list(sb_show_options);}
static void plist_sb_statfs(void){print_hook_list(sb_statfs);}
static void plist_sb_mount(void){print_hook_list(sb_mount);}
static void plist_sb_umount(void){print_hook_list(sb_umount);}
static void plist_sb_pivotroot(void){print_hook_list(sb_pivotroot);}
static void plist_sb_set_mnt_opts(void){print_hook_list(sb_set_mnt_opts);}
static void plist_sb_clone_mnt_opts(void){print_hook_list(sb_clone_mnt_opts);}
static void plist_sb_add_mnt_opt(void){print_hook_list(sb_add_mnt_opt);}
static void plist_move_mount(void){print_hook_list(move_mount);}
static void plist_dentry_init_security(void){print_hook_list(dentry_init_security);}
static void plist_dentry_create_files_as(void){print_hook_list(dentry_create_files_as);}
#ifdef CONFIG_SECURITY_PATH
static void plist_path_unlink(void){print_hook_list(path_unlink);}
static void plist_path_mkdir(void){print_hook_list(path_mkdir);}
static void plist_path_rmdir(void){print_hook_list(path_rmdir);}
static void plist_path_mknod(void){print_hook_list(path_mknod);}
static void plist_path_truncate(void){print_hook_list(path_truncate);}
static void plist_path_symlink(void){print_hook_list(path_symlink);}
static void plist_path_link(void){print_hook_list(path_link);}
static void plist_path_rename(void){print_hook_list(path_rename);}
static void plist_path_chmod(void){print_hook_list(path_chmod);}
static void plist_path_chown(void){print_hook_list(path_chown);}
static void plist_path_chroot(void){print_hook_list(path_chroot);}
#endif
/* Needed for inode based modules aswell */
static void plist_path_notify(void){print_hook_list(path_notify);}
static void plist_inode_alloc_security(void){print_hook_list(inode_alloc_security);}
static void plist_inode_free_security(void){print_hook_list(inode_free_security);}
static void plist_inode_init_security(void){print_hook_list(inode_init_security);}
static void plist_inode_create(void){print_hook_list(inode_create);}
static void plist_inode_link(void){print_hook_list(inode_link);}
static void plist_inode_unlink(void){print_hook_list(inode_unlink);}
static void plist_inode_symlink(void){print_hook_list(inode_symlink);}
static void plist_inode_mkdir(void){print_hook_list(inode_mkdir);}
static void plist_inode_rmdir(void){print_hook_list(inode_rmdir);}
static void plist_inode_mknod(void){print_hook_list(inode_mknod);}
static void plist_inode_rename(void){print_hook_list(inode_rename);}
static void plist_inode_readlink(void){print_hook_list(inode_readlink);}
static void plist_inode_follow_link(void){print_hook_list(inode_follow_link);}
static void plist_inode_permission(void){print_hook_list(inode_permission);}
static void plist_inode_setattr(void){print_hook_list(inode_setattr);}
static void plist_inode_getattr(void){print_hook_list(inode_getattr);}
static void plist_inode_setxattr(void){print_hook_list(inode_setxattr);}
static void plist_inode_post_setxattr(void){print_hook_list(inode_post_setxattr);}
static void plist_inode_getxattr(void){print_hook_list(inode_getxattr);}
static void plist_inode_listxattr(void){print_hook_list(inode_listxattr);}
static void plist_inode_removexattr(void){print_hook_list(inode_removexattr);}
static void plist_inode_need_killpriv(void){print_hook_list(inode_need_killpriv);}
static void plist_inode_killpriv(void){print_hook_list(inode_killpriv);}
static void plist_inode_getsecurity(void){print_hook_list(inode_getsecurity);}
static void plist_inode_setsecurity(void){print_hook_list(inode_setsecurity);}
static void plist_inode_listsecurity(void){print_hook_list(inode_listsecurity);}
static void plist_inode_getsecid(void){print_hook_list(inode_getsecid);}
static void plist_inode_copy_up(void){print_hook_list(inode_copy_up);}
static void plist_inode_copy_up_xattr(void){print_hook_list(inode_copy_up_xattr);}
static void plist_kernfs_init_security(void){print_hook_list(kernfs_init_security);}
static void plist_file_permission(void){print_hook_list(file_permission);}
static void plist_file_alloc_security(void){print_hook_list(file_alloc_security);}
static void plist_file_free_security(void){print_hook_list(file_free_security);}
static void plist_file_ioctl(void){print_hook_list(file_ioctl);}
static void plist_mmap_addr(void){print_hook_list(mmap_addr);}
static void plist_mmap_file(void){print_hook_list(mmap_file);}
static void plist_file_mprotect(void){print_hook_list(file_mprotect);}
static void plist_file_lock(void){print_hook_list(file_lock);}
static void plist_file_fcntl(void){print_hook_list(file_fcntl);}
static void plist_file_set_fowner(void){print_hook_list(file_set_fowner);}
static void plist_file_send_sigiotask(void){print_hook_list(file_send_sigiotask);}
static void plist_file_receive(void){print_hook_list(file_receive);}
static void plist_file_open(void){print_hook_list(file_open);}
static void plist_task_alloc(void){print_hook_list(task_alloc);}
static void plist_task_free(void){print_hook_list(task_free);}
static void plist_cred_alloc_blank(void){print_hook_list(cred_alloc_blank);}
static void plist_cred_free(void){print_hook_list(cred_free);}
static void plist_cred_prepare(void){print_hook_list(cred_prepare);}
static void plist_cred_transfer(void){print_hook_list(cred_transfer);}
static void plist_cred_getsecid(void){print_hook_list(cred_getsecid);}
static void plist_kernel_act_as(void){print_hook_list(kernel_act_as);}
static void plist_kernel_create_files_as(void){print_hook_list(kernel_create_files_as);}
static void plist_kernel_load_data(void){print_hook_list(kernel_load_data);}
static void plist_kernel_read_file(void){print_hook_list(kernel_read_file);}
static void plist_kernel_post_read_file(void){print_hook_list(kernel_post_read_file);}
static void plist_kernel_module_request(void){print_hook_list(kernel_module_request);}
static void plist_task_fix_setuid(void){print_hook_list(task_fix_setuid);}
static void plist_task_setpgid(void){print_hook_list(task_setpgid);}
static void plist_task_getpgid(void){print_hook_list(task_getpgid);}
static void plist_task_getsid(void){print_hook_list(task_getsid);}
static void plist_task_getsecid(void){print_hook_list(task_getsecid);}
static void plist_task_setnice(void){print_hook_list(task_setnice);}
static void plist_task_setioprio(void){print_hook_list(task_setioprio);}
static void plist_task_getioprio(void){print_hook_list(task_getioprio);}
static void plist_task_prlimit(void){print_hook_list(task_prlimit);}
static void plist_task_setrlimit(void){print_hook_list(task_setrlimit);}
static void plist_task_setscheduler(void){print_hook_list(task_setscheduler);}
static void plist_task_getscheduler(void){print_hook_list(task_getscheduler);}
static void plist_task_movememory(void){print_hook_list(task_movememory);}
static void plist_task_kill(void){print_hook_list(task_kill);}
static void plist_task_prctl(void){print_hook_list(task_prctl);}
static void plist_task_to_inode(void){print_hook_list(task_to_inode);}
static void plist_ipc_permission(void){print_hook_list(ipc_permission);}
static void plist_ipc_getsecid(void){print_hook_list(ipc_getsecid);}
static void plist_msg_msg_alloc_security(void){print_hook_list(msg_msg_alloc_security);}
static void plist_msg_msg_free_security(void){print_hook_list(msg_msg_free_security);}
static void plist_msg_queue_alloc_security(void){print_hook_list(msg_queue_alloc_security);}
static void plist_msg_queue_free_security(void){print_hook_list(msg_queue_free_security);}
static void plist_msg_queue_associate(void){print_hook_list(msg_queue_associate);}
static void plist_msg_queue_msgctl(void){print_hook_list(msg_queue_msgctl);}
static void plist_msg_queue_msgsnd(void){print_hook_list(msg_queue_msgsnd);}
static void plist_msg_queue_msgrcv(void){print_hook_list(msg_queue_msgrcv);}
static void plist_shm_alloc_security(void){print_hook_list(shm_alloc_security);}
static void plist_shm_free_security(void){print_hook_list(shm_free_security);}
static void plist_shm_associate(void){print_hook_list(shm_associate);}
static void plist_shm_shmctl(void){print_hook_list(shm_shmctl);}
static void plist_shm_shmat(void){print_hook_list(shm_shmat);}
static void plist_sem_alloc_security(void){print_hook_list(sem_alloc_security);}
static void plist_sem_free_security(void){print_hook_list(sem_free_security);}
static void plist_sem_associate(void){print_hook_list(sem_associate);}
static void plist_sem_semctl(void){print_hook_list(sem_semctl);}
static void plist_sem_semop(void){print_hook_list(sem_semop);}
static void plist_netlink_send(void){print_hook_list(netlink_send);}
static void plist_d_instantiate(void){print_hook_list(d_instantiate);}
static void plist_getprocattr(void){print_hook_list(getprocattr);}
static void plist_setprocattr(void){print_hook_list(setprocattr);}
static void plist_ismaclabel(void){print_hook_list(ismaclabel);}
static void plist_secid_to_secctx(void){print_hook_list(secid_to_secctx);}
static void plist_secctx_to_secid(void){print_hook_list(secctx_to_secid);}
static void plist_release_secctx(void){print_hook_list(release_secctx);}
static void plist_inode_invalidate_secctx(void){print_hook_list(inode_invalidate_secctx);}
static void plist_inode_notifysecctx(void){print_hook_list(inode_notifysecctx);}
static void plist_inode_setsecctx(void){print_hook_list(inode_setsecctx);}
static void plist_inode_getsecctx(void){print_hook_list(inode_getsecctx);}
#ifdef CONFIG_SECURITY_NETWORK
static void plist_unix_stream_connect(void){print_hook_list(unix_stream_connect);}
static void plist_unix_may_send(void){print_hook_list(unix_may_send);}
static void plist_socket_create(void){print_hook_list(socket_create);}
static void plist_socket_post_create(void){print_hook_list(socket_post_create);}
static void plist_socket_socketpair(void){print_hook_list(socket_socketpair);}
static void plist_socket_bind(void){print_hook_list(socket_bind);}
static void plist_socket_connect(void){print_hook_list(socket_connect);}
static void plist_socket_listen(void){print_hook_list(socket_listen);}
static void plist_socket_accept(void){print_hook_list(socket_accept);}
static void plist_socket_sendmsg(void){print_hook_list(socket_sendmsg);}
static void plist_socket_recvmsg(void){print_hook_list(socket_recvmsg);}
static void plist_socket_getsockname(void){print_hook_list(socket_getsockname);}
static void plist_socket_getpeername(void){print_hook_list(socket_getpeername);}
static void plist_socket_getsockopt(void){print_hook_list(socket_getsockopt);}
static void plist_socket_setsockopt(void){print_hook_list(socket_setsockopt);}
static void plist_socket_shutdown(void){print_hook_list(socket_shutdown);}
static void plist_socket_sock_rcv_skb(void){print_hook_list(socket_sock_rcv_skb);}
static void plist_socket_getpeersec_stream(void){print_hook_list(socket_getpeersec_stream);}
static void plist_socket_getpeersec_dgram(void){print_hook_list(socket_getpeersec_dgram);}
static void plist_sk_alloc_security(void){print_hook_list(sk_alloc_security);}
static void plist_sk_free_security(void){print_hook_list(sk_free_security);}
static void plist_sk_clone_security(void){print_hook_list(sk_clone_security);}
static void plist_sk_getsecid(void){print_hook_list(sk_getsecid);}
static void plist_sock_graft(void){print_hook_list(sock_graft);}
static void plist_inet_conn_request(void){print_hook_list(inet_conn_request);}
static void plist_inet_csk_clone(void){print_hook_list(inet_csk_clone);}
static void plist_inet_conn_established(void){print_hook_list(inet_conn_established);}
static void plist_secmark_relabel_packet(void){print_hook_list(secmark_relabel_packet);}
static void plist_secmark_refcount_inc(void){print_hook_list(secmark_refcount_inc);}
static void plist_secmark_refcount_dec(void){print_hook_list(secmark_refcount_dec);}
static void plist_req_classify_flow(void){print_hook_list(req_classify_flow);}
static void plist_tun_dev_alloc_security(void){print_hook_list(tun_dev_alloc_security);}
static void plist_tun_dev_free_security(void){print_hook_list(tun_dev_free_security);}
static void plist_tun_dev_create(void){print_hook_list(tun_dev_create);}
static void plist_tun_dev_attach_queue(void){print_hook_list(tun_dev_attach_queue);}
static void plist_tun_dev_attach(void){print_hook_list(tun_dev_attach);}
static void plist_tun_dev_open(void){print_hook_list(tun_dev_open);}
static void plist_sctp_assoc_request(void){print_hook_list(sctp_assoc_request);}
static void plist_sctp_bind_connect(void){print_hook_list(sctp_bind_connect);}
static void plist_sctp_sk_clone(void){print_hook_list(sctp_sk_clone);}
#endif
/* CONFIG_SECURITY_NETWORK */
#ifdef CONFIG_SECURITY_INFINIBAND
static void plist_ib_pkey_access(void){print_hook_list(ib_pkey_access);}
static void plist_ib_endport_manage_subnet(void){print_hook_list(ib_endport_manage_subnet);}
static void plist_ib_alloc_security(void){print_hook_list(ib_alloc_security);}
static void plist_ib_free_security(void){print_hook_list(ib_free_security);}
#endif
/* CONFIG_SECURITY_INFINIBAND */
#ifdef CONFIG_SECURITY_NETWORK_XFRM
static void plist_xfrm_policy_alloc_security(void){print_hook_list(xfrm_policy_alloc_security);}
static void plist_xfrm_policy_clone_security(void){print_hook_list(xfrm_policy_clone_security);}
static void plist_xfrm_policy_free_security(void){print_hook_list(xfrm_policy_free_security);}
static void plist_xfrm_policy_delete_security(void){print_hook_list(xfrm_policy_delete_security);}
static void plist_xfrm_state_alloc(void){print_hook_list(xfrm_state_alloc);}
static void plist_xfrm_state_alloc_acquire(void){print_hook_list(xfrm_state_alloc_acquire);}
static void plist_xfrm_state_free_security(void){print_hook_list(xfrm_state_free_security);}
static void plist_xfrm_state_delete_security(void){print_hook_list(xfrm_state_delete_security);}
static void plist_xfrm_policy_lookup(void){print_hook_list(xfrm_policy_lookup);}
static void plist_xfrm_state_pol_flow_match(void){print_hook_list(xfrm_state_pol_flow_match);}
static void plist_xfrm_decode_session(void){print_hook_list(xfrm_decode_session);}
#endif
/* CONFIG_SECURITY_NETWORK_XFRM */
#ifdef CONFIG_KEYS
static void plist_key_alloc(void){print_hook_list(key_alloc);}
static void plist_key_free(void){print_hook_list(key_free);}
static void plist_key_permission(void){print_hook_list(key_permission);}
static void plist_key_getsecurity(void){print_hook_list(key_getsecurity);}
#endif
/* CONFIG_KEYS */
#ifdef CONFIG_AUDIT
static void plist_audit_rule_init(void){print_hook_list(audit_rule_init);}
static void plist_audit_rule_known(void){print_hook_list(audit_rule_known);}
static void plist_audit_rule_match(void){print_hook_list(audit_rule_match);}
static void plist_audit_rule_free(void){print_hook_list(audit_rule_free);}
#endif
/* CONFIG_AUDIT */
#ifdef CONFIG_BPF_SYSCALL
static void plist_bpf(void){print_hook_list(bpf);}
static void plist_bpf_map(void){print_hook_list(bpf_map);}
static void plist_bpf_prog(void){print_hook_list(bpf_prog);}
static void plist_bpf_map_alloc_security(void){print_hook_list(bpf_map_alloc_security);}
static void plist_bpf_map_free_security(void){print_hook_list(bpf_map_free_security);}
static void plist_bpf_prog_alloc_security(void){print_hook_list(bpf_prog_alloc_security);}
static void plist_bpf_prog_free_security(void){print_hook_list(bpf_prog_free_security);}
#endif
/* CONFIG_BPF_SYSCALL */
static void plist_locked_down(void){print_hook_list(locked_down);}


#define SZ 250

static void (*plist_func[SZ])(void) = {
	&plist_binder_set_context_mgr,
        &plist_binder_transaction,
        &plist_binder_transfer_binder,
        &plist_binder_transfer_file,
        &plist_ptrace_access_check,
        &plist_ptrace_traceme,
        &plist_capget,
        &plist_capset,
        &plist_capable,
        &plist_quotactl,
        &plist_quota_on,
        &plist_syslog,
        &plist_settime,
        &plist_vm_enough_memory,
        &plist_bprm_set_creds,
        &plist_bprm_check_security,
        &plist_bprm_committing_creds,
        &plist_bprm_committed_creds,
        &plist_fs_context_dup,
        &plist_fs_context_parse_param,
        &plist_sb_alloc_security,
        &plist_sb_free_security,
        &plist_sb_free_mnt_opts,
        &plist_sb_eat_lsm_opts,
        &plist_sb_remount,
        &plist_sb_kern_mount,
        &plist_sb_show_options,
        &plist_sb_statfs,
        &plist_sb_mount,
        &plist_sb_umount,
        &plist_sb_pivotroot,
        &plist_sb_set_mnt_opts,
        &plist_sb_clone_mnt_opts,
        &plist_sb_add_mnt_opt,
        &plist_move_mount,
        &plist_dentry_init_security,
        &plist_dentry_create_files_as,
#ifdef CONFIG_SECURITY_PATH
        &plist_path_unlink,
        &plist_path_mkdir,
        &plist_path_rmdir,
        &plist_path_mknod,
        &plist_path_truncate,
        &plist_path_symlink,
        &plist_path_link,
        &plist_path_rename,
        &plist_path_chmod,
        &plist_path_chown,
        &plist_path_chroot,
#endif
       /* Needed for inode based modules as well */
        &plist_path_notify,
        &plist_inode_alloc_security,
        &plist_inode_free_security,
        &plist_inode_init_security,
        &plist_inode_create,
        &plist_inode_link,
        &plist_inode_unlink,
        &plist_inode_symlink,
        &plist_inode_mkdir,
        &plist_inode_rmdir,
        &plist_inode_mknod,
        &plist_inode_rename,
        &plist_inode_readlink,
        &plist_inode_follow_link,
        &plist_inode_permission,
        &plist_inode_setattr,
        &plist_inode_getattr,
        &plist_inode_setxattr,
        &plist_inode_post_setxattr,
        &plist_inode_getxattr,
        &plist_inode_listxattr,
        &plist_inode_removexattr,
        &plist_inode_need_killpriv,
        &plist_inode_killpriv,
        &plist_inode_getsecurity,
        &plist_inode_setsecurity,
        &plist_inode_listsecurity,
        &plist_inode_getsecid,
        &plist_inode_copy_up,
        &plist_inode_copy_up_xattr,
        &plist_kernfs_init_security,
        &plist_file_permission,
        &plist_file_alloc_security,
        &plist_file_free_security,
        &plist_file_ioctl,
        &plist_mmap_addr,
        &plist_mmap_file,
        &plist_file_mprotect,
        &plist_file_lock,
        &plist_file_fcntl,
        &plist_file_set_fowner,
        &plist_file_send_sigiotask,
        &plist_file_receive,
        &plist_file_open,
        &plist_task_alloc,
        &plist_task_free,
        &plist_cred_alloc_blank,
        &plist_cred_free,
        &plist_cred_prepare,
        &plist_cred_transfer,
        &plist_cred_getsecid,
        &plist_kernel_act_as,
        &plist_kernel_create_files_as,
        &plist_kernel_load_data,
        &plist_kernel_read_file,
        &plist_kernel_post_read_file,
        &plist_kernel_module_request,
        &plist_task_fix_setuid,
        &plist_task_setpgid,
        &plist_task_getpgid,
        &plist_task_getsid,
        &plist_task_getsecid,
        &plist_task_setnice,
        &plist_task_setioprio,
        &plist_task_getioprio,
        &plist_task_prlimit,
        &plist_task_setrlimit,
        &plist_task_setscheduler,
        &plist_task_getscheduler,
        &plist_task_movememory,
        &plist_task_kill,
        &plist_task_prctl,
        &plist_task_to_inode,
        &plist_ipc_permission,
        &plist_ipc_getsecid,
        &plist_msg_msg_alloc_security,
        &plist_msg_msg_free_security,
        &plist_msg_queue_alloc_security,
        &plist_msg_queue_free_security,
        &plist_msg_queue_associate,
        &plist_msg_queue_msgctl,
        &plist_msg_queue_msgsnd,
        &plist_msg_queue_msgrcv,
        &plist_shm_alloc_security,
        &plist_shm_free_security,
        &plist_shm_associate,
        &plist_shm_shmctl,
        &plist_shm_shmat,
        &plist_sem_alloc_security,
        &plist_sem_free_security,
        &plist_sem_associate,
        &plist_sem_semctl,
        &plist_sem_semop,
        &plist_netlink_send,
        &plist_d_instantiate,
        &plist_getprocattr,
        &plist_setprocattr,
        &plist_ismaclabel,
        &plist_secid_to_secctx,
        &plist_secctx_to_secid,
        &plist_release_secctx,
        &plist_inode_invalidate_secctx,
        &plist_inode_notifysecctx,
        &plist_inode_setsecctx,
        &plist_inode_getsecctx,
#ifdef CONFIG_SECURITY_NETWORK
        &plist_unix_stream_connect,
        &plist_unix_may_send,
        &plist_socket_create,
        &plist_socket_post_create,
        &plist_socket_socketpair,
        &plist_socket_bind,
        &plist_socket_connect,
        &plist_socket_listen,
        &plist_socket_accept,
        &plist_socket_sendmsg,
        &plist_socket_recvmsg,
        &plist_socket_getsockname,
        &plist_socket_getpeername,
        &plist_socket_getsockopt,
        &plist_socket_setsockopt,
        &plist_socket_shutdown,
        &plist_socket_sock_rcv_skb,
        &plist_socket_getpeersec_stream,
        &plist_socket_getpeersec_dgram,
        &plist_sk_alloc_security,
        &plist_sk_free_security,
        &plist_sk_clone_security,
        &plist_sk_getsecid,
        &plist_sock_graft,
        &plist_inet_conn_request,
        &plist_inet_csk_clone,
        &plist_inet_conn_established,
        &plist_secmark_relabel_packet,
        &plist_secmark_refcount_inc,
        &plist_secmark_refcount_dec,
        &plist_req_classify_flow,
        &plist_tun_dev_alloc_security,
        &plist_tun_dev_free_security,
        &plist_tun_dev_create,
        &plist_tun_dev_attach_queue,
        &plist_tun_dev_attach,
        &plist_tun_dev_open,
        &plist_sctp_assoc_request,
        &plist_sctp_bind_connect,
        &plist_sctp_sk_clone,
#endif  /* CONFIG_SECURITY_NETWORK */
#ifdef CONFIG_SECURITY_INFINIBAND
        &plist_ib_pkey_access,
        &plist_ib_endport_manage_subnet,
        &plist_ib_alloc_security,
        &plist_ib_free_security,
#endif  /* CONFIG_SECURITY_INFINIBAND */
#ifdef CONFIG_SECURITY_NETWORK_XFRM
        &plist_xfrm_policy_alloc_security,
        &plist_xfrm_policy_clone_security,
        &plist_xfrm_policy_free_security,
        &plist_xfrm_policy_delete_security,
        &plist_xfrm_state_alloc,
        &plist_xfrm_state_alloc_acquire,
        &plist_xfrm_state_free_security,
        &plist_xfrm_state_delete_security,
        &plist_xfrm_policy_lookup,
        &plist_xfrm_state_pol_flow_match,
        &plist_xfrm_decode_session,
#endif  /* CONFIG_SECURITY_NETWORK_XFRM */
#ifdef CONFIG_KEYS
        &plist_key_alloc,
        &plist_key_free,
        &plist_key_permission,
        &plist_key_getsecurity,
#endif  /* CONFIG_KEYS */
#ifdef CONFIG_AUDIT
        &plist_audit_rule_init,
        &plist_audit_rule_known,
        &plist_audit_rule_match,
        &plist_audit_rule_free,
#endif /* CONFIG_AUDIT */
#ifdef CONFIG_BPF_SYSCALL
        &plist_bpf,
        &plist_bpf_map,
        &plist_bpf_prog,
        &plist_bpf_map_alloc_security,
        &plist_bpf_map_free_security,
        &plist_bpf_prog_alloc_security,
        &plist_bpf_prog_free_security,
#endif /* CONFIG_BPF_SYSCALL */
        &plist_locked_down,
};

int print_hooklist(long index){
	print_plist("=================================");
	print_plist("[print_hooklist] syscall called\n");
	if(index > SZ){
		print_plist("[error] index size over\n");
		return -1;
	}
	plist_func[index]();
	print_plist("[print_hooklist] successfully finished\n");
	print_plist("===================================");
	return 1;
}
