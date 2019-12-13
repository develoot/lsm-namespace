#include <linux/capability.h>
#include <linux/err.h>
#include <linux/lsm_namespace.h>
#include <linux/parser.h>
#include <linux/proc_ns.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/user_namespace.h>

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

static struct kmem_cache *lsm_ns_cachep;

extern int parse_lsmns_procfs(void);

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
	new_ns->types = parse_lsmns_procfs();

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
        struct lsm_namespace *ns
		= container_of(kref, struct lsm_namespace, kref);

        dec_lsm_namespaces(ns->ucounts);
        put_user_ns(ns->user_ns);
        ns_free_inum(&ns->ns);
        kmem_cache_free(lsm_ns_cachep, ns);

        //need to free hooking functions
}

struct lsm_namespace *copy_lsm_ns(unsigned long flags,
		struct user_namespace *user_ns, struct lsm_namespace *old_ns)
{
	if (!(flags & CLONE_NEWLSM))
		return get_lsm_ns(old_ns);

	return alloc_lsm_ns(user_ns);
}

static __init int lsm_namespaces_init(void)
{
	lsm_ns_cachep = KMEM_CACHE(lsm_namespace, SLAB_PANIC);

	return 0;
}
__initcall(lsm_namespaces_init);

extern struct security_hook_heads security_hook_heads;

void __init lsmns_init(const struct lsm_info **ordered_lsms)
{
	int types = 0;
	struct lsm_info **lsm;
	struct task_struct *tsk = current;

	for (lsm = ordered_lsms; lsm; lsm++) {
		if (!strcmp((*lsm)->name, "selinux"))
			types |= LSMNS_SELINUX;
		if (!strcmp((*lsm)->name, "apparmor"))
			types |= LSMNS_APPARMOR;
		if (!strcmp((*lsm)->name, "tomoyo"))
			types |= LSMNS_TOMOYO;
	}

	task_lock(tsk);
	tsk->nsproxy->lsm_ns->types = types;
	task_unlock(tsk);
}
