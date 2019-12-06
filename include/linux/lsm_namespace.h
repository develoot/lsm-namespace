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

struct lsm_namespace {
	struct kref kref;
	struct ns_common ns;
	struct user_namespace *user_ns;
	struct ucounts *ucounts;
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
				  struct user_namespace *user_ns,
				  struct lsm_namespace *old_ns);
extern struct lsm_namespace init_lsm_ns;

#endif /* _LINUX_LSM_NS_H */
