#ifndef AGENTSUBAGENT_H
#define AGENTSUBAGENT_H

#include <pthread.h>
#include <sys/types.h>
#ifdef __linux__
#include "queue.h"
#else
#include <sys/queue.h>
#endif

#define MAX_SUBAGENT_OID_LENGTH 3

#ifdef __linux__
#define LOCK_TYPE pthread_mutex_t
#define LOCK_INIT(lock) pthread_mutex_init(lock, NULL)
#define LOCK_WRITE(lock) pthread_mutex_lock(lock)
#define LOCK_READ(lock) pthread_mutex_lock(lock)
#define UNLOCK(lock) pthread_mutex_unlock(lock)
#define LOCK_DESTROY(lock) pthread_mutex_destroy(lock)
#else
#define LOCK_TYPE pthread_rwlock_t
#define LOCK_INIT(lock) pthread_rwlock_init(lock, NULL)
#define LOCK_WRITE(lock) pthread_rwlock_wrlock(lock)
#define LOCK_READ(lock) pthread_rwlock_rdlock(lock)
#define UNLOCK(lock) pthread_rwlock_unlock(lock)
#define LOCK_DESTROY(lock) pthread_rwlock_destroy(lock)
#endif

LOCK_TYPE head_lock;

LIST_HEAD(list_head, snmpdata) head;
struct snmpdata {
    oid		octet[MAX_SUBAGENT_OID_LENGTH];
    size_t	octet_len;
    u_char	type;
    void	*value;
    size_t	value_size;

    LIST_ENTRY(snmpdata)	next;
};

/*
 * function declarations 
 */
void            init_agentsubagent(oid *base_oid, size_t oid_length);
int		compare_oids(oid *oid1, size_t oid1_len, oid *oid2, size_t oid2_len);

#endif     /* AGENTSUBAGENT_H */
