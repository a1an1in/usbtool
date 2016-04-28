#ifndef LIBUSB_THREADS_POSIX_H
#define LIBUSB_THREADS_POSIX_H

#include <pthread.h>

#define usbi_mutex_static_t		pthread_mutex_t
#define USBI_MUTEX_INITIALIZER		PTHREAD_MUTEX_INITIALIZER
#define usbi_mutex_static_lock		pthread_mutex_lock
#define usbi_mutex_static_unlock	pthread_mutex_unlock

#define usbi_mutex_t			pthread_mutex_t
#define usbi_mutex_init			pthread_mutex_init
#define usbi_mutex_lock			pthread_mutex_lock
#define usbi_mutex_unlock		pthread_mutex_unlock
#define usbi_mutex_trylock		pthread_mutex_trylock
#define usbi_mutex_destroy		pthread_mutex_destroy

#define usbi_cond_t			pthread_cond_t
#define usbi_cond_init			pthread_cond_init
#define usbi_cond_wait			pthread_cond_wait
#define usbi_cond_timedwait		pthread_cond_timedwait
#define usbi_cond_broadcast		pthread_cond_broadcast
#define usbi_cond_destroy		pthread_cond_destroy
#define usbi_cond_signal		pthread_cond_signal

extern int usbi_mutex_init_recursive(pthread_mutex_t *mutex, pthread_mutexattr_t *attr);

#endif /* LIBUSB_THREADS_POSIX_H */
