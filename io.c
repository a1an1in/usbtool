#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <sys/timerfd.h>
#include <time.h>

#include "config.h"
#include "libusb.h"

int usb_io_init(struct libusb_context *ctx)
{
	int r;

	usb_mutex_init(&ctx->flying_transfers_lock, NULL);
	usb_mutex_init(&ctx->pollfds_lock, NULL);
	usb_mutex_init(&ctx->pollfd_modify_lock, NULL);
	usb_mutex_init_recursive(&ctx->events_lock, NULL);
	usb_mutex_init(&ctx->event_waiters_lock, NULL);
	usb_cond_init(&ctx->event_waiters_cond, NULL);
	list_init(&ctx->flying_transfers);
	list_init(&ctx->pollfds);

	r = usb_pipe(ctx->ctrl_pipe);
	if (r < 0) {
		r = LIBUSB_ERROR_OTHER;
		goto err;
	}

	r = usb_add_pollfd(ctx, ctx->ctrl_pipe[0], POLLIN);
	if (r < 0)
		goto err_close_pipe;

	return 0;

err_close_pipe:
	usb_close(ctx->ctrl_pipe[0]);
	usb_close(ctx->ctrl_pipe[1]);
err:
	usb_mutex_destroy(&ctx->flying_transfers_lock);
	usb_mutex_destroy(&ctx->pollfds_lock);
	usb_mutex_destroy(&ctx->pollfd_modify_lock);
	usb_mutex_destroy(&ctx->events_lock);
	usb_mutex_destroy(&ctx->event_waiters_lock);
	usb_cond_destroy(&ctx->event_waiters_cond);
	return r;
}

void usb_io_exit(struct libusb_context *ctx)
{
	usb_remove_pollfd(ctx, ctx->ctrl_pipe[0]);
	usb_close(ctx->ctrl_pipe[0]);
	usb_close(ctx->ctrl_pipe[1]);
	usb_mutex_destroy(&ctx->flying_transfers_lock);
	usb_mutex_destroy(&ctx->pollfds_lock);
	usb_mutex_destroy(&ctx->pollfd_modify_lock);
	usb_mutex_destroy(&ctx->events_lock);
	usb_mutex_destroy(&ctx->event_waiters_lock);
	usb_cond_destroy(&ctx->event_waiters_cond);
}

/**
 * calculate_timeout：计算出tranfer传输的绝对超时时间(想对于被提交的时刻算起)
 */
static int calculate_timeout(struct usb_transfer *transfer)
{
	int r;
	struct timespec current_time;
	unsigned int timeout =
		USBI_TRANSFER_TO_LIBUSB_TRANSFER(transfer)->timeout;

	if (!timeout)
		return 0;

	r = usb_backend->clock_gettime(USBI_CLOCK_MONOTONIC, &current_time);
	if (r < 0) {
		usb_err(ITRANSFER_CTX(transfer),
			"failed to read monotonic clock, errno=%d", errno);
		return r;
	}

	current_time.tv_sec += timeout / 1000;
	current_time.tv_nsec += (timeout % 1000) * 1000000;

	if (current_time.tv_nsec > 1000000000) {
		current_time.tv_nsec -= 1000000000;
		current_time.tv_sec++;
	}

	TIMESPEC_TO_TIMEVAL(&transfer->timeout, &current_time);
	return 0;
}

static int add_to_flying_list(struct usb_transfer *transfer)
{
	struct usb_transfer *cur;
	struct timeval *timeout = &transfer->timeout;
	struct libusb_context *ctx = ITRANSFER_CTX(transfer);
	int r = 0;
	int first = 1;

	usb_mutex_lock(&ctx->flying_transfers_lock);

	/* if we have no other flying transfers, start the list with this one */
	if (list_empty(&ctx->flying_transfers)) {
		list_add(&transfer->list, &ctx->flying_transfers);
		if (timerisset(timeout))
			r = 1;
		goto out;
	}

	/* if we have infinite timeout, append to end of list */
	if (!timerisset(timeout)) {
		list_add_tail(&transfer->list, &ctx->flying_transfers);
		goto out;
	}

	/* otherwise, find appropriate place in list */
	list_for_each_entry(cur, &ctx->flying_transfers, list, struct usb_transfer) {
		/* find first timeout that occurs after the transfer in question */
		struct timeval *cur_tv = &cur->timeout;

		if (!timerisset(cur_tv) || (cur_tv->tv_sec > timeout->tv_sec) ||
				(cur_tv->tv_sec == timeout->tv_sec &&
					cur_tv->tv_usec > timeout->tv_usec)) {
			list_add_tail(&transfer->list, &cur->list);
			r = first;
			goto out;
		}
		first = 0;
	}

	/* otherwise we need to be inserted at the end */
	list_add_tail(&transfer->list, &ctx->flying_transfers);
out:
	usb_mutex_unlock(&ctx->flying_transfers_lock);
	return r;
}

struct libusb_transfer *libusb_alloc_transfer(int iso_packets)
	
{
	size_t os_alloc_size = usb_backend->transfer_priv_size
		+ (usb_backend->add_iso_packet_size * iso_packets);
	size_t alloc_size = sizeof(struct usb_transfer)
		+ sizeof(struct libusb_transfer)
		+ (sizeof(struct libusb_iso_packet_descriptor) * iso_packets)
		+ os_alloc_size;
	struct usb_transfer *itransfer = malloc(alloc_size);
	if (!itransfer)
		return NULL;

	memset(itransfer, 0, alloc_size);
	itransfer->num_iso_packets = iso_packets;
	usb_mutex_init(&itransfer->lock, NULL);
	return USBI_TRANSFER_TO_LIBUSB_TRANSFER(itransfer);
}


void  libusb_free_transfer(struct libusb_transfer *transfer)
{
	struct usb_transfer *itransfer;
	if (!transfer)
		return;

	if (transfer->flags & LIBUSB_TRANSFER_FREE_BUFFER && transfer->buffer)
		free(transfer->buffer);

	itransfer = LIBUSB_TRANSFER_TO_USBI_TRANSFER(transfer);
	usb_mutex_destroy(&itransfer->lock);
	free(itransfer);
}


int  libusb_submit_transfer(struct libusb_transfer *transfer)
{
	struct libusb_context *ctx = TRANSFER_CTX(transfer);
	struct usb_transfer *itransfer =
		LIBUSB_TRANSFER_TO_USBI_TRANSFER(transfer);
	int r;
	int first;

	usb_mutex_lock(&itransfer->lock);
	itransfer->transferred = 0;
	itransfer->flags = 0;
	r = calculate_timeout(itransfer);
	if (r < 0) {
		r = LIBUSB_ERROR_OTHER;
		goto out;
	}

	first = add_to_flying_list(itransfer);
	r = usb_backend->submit_transfer(itransfer);
	if (r) {
		usb_mutex_lock(&ctx->flying_transfers_lock);
		list_del(&itransfer->list);
		usb_mutex_unlock(&ctx->flying_transfers_lock);
	}
out:
	usb_mutex_unlock(&itransfer->lock);
	return r;
}


int  libusb_cancel_transfer(struct libusb_transfer *transfer)
{
	struct usb_transfer *itransfer =
		LIBUSB_TRANSFER_TO_USBI_TRANSFER(transfer);
	int r;

	usb_dbg("");
	usb_mutex_lock(&itransfer->lock);
	r = usb_backend->cancel_transfer(itransfer);
	if (r < 0) {
		if (r != LIBUSB_ERROR_NOT_FOUND)
			usb_err(TRANSFER_CTX(transfer),
				"cancel transfer failed error %d", r);
		else
			usb_dbg("cancel transfer failed error %d", r);

		if (r == LIBUSB_ERROR_NO_DEVICE)
			itransfer->flags |= USBI_TRANSFER_DEVICE_DISAPPEARED;
	}

	itransfer->flags |= USBI_TRANSFER_CANCELLING;

	usb_mutex_unlock(&itransfer->lock);
	return r;
}


int usb_handle_transfer_completion(struct usb_transfer *itransfer,
	enum libusb_transfer_status status)
{
	struct libusb_transfer *transfer =
		USBI_TRANSFER_TO_LIBUSB_TRANSFER(itransfer);
	struct libusb_context *ctx = TRANSFER_CTX(transfer);
	uint8_t flags;
	int r = 0;

	usb_mutex_lock(&ctx->flying_transfers_lock);
	list_del(&itransfer->list);
	usb_mutex_unlock(&ctx->flying_transfers_lock);

	if (status == LIBUSB_TRANSFER_COMPLETED
			&& transfer->flags & LIBUSB_TRANSFER_SHORT_NOT_OK) {
		int rqlen = transfer->length;
		if (transfer->type == LIBUSB_TRANSFER_TYPE_CONTROL)
			rqlen -= LIBUSB_CONTROL_SETUP_SIZE;
		if (rqlen != itransfer->transferred) {
			usb_dbg("interpreting short transfer as error");
			status = LIBUSB_TRANSFER_ERROR;
		}
	}

	flags = transfer->flags;
	transfer->status = status;
	transfer->actual_length = itransfer->transferred;
	usb_dbg("transfer %p has callback %p", transfer, transfer->callback);
	if (transfer->callback)
		transfer->callback(transfer);
	/* transfer might have been freed by the above call, do not use from
	 * this point. */
	if (flags & LIBUSB_TRANSFER_FREE_TRANSFER)
		libusb_free_transfer(transfer);
	usb_mutex_lock(&ctx->event_waiters_lock);
	usb_cond_broadcast(&ctx->event_waiters_cond);
	usb_mutex_unlock(&ctx->event_waiters_lock);
	return 0;
}


int usb_handle_transfer_cancellation(struct usb_transfer *transfer)
{
	/* if the URB was cancelled due to timeout, report timeout to the user */
	if (transfer->flags & USBI_TRANSFER_TIMED_OUT) {
		usb_dbg("detected timeout cancellation");
		return usb_handle_transfer_completion(transfer, LIBUSB_TRANSFER_TIMED_OUT);
	}

	/* otherwise its a normal async cancel */
	return usb_handle_transfer_completion(transfer, LIBUSB_TRANSFER_CANCELLED);
}


int libusb_try_lock_events(libusb_context *ctx)
{
	int r;
	USBI_GET_CONTEXT(ctx);

	/* is someone else waiting to modify poll fds? if so, don't let this thread
	 * start event handling */
	usb_mutex_lock(&ctx->pollfd_modify_lock);
	r = ctx->pollfd_modify;
	usb_mutex_unlock(&ctx->pollfd_modify_lock);
	if (r) {
		usb_dbg("someone else is modifying poll fds");
		return 1;
	}

	r = usb_mutex_trylock(&ctx->events_lock);
	if (r)
		return 1;

	ctx->event_handler_active = 1;
	return 0;
}

void libusb_lock_events(libusb_context *ctx)
{
	USBI_GET_CONTEXT(ctx);
	usb_mutex_lock(&ctx->events_lock);
	ctx->event_handler_active = 1;
}

void  libusb_unlock_events(libusb_context *ctx)
{
	USBI_GET_CONTEXT(ctx);
	ctx->event_handler_active = 0;
	usb_mutex_unlock(&ctx->events_lock);

	usb_mutex_lock(&ctx->event_waiters_lock);
	usb_cond_broadcast(&ctx->event_waiters_cond);
	usb_mutex_unlock(&ctx->event_waiters_lock);
}

int  libusb_event_handling_ok(libusb_context *ctx)
{
	int r;
	USBI_GET_CONTEXT(ctx);

	usb_mutex_lock(&ctx->pollfd_modify_lock);
	r = ctx->pollfd_modify;
	usb_mutex_unlock(&ctx->pollfd_modify_lock);
	if (r) {
		usb_dbg("someone else is modifying poll fds");
		return 0;
	}

	return 1;
}

int  libusb_event_handler_active(libusb_context *ctx)
{
	int r;
	USBI_GET_CONTEXT(ctx);

	usb_mutex_lock(&ctx->pollfd_modify_lock);
	r = ctx->pollfd_modify;
	usb_mutex_unlock(&ctx->pollfd_modify_lock);
	if (r) {
		usb_dbg("someone else is modifying poll fds");
		return 1;
	}

	return ctx->event_handler_active;
}


void  libusb_lock_event_waiters(libusb_context *ctx)
{
	USBI_GET_CONTEXT(ctx);
	usb_mutex_lock(&ctx->event_waiters_lock);
}

void  libusb_unlock_event_waiters(libusb_context *ctx)
{
	USBI_GET_CONTEXT(ctx);
	usb_mutex_unlock(&ctx->event_waiters_lock);
}

int  libusb_wait_for_event(libusb_context *ctx, struct timeval *tv)
{
	struct timespec timeout;
	int r;

	USBI_GET_CONTEXT(ctx);
	if (tv == NULL) {
		usb_cond_wait(&ctx->event_waiters_cond, &ctx->event_waiters_lock);
		return 0;
	}

	r = usb_backend->clock_gettime(USBI_CLOCK_REALTIME, &timeout);
	if (r < 0) {
		usb_err(ctx, "failed to read realtime clock, error %d", errno);
		return LIBUSB_ERROR_OTHER;
	}

	timeout.tv_sec += tv->tv_sec;
	timeout.tv_nsec += tv->tv_usec * 1000;
	if (timeout.tv_nsec > 1000000000) {
		timeout.tv_nsec -= 1000000000;
		timeout.tv_sec++;
	}

	r = usb_cond_timedwait(&ctx->event_waiters_cond,
		&ctx->event_waiters_lock, &timeout);
	return (r == ETIMEDOUT);
}

static void handle_timeout(struct usb_transfer *itransfer)
{
	struct libusb_transfer *transfer =
		USBI_TRANSFER_TO_LIBUSB_TRANSFER(itransfer);
	int r;

	itransfer->flags |= USBI_TRANSFER_TIMED_OUT;
	r = libusb_cancel_transfer(transfer);
	if (r < 0)
		usb_warn(TRANSFER_CTX(transfer),
			"async cancel failed %d errno=%d", r, errno);
}

static int handle_timeouts_locked(struct libusb_context *ctx)
{
	int r;
	struct timespec systime_ts;
	struct timeval systime;
	struct usb_transfer *transfer;

	if (list_empty(&ctx->flying_transfers))
		return 0;

	/* get current time */
	r = usb_backend->clock_gettime(USBI_CLOCK_MONOTONIC, &systime_ts);
	if (r < 0)
		return r;

	TIMESPEC_TO_TIMEVAL(&systime, &systime_ts);

	list_for_each_entry(transfer, &ctx->flying_transfers, list, struct usb_transfer) {
		struct timeval *cur_tv = &transfer->timeout;

		/* if we've reached transfers of infinite timeout, we're all done */
		if (!timerisset(cur_tv))
			return 0;

		/* ignore timeouts we've already handled */
		if (transfer->flags & (USBI_TRANSFER_TIMED_OUT | USBI_TRANSFER_OS_HANDLES_TIMEOUT))
			continue;

		/* if transfer has non-expired timeout, nothing more to do */
		if ((cur_tv->tv_sec > systime.tv_sec) ||
				(cur_tv->tv_sec == systime.tv_sec &&
					cur_tv->tv_usec > systime.tv_usec))
			return 0;

		/* otherwise, we've got an expired timeout to handle */
		handle_timeout(transfer);
	}
	return 0;
}

static int handle_timeouts(struct libusb_context *ctx)
{
	int r;
	USBI_GET_CONTEXT(ctx);
	usb_mutex_lock(&ctx->flying_transfers_lock);
	r = handle_timeouts_locked(ctx);
	usb_mutex_unlock(&ctx->flying_transfers_lock);
	return r;
}

static int handle_events(struct libusb_context *ctx, struct timeval *tv)
{
	int r;
	struct usb_pollfd *ipollfd;
	struct pollfd *fds;
	int i = 0;
	int timeout_ms;
	int nfds = 0;

	usb_mutex_lock(&ctx->pollfds_lock);
	list_for_each_entry(ipollfd, &ctx->pollfds, list, struct usb_pollfd)
		nfds++;

	/* TODO: malloc when number of fd's changes, not on every poll */
	fds = malloc(sizeof(*fds) * nfds);
	if (!fds) {
		usb_mutex_unlock(&ctx->pollfds_lock);
		return LIBUSB_ERROR_NO_MEM;
	}

	list_for_each_entry(ipollfd, &ctx->pollfds, list, struct usb_pollfd) {
		struct libusb_pollfd *pollfd = &ipollfd->pollfd;
		int fd = pollfd->fd;
		fds[i].fd = fd;
		fds[i].events = pollfd->events;
		fds[i].revents = 0;
		i++;
	}
	usb_mutex_unlock(&ctx->pollfds_lock);

	timeout_ms = (tv->tv_sec * 1000) + (tv->tv_usec / 1000);

	/* round up to next millisecond */
	if (tv->tv_usec % 1000)
		timeout_ms++;

	usb_dbg("poll() %d fds with timeout in %dms", nfds, timeout_ms);
	r = usb_poll(fds, nfds, timeout_ms);
	if (r == 0) {
		free(fds);
		usb_dbg("poll() timeout");
		return handle_timeouts(ctx);
	} else if (r == -1 && errno == EINTR) {
		free(fds);
		return LIBUSB_ERROR_INTERRUPTED;
	} else if (r < 0) {
		free(fds);
		usb_err(ctx, "poll failed %d err=%d\n", r, errno);
		return LIBUSB_ERROR_IO;
	}

	/* fd[0] is always the ctrl pipe */
	if (fds[0].revents) {
		/* another thread wanted to interrupt event handling, and it succeeded!
		 * handle any other events that cropped up at the same time, and
		 * simply return */
		usb_dbg("caught a fish on the control pipe");

		if (r == 1) {
			r = 0;
			goto handled;
		} else {
			/* prevent OS backend from trying to handle events on ctrl pipe */
			fds[0].revents = 0;
			r--;
		}
	}

	r = usb_backend->handle_events(ctx, fds, nfds, r);
	if (r)
		usb_err(ctx, "backend handle_events failed with error %d", r);

handled:
	free(fds);
	return r;
}

static int get_next_timeout(libusb_context *ctx, struct timeval *tv,
	struct timeval *out)
{
	struct timeval timeout;
	int r = libusb_get_next_timeout(ctx, &timeout);
	if (r) {
		/* timeout already expired? */
		if (!timerisset(&timeout))
			return 1;

		/* choose the smallest of next URB timeout or user specified timeout */
		if (timercmp(&timeout, tv, <))
			*out = timeout;
		else
			*out = *tv;
	} else {
		*out = *tv;
	}
	return 0;
}


int  libusb_handle_events_timeout_completed(libusb_context *ctx,
	struct timeval *tv, int *completed)
{
	int r;
	struct timeval poll_timeout;

	USBI_GET_CONTEXT(ctx);
	r = get_next_timeout(ctx, tv, &poll_timeout);
	if (r) {
		/* timeout already expired */
		return handle_timeouts(ctx);
	}

retry:
	if (libusb_try_lock_events(ctx) == 0) {
		if (completed == NULL || !*completed) {
			/* we obtained the event lock: do our own event handling */
			usb_dbg("doing our own event handling");
			r = handle_events(ctx, &poll_timeout);
		}
		libusb_unlock_events(ctx);
		return r;
	}

	/* another thread is doing event handling. wait for thread events that
	 * notify event completion. */
	libusb_lock_event_waiters(ctx);

	if (completed && *completed)
		goto already_done;

	if (!libusb_event_handler_active(ctx)) {
		/* we hit a race: whoever was event handling earlier finished in the
		 * time it took us to reach this point. try the cycle again. */
		libusb_unlock_event_waiters(ctx);
		usb_dbg("event handler was active but went away, retrying");
		goto retry;
	}

	usb_dbg("another thread is doing event handling");
	r = libusb_wait_for_event(ctx, &poll_timeout);

already_done:
	libusb_unlock_event_waiters(ctx);

	if (r < 0)
		return r;
	else if (r == 1)
		return handle_timeouts(ctx);
	else
		return 0;
}


int  libusb_handle_events_timeout(libusb_context *ctx,
	struct timeval *tv)
{
	return libusb_handle_events_timeout_completed(ctx, tv, NULL);
}


int  libusb_handle_events(libusb_context *ctx)
{
	struct timeval tv;
	tv.tv_sec = 60;
	tv.tv_usec = 0;
	return libusb_handle_events_timeout_completed(ctx, &tv, NULL);
}


int  libusb_handle_events_completed(libusb_context *ctx,
	int *completed)
{
	struct timeval tv;
	tv.tv_sec = 60;
	tv.tv_usec = 0;
	return libusb_handle_events_timeout_completed(ctx, &tv, completed);
}


int  libusb_handle_events_locked(libusb_context *ctx,
	struct timeval *tv)
{
	int r;
	struct timeval poll_timeout;

	USBI_GET_CONTEXT(ctx);
	r = get_next_timeout(ctx, tv, &poll_timeout);
	if (r) {
		/* timeout already expired */
		return handle_timeouts(ctx);
	}

	return handle_events(ctx, &poll_timeout);
}

int  libusb_get_next_timeout(libusb_context *ctx,
	struct timeval *tv)
{
	struct usb_transfer *transfer;
	struct timespec cur_ts;
	struct timeval cur_tv;
	struct timeval *next_timeout;
	int r;
	int found = 0;

	USBI_GET_CONTEXT(ctx);
	usb_mutex_lock(&ctx->flying_transfers_lock);
	if (list_empty(&ctx->flying_transfers)) {
		usb_mutex_unlock(&ctx->flying_transfers_lock);
		usb_dbg("no URBs, no timeout!");
		return 0;
	}

	/* find next transfer which hasn't already been processed as timed out */
	list_for_each_entry(transfer, &ctx->flying_transfers, list, struct usb_transfer) {
		if (transfer->flags & (USBI_TRANSFER_TIMED_OUT | USBI_TRANSFER_OS_HANDLES_TIMEOUT))
			continue;

		/* no timeout for this transfer? */
		if (!timerisset(&transfer->timeout))
			continue;

		found = 1;
		break;
	}
	usb_mutex_unlock(&ctx->flying_transfers_lock);

	if (!found) {
		usb_dbg("no URB with timeout or all handled by OS; no timeout!");
		return 0;
	}

	next_timeout = &transfer->timeout;

	r = usb_backend->clock_gettime(USBI_CLOCK_MONOTONIC, &cur_ts);
	if (r < 0) {
		usb_err(ctx, "failed to read monotonic clock, errno=%d", errno);
		return LIBUSB_ERROR_OTHER;
	}
	TIMESPEC_TO_TIMEVAL(&cur_tv, &cur_ts);

	if (!timercmp(&cur_tv, next_timeout, <)) {
		usb_dbg("first timeout already expired");
		timerclear(tv);
	} else {
		timersub(next_timeout, &cur_tv, tv);
		usb_dbg("next timeout in %d.%06ds", tv->tv_sec, tv->tv_usec);
	}

	return 1;
}

void  libusb_set_pollfd_notifiers(libusb_context *ctx,
	libusb_pollfd_added_cb added_cb, libusb_pollfd_removed_cb removed_cb,
	void *user_data)
{
	USBI_GET_CONTEXT(ctx);
	ctx->fd_added_cb = added_cb;
	ctx->fd_removed_cb = removed_cb;
	ctx->fd_cb_user_data = user_data;
}

int usb_add_pollfd(struct libusb_context *ctx, int fd, short events)
{
	struct usb_pollfd *ipollfd = malloc(sizeof(*ipollfd));
	if (!ipollfd)
		return LIBUSB_ERROR_NO_MEM;

	usb_dbg("add fd %d events %d", fd, events);
	ipollfd->pollfd.fd = fd;
	ipollfd->pollfd.events = events;
	usb_mutex_lock(&ctx->pollfds_lock);
	list_add_tail(&ipollfd->list, &ctx->pollfds);
	usb_mutex_unlock(&ctx->pollfds_lock);

	if (ctx->fd_added_cb)
		ctx->fd_added_cb(fd, events, ctx->fd_cb_user_data);
	return 0;
}

void usb_remove_pollfd(struct libusb_context *ctx, int fd)
{
	struct usb_pollfd *ipollfd;
	int found = 0;

	usb_dbg("remove fd %d", fd);
	usb_mutex_lock(&ctx->pollfds_lock);
	list_for_each_entry(ipollfd, &ctx->pollfds, list, struct usb_pollfd)
		if (ipollfd->pollfd.fd == fd) {
			found = 1;
			break;
		}

	if (!found) {
		usb_dbg("couldn't find fd %d to remove", fd);
		usb_mutex_unlock(&ctx->pollfds_lock);
		return;
	}

	list_del(&ipollfd->list);
	usb_mutex_unlock(&ctx->pollfds_lock);
	free(ipollfd);
	if (ctx->fd_removed_cb)
		ctx->fd_removed_cb(fd, ctx->fd_cb_user_data);
}

const struct libusb_pollfd **libusb_get_pollfds(libusb_context *ctx)
{
	struct libusb_pollfd **ret = NULL;
	struct usb_pollfd *ipollfd;
	size_t i = 0;
	size_t cnt = 0;
	USBI_GET_CONTEXT(ctx);

	usb_mutex_lock(&ctx->pollfds_lock);
	list_for_each_entry(ipollfd, &ctx->pollfds, list, struct usb_pollfd)
		cnt++;

	ret = calloc(cnt + 1, sizeof(struct libusb_pollfd *));
	if (!ret)
		goto out;

	list_for_each_entry(ipollfd, &ctx->pollfds, list, struct usb_pollfd)
		ret[i++] = (struct libusb_pollfd *) ipollfd;
	ret[cnt] = NULL;

out:
	usb_mutex_unlock(&ctx->pollfds_lock);
	return (const struct libusb_pollfd **) ret;
}

void usb_handle_disconnect(struct libusb_device_handle *handle)
{
	struct usb_transfer *cur;
	struct usb_transfer *to_cancel;

	usb_dbg("device %d.%d",
		handle->dev->bus_number, handle->dev->device_address);

	while (1) {
		usb_mutex_lock(&HANDLE_CTX(handle)->flying_transfers_lock);
		to_cancel = NULL;
		list_for_each_entry(cur, &HANDLE_CTX(handle)->flying_transfers, list, struct usb_transfer)
			if (USBI_TRANSFER_TO_LIBUSB_TRANSFER(cur)->dev_handle == handle) {
				to_cancel = cur;
				break;
			}
		usb_mutex_unlock(&HANDLE_CTX(handle)->flying_transfers_lock);

		if (!to_cancel)
			break;

		usb_backend->clear_transfer_priv(to_cancel);
		usb_handle_transfer_completion(to_cancel, LIBUSB_TRANSFER_NO_DEVICE);
	}

}
