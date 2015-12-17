/*
 * Copyright (c) 2014-2016 Intel Corporation, Inc.  All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/time.h>

#include "udpx.h"


//static uint64_t gettime_ms(void)
//{
//	struct timeval now;
//
//	gettimeofday(&now, NULL);
//	return ((uint64_t) now.tv_sec * 1000) +
//		((uint64_t) now.tv_usec / 1000);
//}

static int udpx_wait_run(struct fid_wait *wait_fid, int timeout)
{
//	struct util_wait *wait;
//	uint64_t start_ms, end_ms;
//	struct fid_list_entry *entry;
//	struct dlist_entry *cur;
//	int ret;
//
//	wait = container_of(wait_fid, struct util_wait, wait_fid);
//	if (timeout > 0)
//		start_ms = gettime_ms();
//
	/* TODO: lock */
//	for (cur = wait->fid_list.next; cur != &wait->fid_list; cur = cur->next) {
//		entry = container_of(cur, struct fid_list_entry, entry);
//
		/* TODO: progress routines -- see util_poll_run? */
//	}
//
//	if (timeout > 0) {
//		end_ms = gettime_ms();
//		timeout = MAX(timeout - (int) (end_ms - start_ms), 0);
//	}
//
//	switch (wait->wait_obj) {
//	case FI_WAIT_FD:
//		ret = fd_signal_poll(&wait->obj.signal, timeout);
//		if (!ret)
//			fd_signal_reset(&wait->obj.signal);
//		break;
//	case FI_WAIT_MUTEX_COND:
//		ret = fi_wait_cond(&wait->obj.mutex_cond.cond,
//				   &wait->obj.mutex_cond.mutex, timeout);
//		break;
//	default:
//		assert(0);
//		ret = -FI_EINVAL;
//	}
	return -FI_ENOSYS;
}

static int udpx_wait_control(struct fid *fid, int command, void *arg)
{
	struct udpx_wait *wait;
	int ret;

	wait = container_of(fid, struct udpx_wait, util_wait.wait_fid.fid);
	switch (command) {
	case FI_GETWAIT:
		*(int *) arg = wait->epoll_fd;
		ret = 0;
		break;
	default:
		FI_INFO(&udpx_prov, FI_LOG_FABRIC, "unsupported command\n");
		ret = -FI_ENOSYS;
		break;
	}
	return ret;
}

static int udpx_wait_close(struct fid *fid)
{
	struct udpx_wait *wait;
	int ret;

	wait = container_of(fid, struct udpx_wait, util_wait.wait_fid.fid);
	ret = fi_wait_cleanup(&wait->util_wait);
	if (ret)
		return ret;

	close(wait->epoll_fd);
	free(wait);
	return 0;
}

static struct fi_ops_wait udpx_wait_ops = {
	.size = sizeof(struct fi_ops_wait),
	.wait = udpx_wait_run,
};

static struct fi_ops udpx_wait_fi_ops = {
	.size = sizeof(struct fi_ops),
	.close = udpx_wait_close,
	.bind = fi_no_bind,
	.control = udpx_wait_control,
	.ops_open = fi_no_ops_open,
};

static int udpx_verify_wait_attr(const struct fi_wait_attr *attr)
{
	int ret;

	ret = fi_check_wait_attr(&udpx_prov, attr);
	if (ret)
		return ret;

	switch (attr->wait_obj) {
	case FI_WAIT_UNSPEC:
	case FI_WAIT_FD:
		break;
	default:
		FI_WARN(&udpx_prov, FI_LOG_FABRIC, "unsupported wait object\n");
		return -FI_EINVAL;
	}

	return 0;
}

int udpx_wait_open(struct fid_fabric *fabric, struct fi_wait_attr *attr,
		   struct fid_wait **waitset)
{
	struct udpx_wait *wait;
	int ret;

	ret = udpx_verify_wait_attr(attr);
	if (ret)
		return ret;

	wait = calloc(1, sizeof(*wait));
	if (!wait)
		return -FI_ENOMEM;

	ret = fi_wait_init(container_of(fabric, struct util_fabric, fabric_fid),
			   attr, &wait->util_wait);
	if (ret)
		goto err;

	wait->epoll_fd = epoll_create(4);
	if (wait->epoll_fd < 0) {
		ret = errno;
		goto err;
	}
	wait->util_wait.wait_fid.fid.ops = &udpx_wait_fi_ops;
	wait->util_wait.wait_fid.ops = &udpx_wait_ops;

	*waitset = &wait->util_wait.wait_fid;
	return 0;

err:
	free(wait);
	return ret;
}
