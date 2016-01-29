/*
 * Copyright (c) 2013-2016 Intel Corporation. All rights reserved.
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

#include "udpx.h"


int udpx_setname(fid_t fid, void *addr, size_t addrlen)
{
	struct udpx_ep *ep;
	int ret;

	ep = container_of(fid, struct udpx_ep, ep_fid.fid);
	ret = bind(ep->sock, addr, addrlen);
	return ret ? -errno : 0;
}

int udpx_getname(fid_t fid, void *addr, size_t *addrlen)
{
	struct udpx_ep *ep;
	int ret;

	ep = container_of(fid, struct udpx_ep, ep_fid.fid);
	ret = getsockname(ep->sock, addr, addrlen);
	return ret ? -errno : 0;
}

static struct fi_ops_cm udpx_cm_ops = {
	.size = sizeof(struct fi_ops_cm),
	.setname = udpx_setname,
	.getname = udpx_getname,
	.getpeer = fi_no_getpeer,
	.connect = fi_no_connect,
	.listen = fi_no_listen,
	.accept = fi_no_accept,
	.reject = fi_no_reject,
	.shutdown = fi_no_shutdown,
};

int udpx_getopt(fid_t fid, int level, int optname,
		void *optval, size_t *optlen)
{
	struct udpx_ep *ep;

	ep = container_of(fid, struct udpx_ep, ep_fid.fid);
	if (level != FI_OPT_ENDPOINT)
		return -FI_ENOPROTOOPT;

	switch (optname) {
	case FI_OPT_MIN_MULTI_RECV:
		*(size_t *) optval = ep->min_multi_recv;
		*optlen = sizeof(size_t);
		break;
	default:
		return -FI_ENOPROTOOPT;
	}
	return 0;
}

int udpx_setopt(fid_t fid, int level, int optname,
		const void *optval, size_t optlen)
{
	struct udpx_ep *ep;

	ep = container_of(fid, struct udpx_ep, ep_fid.fid);
	if (level != FI_OPT_ENDPOINT)
		return -FI_ENOPROTOOPT;

	switch (optname) {
	case FI_OPT_MIN_MULTI_RECV:
		ep->min_multi_recv = *(size_t *) optval;
		break;
	default:
		return -FI_ENOPROTOOPT;
	}
	return 0;
}

static struct fi_ops_ep udpx_ep_ops = {
	.size = sizeof(struct fi_ops_ep),
	.cancel = fi_no_cancel,
	.getopt = udpx_getopt,
	.setopt = udpx_setopt,
	.tx_ctx = fi_no_tx_ctx,
	.rx_ctx = fi_no_rx_ctx,
	.rx_size_left = fi_no_rx_size_left,
	.tx_size_left = fi_no_tx_size_left,
};

static void udpx_tx_comp(struct udpx_ep *ep, void *context)
{
	struct fi_cq_data_entry *comp;

	comp = cirque_tail(&ep->tx_cq->cirq);
	comp->op_context = context;
	comp->flags = FI_SEND;
	comp->len = 0;
	comp->buf = NULL;
	comp->data = 0;
	cirque_commit(&ep->tx_cq->cirq);
}

static void udpx_tx_comp_signal(struct udpx_ep *ep, void *context)
{
	udpx_tx_comp(ep, context);
	ep->tx_cq->util_cq.wait->signal(ep->tx_cq->util_cq.wait);
}

static void udpx_rx_comp(struct udpx_ep *ep, void *context, uint64_t flags,
			 size_t len, void *buf, void *addr)
{
	struct fi_cq_data_entry *comp;

	comp = cirque_tail(&ep->rx_cq->cirq);
	comp->op_context = context;
	comp->flags = FI_RECV | flags;
	comp->len = len;
	comp->buf = buf;
	comp->data = 0;
	cirque_commit(&ep->rx_cq->cirq);
}

static void udpx_rx_src_comp(struct udpx_ep *ep, void *context, uint64_t flags,
			     size_t len, void *buf, void *addr)
{
	ep->rx_cq->src[cirque_windex(&ep->rx_cq->cirq)] =
			ip_av_get_index(ep->av, addr);
	udpx_rx_comp(ep, context, flags, len, buf, addr);
}

static void udpx_rx_comp_signal(struct udpx_ep *ep, void *context,
			uint64_t flags, size_t len, void *buf, void *addr)
{
	udpx_rx_comp(ep, context, flags, len, buf, addr);
	ep->rx_cq->util_cq.wait->signal(ep->rx_cq->util_cq.wait);
}

static void udpx_rx_src_comp_signal(struct udpx_ep *ep, void *context,
			uint64_t flags, size_t len, void *buf, void *addr)
{
	udpx_rx_src_comp(ep, context, flags, len, buf, addr);
	ep->rx_cq->util_cq.wait->signal(ep->rx_cq->util_cq.wait);

}

void udpx_ep_progress(struct udpx_ep *ep)
{
	struct udpx_ep_entry *entry;
	struct msghdr hdr;
	struct sockaddr_in6 addr;
	int ret;

	hdr.msg_name = &addr;
	hdr.msg_namelen = sizeof(addr);
	hdr.msg_control = NULL;
	hdr.msg_controllen = 0;
	hdr.msg_flags = 0;

	fastlock_acquire(&ep->rx_cq->util_cq.cq_lock);
	if (cirque_empty(&ep->rxq))
		goto out;

	entry = cirque_head(&ep->rxq);
	hdr.msg_iov = entry->iov;
	hdr.msg_iovlen = entry->iov_count;

	ret = recvmsg(ep->sock, &hdr, 0);
	if (ret >= 0) {
		ep->rx_comp(ep, entry->context, 0, ret, NULL, &addr);
		cirque_discard(&ep->rxq);
	}
out:
	fastlock_release(&ep->rx_cq->util_cq.cq_lock);
}

ssize_t udpx_recvmsg(struct fid_ep *ep_fid, const struct fi_msg *msg,
		uint64_t flags)
{
	struct udpx_ep *ep;
	struct udpx_ep_entry entry;
	ssize_t ret;

	ep = container_of(ep_fid, struct udpx_ep, ep_fid.fid);
	fastlock_acquire(&ep->rx_cq->util_cq.cq_lock);
	if (cirque_full(&ep->rxq)) {
		ret = -FI_EAGAIN;
		goto out;
	}

	entry.context = msg->context;
	for (entry.iov_count = 0; entry.iov_count < msg->iov_count;
	     entry.iov_count++) {
		entry.iov[entry.iov_count] = msg->msg_iov[entry.iov_count];
	}
	entry.flags = 0;

	cirque_insert(&ep->rxq, entry);
	ret = 0;
out:
	fastlock_release(&ep->rx_cq->util_cq.cq_lock);
	return ret;
}

ssize_t udpx_recvv(struct fid_ep *ep_fid, const struct iovec *iov, void **desc,
		size_t count, fi_addr_t src_addr, void *context)
{
	struct fi_msg msg;

	msg.msg_iov = iov;
	msg.iov_count = count;
	msg.context = context;
	return udpx_recvmsg(ep_fid, &msg, 0);
}

ssize_t udpx_recv(struct fid_ep *ep_fid, void *buf, size_t len, void *desc,
		fi_addr_t src_addr, void *context)
{
	struct udpx_ep *ep;
	struct udpx_ep_entry entry;
	ssize_t ret;

	ep = container_of(ep_fid, struct udpx_ep, ep_fid.fid);
	fastlock_acquire(&ep->rx_cq->util_cq.cq_lock);
	if (cirque_full(&ep->rxq)) {
		ret = -FI_EAGAIN;
		goto out;
	}

	entry.context = context;
	entry.iov_count = 1;
	entry.iov[0].iov_base = buf;
	entry.iov[0].iov_len = len;
	entry.flags = 0;

	cirque_insert(&ep->rxq, entry);
	ret = 0;
out:
	fastlock_release(&ep->rx_cq->util_cq.cq_lock);
	return ret;
}

ssize_t udpx_send(struct fid_ep *ep_fid, const void *buf, size_t len, void *desc,
		fi_addr_t dest_addr, void *context)
{
	struct udpx_ep *ep;
	ssize_t ret;

	ep = container_of(ep_fid, struct udpx_ep, ep_fid.fid);
	fastlock_acquire(&ep->tx_cq->util_cq.cq_lock);
	if (cirque_full(&ep->tx_cq->cirq)) {
		ret = -FI_EAGAIN;
		goto out;
	}

	ret = sendto(ep->sock, buf, len, 0, ip_av_get_addr(ep->av, dest_addr),
		     ep->av->addrlen);
	if (ret == len) {
		ep->tx_comp(ep, context);
		ret = 0;
	} else {
		ret = -errno;
	}
out:
	fastlock_release(&ep->tx_cq->util_cq.cq_lock);
	return ret;
}

ssize_t udpx_sendmsg(struct fid_ep *ep_fid, const struct fi_msg *msg,
		uint64_t flags)
{
	struct udpx_ep *ep;
	struct msghdr hdr;
	ssize_t ret;

	ep = container_of(ep_fid, struct udpx_ep, ep_fid.fid);
	hdr.msg_name = ip_av_get_addr(ep->av, msg->addr);
	hdr.msg_namelen = ep->av->addrlen;
	hdr.msg_iov = (struct iovec *) msg->msg_iov;
	hdr.msg_iovlen = msg->iov_count;
	hdr.msg_control = NULL;
	hdr.msg_controllen = 0;
	hdr.msg_flags = 0;

	fastlock_acquire(&ep->tx_cq->util_cq.cq_lock);
	if (cirque_full(&ep->tx_cq->cirq)) {
		ret = -FI_EAGAIN;
		goto out;
	}

	ret = sendmsg(ep->sock, &hdr, 0);
	if (ret >= 0) {
		ep->tx_comp(ep, msg->context);
		ret = 0;
	} else {
		ret = -errno;
	}
out:
	fastlock_release(&ep->tx_cq->util_cq.cq_lock);
	return ret;
}

ssize_t udpx_sendv(struct fid_ep *ep_fid, const struct iovec *iov, void **desc,
		size_t count, fi_addr_t dest_addr, void *context)
{
	struct fi_msg msg;

	msg.msg_iov = iov;
	msg.iov_count = count;
	msg.addr = dest_addr;
	msg.context = context;

	return udpx_sendmsg(ep_fid, &msg, 0);
}

ssize_t udpx_inject(struct fid_ep *ep_fid, const void *buf, size_t len,
		fi_addr_t dest_addr)
{
	struct udpx_ep *ep;
	ssize_t ret;

	ep = container_of(ep_fid, struct udpx_ep, ep_fid.fid);
	ret = sendto(ep->sock, buf, len, 0, ip_av_get_addr(ep->av, dest_addr),
		     ep->av->addrlen);
	return ret == len ? 0 : -errno;
}

static struct fi_ops_msg udpx_msg_ops = {
	.size = sizeof(struct fi_ops_msg),
	.recv = udpx_recv,
	.recvv = udpx_recvv,
	.recvmsg = udpx_recvmsg,
	.send = udpx_send,
	.sendv = udpx_sendv,
	.sendmsg = udpx_sendmsg,
	.inject = udpx_inject,
	.senddata = fi_no_msg_senddata,
	.injectdata = fi_no_msg_injectdata,
};

static int udpx_ep_close(struct fid *fid)
{
	struct udpx_ep *ep;
	struct util_wait_fd *wait;

	ep = container_of(fid, struct udpx_ep, ep_fid.fid);

	if (ep->av)
		atomic_dec(&ep->av->ref);

	if (ep->rx_cq) {
		if (ep->rx_cq->util_cq.wait) {
			wait = container_of(ep->rx_cq->util_cq.wait,
					    struct util_wait_fd, util_wait);
			fi_epoll_del(wait->epoll_fd, ep->sock);
		}
		fid_list_remove(&ep->rx_cq->util_cq.list,
				&ep->rx_cq->util_cq.list_lock,
				&ep->ep_fid.fid);
		atomic_dec(&ep->rx_cq->util_cq.ref);
	}

	if (ep->tx_cq)
		atomic_dec(&ep->tx_cq->util_cq.ref);

	udpx_rx_cirq_free(&ep->rxq);
	close(ep->sock);
	atomic_dec(&ep->domain->ref);
	free(ep);
	return 0;
}

static int udpx_ep_bind_cq(struct udpx_ep *ep, struct udpx_cq *cq, uint64_t flags)
{
	struct util_wait_fd *wait;
	int ret;

	if (flags & ~(FI_TRANSMIT | FI_RECV)) {
		FI_WARN(&udpx_prov, FI_LOG_EP_CTRL,
			"unsupported flags\n");
		return -FI_EBADFLAGS;
	}

	if (((flags & FI_TRANSMIT) && ep->tx_cq) ||
	    ((flags & FI_RECV) && ep->rx_cq)) {
		FI_WARN(&udpx_prov, FI_LOG_EP_CTRL,
			"duplicate CQ binding\n");
		return -FI_EINVAL;
	}

	if (flags & FI_TRANSMIT) {
		ep->tx_cq = cq;
		atomic_inc(&cq->util_cq.ref);
		ep->tx_comp = cq->util_cq.wait ?
			      udpx_tx_comp_signal : udpx_tx_comp;
	}

	if (flags & FI_RECV) {
		ep->rx_cq = cq;
		atomic_inc(&cq->util_cq.ref);

		if (cq->util_cq.wait) {
			ep->rx_comp = (cq->util_cq.domain->caps & FI_SOURCE) ?
				      udpx_rx_src_comp_signal :
				      udpx_rx_comp_signal;

			wait = container_of(cq->util_cq.wait,
					    struct util_wait_fd, util_wait);
			ret = fi_epoll_add(wait->epoll_fd, ep->sock,
					   &ep->ep_fid.fid);
			if (ret)
				return ret;
		} else {
			ep->rx_comp = (cq->util_cq.domain->caps & FI_SOURCE) ?
				      udpx_rx_src_comp : udpx_rx_comp;
		}

		ret = fid_list_insert(&cq->util_cq.list,
				      &cq->util_cq.list_lock,
				      &ep->ep_fid.fid);
		if (ret)
			return ret;
	}

	return 0;
}

static int udpx_ep_bind(struct fid *ep_fid, struct fid *bfid, uint64_t flags)
{
	struct udpx_ep *ep;
	struct util_av *av;
	int ret;

	ep = container_of(ep_fid, struct udpx_ep, ep_fid.fid);
	switch (bfid->fclass) {
	case FI_CLASS_AV:
		if (ep->av) {
			FI_WARN(&udpx_prov, FI_LOG_EP_CTRL,
				"duplicate AV binding\n");
			return -FI_EINVAL;
		}
		av = container_of(bfid, struct util_av, av_fid.fid);
		atomic_inc(&av->ref);
		ep->av = av;
		ret = 0;
		break;
	case FI_CLASS_CQ:
		ret = udpx_ep_bind_cq(ep, container_of(bfid, struct udpx_cq,
						util_cq.cq_fid.fid), flags);
		break;
	default:
		FI_WARN(&udpx_prov, FI_LOG_EP_CTRL,
			"invalid fid class\n");
		ret = -FI_EINVAL;
		break;
	}
	return ret;
}

static int udpx_ep_ctrl(struct fid *fid, int command, void *arg)
{
	struct udpx_ep *ep;

	ep = container_of(fid, struct udpx_ep, ep_fid.fid);
	switch (command) {
	case FI_ENABLE:
		if (!ep->rx_cq || !ep->tx_cq)
			return -FI_ENOCQ;
		if (!ep->av)
			return -FI_EOPBADSTATE; /* TODO: Add FI_ENOAV */
		break;
	default:
		return -FI_ENOSYS;
	}
	return 0;
}

static struct fi_ops udpx_ep_fi_ops = {
	.size = sizeof(struct fi_ops),
	.close = udpx_ep_close,
	.bind = udpx_ep_bind,
	.control = udpx_ep_ctrl,
	.ops_open = fi_no_ops_open,
};

static int udpx_ep_init(struct udpx_ep *ep, struct fi_info *info)
{
	int family;
	int ret;

	ret = udpx_rx_cirq_init(&ep->rxq, info->rx_attr->size);
	if (ret)
		return ret;

	family = info->src_addr ?
		 ((struct sockaddr *) info->src_addr)->sa_family : AF_INET;
	ep->sock = socket(family, SOCK_DGRAM, IPPROTO_UDP);
	if (ep->sock < 0) {
		ret = -errno;
		goto err1;
	}

	if (info->src_addr) {
		ret = bind(ep->sock, info->src_addr, info->src_addrlen);
		if (ret) {
			ret = -errno;
			goto err1;
		}
	}

	if (info->dest_addr) {
		ret = connect(ep->sock, info->dest_addr, info->dest_addrlen);
		if (ret) {
			ret = -errno;
			goto err1;
		}
	}

	ret = fi_fd_nonblock(ep->sock);
	if (ret)
		goto err2;

	return 0;
err2:
	close(ep->sock);
err1:
	udpx_rx_cirq_free(&ep->rxq);
	return ret;
}

int udpx_endpoint(struct fid_domain *domain, struct fi_info *info,
		  struct fid_ep **ep_fid, void *context)
{
	struct udpx_ep *ep;
	int ret;

	if (!info || !info->ep_attr || !info->rx_attr || !info->tx_attr)
		return -FI_EINVAL;

	ret = fi_check_info(&udpx_prov, &udpx_info, info);
	if (ret)
		return ret;

	ep = calloc(1, sizeof(*ep));
	if (!ep)
		return -FI_ENOMEM;

	ret = udpx_ep_init(ep, info);
	if (ret) {
		free(ep);
		return ret;
	}

	ep->ep_fid.fid.fclass = FI_CLASS_EP;
	ep->ep_fid.fid.context = context;
	ep->ep_fid.fid.ops = &udpx_ep_fi_ops;
	ep->ep_fid.ops = &udpx_ep_ops;
	ep->ep_fid.cm = &udpx_cm_ops;
	ep->ep_fid.msg = &udpx_msg_ops;

	ep->domain = container_of(domain, struct util_domain, domain_fid);
	atomic_inc(&ep->domain->ref);

	*ep_fid = &ep->ep_fid;
	return 0;
}
