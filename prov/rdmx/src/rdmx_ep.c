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

#include "rdmx.h"

static inline fid_t rdmx_ep_get_dgram_fid(fid_t fid)
{
	struct rdmx_ep *rdmx_ep;
	rdmx_ep = container_of(fid, struct rdmx_ep, ep_fid.fid);
	return rdmx_ep->dg_ep->fid;
}


int rdmx_setname(fid_t fid, void *addr, size_t addrlen)
{
	struct rdmx_ep *ep;
	int ret;

	ep = container_of(fid, struct rdmx_ep, ep_fid.fid);
	ret = bind(ep->sock, addr, addrlen);
	return ret ? -errno : 0;
}

int rdmx_getname(fid_t fid, void *addr, size_t *addrlen)
{
	struct rdmx_ep *ep;
	int ret;

	ep = container_of(fid, struct rdmx_ep, ep_fid.fid);
	ret = getsockname(ep->sock, addr, addrlen);
	return ret ? -errno : 0;
}

static struct fi_ops_cm rdmx_cm_ops = {
	.size = sizeof(struct fi_ops_cm),
	.setname = rdmx_setname,
	.getname = rdmx_getname,
	.getpeer = fi_no_getpeer,
	.connect = fi_no_connect,
	.listen = fi_no_listen,
	.accept = fi_no_accept,
	.reject = fi_no_reject,
	.shutdown = fi_no_shutdown,
};

int rdmx_getopt(fid_t fid, int level, int optname,
		void *optval, size_t *optlen)
{
	struct rdmx_ep *ep;

	ep = container_of(fid, struct rdmx_ep, ep_fid.fid);
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

int rdmx_setopt(fid_t fid, int level, int optname,
		const void *optval, size_t optlen)
{
	struct rdmx_ep *ep;

	ep = container_of(fid, struct rdmx_ep, ep_fid.fid);
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

static struct fi_ops_ep rdmx_ep_ops = {
	.size = sizeof(struct fi_ops_ep),
	.cancel = fi_no_cancel,
	.getopt = rdmx_getopt,
	.setopt = rdmx_setopt,
	.tx_ctx = fi_no_tx_ctx,
	.rx_ctx = fi_no_rx_ctx,
	.rx_size_left = fi_no_rx_size_left,
	.tx_size_left = fi_no_tx_size_left,
};

static void rdmx_tx_comp(struct rdmx_ep *ep, void *context)
{
	struct fi_cq_data_entry comp;

	comp.op_context = context;
	comp.flags = FI_SEND;
	comp.len = 0;
	comp.buf = NULL;
	comp.data = 0;

	cirque_insert(&ep->tx_cq->cirq, comp);
	/* TODO: signal wait set if used */
}

static void rdmx_rx_comp(struct rdmx_ep *ep, void *context, uint64_t flags,
			 size_t len, void *buf, void *addr)
{
	struct fi_cq_data_entry comp;

	comp.op_context = context;
	comp.flags = FI_RECV | flags;
	comp.len = len;
	comp.buf = buf;
	comp.data = 0;

	if (ep->rx_cq->util_cq.domain->caps & FI_SOURCE) {
		ep->rx_cq->src[cirque_windex(&ep->rx_cq->cirq)] =
			ip_av_get_index(ep->av, addr);
	}
	cirque_insert(&ep->rx_cq->cirq, comp);
	/* TODO: signal wait set if used */
}

void rdmx_ep_progress(struct rdmx_ep *ep)
{
	struct rdmx_ep_entry *entry;
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
		rdmx_rx_comp(ep, entry->context, 0, ret, NULL, &addr);
		cirque_discard(&ep->rxq);
	}
out:
	fastlock_release(&ep->rx_cq->util_cq.cq_lock);
}

ssize_t rdmx_recvmsg(struct fid_ep *ep_fid, const struct fi_msg *msg,
		uint64_t flags)
{
	struct rdmx_ep *ep;
	struct rdmx_ep_entry entry;
	ssize_t ret;

	ep = container_of(ep_fid, struct rdmx_ep, ep_fid.fid);
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

ssize_t rdmx_recvv(struct fid_ep *ep_fid, const struct iovec *iov, void **desc,
		size_t count, fi_addr_t src_addr, void *context)
{
	struct fi_msg msg;

	msg.msg_iov = iov;
	msg.iov_count = count;
	msg.context = context;
	return rdmx_recvmsg(ep_fid, &msg, 0);
}

ssize_t rdmx_recv(struct fid_ep *ep_fid, void *buf, size_t len, void *desc,
		fi_addr_t src_addr, void *context)
{
	struct rdmx_ep *ep;
	struct rdmx_ep_entry entry;
	ssize_t ret;

	ep = container_of(ep_fid, struct rdmx_ep, ep_fid.fid);
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

ssize_t rdmx_send(struct fid_ep *ep_fid, const void *buf, size_t len, void *desc,
		fi_addr_t dest_addr, void *context)
{
	struct rdmx_ep *ep;
	ssize_t ret;

	ep = container_of(ep_fid, struct rdmx_ep, ep_fid.fid);
	fastlock_acquire(&ep->tx_cq->util_cq.cq_lock);
	if (cirque_full(&ep->tx_cq->cirq)) {
		ret = -FI_EAGAIN;
		goto out;
	}

	/* find the TX queue */



	ret = sendto(ep->sock, buf, len, 0, ip_av_get_addr(ep->av, dest_addr),
		     ep->av->addrlen);
	if (ret == len) {
		rdmx_tx_comp(ep, context);
		ret = 0;
	} else {
		ret = -errno;
	}
out:
	fastlock_release(&ep->tx_cq->util_cq.cq_lock);
	return ret;
}

ssize_t rdmx_sendmsg(struct fid_ep *ep_fid, const struct fi_msg *msg,
		uint64_t flags)
{
	struct rdmx_ep *ep;
	struct msghdr hdr;
	ssize_t ret;

	ep = container_of(ep_fid, struct rdmx_ep, ep_fid.fid);
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
		rdmx_tx_comp(ep, msg->context);
		ret = 0;
	} else {
		ret = -errno;
	}
out:
	fastlock_release(&ep->tx_cq->util_cq.cq_lock);
	return ret;
}

ssize_t rdmx_sendv(struct fid_ep *ep_fid, const struct iovec *iov, void **desc,
		size_t count, fi_addr_t dest_addr, void *context)
{
	struct fi_msg msg;

	msg.msg_iov = iov;
	msg.iov_count = count;
	msg.addr = dest_addr;
	msg.context = context;

	return rdmx_sendmsg(ep_fid, &msg, 0);
}

ssize_t rdmx_inject(struct fid_ep *ep_fid, const void *buf, size_t len,
		fi_addr_t dest_addr)
{
	struct rdmx_ep *ep;
	ssize_t ret;

	ep = container_of(ep_fid, struct rdmx_ep, ep_fid.fid);
	ret = sendto(ep->sock, buf, len, 0, ip_av_get_addr(ep->av, dest_addr),
		     ep->av->addrlen);
	return ret == len ? 0 : -errno;
}

static struct fi_ops_msg rdmx_msg_ops = {
	.size = sizeof(struct fi_ops_msg),
	.recv = rdmx_recv,
	.recvv = rdmx_recvv,
	.recvmsg = rdmx_recvmsg,
	.send = rdmx_send,
	.sendv = rdmx_sendv,
	.sendmsg = rdmx_sendmsg,
	.inject = rdmx_inject,
	.senddata = fi_no_msg_senddata,
	.injectdata = fi_no_msg_injectdata,
};

static int rdmx_ep_close(struct fid *fid)
{
	struct rdmx_ep *ep;

	ep = container_of(fid, struct rdmx_ep, ep_fid.fid);

	if (ep->av)
		atomic_dec(&ep->av->ref);
	if (ep->rx_cq) {
		if (ep->rx_cq != ep->tx_cq) {
			fid_list_remove(&ep->rx_cq->util_cq.list,
					&ep->rx_cq->util_cq.list_lock,
					&ep->ep_fid.fid);
		}
		atomic_dec(&ep->rx_cq->util_cq.ref);
	}
	if (ep->tx_cq) {
		fid_list_remove(&ep->tx_cq->util_cq.list,
				&ep->tx_cq->util_cq.list_lock,
				&ep->ep_fid.fid);
		atomic_dec(&ep->tx_cq->util_cq.ref);
	}

	/* jose:
	   - close dgram ep
	 */

	rdmx_rx_cirq_free(&ep->rxq);
	close(ep->sock);
	atomic_dec(&ep->domain->ref);
	free(ep);
	return 0;
}

static int rdmx_bind_cq(struct rdmx_ep *ep, struct rdmx_cq *cq, uint64_t flags)
{
	int ret;

	if (flags & ~(FI_TRANSMIT | FI_RECV)) {
		FI_WARN(&rdmx_prov, FI_LOG_EP_CTRL,
			"unsupported flags\n");
		return -FI_EBADFLAGS;
	}

	if (((flags & FI_TRANSMIT) && ep->tx_cq) ||
	    ((flags & FI_RECV) && ep->rx_cq)) {
		FI_WARN(&rdmx_prov, FI_LOG_EP_CTRL,
			"duplicate CQ binding\n");
		return -FI_EINVAL;
	}

	if (flags & FI_TRANSMIT) {
		ep->tx_cq = cq;
		atomic_inc(&cq->util_cq.ref);
		if (ep->tx_cq != ep->rx_cq) {
			ret = fid_list_insert(&cq->util_cq.list,
					      &cq->util_cq.list_lock,
					      &ep->ep_fid.fid);
			if (ret)
				return ret;
		}
	}

	if (flags & FI_RECV) {
		ep->rx_cq = cq;
		atomic_inc(&cq->util_cq.ref);
		if (ep->tx_cq != ep->rx_cq) {
			ret = fid_list_insert(&cq->util_cq.list,
					      &cq->util_cq.list_lock,
					      &ep->ep_fid.fid);
			if (ret)
				return ret;
		}
	}

	return 0;
}

static int rdmx_ep_bind(struct fid *ep_fid, struct fid *bfid, uint64_t flags)
{
	struct rdmx_ep *ep;
	struct util_av *av;
	int ret;

	ep = container_of(ep_fid, struct rdmx_ep, ep_fid.fid);
	switch (bfid->fclass) {
	case FI_CLASS_AV:
		if (ep->av) {
			FI_WARN(&rdmx_prov, FI_LOG_EP_CTRL,
				"duplicate AV binding\n");
			return -FI_EINVAL;
		}
		av = container_of(bfid, struct util_av, av_fid.fid);
		atomic_inc(&av->ref);
		ep->av = av;
		ret = 0;
		break;
	case FI_CLASS_CQ:
		ret = rdmx_bind_cq(ep, container_of(bfid, struct rdmx_cq,
						    util_cq.cq_fid.fid), flags);
		break;
	default:
		FI_WARN(&rdmx_prov, FI_LOG_EP_CTRL,
			"invalid fid class\n");
		ret = -FI_EINVAL;
		break;
	}
	return ret;
}

static int rdmx_ep_ctrl(struct fid *fid, int command, void *arg)
{
	struct rdmx_ep *ep;

	ep = container_of(fid, struct rdmx_ep, ep_fid.fid);
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

static struct fi_ops rdmx_ep_fi_ops = {
	.size = sizeof(struct fi_ops),
	.close = rdmx_ep_close,
	.bind = rdmx_ep_bind,
	.control = rdmx_ep_ctrl,
	.ops_open = fi_no_ops_open,
};

static int rdmx_ep_init(struct rdmx_ep *ep, struct fi_info *info)
{
	int family;
	int ret;

	ret = rdmx_rx_cirq_init(&ep->rxq, info->rx_attr->size);
	if (ret)
		return ret;

	/* jose:
	   - Open DGRAM EP
	 */

	return 0;
}

int rdmx_endpoint(struct fid_domain *domain, struct fi_info *info,
		  struct fid_ep **ep, void *context)
{
	struct rdmx_ep *ep_priv;
	struct util_domain *util_domain;
	struct rdmx_domain *rdmx_domain;
	int ret;

	if (!info || !info->ep_attr || !info->rx_attr || !info->tx_attr)
		return -FI_EINVAL;

	ret = fi_check_info(&rdmx_prov, &rdmx_info, info);
	if (ret)
		return ret;

	ep_priv = calloc(1, sizeof(*ep_priv));
	if (!ep_priv)
		return -FI_ENOMEM;

	ret = rdmx_ep_init(ep_priv, info);
	if (ret) {
		free(ep_priv);
		return ret;
	}


	/* todo: map fi_addr_t => remote EP info */

	ep_priv->ep_fid.fid.fclass = FI_CLASS_EP;
	ep_priv->ep_fid.fid.context = context;
	ep_priv->ep_fid.fid.ops = &rdmx_ep_fi_ops;
	ep_priv->ep_fid.ops = &rdmx_ep_ops;
	ep_priv->ep_fid.cm = &rdmx_cm_ops;
	ep_priv->ep_fid.msg = &rdmx_msg_ops;

/*
	util_domain = container_of(domain, struct util_domain, domain_fid);
	rdmx_domain = container_of(util_domain, struct rdmx_domain, util_domain);

	ret = fi_endpoint(util_domain->fid, dg_info, &ep_priv->dg_ep, context);
	if (ret) {
		free(ep_priv);
		return ret;
	}


	ep_priv->domain = rdmx_domain;
	atomic_inc(&ep_priv->domain->ref);
*/

	*ep = &ep_priv->ep_fid;
	return 0;
}
