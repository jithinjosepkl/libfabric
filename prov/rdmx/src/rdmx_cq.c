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

static void rdmx_cq_progress(struct rdmx_cq *cq)
{
	struct rdmx_ep *ep;
	struct fid_list_entry *fid_entry;
	struct dlist_entry *item;

	fastlock_acquire(&cq->util_cq.list_lock);
	dlist_foreach(&cq->util_cq.list, item) {
		fid_entry = container_of(item, struct fid_list_entry, entry);
		ep = container_of(fid_entry->fid, struct rdmx_ep, ep_fid.fid);
		rdmx_ep_progress(ep);

	}
	fastlock_release(&cq->util_cq.list_lock);
}

static void rdmx_cq_read_ctx(void **dst, void *src)
{
	*(struct fi_cq_entry *) *dst = *(struct fi_cq_entry *) src;
	*dst += sizeof(struct fi_cq_entry);
}

static void rdmx_cq_read_msg(void **dst, void *src)
{
	*(struct fi_cq_msg_entry *) *dst = *(struct fi_cq_msg_entry *) src;
	*dst += sizeof(struct fi_cq_msg_entry);
}

static void rdmx_cq_read_data(void **dst, void *src)
{
	*(struct fi_cq_data_entry *) *dst = *(struct fi_cq_data_entry *) src;
	*dst += sizeof(struct fi_cq_data_entry);
}

static void rdmx_cq_read_tagged(void **dst, void *src)
{
	rdmx_cq_read_data(dst, src);
	((struct fi_cq_tagged_entry *) *dst)->tag = 0;
	*dst += sizeof(struct fi_cq_tagged_entry);
}

static ssize_t rdmx_cq_read(struct fid_cq *cq_fid, void *buf, size_t count)
{
	struct rdmx_cq *cq;
	struct fi_cq_data_entry *entry;
	ssize_t i;

	cq = container_of(cq_fid, struct rdmx_cq, util_cq.cq_fid);
	fastlock_acquire(&cq->util_cq.cq_lock);
	if (cirque_empty(&cq->cirq)) {
		fastlock_release(&cq->util_cq.cq_lock);
		rdmx_cq_progress(cq);
		fastlock_acquire(&cq->util_cq.cq_lock);
		if (cirque_empty(&cq->cirq)) {
			i = -FI_EAGAIN;
			goto out;
		}
	}

	if (count > cirque_avail(&cq->cirq))
		count = cirque_avail(&cq->cirq);

	for (i = 0; i < count; i++) {
		entry = cirque_head(&cq->cirq);
		if (entry->flags & UTIL_FLAG_ERROR) {
			if (!i)
				i = -FI_EAVAIL;
			break;
		}
		cq->util_cq.read_entry(&buf, cirque_remove(&cq->cirq));
	}
out:
	fastlock_release(&cq->util_cq.cq_lock);
	return i;
}

static ssize_t rdmx_cq_readfrom(struct fid_cq *cq_fid, void *buf,
				size_t count, fi_addr_t *src_addr)
{
	struct rdmx_cq *cq;
	struct fi_cq_data_entry *entry;
	ssize_t i;

	cq = container_of(cq_fid, struct rdmx_cq, util_cq.cq_fid);
	if (!cq->src) {
		i = rdmx_cq_read(cq_fid, buf, count);
		for (count = 0; count < i; count++)
			src_addr[i] = FI_ADDR_NOTAVAIL;
		return i;
	}

	fastlock_acquire(&cq->util_cq.cq_lock);
	if (cirque_empty(&cq->cirq)) {
		fastlock_release(&cq->util_cq.cq_lock);
		rdmx_cq_progress(cq);
		fastlock_acquire(&cq->util_cq.cq_lock);
		if (cirque_empty(&cq->cirq)) {
			i = -FI_EAGAIN;
			goto out;
		}
	}

	if (count > cirque_avail(&cq->cirq))
		count = cirque_avail(&cq->cirq);

	for (i = 0; i < count; i++) {
		entry = cirque_head(&cq->cirq);
		if (entry->flags & UTIL_FLAG_ERROR) {
			if (!i)
				i = -FI_EAVAIL;
			break;
		}
		src_addr[i] = cq->src[cirque_rindex(&cq->cirq)];
		cq->util_cq.read_entry(&buf, cirque_remove(&cq->cirq));
	}
out:
	fastlock_release(&cq->util_cq.cq_lock);
	return i;
}

static ssize_t rdmx_cq_readerr(struct fid_cq *cq_fid, struct fi_cq_err_entry *buf,
			       uint64_t flags)
{
	struct rdmx_cq *cq;
	struct util_cq_err_entry *err;
	struct slist_entry *entry;
	ssize_t ret;

	cq = container_of(cq_fid, struct rdmx_cq, util_cq.cq_fid);
	fastlock_acquire(&cq->util_cq.cq_lock);
	if (!cirque_empty(&cq->cirq) &&
	    (cirque_head(&cq->cirq)->flags & UTIL_FLAG_ERROR)) {
		cirque_discard(&cq->cirq);
		entry = slist_remove_head(&cq->util_cq.err_list);
		err = container_of(entry, struct util_cq_err_entry, list_entry);
		*buf = err->err_entry;
		free(err);
		ret = 0;
	} else {
		ret = -FI_EAGAIN;
	}
	fastlock_release(&cq->util_cq.cq_lock);
	return ret;
}

static ssize_t rdmx_cq_sread(struct fid_cq *cq_fid, void *buf, size_t count,
			     const void *cond, int timeout)
{
//	struct rdmx_cq *cq;
//	ssize_t ret;

//	cq = container_of(cq_fid, struct rdmx_cq, util_cq.cq_fid);
//	assert(cq->util_cq.wait && cq->util_cq.internal_wait);

	return -FI_ENOSYS;
}

static ssize_t rdmx_cq_sreadfrom(struct fid_cq *cq_fid, void *buf, size_t count,
				 fi_addr_t *src_addr, const void *cond,
				 int timeout)
{
//	struct rdmx_cq *cq;
//	ssize_t ret;

//	cq = container_of(cq_fid, struct rdmx_cq, util_cq.cq_fid);
//	assert(cq->util_cq.wait && cq->util_cq.internal_wait);

	return -FI_ENOSYS;
}

static int rdmx_cq_signal(struct fid_cq *cq_fid)
{
//	struct rdmx_cq *cq;

//	cq = container_of(cq_fid, struct rdmx_cq, util_cq.cq_fid);

	return -FI_ENOSYS;
}

static const char *rdmx_cq_strerror(struct fid_cq *cq, int prov_errno,
				    const void *err_data, char *buf, size_t len)
{
	return fi_strerror(prov_errno);
}

static struct fi_ops_cq rdmx_cq_ops = {
	.size = sizeof(struct fi_ops_cq),
	.read = rdmx_cq_read,
	.readfrom = rdmx_cq_readfrom,
	.readerr = rdmx_cq_readerr,
	.sread = rdmx_cq_sread,
	.sreadfrom = rdmx_cq_sreadfrom,
	.signal = rdmx_cq_signal,
	.strerror = rdmx_cq_strerror,
};

static int rdmx_cq_close(struct fid *fid)
{
	struct rdmx_cq *cq;
	int ret;

	cq = container_of(fid, struct rdmx_cq, util_cq.cq_fid.fid);
	ret = fi_cq_cleanup(&cq->util_cq);
	if (ret)
		return ret;

	rdmx_comp_cirq_free(&cq->cirq);
	free(cq->src);
	free(cq);
	return 0;
}

static struct fi_ops rdmx_cq_fi_ops = {
	.size = sizeof(struct fi_ops),
	.close = rdmx_cq_close,
	.bind = fi_no_bind,
	.control = fi_no_control,
	.ops_open = fi_no_ops_open,
};

static int rdmx_cq_init(struct fid_domain *domain, struct fi_cq_attr *attr,
			struct rdmx_cq *cq, void *context)
{
	fi_cq_read_func read_func;
	int ret;

	switch (attr->format) {
	case FI_CQ_FORMAT_UNSPEC:
	case FI_CQ_FORMAT_CONTEXT:
		read_func = rdmx_cq_read_ctx;
		break;
	case FI_CQ_FORMAT_MSG:
		read_func = rdmx_cq_read_msg;
		break;
	case FI_CQ_FORMAT_DATA:
		read_func = rdmx_cq_read_data;
		break;
	case FI_CQ_FORMAT_TAGGED:
		read_func = rdmx_cq_read_tagged;
		break;
	default:
		assert(0);
		return -FI_EINVAL;
	}

	ret = fi_cq_init(domain, attr, read_func, &cq->util_cq, context);
	if (ret)
		return ret;

	ret = rdmx_comp_cirq_init(&cq->cirq, attr->size);
	if (ret)
		goto err1;

	if (cq->util_cq.domain->caps & FI_SOURCE) {
		cq->src = calloc(cq->cirq.size, sizeof *cq->src);
		if (!cq->src) {
			ret = -FI_ENOMEM;
			goto err2;
		}
	}
	return 0;

err2:
	rdmx_comp_cirq_free(&cq->cirq);
err1:
	fi_cq_cleanup(&cq->util_cq);
	return ret;
}

int rdmx_cq_open(struct fid_domain *domain, struct fi_cq_attr *attr,
		 struct fid_cq **cq_fid, void *context)
{
	struct rdmx_cq *cq;
	int ret;

	ret = fi_check_cq_attr(&rdmx_prov, attr);
	if (ret)
		return ret;

	cq = calloc(1, sizeof(*cq));
	if (!cq)
		return -FI_ENOMEM;

	ret = rdmx_cq_init(domain, attr, cq, context);
	if (ret) {
		free(cq);
		return ret;
	}

	cq->util_cq.cq_fid.fid.ops = &rdmx_cq_fi_ops;
	cq->util_cq.cq_fid.ops = &rdmx_cq_ops;

	*cq_fid = &cq->util_cq.cq_fid;
	return 0;
}
