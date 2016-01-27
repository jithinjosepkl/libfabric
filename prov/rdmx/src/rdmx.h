/*
 * Copyright (c) 2015-2016 Intel Corporation, Inc.  All rights reserved.
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

#if HAVE_CONFIG_H
#  include <config.h>
#endif /* HAVE_CONFIG_H */

#include <netdb.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <rdma/fabric.h>
#include <rdma/fi_atomic.h>
#include <rdma/fi_cm.h>
#include <rdma/fi_domain.h>
#include <rdma/fi_endpoint.h>
#include <rdma/fi_eq.h>
#include <rdma/fi_errno.h>
#include <rdma/fi_prov.h>
#include <rdma/fi_rma.h>
#include <rdma/fi_tagged.h>
#include <rdma/fi_trigger.h>

#include <fi.h>
#include <fi_enosys.h>
#include <fi_indexer.h>
#include <fi_rbuf.h>
#include <fi_list.h>
#include <fi_signal.h>
#include <fi_util.h>

#ifndef _RDMX_H_
#define _RDMX_H_


#define RDMX_MAJOR_VERSION 1
#define RDMX_MINOR_VERSION 0

#define RDMX_IOV_LIMIT		4

extern struct fi_provider rdmx_prov;
extern struct fi_info rdmx_info;
extern struct fi_info dg_hints;
extern struct fi_fabric_attr rdmx_fabric_attr;
extern struct fi_fabric_attr dg_fabric_attr;

struct rdmx_fabric {
	struct util_fabric util_fabric;
	struct fid_fabric *dg_fabric;
};

struct rdmx_domain {
	struct util_domain util_domain;
	struct fid_domain *dg_domain;
};


struct rdmx_ep_entry {
	void			*context;
	struct iovec		iov[RDMX_IOV_LIMIT];
	uint8_t			iov_count;
	uint8_t			flags;
	uint8_t			resv[sizeof(size_t) - 2];
};

DECLARE_CIRQUE(struct rdmx_ep_entry, rdmx_rx_cirq);

struct rdmx_ep {
	struct fid_ep		ep_fid;
	struct util_domain	*domain;
	struct util_av		*av;
	struct rdmx_cq		*rx_cq;
	struct rdmx_cq		*tx_cq;
	struct rdmx_rx_cirq	rxq; /* protected by rx_cq lock */
	uint64_t		caps;
	uint64_t		flags;
	size_t			min_multi_recv;
	int			sock;
};

DECLARE_CIRQUE(struct fi_cq_data_entry, rdmx_comp_cirq);

struct rdmx_cq {
	struct util_cq		util_cq;
	struct rdmx_comp_cirq	cirq;
	fi_addr_t		*src;
};

int rdmx_fabric(struct fi_fabric_attr *attr, struct fid_fabric **fabric,
			void *context);
int rdmx_domain_open(struct fid_fabric *fabric, struct fi_info *info,
			     struct fid_domain **dom, void *context);
int rdmx_eq_open(struct fid_fabric *fabric, struct fi_eq_attr *attr,
			 struct fid_eq **eq, void *context);
int rdmx_cq_open(struct fid_domain *domain, struct fi_cq_attr *attr,
			 struct fid_cq **cq_fid, void *context);
int rdmx_endpoint(struct fid_domain *domain, struct fi_info *info,
			  struct fid_ep **ep, void *context);
void rdmx_ep_progress(struct rdmx_ep *ep);

#endif
