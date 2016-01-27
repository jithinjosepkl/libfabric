/*
 * Copyright (c) 2015-2016 Intel Corporation. All rights reserved.
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

#include "rdmx.h"


/* Internal DGRAM attributes */

struct fi_tx_attr dg_tx_attr = {
	.caps = FI_MSG,
	.comp_order = FI_ORDER_STRICT,
	.inject_size = 0,
	.size = 0,
	.iov_limit = 0,
};

struct fi_rx_attr dg_rx_attr = {
	.caps = FI_MSG | FI_RECV | FI_SOURCE,
	.comp_order = FI_ORDER_STRICT,
	.total_buffered_recv = 0,
	.size = 0,
	.iov_limit = 0,
};

struct fi_ep_attr dg_ep_attr = {
	.type = FI_EP_DGRAM,
	.tx_ctx_cnt = 1,
	.rx_ctx_cnt = 1
};

struct fi_domain_attr dg_domain_attr = {
	.threading = FI_THREAD_SAFE,
	.control_progress = FI_PROGRESS_AUTO,
	.data_progress = FI_PROGRESS_AUTO,
	.resource_mgmt = FI_RM_ENABLED,
	.av_type = FI_AV_MAP,
	.mr_mode = FI_MR_SCALABLE,
	.cq_cnt = 0,
	.ep_cnt = 0,
	.tx_ctx_cnt = 1,
	.rx_ctx_cnt = 1,
	.max_ep_tx_ctx = 1,
	.max_ep_rx_ctx = 1
};

struct fi_info dg_hints = {
	.caps = FI_MSG | FI_SEND | FI_RECV | FI_SOURCE,
	.addr_format = FI_SOCKADDR,
	.tx_attr = &dg_tx_attr,
	.rx_attr = &dg_rx_attr,
	.ep_attr = &dg_ep_attr,
	.domain_attr = &dg_domain_attr,
};


struct fi_tx_attr rdmx_tx_attr = {
	.caps = FI_MSG | FI_SEND,
	.comp_order = FI_ORDER_STRICT,
	// jose: dgram_mtu_size - hdr_sz
	.inject_size = 1472,
	// jose: ??
	.size = 1024,
	.iov_limit = RDMX_IOV_LIMIT
};

struct fi_rx_attr rdmx_rx_attr = {
	.caps = FI_MSG | FI_RECV | FI_SOURCE | FI_MULTI_RECV,
	.comp_order = FI_ORDER_STRICT,
	// jose: ??
	.total_buffered_recv = (1 << 16),
	// jose: ??
	.size = 1024,
	.iov_limit = RDMX_IOV_LIMIT
};

struct fi_ep_attr rdmx_ep_attr = {
	.type = FI_EP_DGRAM,
	.protocol = FI_PROTO_RDMX,
	.protocol_version = 4,
	// jose: ??
	.max_msg_size = 1472,
	// jose: should we support scalable-endpoint for rdmx?
	.tx_ctx_cnt = 1,
	.rx_ctx_cnt = 1
};

struct fi_domain_attr rdmx_domain_attr = {
	.name = "rdmx",
	.threading = FI_THREAD_SAFE,
	.control_progress = FI_PROGRESS_AUTO,
	.data_progress = FI_PROGRESS_AUTO,
	.resource_mgmt = FI_RM_ENABLED,
	.av_type = FI_AV_MAP,
	.mr_mode = FI_MR_SCALABLE,
	// jose: ??
	.cq_cnt = (1 << 16),
	.ep_cnt = (1 << 15),
	.tx_ctx_cnt = (1 << 15),
	.rx_ctx_cnt = (1 << 15),
	// jose: should we support scalable-endpoint for rdmx?
	.max_ep_tx_ctx = 1,
	.max_ep_rx_ctx = 1
};

struct fi_fabric_attr rdmx_fabric_attr = {
	.name = "rdmx",
	.prov_version = FI_VERSION(RDMX_MAJOR_VERSION, RDMX_MINOR_VERSION)
};

struct fi_info rdmx_info = {
	.caps = FI_MSG | FI_SEND | FI_RECV | FI_SOURCE, /* | FI_MULTI_RECV, */
	.addr_format = FI_SOCKADDR,
	.tx_attr = &rdmx_tx_attr,
	.rx_attr = &rdmx_rx_attr,
	.ep_attr = &rdmx_ep_attr,
	.domain_attr = &rdmx_domain_attr,
	.fabric_attr = &rdmx_fabric_attr
};
