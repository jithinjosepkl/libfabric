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

#include <rdma/fi_errno.h>

#include <prov.h>
#include "rdmx.h"

struct fi_fabric_attr dg_fabric_attr;

static int rdmx_getinfo(uint32_t version, const char *node, const char *service,
			uint64_t flags, struct fi_info *hints, struct fi_info **info)
{
	int ret;
	struct fi_info *dg_info;

	if (!hints || !hints->ep_attr || (hints && hints->ep_attr->type != FI_EP_RDM))
		return -FI_ENOSYS;

	ret = fi_getinfo(version, node, service, flags, &dg_hints, &dg_info);
	if (ret)
		return ret;

	dg_fabric_attr = *dg_info->fabric_attr;

	dg_info->caps = rdmx_info.caps;
	dg_info->tx_attr = rdmx_info.tx_attr;
	dg_info->rx_attr = rdmx_info.rx_attr;
	dg_info->ep_attr = rdmx_info.ep_attr;
	dg_info->fabric_attr = rdmx_info.fabric_attr;
	dg_info->domain_attr = rdmx_info.domain_attr;

	*info = dg_info;
	return 0;
}

static void rdmx_fini(void)
{
	/* yawn */
}

struct fi_provider rdmx_prov = {
	.name = "rdmx",
	.version = FI_VERSION(RDMX_MAJOR_VERSION, RDMX_MINOR_VERSION),
	.fi_version = FI_VERSION(1, 1),
	.getinfo = rdmx_getinfo,
	.fabric = rdmx_fabric,
	.cleanup = rdmx_fini
};

RDMX_INI
{
	return &rdmx_prov;
}
