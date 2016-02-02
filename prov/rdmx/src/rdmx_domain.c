/*
 * Copyright (c) 2016 Intel Corporation, Inc.  All rights reserved.
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


static struct fi_ops_domain rdmx_domain_ops = {
	.size = sizeof(struct fi_ops_domain),

	/* jose: point to the dgram av open */
	.av_open = ip_av_create,
	.cq_open = rdmx_cq_open,
	.endpoint = rdmx_endpoint,
	.scalable_ep = fi_no_scalable_ep,
	.cntr_open = fi_no_cntr_open,
	.poll_open = fi_poll_create,
	.stx_ctx = fi_no_stx_context,
	.srx_ctx = fi_no_srx_context,
};

static int rdmx_domain_close(fid_t fid)
{
	int ret;
	struct util_domain *util_domain;
	struct rdmx_domain *rdmx_domain;
	util_domain = container_of(fid, struct util_domain, domain_fid.fid);
	rdmx_domain = container_of(util_domain, struct rdmx_domain, util_domain);

	ret = fi_close(&rdmx_domain->dg_domain->fid);
	if (ret)
		return ret;

	ret = util_domain_close(util_domain);
	if (ret)
		return ret;
	free(util_domain);
	return 0;
}

static struct fi_ops rdmx_domain_fi_ops = {
	.size = sizeof(struct fi_ops),
	.close = rdmx_domain_close,
	.bind = fi_no_bind,
	.control = fi_no_control,
	.ops_open = fi_no_ops_open,
};

int rdmx_domain_open(struct fid_fabric *fabric, struct fi_info *info,
		struct fid_domain **domain, void *context)
{
	int ret;
	struct rdmx_domain *rdmx_domain;

	ret = fi_check_info(&rdmx_prov, &rdmx_info, info);
	if (ret)
		return ret;

	rdmx_domain = calloc(1, sizeof(*rdmx_domain));
	if (!rdmx_domain)
		return -FI_ENOMEM;

	ret = fi_domain_init(fabric, info, &rdmx_domain->util_domain, context);
	if (ret) {
		free(rdmx_domain);
		return ret;
	}

	*domain = &rdmx_domain->util_domain.domain_fid;
	(*domain)->fid.ops = &rdmx_domain_fi_ops;
	(*domain)->ops = &rdmx_domain_ops;
	return 0;
}



