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

static struct fi_ops_fabric rdmx_fabric_ops = {
	.size = sizeof(struct fi_ops_fabric),
	.domain = rdmx_domain_open,
	.passive_ep = fi_no_passive_ep,
	.eq_open = NULL,
	.wait_open = NULL,
};

int rdmx_fabric(struct fi_fabric_attr *attr, struct fid_fabric **fabric,
		void *context)
{
	int ret;
	struct rdmx_fabric *rdmx_fabric;

	rdmx_fabric = calloc(1, sizeof(*rdmx_fabric));
	if (!rdmx_fabric)
		return -FI_ENOMEM;

	ret = fi_fabric(&dg_fabric_attr, &rdmx_fabric->dg_fabric, context);
	if (ret) {
		goto err1;
	}

	ret = fi_fabric_init(&rdmx_prov, rdmx_info.fabric_attr, attr,
			     &rdmx_fabric->util_fabric, context);
	if (ret) {
		goto err2;
	}

	*fabric = &rdmx_fabric->util_fabric.fabric_fid;
	(*fabric)->ops = &rdmx_fabric_ops;
	return 0;

err2:
	fi_close(&rdmx_fabric->dg_fabric->fid);

err1:
	free(rdmx_fabric);
	return ret;
}
