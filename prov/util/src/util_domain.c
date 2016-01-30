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

#include <fi_enosys.h>
#include <fi_util.h>


static int util_domain_close(fid_t fid)
{
	struct util_domain *domain;

	domain = container_of(fid, struct util_domain, domain_fid.fid);
	if (atomic_get(&domain->ref))
		return -FI_EBUSY;

	fastlock_acquire(&domain->fabric->lock);
	dlist_remove(&domain->list_entry);
	fastlock_release(&domain->fabric->lock);

	fastlock_destroy(&domain->lock);
	free(domain);
	return 0;
}

static struct fi_ops util_domain_fi_ops = {
	.size = sizeof(struct fi_ops),
	.close = util_domain_close,
	.bind = fi_no_bind,
	.control = fi_no_control,
	.ops_open = fi_no_ops_open,
};

static struct fi_ops_mr util_domain_mr_ops = {
	.size = sizeof(struct fi_ops_mr),
	.reg = fi_no_mr_reg,
	.regv = fi_no_mr_regv,
	.regattr = fi_no_mr_regattr,
};

static int util_domain_init(struct util_domain *domain,
			    const struct fi_info *info)
{
	atomic_initialize(&domain->ref, 0);
	fastlock_init(&domain->lock);
	domain->caps = info->caps;
	domain->mode = info->mode;
	domain->addr_format = info->addr_format;
	domain->name = strdup(info->domain_attr->name);
	return domain->name ? 0 : -FI_ENOMEM;
}

int fi_domain_init(struct fid_fabric *fabric_fid, const struct fi_info *info,
		   struct util_domain *domain, void *context)
{
	int ret;
	struct util_fabric *fabric;

	fabric = container_of(fabric_fid, struct util_fabric, fabric_fid);

	domain->fabric = fabric;
	domain->prov = fabric->prov;
	ret = util_domain_init(domain, info);
	if (ret) {
		return ret;
	}

	domain->domain_fid.fid.fclass = FI_CLASS_DOMAIN;
	domain->domain_fid.fid.context = context;
	/*
	 * domain ops set by provider
	 */
	domain->domain_fid.fid.ops = &util_domain_fi_ops;
	domain->domain_fid.mr = &util_domain_mr_ops;

	fastlock_acquire(&fabric->lock);
	dlist_insert_tail(&domain->list_entry, &fabric->domain_list);
	fastlock_release(&fabric->lock);

	atomic_inc(&fabric->ref);
	return 0;
}
