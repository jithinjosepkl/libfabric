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
#include "rxd.h"

int rxd_alter_layer_info(struct fi_info *layer_info, struct fi_info *base_info)
{
	/* TODO choose base_info attr based on layer_info attr */
	base_info->caps = FI_MSG;
	base_info->mode = FI_LOCAL_MR;
	base_info->ep_attr->type = FI_EP_DGRAM;

	return 0;
}

int rxd_alter_base_info(struct fi_info *base_info, struct fi_info *layer_info)
{
	// TODO choose caps based on base_info caps
	layer_info->caps = rxd_info.caps;
	layer_info->mode = rxd_info.mode;

	*layer_info->tx_attr = *rxd_info.tx_attr;
	*layer_info->rx_attr = *rxd_info.rx_attr;
	*layer_info->ep_attr = *rxd_info.ep_attr;
	*layer_info->domain_attr = *rxd_info.domain_attr;

	return 0;
}

static int rxd_getinfo(uint32_t version, const char *node, const char *service,
			uint64_t flags, struct fi_info *hints, struct fi_info **info)
{
	return ofix_getinfo(version, node, service, flags, &rxd_util_prov,
			    hints, rxd_alter_layer_info, rxd_alter_base_info, 0, info);
/*
	int ret;
	struct fi_info *dg_info, *entry;

	if (!hints || !hints->ep_attr ||
	    (hints->ep_attr->type != FI_EP_RDM) ||
	    ((hints->caps | rxd_info.caps) != rxd_info.caps))
		return -FI_ENODATA;

	ret = fi_getinfo(version, node, service, flags, &dg_hints, &dg_info);
	if (ret)
		return ret;

	entry = dg_info;
	while (entry) {
		entry->caps = rxd_info.caps;
		*(entry->tx_attr) = *(rxd_info.tx_attr);
		*(entry->rx_attr) = *(rxd_info.rx_attr);
		*(entry->ep_attr) = *(rxd_info.ep_attr);
		*(entry->fabric_attr) = *(rxd_info.fabric_attr);
		*(entry->domain_attr) = *(rxd_info.domain_attr);
		entry->domain_attr->name = strdup(rxd_info.domain_attr->name);
		entry->fabric_attr->name = strdup(rxd_info.fabric_attr->name);
		entry = entry->next;
	}

	*info = dg_info;
	return 0;
*/
}

static void rxd_fini(void)
{
	/* yawn */
}

struct fi_provider rxd_prov = {
	.name = "rxd",
	.version = FI_VERSION(RXD_MAJOR_VERSION, RXD_MINOR_VERSION),
	.fi_version = RXD_FI_VERSION,
	.getinfo = rxd_getinfo,
	.fabric = rxd_fabric,
	.cleanup = rxd_fini
};

RXD_INI
{
	return &rxd_prov;
}
