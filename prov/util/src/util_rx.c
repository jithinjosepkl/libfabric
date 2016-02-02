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
#include <fi_util.h>

struct util_rx_list *util_rx_list_init(size_t max_len)
{
	struct util_rx_list *rx_list;

	rx_list = calloc(1, sizeof(*rx_list));
	if (!rx_list)
		return NULL;

	rx_list->max_len = max_len;
	rx_list->curr_len = 0;
	dlist_init(&rx_list->rx_list);
	return rx_list;
}

int util_rx_list_post(struct util_rx_list *rx_list, struct util_rx_entry *rx_entry)
{
	if (rx_list->curr_len == rx_list->max_len)
		return -FI_EAGAIN;

	dlist_insert_tail(&rx_entry->entry, &rx_list->rx_list);
	return 0;
}

struct util_rx_entry *util_rx_list_dequeue(struct util_rx_list *rx_list,
					   uint64_t addr, uint64_t tag)
{
	struct dlist_entry *entry;
	struct util_rx_entry *rx_entry;

	for (entry = rx_list->rx_list.next; entry != &rx_list->rx_list; entry = entry->next) {
		rx_entry = container_of(entry, struct util_rx_entry, entry);
		
		if (((rx_entry->tag & ~rx_entry->ignore) == (tag & ~rx_entry->ignore)) &&
		    (rx_entry->addr == FI_ADDR_UNSPEC || addr == FI_ADDR_UNSPEC ||
		     rx_entry->addr == addr)) {
			dlist_remove(&rx_entry->entry);
			return rx_entry;
		}
	}
	return NULL;
}
