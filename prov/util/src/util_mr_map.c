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
#include <config.h>
#include <stdlib.h>
#include <fi_enosys.h>
#include <fi_util.h>
#include <ofi_mr.h>
#include <assert.h>
#include <rbtree.h>


static struct fi_mr_attr *
dup_mr_attr(const struct fi_mr_attr *attr)
{
	struct fi_mr_attr *dup_attr;

	dup_attr = calloc(1, sizeof(*attr) +
			     sizeof(*attr->mr_iov) * attr->iov_count);
	if (!dup_attr)
		return NULL;

	*dup_attr = *attr;
	dup_attr->mr_iov = (struct iovec *) (dup_attr + 1);
	memcpy((void *) dup_attr->mr_iov, attr->mr_iov,
		sizeof(*attr->mr_iov) * attr->iov_count);

	return dup_attr;
}

int ofi_mr_map_insert(struct ofi_mr_map *map, const struct fi_mr_attr *attr,
		      uint64_t *key, void *context)
{
	struct fi_mr_attr *item;

	item = dup_mr_attr(attr);
	if (!item)
		return -FI_ENOMEM;

	if (!(map->mode & FI_MR_VIRT_ADDR))
		item->offset = (uintptr_t) attr->mr_iov[0].iov_base;

	if (!(map->mode & FI_MR_PROV_KEY)) {
		if (rbtFind(map->rbtree, &item->requested_key)) {
			free(item);
			return -FI_ENOKEY;
		}
	} else {
		item->requested_key = map->key++;
	}

	rbtInsert(map->rbtree, &item->requested_key, item);
	*key = item->requested_key;
	item->context = context;

	return 0;
}

void *ofi_mr_map_get(struct ofi_mr_map *map, uint64_t key)
{
	struct fi_mr_attr *attr;
	void *itr, *key_ptr;

	itr = rbtFind(map->rbtree, &key);
	if (!itr)
		return NULL;

	rbtKeyValue(map->rbtree, itr, &key_ptr, (void **) &attr);
	return attr->context;
}

int ofi_mr_map_verify(struct ofi_mr_map *map, uintptr_t *io_addr,
		      size_t len, uint64_t key, uint64_t access,
		      void **context)
{
	struct fi_mr_attr *attr;
	void *itr, *key_ptr, *addr;

	itr = rbtFind(map->rbtree, &key);
	if (!itr)
		return -FI_EINVAL;

	rbtKeyValue(map->rbtree, itr, &key_ptr, (void **) &attr);
	assert(attr);

	if ((access & attr->access) != access) {
		FI_DBG(map->prov, FI_LOG_MR, "verify_addr: invalid access\n");
		return -FI_EACCES;
	}

	addr = (void *) (*io_addr + (uintptr_t) attr->offset);

	if ((addr < attr->mr_iov[0].iov_base) ||
	    (((char *) addr + len) > ((char *) attr->mr_iov[0].iov_base +
			    	      attr->mr_iov[0].iov_len))) {
		return -FI_EACCES;
	}

	if (context)
		*context = attr->context;
	*io_addr = (uintptr_t) addr;
	return 0;
}

int ofi_mr_map_remove(struct ofi_mr_map *map, uint64_t key)
{
	struct fi_mr_attr *attr;
	void *itr, *key_ptr;

	itr = rbtFind(map->rbtree, &key);
	if (!itr)
		return -FI_ENOKEY;

	rbtKeyValue(map->rbtree, itr, &key_ptr, (void **) &attr);
	rbtErase(map->rbtree, itr);
	free(attr);

	return 0;
}

/* assumes uint64_t keys */
static int compare_mr_keys(void *key1, void *key2)
{
	uint64_t k1 = *((uint64_t *) key1);
	uint64_t k2 = *((uint64_t *) key2);
	return (k1 < k2) ? -1 : (k1 > k2);
}


/*
 * If a provider or app whose version is < 1.5, calls this function and passes
 * FI_MR_UNSPEC as mode, it would be treated as MR scalable.
 */
int ofi_mr_map_init(const struct fi_provider *prov, int mode,
		    struct ofi_mr_map *map)
{
	map->rbtree = rbtNew(compare_mr_keys);
	if (!map->rbtree)
		return -FI_ENOMEM;

	switch (mode) {
	case FI_MR_BASIC:
		map->mode = OFI_MR_BASIC_MAP;
		break;
	case FI_MR_SCALABLE:
		map->mode = 0;
		break;
	default:
		map->mode = mode;
	}
	map->prov = prov;
	map->key = 1;

	return 0;
}

void ofi_mr_map_close(struct ofi_mr_map *map)
{
	rbtDelete(map->rbtree);
}