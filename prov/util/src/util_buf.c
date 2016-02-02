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

#include <fi_enosys.h>
#include <fi_util.h>


static inline struct util_buf_pool_t *create_buf_pool(size_t num, size_t size,
                                                      struct util_buf_pool_t *parent_pool)
{
	int i;
	struct util_buf_pool_t *buf_pool;
	struct util_buf_t *curr, *next;

	buf_pool = (struct util_buf_pool_t *) calloc(1, sizeof(*buf_pool));
	if (!buf_pool)
		return NULL;

	pthread_mutex_init(&buf_pool->lock, NULL);
	buf_pool->size = size;
	buf_pool->num = num;
	buf_pool->next = NULL;
	buf_pool->memory_region = calloc(1, (sizeof(struct util_buf_t) + size));
	if(!buf_pool->memory_region) {
		free(buf_pool);
		return NULL;
	}

	curr = (struct util_buf_t *)buf_pool->memory_region;
	buf_pool->head = curr;
	for (i = 0; i < num - 1; i++) {
		next = (struct util_buf_t *)((char *)curr + size + sizeof(struct util_buf_t));
		curr->next = next;
		curr->pool = parent_pool ? parent_pool : buf_pool;
		curr = curr->next;
	}
	curr->next = NULL;
	curr->pool = parent_pool ? parent_pool : buf_pool;
	return buf_pool;
}

struct util_buf_pool_t *util_buf_pool_create(size_t num, size_t size)
{
	struct util_buf_pool_t *buf_pool;
	buf_pool = create_buf_pool(num, size, NULL);
	return buf_pool;
}

static void *util_buf_pool_get_head(struct util_buf_pool_t *pool)
{
	void *buf;
	struct util_buf_t *curr;

	curr = pool->head;
	pool->head = curr->next;
	buf = curr->data;
	return buf;
}

void *util_buf_get_safe(struct util_buf_pool_t *pool)
{
	void *buf;
	struct util_buf_pool_t *curr_pool;

	if (pool->head) {
		buf = util_buf_pool_get_head(pool);
		goto fn_exit;
	}

	curr_pool = pool;
	while (curr_pool->next)
		curr_pool = curr_pool->next;
    
	curr_pool->next = create_buf_pool(pool->num, pool->size, pool);
	pool->head = curr_pool->next->head;
	buf = util_buf_pool_get_head(pool);

fn_exit:    
	return buf;
}


void *util_buf_get(struct util_buf_pool_t *pool)
{
	void *buf;
	pthread_mutex_lock(&pool->lock);
	buf = util_buf_get_safe(pool);
	pthread_mutex_unlock(&pool->lock);
	return buf;
}

void util_buf_release_safe(void *buf)
{
	struct util_buf_t *curr_buf;
	curr_buf = container_of(buf, struct util_buf_t, data);
	curr_buf->next = curr_buf->pool->head;
	curr_buf->pool->head = curr_buf;
}

void util_buf_release(void *buf)
{
	struct util_buf_t *curr_buf;

	curr_buf = container_of(buf, struct util_buf_t, data);
	pthread_mutex_lock(&curr_buf->pool->lock);
	curr_buf->next = curr_buf->pool->head;
	curr_buf->pool->head = curr_buf;
	pthread_mutex_unlock(&curr_buf->pool->lock);
}

void util_buf_pool_destroy(struct util_buf_pool_t *pool)
{
	if (pool->next)
		util_buf_pool_destroy(pool->next);

	free(pool->memory_region);
	free(pool);
}
