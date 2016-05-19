/*
 * Copyright (c) 2014 Intel Corporation. All rights reserved.
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

#ifndef FI_TRIGGER_H
#define FI_TRIGGER_H

#include <stdint.h>
#include <stddef.h>
#include <rdma/fabric.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
* FI_TRIGGER_THRESHOLD
* 	- looks only at trig_cntr; operates like normal triggered operation

* FI_TRIGGER_COMPLETION
*	- looks only at cmp_cntr; increments the cmp_cntr after this operation
* 	is completed
*
* FI_TRIGGER_THRESHOLD_COMPLETION
*	- looks for both trig_cntr and cmp_cntr; operates like a normal	triggered
*	operation, and increments the cmp_cntr after the operation is completed
*/

enum fi_trigger_event {
	FI_TRIGGER_THRESHOLD,
	FI_TRIGGER_COMPLETION,
	FI_TRIGGER_THRESHOLD_COMPLETION,
};

struct fi_trigger_threshold {
	struct fid_cntr		*trig_cntr;
	struct fid_cntr		*cmp_cntr;
	size_t			threshold;
};

#ifdef FABRIC_DIRECT
#include <rdma/fi_direct_trigger.h>
#endif

#ifndef FABRIC_DIRECT_TRIGGER

/* Size must match struct fi_context */
struct fi_triggered_context {
	enum fi_trigger_event	event_type;
	union {
		struct fi_trigger_threshold	threshold;
		void				*internal[2];
	} trigger;
};

#endif


#ifdef __cplusplus
}
#endif

#endif /* FI_TRIGGER_H */
