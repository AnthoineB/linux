/*
 * Copyright (c) 2016 Citrix Systems Inc.
 * Copyright (c) 2002-2005, K A Fraser
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation; or, when distributed
 * separately from the Linux kernel or incorporated into other
 * software packages, subject to the following license:
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this source file (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy, modify,
 * merge, publish, distribute, sublicense, and/or sell copies of the Software,
 * and to permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#include "common.h"

#include <linux/kthread.h>

#include <xen/xen.h>
#include <xen/events.h>

static bool xenvif_rx_ring_slots_available(struct xenvif_queue *queue)
{
	RING_IDX prod, cons;
	struct sk_buff *skb;
	int needed;

	skb = skb_peek(&queue->rx_queue);
	if (!skb)
		return false;

	needed = DIV_ROUND_UP(skb->len, XEN_PAGE_SIZE);
	if (skb_is_gso(skb))
		needed++;
	if (skb->sw_hash)
		needed++;

	do {
		prod = queue->rx.sring->req_prod;
		cons = queue->rx.req_cons;

		if (prod - cons >= needed)
			return true;

		queue->rx.sring->req_event = prod + 1;

		/* Make sure event is visible before we check prod
		 * again.
		 */
		mb();
	} while (queue->rx.sring->req_prod != prod);

	return false;
}

void xenvif_rx_queue_tail(struct xenvif_queue *queue, struct sk_buff *skb)
{
	unsigned long flags;

	spin_lock_irqsave(&queue->rx_queue.lock, flags);

	__skb_queue_tail(&queue->rx_queue, skb);

	queue->rx_queue_len += skb->len;
	if (queue->rx_queue_len > queue->rx_queue_max) {
		struct net_device *dev = queue->vif->dev;

		netif_tx_stop_queue(netdev_get_tx_queue(dev, queue->id));
	}

	spin_unlock_irqrestore(&queue->rx_queue.lock, flags);
}

static struct sk_buff *xenvif_rx_dequeue(struct xenvif_queue *queue)
{
	struct sk_buff *skb;

	spin_lock_irq(&queue->rx_queue.lock);

	skb = __skb_dequeue(&queue->rx_queue);
	if (skb)
		queue->rx_queue_len -= skb->len;

	spin_unlock_irq(&queue->rx_queue.lock);

	return skb;
}

static void xenvif_rx_queue_maybe_wake(struct xenvif_queue *queue)
{
	spin_lock_irq(&queue->rx_queue.lock);

	if (queue->rx_queue_len < queue->rx_queue_max) {
		struct net_device *dev = queue->vif->dev;

		netif_tx_wake_queue(netdev_get_tx_queue(dev, queue->id));
	}

	spin_unlock_irq(&queue->rx_queue.lock);
}

static void xenvif_rx_queue_purge(struct xenvif_queue *queue)
{
	struct sk_buff *skb;

	while ((skb = xenvif_rx_dequeue(queue)) != NULL)
		kfree_skb(skb);
}

static void xenvif_rx_queue_drop_expired(struct xenvif_queue *queue)
{
	struct sk_buff *skb;

	for (;;) {
		skb = skb_peek(&queue->rx_queue);
		if (!skb)
			break;
		if (time_before(jiffies, XENVIF_RX_CB(skb)->expires))
			break;
		xenvif_rx_dequeue(queue);
		kfree_skb(skb);
	}
}

struct netrx_pending_operations {
	unsigned map_prod, map_cons;
	unsigned int copy_prod, copy_cons;
	unsigned int meta_prod, meta_cons;
	struct gnttab_copy *copy;
	struct xenvif_rx_meta *meta;
	int copy_off;
	grant_ref_t copy_gref;
	struct page *copy_page;
	unsigned copy_done;
};

static void xenvif_create_rx_map_op(struct xenvif_queue *queue,
				    struct gnttab_map_grant_ref *mop,
				    grant_ref_t ref,
				    struct page *page)
{
	queue->rx_pages_to_map[mop - queue->rx_map_ops] = page;
	gnttab_set_map_op(mop,
			  (unsigned long)page_to_kaddr(page),
			  GNTMAP_host_map,
			  ref, queue->vif->domid);
}

static struct page *get_next_rx_page(struct xenvif_queue *queue,
				     struct netrx_pending_operations *npo)
{
	struct persistent_gnt_tree *tree = &queue->rx_gnts_tree;
	struct persistent_gnt *gnt;
	struct page *page = NULL;

	gnt = get_persistent_gnt(tree, npo->copy_gref);
	BUG_ON(IS_ERR(gnt));

	if (likely(gnt)) {
		page = gnt->page;
		put_persistent_gnt(tree, gnt);
		npo->copy_done++;
		return page;
	}

	/* We couldn't find a match for the gref in the tree.
	 * Map the page and add it to the tree. This page won't
	 * be used for copying the packet but instead we will rely
	 * grant copy. On the second time the gref is requested, the
	 * persistent grant will be used instead.
	 */
	if (!get_free_page(tree, &page)) {
		struct gnttab_map_grant_ref *mop;

		mop = queue->rx_map_ops + npo->map_prod++;
		xenvif_create_rx_map_op(queue, mop, npo->copy_gref, page);
	}

	return NULL;
}

static struct xenvif_rx_meta *get_next_rx_buffer(
	struct xenvif_queue *queue,
	struct netrx_pending_operations *npo)
{
	struct xenvif_rx_meta *meta;
	struct xen_netif_rx_request req;

	RING_COPY_REQUEST(&queue->rx, queue->rx.req_cons++, &req);

	meta = npo->meta + npo->meta_prod++;
	meta->gso_type = XEN_NETIF_GSO_TYPE_NONE;
	meta->gso_size = 0;
	meta->size = 0;
	meta->id = req.id;

	npo->copy_off = 0;
	npo->copy_gref = req.gref;
	npo->copy_page = NULL;
	if (queue->vif->persistent_grants)
		npo->copy_page = get_next_rx_page(queue, npo);
	return meta;
}

static void xenvif_rx_copy_page(struct xenvif_queue *queue,
				struct netrx_pending_operations *npo,
				unsigned long gfn, unsigned len,
				unsigned offset)
{
	struct gnttab_copy *copy_gop;
	struct xen_page_foreign *foreign = xen_page_foreign(page);

	if (likely(npo->copy_page)) {
		memcpy(page_address(npo->copy_page) + npo->copy_off,
		       page_to_kaddr(page) + offset, len);
		return;
	}

	/* No persistent grant found, so we rely on grant copy
	 */
	copy_gop = npo->copy + npo->copy_prod++;
	copy_gop->flags = GNTCOPY_dest_gref;
	copy_gop->len = len;

	if (foreign) {
		copy_gop->source.domid = foreign->domid;
		copy_gop->source.u.ref = foreign->gref;
		copy_gop->flags |= GNTCOPY_source_gref;
	} else {
		copy_gop->source.domid = DOMID_SELF;
		copy_gop->source.u.gmfn = gfn;
	}
	copy_gop->source.offset = offset;

	copy_gop->dest.domid = queue->vif->domid;
	copy_gop->dest.offset = npo->copy_off;
	copy_gop->dest.u.ref = npo->copy_gref;
}

struct gop_frag_copy {
	struct xenvif_queue *queue;
	struct netrx_pending_operations *npo;
	struct xenvif_rx_meta *meta;
	int head;
	int gso_type;
	int protocol;
	int hash_present;

	struct page *page;
};

static void xenvif_setup_copy_gop(unsigned long gfn,
				  unsigned int offset,
				  unsigned int *len,
				  struct gop_frag_copy *info)
{
	struct gnttab_copy *copy_gop;
	struct xen_page_foreign *foreign;
	/* Convenient aliases */
	struct xenvif_queue *queue = info->queue;
	struct netrx_pending_operations *npo = info->npo;
	struct page *page = info->page;

	WARN_ON(npo->copy_off > MAX_BUFFER_OFFSET);

	if (npo->copy_off == MAX_BUFFER_OFFSET)
		info->meta = get_next_rx_buffer(queue, npo);

	if (npo->copy_off + *len > MAX_BUFFER_OFFSET)
		*len = MAX_BUFFER_OFFSET - npo->copy_off;

	xenvif_rx_copy_page(queue, npo, gfn, *len, offset);

	npo->copy_off += *len;
	info->meta->size += *len;

	if (!info->head)
		return;

	/* Leave a gap for the GSO descriptor. */
	if ((1 << info->gso_type) & queue->vif->gso_mask)
		queue->rx.req_cons++;

	/* Leave a gap for the hash extra segment. */
	if (info->hash_present)
		queue->rx.req_cons++;

	info->head = 0; /* There must be something in this buffer now */
}

static void xenvif_gop_frag_copy_grant(unsigned long gfn,
				       unsigned int offset,
				       unsigned int len,
				       void *data)
{
	unsigned int bytes;

	while (len) {
		bytes = len;
		xenvif_setup_copy_gop(gfn, offset, &bytes, data);
		offset += bytes;
		len -= bytes;
	}
}

/* Set up the grant operations for this fragment. If it's a flipping
 * interface, we also set up the unmap request from here.
 */
static void xenvif_gop_frag_copy(struct xenvif_queue *queue,
				 struct sk_buff *skb,
				 struct netrx_pending_operations *npo,
				 struct page *page, unsigned long size,
				 unsigned long offset, int *head)
{
	struct gop_frag_copy info = {
		.queue = queue,
		.npo = npo,
		.head = *head,
		.gso_type = XEN_NETIF_GSO_TYPE_NONE,
		/* xenvif_set_skb_hash() will have either set a s/w
		 * hash or cleared the hash depending on
		 * whether the the frontend wants a hash for this skb.
		 */
		.hash_present = skb->sw_hash,
	};
	unsigned long bytes;

	if (skb_is_gso(skb)) {
		if (skb_shinfo(skb)->gso_type & SKB_GSO_TCPV4)
			info.gso_type = XEN_NETIF_GSO_TYPE_TCPV4;
		else if (skb_shinfo(skb)->gso_type & SKB_GSO_TCPV6)
			info.gso_type = XEN_NETIF_GSO_TYPE_TCPV6;
	}

	/* Data must not cross a page boundary. */
	WARN_ON(size + offset > (PAGE_SIZE << compound_order(page)));

	info.meta = npo->meta + npo->meta_prod - 1;

	/* Skip unused frames from start of page */
	page += offset >> PAGE_SHIFT;
	offset &= ~PAGE_MASK;

	while (size > 0) {
		WARN_ON(offset >= PAGE_SIZE);

		bytes = PAGE_SIZE - offset;
		if (bytes > size)
			bytes = size;

		info.page = page;
		gnttab_foreach_grant_in_range(page, offset, bytes,
					      xenvif_gop_frag_copy_grant,
					      &info);
		size -= bytes;
		offset = 0;

		/* Next page */
		if (size) {
			WARN_ON(!PageCompound(page));
			page++;
		}
	}

	*head = info.head;
}

/* Prepare an SKB to be transmitted to the frontend.
 *
 * This function is responsible for allocating grant operations, meta
 * structures, etc.
 *
 * It returns the number of meta structures consumed. The number of
 * ring slots used is always equal to the number of meta slots used
 * plus the number of GSO descriptors used. Currently, we use either
 * zero GSO descriptors (for non-GSO packets) or one descriptor (for
 * frontend-side LRO).
 */
static int xenvif_gop_skb(struct sk_buff *skb,
			  struct netrx_pending_operations *npo,
			  struct xenvif_queue *queue)
{
	struct xenvif *vif = netdev_priv(skb->dev);
	int nr_frags = skb_shinfo(skb)->nr_frags;
	int i;
	struct xen_netif_rx_request req;
	struct xenvif_rx_meta *meta;
	unsigned char *data;
	int head = 1;
	int old_meta_prod;
	int gso_type;

	old_meta_prod = npo->meta_prod;

	gso_type = XEN_NETIF_GSO_TYPE_NONE;
	if (skb_is_gso(skb)) {
		if (skb_shinfo(skb)->gso_type & SKB_GSO_TCPV4)
			gso_type = XEN_NETIF_GSO_TYPE_TCPV4;
		else if (skb_shinfo(skb)->gso_type & SKB_GSO_TCPV6)
			gso_type = XEN_NETIF_GSO_TYPE_TCPV6;
	}

	/* Set up a GSO prefix descriptor, if necessary */
	if ((1 << gso_type) & vif->gso_prefix_mask) {
		RING_COPY_REQUEST(&queue->rx, queue->rx.req_cons++, &req);
		meta = npo->meta + npo->meta_prod++;
		meta->gso_type = gso_type;
		meta->gso_size = skb_shinfo(skb)->gso_size;
		meta->size = 0;
		meta->id = req.id;
	}

	RING_COPY_REQUEST(&queue->rx, queue->rx.req_cons++, &req);
	meta = npo->meta + npo->meta_prod++;

	if ((1 << gso_type) & vif->gso_mask) {
		meta->gso_type = gso_type;
		meta->gso_size = skb_shinfo(skb)->gso_size;
	} else {
		meta->gso_type = XEN_NETIF_GSO_TYPE_NONE;
		meta->gso_size = 0;
	}

	meta->size = 0;
	meta->id = req.id;
	npo->copy_off = 0;
	npo->copy_gref = req.gref;
	if (queue->vif->persistent_grants)
		npo->copy_page = get_next_rx_page(queue, npo);

	data = skb->data;
	while (data < skb_tail_pointer(skb)) {
		unsigned int offset = offset_in_page(data);
		unsigned int len = PAGE_SIZE - offset;

		if (data + len > skb_tail_pointer(skb))
			len = skb_tail_pointer(skb) - data;

		xenvif_gop_frag_copy(queue, skb, npo,
				     virt_to_page(data), len, offset, &head);
		data += len;
	}

	for (i = 0; i < nr_frags; i++) {
		xenvif_gop_frag_copy(queue, skb, npo,
				     skb_frag_page(&skb_shinfo(skb)->frags[i]),
				     skb_frag_size(&skb_shinfo(skb)->frags[i]),
				     skb_shinfo(skb)->frags[i].page_offset,
				     &head);
	}

	return npo->meta_prod - old_meta_prod;
}

/*
 * Called to check if the grant maps succeded, and also adding
 * them to the grant tree. If some of the grants already exist in the tree
 * it will unmap those.
 */
static void xenvif_check_mop(struct xenvif_queue *queue, int nr_mops,
			     struct netrx_pending_operations *npo)
{
	struct persistent_gnt_tree *tree = &queue->rx_gnts_tree;
	struct gnttab_map_grant_ref *gop_map;
	struct page *page;
	int i;

	for (i = 0; i < nr_mops; i++) {
		struct persistent_gnt *persistent_gnt;

		gop_map = queue->rx_map_ops + npo->map_cons++;
		page = virt_to_page(gop_map->host_addr);

		if (gop_map->status != GNTST_okay) {
			if (net_ratelimit())
				netdev_err(queue->vif->dev,
					   "Bad status %d from map to DOM%d.\n",
					   gop_map->status, queue->vif->domid);
			put_free_pages(tree, &page, 1);
			continue;
		}

		persistent_gnt = xenvif_pgrant_new(tree, gop_map);
		if (unlikely(!persistent_gnt)) {
			netdev_err(queue->vif->dev,
				   "Couldn't add gref to the tree! ref: %d",
				   gop_map->ref);
			xenvif_page_unmap(queue, gop_map->handle, &page);
			put_free_pages(tree, &page, 1);
			kfree(persistent_gnt);
			persistent_gnt = NULL;
			continue;
		}

		put_persistent_gnt(tree, persistent_gnt);
	}
}

/* This is a twin to xenvif_gop_skb.  Assume that xenvif_gop_skb was
 * used to set up the operations on the top of
 * netrx_pending_operations, which have since been done.  Check that
 * they didn't give any errors and advance over them.
 */
static int xenvif_check_gop(struct xenvif_queue *queue, int nr_meta_slots,
			    struct netrx_pending_operations *npo)
{
	struct gnttab_copy     *copy_op;
	int status = XEN_NETIF_RSP_OKAY;
	int i;

	nr_meta_slots -= npo->copy_done;
	if (npo->map_prod)
		xenvif_check_mop(queue,
				 npo->map_prod - npo->map_cons,
				 npo);

	for (i = 0; i < nr_meta_slots; i++) {
		copy_op = npo->copy + npo->copy_cons++;
		if (copy_op->status != GNTST_okay) {
			netdev_dbg(queue->vif->dev,
				   "Bad status %d from copy to DOM%d.\n",
				   copy_op->status, queue->vif->domid);
			status = XEN_NETIF_RSP_ERROR;
		}
	}

	return status;
}

static struct xen_netif_rx_response *make_rx_response(
	struct xenvif_queue *queue, u16 id, s8 st, u16 offset, u16 size,
	u16 flags)
{
	RING_IDX i = queue->rx.rsp_prod_pvt;
	struct xen_netif_rx_response *resp;

	resp = RING_GET_RESPONSE(&queue->rx, i);
	resp->offset     = offset;
	resp->flags      = flags;
	resp->id         = id;
	resp->status     = (s16)size;
	if (st < 0)
		resp->status = (s16)st;

	queue->rx.rsp_prod_pvt = ++i;

	return resp;
}

static void xenvif_add_frag_responses(struct xenvif_queue *queue,
				      int status,
				      struct xenvif_rx_meta *meta,
				      int nr_meta_slots)
{
	int i;
	unsigned long offset;

	/* No fragments used */
	if (nr_meta_slots <= 1)
		return;

	nr_meta_slots--;

	for (i = 0; i < nr_meta_slots; i++) {
		int flags;

		if (i == nr_meta_slots - 1)
			flags = 0;
		else
			flags = XEN_NETRXF_more_data;

		offset = 0;
		make_rx_response(queue, meta[i].id, status, offset,
				 meta[i].size, flags);
	}
}

static void xenvif_rx_build_gops(struct xenvif_queue *queue,
				 struct netrx_pending_operations *npo,
				 struct sk_buff *skb)
{
        queue->last_rx_time = jiffies;

        XENVIF_RX_CB(skb)->meta_slots_used = xenvif_gop_skb(skb, &npo, queue);
}

static bool xenvif_rx_submit(struct xenvif_queue *queue,
			     struct netrx_pending_operations *npo,
			     struct sk_buff *skb)
{
	struct xenvif *vif = queue->vif;
	s8 status;
	u16 flags;
	struct xen_netif_rx_response *resp;
	LIST_HEAD(notify);
	int ret;
	unsigned long offset;
	struct xen_netif_extra_info *extra = NULL;

	if ((1 << queue->meta[npo->meta_cons].gso_type) &
	    queue->vif->gso_prefix_mask) {
		resp = RING_GET_RESPONSE(&queue->rx,
					 queue->rx.rsp_prod_pvt++);

		resp->flags = XEN_NETRXF_gso_prefix | XEN_NETRXF_more_data;

		resp->offset = queue->meta[npo->meta_cons].gso_size;
		resp->id = queue->meta[npo->meta_cons].id;
		resp->status = XENVIF_RX_CB(skb)->meta_slots_used;

		npo->meta_cons++;
		XENVIF_RX_CB(skb)->meta_slots_used--;
	}

	queue->stats.tx_bytes += skb->len;
	queue->stats.tx_packets++;

	status = xenvif_check_gop(queue,
				  XENVIF_RX_CB(skb)->meta_slots_used,
				  npo);

	if (XENVIF_RX_CB(skb)->meta_slots_used == 1)
		flags = 0;
	else
		flags = XEN_NETRXF_more_data;

	if (skb->ip_summed == CHECKSUM_PARTIAL) /* local packet? */
		flags |= XEN_NETRXF_csum_blank | XEN_NETRXF_data_validated;
	else if (skb->ip_summed == CHECKSUM_UNNECESSARY)
		/* remote but checksummed. */
		flags |= XEN_NETRXF_data_validated;

	offset = 0;
	resp = make_rx_response(queue, queue->meta[npo->meta_cons].id,
				status, offset,
				queue->meta[npo->meta_cons].size,
				flags);

	if ((1 << queue->meta[npo->meta_cons].gso_type) &
	    queue->vif->gso_mask) {
		extra = (struct xen_netif_extra_info *)
			RING_GET_RESPONSE(&queue->rx,
					  queue->rx.rsp_prod_pvt++);

		resp->flags |= XEN_NETRXF_extra_info;

		extra->u.gso.type = queue->meta[npo->meta_cons].gso_type;
		extra->u.gso.size = queue->meta[npo->meta_cons].gso_size;
		extra->u.gso.pad = 0;
		extra->u.gso.features = 0;

		extra->type = XEN_NETIF_EXTRA_TYPE_GSO;
		extra->flags = 0;
	}

	if (skb->sw_hash) {
		/* Since the skb got here via xenvif_select_queue()
		 * we know that the hash has been re-calculated
		 * according to a configuration set by the frontend
		 * and therefore we know that it is legitimate to
		 * pass it to the frontend.
		 */
		if (resp->flags & XEN_NETRXF_extra_info)
			extra->flags |= XEN_NETIF_EXTRA_FLAG_MORE;
		else
			resp->flags |= XEN_NETRXF_extra_info;

		extra = (struct xen_netif_extra_info *)
			RING_GET_RESPONSE(&queue->rx,
					  queue->rx.rsp_prod_pvt++);

		extra->u.hash.algorithm =
			XEN_NETIF_CTRL_HASH_ALGORITHM_TOEPLITZ;

		if (skb->l4_hash)
			extra->u.hash.type =
				skb->protocol == htons(ETH_P_IP) ?
				_XEN_NETIF_CTRL_HASH_TYPE_IPV4_TCP :
				_XEN_NETIF_CTRL_HASH_TYPE_IPV6_TCP;
		else
			extra->u.hash.type =
				skb->protocol == htons(ETH_P_IP) ?
				_XEN_NETIF_CTRL_HASH_TYPE_IPV4 :
				_XEN_NETIF_CTRL_HASH_TYPE_IPV6;

		*(uint32_t *)extra->u.hash.value =
			skb_get_hash_raw(skb);

		extra->type = XEN_NETIF_EXTRA_TYPE_HASH;
		extra->flags = 0;
	}

	xenvif_add_frag_responses(queue, status,
				  queue->meta + npo->meta_cons + 1,
				  XENVIF_RX_CB(skb)->meta_slots_used);

	RING_PUSH_RESPONSES_AND_CHECK_NOTIFY(&queue->rx, ret);

	npo->meta_cons += XENVIF_RX_CB(skb)->meta_slots_used;
	dev_kfree_skb(skb);

	return !!ret;
}

int xenvif_rx_map(struct xenvif_queue *queue, struct sk_buff *skb)
{
	int ret = -EBUSY;
	struct netrx_pending_operations npo = {
		.copy  = queue->grant_copy_op,
		.meta  = queue->meta
	};

	if (!xenvif_rx_ring_slots_available(queue, XEN_NETBK_LEGACY_SLOTS_MAX))
		goto done;

	xenvif_rx_build_gops(queue, &npo, skb);

	BUG_ON(npo.meta_prod > ARRAY_SIZE(queue->meta));
	if (!npo.copy_done && !npo.copy_prod)
		goto done;

	BUG_ON(npo.map_prod > MAX_GRANT_COPY_OPS);
	if (npo.map_prod) {
		ret = gnttab_map_refs(queue->rx_map_ops,
				      NULL,
				      queue->rx_pages_to_map,
				      npo.map_prod);
		BUG_ON(ret);
	}

	BUG_ON(npo.copy_prod > MAX_GRANT_COPY_OPS);
	if (npo.copy_prod)
		gnttab_batch_copy(npo.copy, npo.copy_prod);

	if (xenvif_rx_submit(queue, &npo, skb))
		notify_remote_via_irq(queue->rx_irq);

	ret = 0; /* clear error */
done:
	if (xenvif_queue_stopped(queue))
		xenvif_wake_queue(queue);
	return ret;
}

static void xenvif_rx_action(struct xenvif_queue *queue)
{
	struct sk_buff *skb;
	struct sk_buff_head rxq;
	bool need_to_notify = false;

	struct netrx_pending_operations npo = {
		.copy  = queue->grant_copy_op,
		.meta  = queue->meta,
	};

	skb_queue_head_init(&rxq);

	while (xenvif_rx_ring_slots_available(queue) &&
	       (skb = xenvif_rx_dequeue(queue)) != NULL) {

		xenvif_rx_build_gops(queue, &npo, skb);
		__skb_queue_tail(&rxq, skb);
	}

	WARN_ON(npo.meta_prod > XEN_NETIF_RX_RING_SIZE);
	if (!npo.copy_prod)
		return;

	WARN_ON(npo.copy_prod > MAX_GRANT_COPY_OPS);
	if (npo.copy_prod)
		gnttab_batch_copy(npo.copy, npo.copy_prod);

	while ((skb = __skb_dequeue(&rxq)) != NULL)
		need_to_notify |= xenvif_rx_submit(queue, &npo, skb);

	if (need_to_notify)
		notify_remote_via_irq(queue->rx_irq);
}

static bool xenvif_rx_queue_stalled(struct xenvif_queue *queue)
{
	RING_IDX prod, cons;

	prod = queue->rx.sring->req_prod;
	cons = queue->rx.req_cons;

	return !queue->stalled &&
		prod - cons < 1 &&
		time_after(jiffies,
			   queue->last_rx_time + queue->vif->stall_timeout);
}

static bool xenvif_rx_queue_ready(struct xenvif_queue *queue)
{
	RING_IDX prod, cons;

	prod = queue->rx.sring->req_prod;
	cons = queue->rx.req_cons;

	return queue->stalled && prod - cons >= 1;
}

static bool xenvif_have_rx_work(struct xenvif_queue *queue)
{
	return xenvif_rx_ring_slots_available(queue) ||
		(queue->vif->stall_timeout &&
		 (xenvif_rx_queue_stalled(queue) ||
		  xenvif_rx_queue_ready(queue))) ||
		kthread_should_stop() ||
		queue->vif->disabled;
}

static long xenvif_rx_queue_timeout(struct xenvif_queue *queue)
{
	struct sk_buff *skb;
	long timeout;

	skb = skb_peek(&queue->rx_queue);
	if (!skb)
		return MAX_SCHEDULE_TIMEOUT;

	timeout = XENVIF_RX_CB(skb)->expires - jiffies;
	return timeout < 0 ? 0 : timeout;
}

/* Wait until the guest Rx thread has work.
 *
 * The timeout needs to be adjusted based on the current head of the
 * queue (and not just the head at the beginning).  In particular, if
 * the queue is initially empty an infinite timeout is used and this
 * needs to be reduced when a skb is queued.
 *
 * This cannot be done with wait_event_timeout() because it only
 * calculates the timeout once.
 */
static void xenvif_wait_for_rx_work(struct xenvif_queue *queue)
{
	DEFINE_WAIT(wait);

	if (xenvif_have_rx_work(queue))
		return;

	for (;;) {
		long ret;

		prepare_to_wait(&queue->wq, &wait, TASK_INTERRUPTIBLE);
		if (xenvif_have_rx_work(queue))
			break;
		ret = schedule_timeout(xenvif_rx_queue_timeout(queue));
		if (!ret)
			break;
	}
	finish_wait(&queue->wq, &wait);
}

static void xenvif_queue_carrier_off(struct xenvif_queue *queue)
{
	struct xenvif *vif = queue->vif;

	queue->stalled = true;

	/* At least one queue has stalled? Disable the carrier. */
	spin_lock(&vif->lock);
	if (vif->stalled_queues++ == 0) {
		netdev_info(vif->dev, "Guest Rx stalled");
		netif_carrier_off(vif->dev);
	}
	spin_unlock(&vif->lock);
}

static void xenvif_queue_carrier_on(struct xenvif_queue *queue)
{
	struct xenvif *vif = queue->vif;

	queue->last_rx_time = jiffies; /* Reset Rx stall detection. */
	queue->stalled = false;

	/* All queues are ready? Enable the carrier. */
	spin_lock(&vif->lock);
	if (--vif->stalled_queues == 0) {
		netdev_info(vif->dev, "Guest Rx ready");
		netif_carrier_on(vif->dev);
	}
	spin_unlock(&vif->lock);
}

int xenvif_kthread_guest_rx(void *data)
{
	struct xenvif_queue *queue = data;
	struct xenvif *vif = queue->vif;

	if (!vif->stall_timeout)
		xenvif_queue_carrier_on(queue);

	for (;;) {
		xenvif_wait_for_rx_work(queue);

		if (kthread_should_stop())
			break;

		/* This frontend is found to be rogue, disable it in
		 * kthread context. Currently this is only set when
		 * netback finds out frontend sends malformed packet,
		 * but we cannot disable the interface in softirq
		 * context so we defer it here, if this thread is
		 * associated with queue 0.
		 */
		if (unlikely(vif->disabled && queue->id == 0)) {
			xenvif_carrier_off(vif);
			break;
		}

		if (!skb_queue_empty(&queue->rx_queue))
			xenvif_rx_action(queue);

		/* If the guest hasn't provided any Rx slots for a
		 * while it's probably not responsive, drop the
		 * carrier so packets are dropped earlier.
		 */
		if (vif->stall_timeout) {
			if (xenvif_rx_queue_stalled(queue))
				xenvif_queue_carrier_off(queue);
			else if (xenvif_rx_queue_ready(queue))
				xenvif_queue_carrier_on(queue);
		}

		/* Queued packets may have foreign pages from other
		 * domains.  These cannot be queued indefinitely as
		 * this would starve guests of grant refs and transmit
		 * slots.
		 */
		xenvif_rx_queue_drop_expired(queue);

		xenvif_rx_queue_maybe_wake(queue);

		cond_resched();
	}

	/* Bin any remaining skbs */
	xenvif_rx_queue_purge(queue);

	return 0;
}
