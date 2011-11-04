/*
 * Copyright (c) 2007-2011 Atheros Communications Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
#include "usb.h"
#include "debug.h"
#include "cfg80211.h"

/* constants */
#define VENDOR_ATHR             0x0CF3

#define TX_URB_COUNT            32
#define RX_URB_COUNT            32
#define ATH6KL_USB_RX_BUFFER_SIZE  1700

/* tx/rx pipes for usb */
enum ATH6KL_USB_PIPE_ID {
	HIF_TX_CTRL_PIPE = 0,
	HIF_TX_DATA_LP_PIPE,
	HIF_TX_DATA_MP_PIPE,
	HIF_TX_DATA_HP_PIPE,
	HIF_RX_CTRL_PIPE,
	HIF_RX_DATA_PIPE,
	HIF_RX_DATA2_PIPE,
	HIF_RX_INT_PIPE,
	ATH6KL_USB_PIPE_MAX
};


#define ATH6KL_USB_PIPE_INVALID ATH6KL_USB_PIPE_MAX

struct ath6kl_usb_pipe {
	struct list_head urb_list_head;
	struct usb_anchor urb_submitted;
	u32 urb_alloc;
	u32 urb_cnt;
	u32 urb_cnt_thresh;
	unsigned int usb_pipe_handle;
	u32 flags;
	u8 ep_address;
	u8 logical_pipe_num;
	struct ath6kl_usb *ar_usb;
	u16 max_packet_size;
	struct work_struct io_complete_work;
	struct sk_buff_head io_comp_queue;
	struct usb_endpoint_descriptor *ep_desc;
};

#define ATH6KL_USB_PIPE_FLAG_TX    (1 << 0)

/* usb device object */
struct ath6kl_usb {
	spinlock_t cs_lock;
	spinlock_t tx_lock;
	spinlock_t rx_lock;
	struct hif_callbacks htc_callbacks;
	struct usb_device *udev;
	struct usb_interface *interface;
	struct ath6kl_usb_pipe pipes[ATH6KL_USB_PIPE_MAX];
	u8 surprise_removed;
	u8 *diag_cmd_buffer;
	u8 *diag_resp_buffer;
	struct ath6kl *claimed_context;
};

/* usb urb object */
struct hif_urb_context {
	struct list_head link;
	struct ath6kl_usb_pipe *pipe;
	struct sk_buff *buf;
};

/* USB endpoint definitions */
#define USB_EP_ADDR_APP_CTRL_IN          0x81
#define USB_EP_ADDR_APP_DATA_IN          0x82
#define USB_EP_ADDR_APP_DATA2_IN         0x83
#define USB_EP_ADDR_APP_INT_IN           0x84

#define USB_EP_ADDR_APP_CTRL_OUT         0x01
#define USB_EP_ADDR_APP_DATA_LP_OUT      0x02
#define USB_EP_ADDR_APP_DATA_MP_OUT      0x03
#define USB_EP_ADDR_APP_DATA_HP_OUT      0x04

/* diagnostic command defnitions */
#define USB_CONTROL_REQ_SEND_BMI_CMD        1
#define USB_CONTROL_REQ_RECV_BMI_RESP       2
#define USB_CONTROL_REQ_DIAG_CMD            3
#define USB_CONTROL_REQ_DIAG_RESP           4

#define USB_CTRL_DIAG_CC_READ               0
#define USB_CTRL_DIAG_CC_WRITE              1

struct usb_ctrl_diag_cmd_write {
	u32 cmd;
	u32 address;
	u32 value;
	u32 _pad[1];
} __packed;

struct usb_ctrl_diag_cmd_read {
	u32 cmd;
	u32 address;
} __packed;

struct usb_ctrl_diag_resp_read {
	u32 value;
} __packed;

#define USB_CTRL_MAX_DIAG_CMD_SIZE  (sizeof(struct usb_ctrl_diag_cmd_write))
#define USB_CTRL_MAX_DIAG_RESP_SIZE (sizeof(struct usb_ctrl_diag_resp_read))

/* function declarations */
static void ath6kl_usb_recv_complete(struct urb *urb);

#define ATH6KL_USB_IS_BULK_EP(attr) (((attr) & 3) == 0x02)
#define ATH6KL_USB_IS_INT_EP(attr)  (((attr) & 3) == 0x03)
#define ATH6KL_USB_IS_ISOC_EP(attr)  (((attr) & 3) == 0x01)
#define ATH6KL_USB_IS_DIR_IN(addr)  ((addr) & 0x80)

/* pipe/urb operations */
static struct hif_urb_context *ath6kl_usb_alloc_urb_from_pipe(struct ath6kl_usb_pipe
							   *pipe)
{
	struct hif_urb_context *urb_context = NULL;
	unsigned long flags;

	spin_lock_irqsave(&pipe->ar_usb->cs_lock, flags);
	if (!list_empty(&pipe->urb_list_head)) {
		urb_context =
		    list_first_entry(&pipe->urb_list_head,
				     struct hif_urb_context, link);
		list_del(&urb_context->link);
		pipe->urb_cnt--;
	}
	spin_unlock_irqrestore(&pipe->ar_usb->cs_lock, flags);

	return urb_context;
}

static void ath6kl_usb_free_urb_to_pipe(struct ath6kl_usb_pipe *pipe,
				     struct hif_urb_context *urb_context)
{
	unsigned long flags;

	spin_lock_irqsave(&pipe->ar_usb->cs_lock, flags);
	pipe->urb_cnt++;

	list_add(&urb_context->link, &pipe->urb_list_head);
	spin_unlock_irqrestore(&pipe->ar_usb->cs_lock, flags);
}

static void ath6kl_usb_cleanup_recv_urb(struct hif_urb_context *urb_context)
{
	if (urb_context->buf != NULL) {
		dev_kfree_skb(urb_context->buf);
		urb_context->buf = NULL;
	}

	ath6kl_usb_free_urb_to_pipe(urb_context->pipe, urb_context);
}

static inline struct ath6kl_usb *ath6kl_usb_priv(struct ath6kl *ar)
{
	return ar->hif_priv;
}

/* pipe resource allocation/cleanup */
static int ath6kl_usb_alloc_pipe_resources(struct ath6kl_usb_pipe *pipe, int urb_cnt)
{
	int status = 0;
	int i;
	struct hif_urb_context *urb_context;

	INIT_LIST_HEAD(&pipe->urb_list_head);
	init_usb_anchor(&pipe->urb_submitted);

	for (i = 0; i < urb_cnt; i++) {
		urb_context = (struct hif_urb_context *)
		    kzalloc(sizeof(struct hif_urb_context), GFP_KERNEL);
		if (urb_context == NULL)
			break;

		memset(urb_context, 0, sizeof(struct hif_urb_context));
		urb_context->pipe = pipe;

		/*
		 * we are only allocate the urb contexts here, the actual URB
		 * is allocated from the kernel as needed to do a transaction
		 */
		pipe->urb_alloc++;
		ath6kl_usb_free_urb_to_pipe(pipe, urb_context);
	}
	ath6kl_dbg(ATH6KL_DBG_USB,
		   "ath6kl usb: alloc resources lpipe:%d"
		   "hpipe:0x%X urbs:%d\n",
		   pipe->logical_pipe_num, pipe->usb_pipe_handle,
		   pipe->urb_alloc);

	return status;
}

static void ath6kl_usb_free_pipe_resources(struct ath6kl_usb_pipe *pipe)
{
	struct hif_urb_context *urb_context;

	if (pipe->ar_usb == NULL) {
		/* nothing allocated for this pipe */
		return;
	}

	ath6kl_dbg(ATH6KL_DBG_USB,
		   "ath6kl usb: free resources lpipe:%d"
		   "hpipe:0x%X urbs:%d avail:%d\n",
		   pipe->logical_pipe_num, pipe->usb_pipe_handle,
		   pipe->urb_alloc, pipe->urb_cnt);

	if (pipe->urb_alloc != pipe->urb_cnt) {
		ath6kl_dbg(ATH6KL_DBG_USB,
			   "ath6kl usb: urb leak! lpipe:%d"
			   "hpipe:0x%X urbs:%d avail:%d\n",
			   pipe->logical_pipe_num, pipe->usb_pipe_handle,
			   pipe->urb_alloc, pipe->urb_cnt);
	}

	while (true) {
		urb_context = ath6kl_usb_alloc_urb_from_pipe(pipe);
		if (urb_context == NULL)
			break;
		kfree(urb_context);
	}

}

static void ath6kl_usb_cleanup_pipe_resources(struct ath6kl_usb *device)
{
	int i;

	for (i = 0; i < ATH6KL_USB_PIPE_MAX; i++)
		ath6kl_usb_free_pipe_resources(&device->pipes[i]);

}

static u8 ath6kl_usb_get_logical_pipe_num(struct ath6kl_usb *device,
				       u8 ep_address, int *urb_count)
{
	u8 pipe_num = ATH6KL_USB_PIPE_INVALID;

	switch (ep_address) {
	case USB_EP_ADDR_APP_CTRL_IN:
		pipe_num = HIF_RX_CTRL_PIPE;
		*urb_count = RX_URB_COUNT;
		break;
	case USB_EP_ADDR_APP_DATA_IN:
		pipe_num = HIF_RX_DATA_PIPE;
		*urb_count = RX_URB_COUNT;
		break;
	case USB_EP_ADDR_APP_INT_IN:
		pipe_num = HIF_RX_INT_PIPE;
		*urb_count = RX_URB_COUNT;
		break;
	case USB_EP_ADDR_APP_DATA2_IN:
		pipe_num = HIF_RX_DATA2_PIPE;
		*urb_count = RX_URB_COUNT;
		break;
	case USB_EP_ADDR_APP_CTRL_OUT:
		pipe_num = HIF_TX_CTRL_PIPE;
		*urb_count = TX_URB_COUNT;
		break;
	case USB_EP_ADDR_APP_DATA_LP_OUT:
		pipe_num = HIF_TX_DATA_LP_PIPE;
		*urb_count = TX_URB_COUNT;
		break;
	case USB_EP_ADDR_APP_DATA_MP_OUT:
		pipe_num = HIF_TX_DATA_MP_PIPE;
		*urb_count = TX_URB_COUNT;
		break;
	case USB_EP_ADDR_APP_DATA_HP_OUT:
		pipe_num = HIF_TX_DATA_HP_PIPE;
		*urb_count = TX_URB_COUNT;
		break;
	default:
		/* note: there may be endpoints not currently used */
		break;
	}

	return pipe_num;
}

static int ath6kl_usb_setup_pipe_resources(struct ath6kl_usb *device)
{
	struct usb_interface *interface = device->interface;
	struct usb_host_interface *iface_desc = interface->cur_altsetting;
	struct usb_endpoint_descriptor *endpoint;
	int i;
	int urbcount;
	int status = 0;
	struct ath6kl_usb_pipe *pipe;
	u8 pipe_num;
	ath6kl_dbg(ATH6KL_DBG_USB, "setting up USB Pipes using interface\n");
	/* walk decriptors and setup pipes */
	for (i = 0; i < iface_desc->desc.bNumEndpoints; ++i) {
		endpoint = &iface_desc->endpoint[i].desc;

		if (ATH6KL_USB_IS_BULK_EP(endpoint->bmAttributes)) {
			ath6kl_dbg(ATH6KL_DBG_USB,
				   "%s Bulk Ep:0x%2.2X maxpktsz:%d\n",
				   ATH6KL_USB_IS_DIR_IN
				   (endpoint->bEndpointAddress) ?
				   "RX" : "TX", endpoint->bEndpointAddress,
				   le16_to_cpu(endpoint->wMaxPacketSize));
		} else if (ATH6KL_USB_IS_INT_EP(endpoint->bmAttributes)) {
			ath6kl_dbg(ATH6KL_DBG_USB,
				   "%s Int Ep:0x%2.2X maxpktsz:%d interval:%d\n",
				   ATH6KL_USB_IS_DIR_IN
				   (endpoint->bEndpointAddress) ?
				   "RX" : "TX", endpoint->bEndpointAddress,
				   le16_to_cpu(endpoint->wMaxPacketSize),
				   endpoint->bInterval);
		} else if (ATH6KL_USB_IS_ISOC_EP(endpoint->bmAttributes)) {
			/* TODO for ISO */
			ath6kl_dbg(ATH6KL_DBG_USB,
				   "%s ISOC Ep:0x%2.2X maxpktsz:%d interval:%d\n",
				   ATH6KL_USB_IS_DIR_IN
				   (endpoint->bEndpointAddress) ?
				   "RX" : "TX", endpoint->bEndpointAddress,
				   le16_to_cpu(endpoint->wMaxPacketSize),
				   endpoint->bInterval);
		}
		urbcount = 0;

		pipe_num =
		    ath6kl_usb_get_logical_pipe_num(device,
						 endpoint->bEndpointAddress,
						 &urbcount);
		if (pipe_num == ATH6KL_USB_PIPE_INVALID)
			continue;

		pipe = &device->pipes[pipe_num];
		if (pipe->ar_usb != NULL) {
			/* hmmm..pipe was already setup */
			continue;
		}

		pipe->ar_usb = device;
		pipe->logical_pipe_num = pipe_num;
		pipe->ep_address = endpoint->bEndpointAddress;
		pipe->max_packet_size = le16_to_cpu(endpoint->wMaxPacketSize);

		if (ATH6KL_USB_IS_BULK_EP(endpoint->bmAttributes)) {
			if (ATH6KL_USB_IS_DIR_IN(pipe->ep_address)) {
				pipe->usb_pipe_handle =
				    usb_rcvbulkpipe(device->udev,
						    pipe->ep_address);
			} else {
				pipe->usb_pipe_handle =
				    usb_sndbulkpipe(device->udev,
						    pipe->ep_address);
			}
		} else if (ATH6KL_USB_IS_INT_EP(endpoint->bmAttributes)) {
			if (ATH6KL_USB_IS_DIR_IN(pipe->ep_address)) {
				pipe->usb_pipe_handle =
				    usb_rcvintpipe(device->udev,
						   pipe->ep_address);
			} else {
				pipe->usb_pipe_handle =
				    usb_sndintpipe(device->udev,
						   pipe->ep_address);
			}
		} else if (ATH6KL_USB_IS_ISOC_EP(endpoint->bmAttributes)) {
			/* TODO for ISO */
			if (ATH6KL_USB_IS_DIR_IN(pipe->ep_address)) {
				pipe->usb_pipe_handle =
				    usb_rcvisocpipe(device->udev,
						    pipe->ep_address);
			} else {
				pipe->usb_pipe_handle =
				    usb_sndisocpipe(device->udev,
						    pipe->ep_address);
			}
		}
		pipe->ep_desc = endpoint;

		if (!ATH6KL_USB_IS_DIR_IN(pipe->ep_address))
			pipe->flags |= ATH6KL_USB_PIPE_FLAG_TX;

		status = ath6kl_usb_alloc_pipe_resources(pipe, urbcount);
		if (status != 0)
			break;

	}

	return status;
}

/* pipe operations */
static void ath6kl_usb_post_recv_transfers(struct ath6kl_usb_pipe *recv_pipe,
					int buffer_length)
{
	struct hif_urb_context *urb_context;
	u8 *data;
	u32 len;
	struct urb *urb;
	int usb_status;

	while (1) {

		urb_context = ath6kl_usb_alloc_urb_from_pipe(recv_pipe);
		if (urb_context == NULL)
			break;

		urb_context->buf = dev_alloc_skb(buffer_length);
		if (urb_context->buf == NULL) {
			goto err_cleanup_urb;
		}

		data = urb_context->buf->data;
		len = urb_context->buf->len;

		urb = usb_alloc_urb(0, GFP_ATOMIC);
		if (urb == NULL) {
			goto err_cleanup_urb;
		}

		usb_fill_bulk_urb(urb,
				  recv_pipe->ar_usb->udev,
				  recv_pipe->usb_pipe_handle,
				  data,
				  buffer_length,
				  ath6kl_usb_recv_complete, urb_context);

		ath6kl_dbg(ATH6KL_DBG_USB_BULK,
			   "ath6kl usb: bulk recv submit:%d, 0x%X"
			   "(ep:0x%2.2X), %d bytes buf:0x%p\n",
			   recv_pipe->logical_pipe_num,
			   recv_pipe->usb_pipe_handle, recv_pipe->ep_address,
			   buffer_length, urb_context->buf);

		usb_anchor_urb(urb, &recv_pipe->urb_submitted);
		usb_status = usb_submit_urb(urb, GFP_ATOMIC);

		if (usb_status) {
			ath6kl_dbg(ATH6KL_DBG_USB_BULK,
				   "ath6kl usb : usb bulk recv failed %d\n",
				   usb_status);
			usb_unanchor_urb(urb);
			usb_free_urb(urb);
			goto err_cleanup_urb;
		}
		usb_free_urb(urb);
	}
	return;

err_cleanup_urb:
	ath6kl_usb_cleanup_recv_urb(urb_context);
	return;
}

static void ath6kl_usb_flush_all(struct ath6kl_usb *device)
{
	int i;

	for (i = 0; i < ATH6KL_USB_PIPE_MAX; i++) {
		if (device->pipes[i].ar_usb != NULL)
			usb_kill_anchored_urbs(&device->pipes[i].urb_submitted);
	}

	/* flushing any pending I/O may schedule work
	 * this call will block until all scheduled work runs to completion */
	flush_scheduled_work();
}

static void ath6kl_usb_start_recv_pipes(struct ath6kl_usb *device)
{
	/*
	 * note: control pipe is no longer used
	 * device->pipes[HIF_RX_CTRL_PIPE].urb_cnt_thresh =
	 *      device->pipes[HIF_RX_CTRL_PIPE].urb_alloc/2;
	 * ath6kl_usb_post_recv_transfers(&device->pipes[HIF_RX_CTRL_PIPE],
	 *       ATH6KL_USB_RX_BUFFER_SIZE);
	 */

	device->pipes[HIF_RX_DATA_PIPE].urb_cnt_thresh =
	    device->pipes[HIF_RX_DATA_PIPE].urb_alloc / 2;
	ath6kl_usb_post_recv_transfers(&device->pipes[HIF_RX_DATA_PIPE],
				    ATH6KL_USB_RX_BUFFER_SIZE);
	/*
	* Disable rxdata2 directly, it will be enabled
	* if FW enable rxdata2
	*/
	if (0) {
		device->pipes[HIF_RX_DATA2_PIPE].urb_cnt_thresh =
		    device->pipes[HIF_RX_DATA2_PIPE].urb_alloc / 2;
		ath6kl_usb_post_recv_transfers(&device->pipes[HIF_RX_DATA2_PIPE],
					    ATH6KL_USB_RX_BUFFER_SIZE);
	}
}

/* hif usb rx/tx completion functions */
static void ath6kl_usb_recv_complete(struct urb *urb)
{
	struct hif_urb_context *urb_context =
	    (struct hif_urb_context *)urb->context;
	int status = 0;
	struct sk_buff *buf = NULL;
	struct ath6kl_usb_pipe *pipe = urb_context->pipe;

	ath6kl_dbg(ATH6KL_DBG_USB_BULK,
		   "%s: recv pipe: %d, stat:%d, len:%d urb:0x%p\n", __func__,
		   pipe->logical_pipe_num, urb->status, urb->actual_length,
		   urb);

	if (urb->status != 0) {
		status = -EIO;
		switch (urb->status) {
		case -ECONNRESET:
		case -ENOENT:
		case -ESHUTDOWN:
			/*
			 * no need to spew these errors when device
			 * removed or urb killed due to driver shutdown
			 */
			status = -ECANCELED;
			break;
		default:
			ath6kl_dbg(ATH6KL_DBG_USB_BULK,
				   "%s recv pipe: %d (ep:0x%2.2X), failed:%d\n",
				   __func__, pipe->logical_pipe_num,
				   pipe->ep_address, urb->status);
			break;
		}
		goto cleanup_recv_urb;
	}
	if (urb->actual_length == 0)
		goto cleanup_recv_urb;

	buf = urb_context->buf;
	/* we are going to pass it up */
	urb_context->buf = NULL;
	skb_put(buf, urb->actual_length);
	/* note: queue implements a lock */
	skb_queue_tail(&pipe->io_comp_queue, buf);
	schedule_work(&pipe->io_complete_work);

cleanup_recv_urb:
	ath6kl_usb_cleanup_recv_urb(urb_context);

	if (status == 0) {
		if (pipe->urb_cnt >= pipe->urb_cnt_thresh) {
			/* our free urbs are piling up, post more transfers */
			ath6kl_usb_post_recv_transfers(pipe,
						    ATH6KL_USB_RX_BUFFER_SIZE);
		}
	}
	return;
}

static void ath6kl_usb_usb_transmit_complete(struct urb *urb)
{
	struct hif_urb_context *urb_context =
	    (struct hif_urb_context *)urb->context;
	struct sk_buff *buf;
	struct ath6kl_usb_pipe *pipe = urb_context->pipe;

	ath6kl_dbg(ATH6KL_DBG_USB_BULK,
			"%s: pipe: %d, stat:%d, len:%d\n",
			__func__, pipe->logical_pipe_num, urb->status,
			urb->actual_length);

	if (urb->status != 0) {
		ath6kl_dbg(ATH6KL_DBG_USB_BULK,
			"%s:  pipe: %d, failed:%d\n",
			__func__, pipe->logical_pipe_num, urb->status);
	}

	buf = urb_context->buf;
	urb_context->buf = NULL;
	ath6kl_usb_free_urb_to_pipe(urb_context->pipe, urb_context);

	/* note: queue implements a lock */
	skb_queue_tail(&pipe->io_comp_queue, buf);
	schedule_work(&pipe->io_complete_work);
}

static void ath6kl_usb_io_comp_work(struct work_struct *work)
{
	struct ath6kl_usb_pipe *pipe =
	    container_of(work, struct ath6kl_usb_pipe, io_complete_work);
	struct sk_buff *buf;
	struct ath6kl_usb *device;

	device = pipe->ar_usb;
	while ((buf = skb_dequeue(&pipe->io_comp_queue))) {
		if (pipe->flags & ATH6KL_USB_PIPE_FLAG_TX) {
			ath6kl_dbg(ATH6KL_DBG_USB_BULK,
				   "ath6kl usb xmit callback buf:0x%p\n", buf);
			device->htc_callbacks.
				tx_completion(device->claimed_context->
					htc_target, buf);
		} else {
			ath6kl_dbg(ATH6KL_DBG_USB_BULK,
				   "ath6kl usb recv callback buf:0x%p\n", buf);
			device->htc_callbacks.
				rx_completion(device->claimed_context->
					htc_target, buf,
					pipe->logical_pipe_num);
		}
	}
}

static void ath6kl_usb_destroy(struct ath6kl_usb *device)
{
	ath6kl_usb_flush_all(device);

	ath6kl_usb_cleanup_pipe_resources(device);

	usb_set_intfdata(device->interface, NULL);

	kfree(device->diag_cmd_buffer);
	kfree(device->diag_resp_buffer);

	kfree(device);
}

static struct ath6kl_usb *ath6kl_usb_create(struct usb_interface *interface)
{
	struct ath6kl_usb *device = NULL;
	struct usb_device *dev = interface_to_usbdev(interface);
	int status = 0;
	int i;
	struct ath6kl_usb_pipe *pipe;

	device = (struct ath6kl_usb *)
	    kzalloc(sizeof(struct ath6kl_usb), GFP_KERNEL);
	if (device == NULL)
		goto fail_ath6kl_usb_create;

	memset(device, 0, sizeof(struct ath6kl_usb));
	usb_set_intfdata(interface, device);
	spin_lock_init(&(device->cs_lock));
	spin_lock_init(&(device->rx_lock));
	spin_lock_init(&(device->tx_lock));
	device->udev = dev;
	device->interface = interface;

	for (i = 0; i < ATH6KL_USB_PIPE_MAX; i++) {
		pipe = &device->pipes[i];
		INIT_WORK(&pipe->io_complete_work,
			  ath6kl_usb_io_comp_work);
		skb_queue_head_init(&pipe->io_comp_queue);
	}

	device->diag_cmd_buffer =
			kzalloc(USB_CTRL_MAX_DIAG_CMD_SIZE, GFP_KERNEL);
	if (device->diag_cmd_buffer == NULL) {
		status = -ENOMEM;
		goto fail_ath6kl_usb_create;
	}
	device->diag_resp_buffer =
		kzalloc(USB_CTRL_MAX_DIAG_RESP_SIZE, GFP_KERNEL);
	if (device->diag_resp_buffer == NULL) {
		status = -ENOMEM;
		goto fail_ath6kl_usb_create;
	}

	status = ath6kl_usb_setup_pipe_resources(device);

fail_ath6kl_usb_create:
	if (status != 0) {
		ath6kl_usb_destroy(device);
		device = NULL;
	}
	return device;
}

static void ath6kl_usb_device_detached(struct usb_interface *interface,
				    u8 surprise_removed)
{
	struct ath6kl_usb *device;

	device = (struct ath6kl_usb *)usb_get_intfdata(interface);
	if (device == NULL)
		return;

	ath6kl_stop_txrx(device->claimed_context);

	device->surprise_removed = surprise_removed;

	/* inform upper layer if it is still interested */
	if (surprise_removed && device->claimed_context != NULL)
		ath6kl_core_cleanup(device->claimed_context);

	ath6kl_usb_destroy(device);
}

/* exported hif usb APIs for htc pipe */
void hif_start(struct ath6kl *ar)
{
	struct ath6kl_usb *device = ath6kl_usb_priv(ar);
	int i;
	ath6kl_usb_start_recv_pipes(device);

	/* set the TX resource avail threshold for each TX pipe */
	for (i = HIF_TX_CTRL_PIPE; i <= HIF_TX_DATA_HP_PIPE; i++) {
		device->pipes[i].urb_cnt_thresh =
		    device->pipes[i].urb_alloc / 2;
	}
}

int hif_send(struct ath6kl *ar, u8 PipeID, struct sk_buff *hdr_buf,
	     struct sk_buff *buf)
{
	int status = 0;
	struct ath6kl_usb *device = ath6kl_usb_priv(ar);
	struct ath6kl_usb_pipe *pipe = &device->pipes[PipeID];
	struct hif_urb_context *urb_context;
	u8 *data;
	u32 len;
	struct urb *urb;
	int usb_status;

	ath6kl_dbg(ATH6KL_DBG_USB_BULK,
			"+%s pipe : %d, buf:0x%p\n",
			__func__, PipeID, buf);

	urb_context = ath6kl_usb_alloc_urb_from_pipe(pipe);

	if (urb_context == NULL) {
		/*
		 * TODO: it is possible to run out of urbs if
		 * 2 endpoints map to the same pipe ID
		 */
		ath6kl_dbg(ATH6KL_DBG_USB_BULK,
			   "%s pipe:%d no urbs left. URB Cnt : %d\n",
			   __func__, PipeID, pipe->urb_cnt);
		status = -ENOMEM;
		goto fail_hif_send;
	}
	urb_context->buf = buf;

	data = buf->data;
	len = buf->len;
	urb = usb_alloc_urb(0, GFP_ATOMIC);
	if (urb == NULL) {
		status = -ENOMEM;
		ath6kl_usb_free_urb_to_pipe(urb_context->pipe,
			urb_context);
		goto fail_hif_send;
	}

	usb_fill_bulk_urb(urb,
			  device->udev,
			  pipe->usb_pipe_handle,
			  data,
			  len,
			  ath6kl_usb_usb_transmit_complete, urb_context);

	if ((len % pipe->max_packet_size) == 0) {
		/* hit a max packet boundary on this pipe */
		urb->transfer_flags |= URB_ZERO_PACKET;
	}

	ath6kl_dbg(ATH6KL_DBG_USB_BULK,
		   "athusb bulk send submit:%d, 0x%X (ep:0x%2.2X), %d bytes\n",
		   pipe->logical_pipe_num, pipe->usb_pipe_handle,
		   pipe->ep_address, len);

	usb_anchor_urb(urb, &pipe->urb_submitted);
	usb_status = usb_submit_urb(urb, GFP_ATOMIC);

	if (usb_status) {
		ath6kl_dbg(ATH6KL_DBG_USB_BULK,
			   "ath6kl usb : usb bulk transmit failed %d\n",
			   usb_status);
		usb_unanchor_urb(urb);
		ath6kl_usb_free_urb_to_pipe(urb_context->pipe,
					 urb_context);
		status = -EINVAL;
	}
	usb_free_urb(urb);

fail_hif_send:
	return status;
}

void hif_stop(struct ath6kl *ar)
{
	struct ath6kl_usb *device = ath6kl_usb_priv(ar);

	ath6kl_usb_flush_all(device);
}

void hif_get_default_pipe(struct ath6kl *ar, u8 *ULPipe, u8 *DLPipe)
{
	*ULPipe = HIF_TX_CTRL_PIPE;
	*DLPipe = HIF_RX_CTRL_PIPE;
}

int hif_map_service_pipe(struct ath6kl *ar, u16 ServiceId, u8 *ULPipe,
			 u8 *DLPipe)
{
	int status = 0;

	switch (ServiceId) {
	case HTC_CTRL_RSVD_SVC:
	case WMI_CONTROL_SVC:
		*ULPipe = HIF_TX_CTRL_PIPE;
		/* due to large control packets, shift to data pipe */
		if (0)
			*DLPipe = HIF_RX_CTRL_PIPE;
		else
			*DLPipe = HIF_RX_DATA_PIPE;
		break;
	case WMI_DATA_BE_SVC:
	case WMI_DATA_BK_SVC:
		*ULPipe = HIF_TX_DATA_LP_PIPE;
		/*
		* Disable rxdata2 directly, it will be enabled
		* if FW enable rxdata2
		*/
		if (1)
			*DLPipe = HIF_RX_DATA_PIPE;
		else
			*DLPipe = HIF_RX_DATA2_PIPE;
		break;
	case WMI_DATA_VI_SVC:
		*ULPipe = HIF_TX_DATA_MP_PIPE;
		/*
		* Disable rxdata2 directly, it will be enabled
		* if FW enable rxdata2
		*/
		if (1)
			*DLPipe = HIF_RX_DATA_PIPE;
		else
			*DLPipe = HIF_RX_DATA2_PIPE;
		break;
	case WMI_DATA_VO_SVC:
		*ULPipe = HIF_TX_DATA_HP_PIPE;
		/*
		* Disable rxdata2 directly, it will be enabled
		* if FW enable rxdata2
		*/
		if (1)
			*DLPipe = HIF_RX_DATA_PIPE;
		else
			*DLPipe = HIF_RX_DATA2_PIPE;
		break;
	default:
		status = -EPERM;
		break;
	}

	return status;
}

void hif_postinit(struct ath6kl *ar,
		void *unused,
		struct hif_callbacks *callbacks)
{
	struct ath6kl_usb *device = ath6kl_usb_priv(ar);

	memcpy(&device->htc_callbacks, callbacks,
	       sizeof(struct hif_callbacks));
}

u16 hif_get_free_queue_number(struct ath6kl *ar, u8 PipeID)
{
	struct ath6kl_usb *device = ath6kl_usb_priv(ar);
	return device->pipes[PipeID].urb_cnt;
}

void hif_detach_htc(struct ath6kl *ar)
{
	struct ath6kl_usb *device = ath6kl_usb_priv(ar);

	ath6kl_usb_flush_all(device);

	memset(&device->htc_callbacks, 0, sizeof(struct hif_callbacks));
}

static int ath6kl_usb_submit_ctrl_out(struct ath6kl_usb *device,
				   u8 req, u16 value, u16 index, void *data,
				   u32 size)
{
	u32 result = 0;
	int ret = 0;
	u8 *buf = NULL;

	if (size > 0) {
		buf = kmalloc(size, GFP_KERNEL);
		if (buf == NULL)
			return -ENOMEM;

		memcpy(buf, (u8 *) data, size);
	}
	result = usb_control_msg(device->udev,
				 usb_sndctrlpipe(device->udev, 0),
				 req,
				 USB_DIR_OUT | USB_TYPE_VENDOR |
				 USB_RECIP_DEVICE, value, index, buf,
				 size, 1000);

	if (result < 0) {
		ath6kl_dbg(ATH6KL_DBG_USB, "%s failed,result = %d\n",
			   __func__, result);
		ret = -EPERM;
	}

	kfree(buf);

	return ret;
}

static int ath6kl_usb_submit_ctrl_in(struct ath6kl_usb *device,
				  u8 req, u16 value, u16 index, void *data,
				  u32 size)
{
	u32 result = 0;
	int ret = 0;
	u8 *buf = NULL;

	if (size > 0) {
		buf = kmalloc(size, GFP_KERNEL);
		if (buf == NULL)
			return -ENOMEM;
	}
	result = usb_control_msg(device->udev,
				 usb_rcvctrlpipe(device->udev, 0),
				 req,
				 USB_DIR_IN | USB_TYPE_VENDOR |
				 USB_RECIP_DEVICE, value, index, buf,
				 size, 2 * HZ);

	if (result < 0) {
		ath6kl_dbg(ATH6KL_DBG_USB, "%s failed,result = %d\n",
			   __func__, result);
		ret = -EPERM;
	}
	memcpy((u8 *) data, buf, size);

	kfree(buf);

	return ret;
}

static int ath6kl_usb_ctrl_msg_exchange(struct ath6kl_usb *device,
				     u8 req_val, u8 *req_buf, u32 req_len,
				     u8 resp_val, u8 *resp_buf, u32 *resp_len)
{
	int status;

	/* send command */
	status =
	    ath6kl_usb_submit_ctrl_out(device, req_val, 0, 0,
				    req_buf, req_len);

	if (status != 0)
		return status;

	if (resp_buf == NULL) {
		/* no expected response */
		return status;
	}

	/* get response */
	status =
	    ath6kl_usb_submit_ctrl_in(device, resp_val, 0, 0,
				   resp_buf, *resp_len);

	return status;
}

static int ath6kl_usb_read_reg_diag(struct ath6kl *ar, u32 address, u32 *data)
{
	struct ath6kl_usb *device = (struct ath6kl_usb *)ar->hif_priv;
	int status;
	struct usb_ctrl_diag_cmd_read *cmd;
	u32 resp_len;

	cmd = (struct usb_ctrl_diag_cmd_read *)device->diag_cmd_buffer;

	memset(cmd, 0, sizeof(struct usb_ctrl_diag_cmd_read));
	cmd->cmd = USB_CTRL_DIAG_CC_READ;
	cmd->address = address;
	resp_len = sizeof(struct usb_ctrl_diag_resp_read);

	status = ath6kl_usb_ctrl_msg_exchange(device,
					   USB_CONTROL_REQ_DIAG_CMD,
					   (u8 *) cmd,
					   sizeof(struct
						  usb_ctrl_diag_cmd_read),
					   USB_CONTROL_REQ_DIAG_RESP,
					   device->diag_resp_buffer, &resp_len);

	if (status == 0) {
		struct usb_ctrl_diag_resp_read *pResp =
		    (struct usb_ctrl_diag_resp_read *)device->diag_resp_buffer;
		*data = pResp->value;
	}

	return status;
}

static int ath6kl_usb_write_reg_diag(struct ath6kl *ar, u32 address, __le32 data)
{
	struct ath6kl_usb *device = (struct ath6kl_usb *)ar->hif_priv;
	struct usb_ctrl_diag_cmd_write *cmd;

	cmd = (struct usb_ctrl_diag_cmd_write *)device->diag_cmd_buffer;

	memset(cmd, 0, sizeof(struct usb_ctrl_diag_cmd_write));
	cmd->cmd = USB_CTRL_DIAG_CC_WRITE;
	cmd->address = address;
	cmd->value = (__force unsigned ) data;

	return ath6kl_usb_ctrl_msg_exchange(device,
					 USB_CONTROL_REQ_DIAG_CMD,
					 (u8 *) cmd,
					 sizeof(struct usb_ctrl_diag_cmd_write),
					 0, NULL, NULL);

}

static int ath6kl_usb_bmi_recv_buf(struct ath6kl *ar,
				   u8 *buf, u32 len, bool want_timeout)
{
	int status;
	struct ath6kl_usb *device = (struct ath6kl_usb *)ar->hif_priv;
	/* get response */
	status = ath6kl_usb_submit_ctrl_in(device, USB_CONTROL_REQ_RECV_BMI_RESP,
					0, 0, buf, len);

	if (status != 0) {
		ath6kl_err("Unable to read the bmi data from the device: %d\n",
			   status);
		return status;
	}

	return 0;
}

static int ath6kl_usb_bmi_send_buf(struct ath6kl *ar, u8 * buf, u32 len)
{
	int status;
	struct ath6kl_usb *device = (struct ath6kl_usb *)ar->hif_priv;
	/* send command */
	status =
	    ath6kl_usb_submit_ctrl_out(device, USB_CONTROL_REQ_SEND_BMI_CMD, 0, 0,
				    buf, len);

	if (status != 0) {
		ath6kl_err("unable to send the bmi data to the device\n");
		return status;
	}
	return 0;
}

static int ath6kl_usb_power_on(struct ath6kl *ar)
{
	return 0;
}

static int ath6kl_usb_power_off(struct ath6kl *ar)
{
	return 0;
}

static const struct ath6kl_hif_ops ath6kl_usb_ops = {
	.read_reg_diag = ath6kl_usb_read_reg_diag,
	.write_reg_diag = ath6kl_usb_write_reg_diag,
	.bmi_recv_buf = ath6kl_usb_bmi_recv_buf,
	.bmi_send_buf = ath6kl_usb_bmi_send_buf,
	.power_on = ath6kl_usb_power_on,
	.power_off = ath6kl_usb_power_off,
};

/* ath6kl usb driver registered functions */
static int ath6kl_usb_probe(struct usb_interface *interface,
			    const struct usb_device_id *id)
{
	struct usb_device *dev = interface_to_usbdev(interface);
	struct ath6kl *ar;
	struct ath6kl_usb *ar_usb = NULL;
	int vendor_id, product_id;
	int result = 0;

	usb_get_dev(dev);
	vendor_id = le16_to_cpu(dev->descriptor.idVendor);
	product_id = le16_to_cpu(dev->descriptor.idProduct);

	ath6kl_dbg(ATH6KL_DBG_USB, "vendor_id = %04x\n", vendor_id);
	ath6kl_dbg(ATH6KL_DBG_USB, "product_id = %04x\n", product_id);
	if (interface->cur_altsetting) {
		unsigned int i =
		    interface->cur_altsetting->desc.bInterfaceNumber;
		ath6kl_dbg(ATH6KL_DBG_USB, "USB Interface %d\n ", i);
	}

	if (dev->speed == USB_SPEED_HIGH)
		ath6kl_dbg(ATH6KL_DBG_USB, "USB 2.0 Host\n");
	else
		ath6kl_dbg(ATH6KL_DBG_USB, "USB 1.1 Host\n");

	ar_usb = ath6kl_usb_create(interface);

	if (!ar_usb) {
		result = -ENOMEM;
		goto err_usb_device;
	}

	ar = ath6kl_core_alloc(&ar_usb->udev->dev);
	if (!ar) {
		ath6kl_err("Failed to alloc ath6kl core\n");
		result = -ENOMEM;
		goto err_ath6kl_core;
	}

	ar->hif_priv = ar_usb;
	ar->hif_type = ATH6KL_HIF_TYPE_USB;
	ar->hif_ops = &ath6kl_usb_ops;
	ar->mbox_info.block_size = 16;
	ar->bmi.max_data_size = 252;

	ar_usb->claimed_context = ar;

	result = ath6kl_core_init(ar);

	if (result) {
		ath6kl_core_free(ar);
		ath6kl_err("Failed to init ath6kl core\n");
		goto err_ath6kl_core;
	}

	return result;

err_ath6kl_core:
	ath6kl_usb_destroy(ar_usb);
err_usb_device:
	usb_put_dev(dev);
	return result;
}

static void ath6kl_usb_remove(struct usb_interface *interface)
{
	if (usb_get_intfdata(interface)) {
		usb_put_dev(interface_to_usbdev(interface));
		ath6kl_usb_device_detached(interface, 1);
	}
}

#ifdef CONFIG_PM
static int ath6kl_usb_suspend(struct usb_interface *interface,
			      pm_message_t message)
{
	struct ath6kl_usb *device;
	device = (struct ath6kl_usb *)usb_get_intfdata(interface);

	ath6kl_usb_flush_all(device);
	return 0;
}

static int ath6kl_usb_resume(struct usb_interface *interface)
{
	struct ath6kl_usb *device;
	device = (struct ath6kl_usb *)usb_get_intfdata(interface);
	/* re-post urbs? */
	if (0) {
		ath6kl_usb_post_recv_transfers(&device->pipes[HIF_RX_CTRL_PIPE],
					    ATH6KL_USB_RX_BUFFER_SIZE);
	}
	ath6kl_usb_post_recv_transfers(&device->pipes[HIF_RX_DATA_PIPE],
				    ATH6KL_USB_RX_BUFFER_SIZE);
	ath6kl_usb_post_recv_transfers(&device->pipes[HIF_RX_DATA2_PIPE],
				    ATH6KL_USB_RX_BUFFER_SIZE);

	return 0;
}

static int ath6kl_usb_reset_resume(struct usb_interface *intf)
{
	if (usb_get_intfdata(intf))
		ath6kl_usb_remove(intf);
	return 0;
}
#endif

/* table of devices that work with this driver */
static struct usb_device_id ath6kl_usb_ids[] = {
	{USB_DEVICE(VENDOR_ATHR, 0x9374)},
	{ /* Terminating entry */ },
};

MODULE_DEVICE_TABLE(usb, ath6kl_usb_ids);

static struct usb_driver ath6kl_usb_driver = {
	.name = "ath6kl_usb",
	.probe = ath6kl_usb_probe,
#ifdef CONFIG_PM
	.suspend = ath6kl_usb_suspend,
	.resume = ath6kl_usb_resume,
	.reset_resume = ath6kl_usb_reset_resume,
#endif
	.disconnect = ath6kl_usb_remove,
	.id_table = ath6kl_usb_ids,
	.supports_autosuspend = true,
};

static int ath6kl_usb_init(void)
{
	usb_register(&ath6kl_usb_driver);
	return 0;
}

static void ath6kl_usb_exit(void)
{
	usb_deregister(&ath6kl_usb_driver);
}

module_init(ath6kl_usb_init);
module_exit(ath6kl_usb_exit);

MODULE_AUTHOR("Atheros Communications, Inc.");
MODULE_DESCRIPTION("Driver support for Atheros AR600x USB devices");
MODULE_LICENSE("Dual BSD/GPL");
MODULE_FIRMWARE(AR6004_REV1_FIRMWARE_FILE);
MODULE_FIRMWARE(AR6004_REV1_BOARD_DATA_FILE);
MODULE_FIRMWARE(AR6004_REV1_DEFAULT_BOARD_DATA_FILE);
MODULE_FIRMWARE(AR6004_REV2_FIRMWARE_FILE);
MODULE_FIRMWARE(AR6004_REV2_BOARD_DATA_FILE);
MODULE_FIRMWARE(AR6004_REV2_DEFAULT_BOARD_DATA_FILE);
