/*
 * Copyright (c) 2004-2011 Atheros Communications Inc.
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

#ifndef HIF_USB_INTERNAL_H
#define HIF_USB_INTERNAL_H

#include <linux/usb.h>

#include "hif.h"

/* constants */
#define VENDOR_ATHR             0x0CF3

#define TX_URB_COUNT            32
#define RX_URB_COUNT            32
#define HIF_USB_RX_BUFFER_SIZE  1700

/* callbacks make os/driver to indiate uniform events */
struct osdrv_callbacks {
	void *context;
	int (*device_inserted) (void *context);
	int (*device_removed) (void *context);
	int (*device_suspend) (void *context);
	int (*device_resume) (void *context);
	int (*device_wakeup) (void *context);
};

/* tx/rx pipes for usb */
enum HIF_USB_PIPE_ID {
	HIF_TX_CTRL_PIPE = 0,
	HIF_TX_DATA_LP_PIPE,
	HIF_TX_DATA_MP_PIPE,
	HIF_TX_DATA_HP_PIPE,
	HIF_RX_CTRL_PIPE,
	HIF_RX_DATA_PIPE,
	HIF_RX_DATA2_PIPE,
	HIF_RX_INT_PIPE,
	HIF_USB_PIPE_MAX
};

#define HIF_USB_PIPE_INVALID HIF_USB_PIPE_MAX

struct hif_usb_pipe {
	struct list_head urb_list_head;
	struct list_head urb_pending_list;
	u32 urb_alloc;
	u32 urb_cnt;
	u32 urb_cnt_thresh;
	unsigned int usb_pipe_handle;
	u32 flags;
	u8 ep_address;
	u8 logical_pipe_num;
	struct hif_device_usb *device;
	u16 max_packet_size;
	struct work_struct io_complete_work;
	struct sk_buff_head io_comp_queue;
	struct usb_endpoint_descriptor *ep_desc;
};

#define HIF_USB_PIPE_FLAG_TX    (1 << 0)

/* usb device object */
struct hif_device_usb {
	spinlock_t cs_lock;
	spinlock_t tx_lock;
	spinlock_t rx_lock;
	struct hif_callbacks htc_callbacks;
	struct usb_device *udev;
	struct usb_interface *interface;
	struct hif_usb_pipe pipes[HIF_USB_PIPE_MAX];
	u8 surprise_removed;
	u8 *diag_cmd_buffer;
	u8 *diag_resp_buffer;
	void *claimed_context;
};

/* usb urb object */
struct hif_urb_context {
	struct list_head link;
	struct hif_usb_pipe *pipe;
	struct sk_buff *buf;
	struct urb *urb;
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
	__le32 cmd;
	__le32 address;
	__le32 value;
	__le32 _pad[1];
} __packed;

struct usb_ctrl_diag_cmd_read {
	__le32 cmd;
	__le32 address;
} __packed;

struct usb_ctrl_diag_resp_read {
	__le32 value;
} __packed;

#define USB_CTRL_MAX_DIAG_CMD_SIZE  (sizeof(struct usb_ctrl_diag_cmd_write))
#define USB_CTRL_MAX_DIAG_RESP_SIZE (sizeof(struct usb_ctrl_diag_resp_read))

#endif
