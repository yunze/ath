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

#ifndef HIF_USB_H
#define HIF_USB_H

#include <linux/usb.h>
#include "hif.h"

/**
 * @brief List of callbacks - filled in by HTC.
 */
struct hif_callbacks {
	int (*tx_completion) (struct htc_target *context, struct sk_buff * skb);
	int (*rx_completion) (struct htc_target *context,
				struct sk_buff *skb, u8 pipe);
	void (*tx_resource_available) (struct htc_target *context, u8 pipe);
};

/**
 * @brief: This API is used by the HTC layer to initialize the HIF layer and to
 * register different callback routines. Support for following events has
 * been captured - DSR, Read/Write completion, Device insertion/removal,
 * Device suspension/resumption/wakeup. In addition to this, the API is
 * also used to register the name and the revision of the chip. The latter
 * can be used to verify the revision of the chip read from the device
 * before reporting it to HTC.
 * @param[in]: callbacks - List of HTC callbacks
 * @param[out]:
 * @return: an opaque HIF handle
 */
void hif_postinit(struct ath6kl *ar,
		void *htc_context,
		struct hif_callbacks *callbacks);

void hif_start(struct ath6kl *ar);

void hif_stop(struct ath6kl *ar);

/**
 * @brief: Send a buffer to HIF for transmission to the target.
 * @param[in]: dev - HIF handle
 * @param[in]: pipeID - pipe to use
 * @param[in]: netbuf - buffer to send
 * @param[out]:
 * @return: Status of the send operation.
 */
int hif_send(struct ath6kl *ar, u8 pipe, struct sk_buff *hdr_buf,
	     struct sk_buff *buf);

void hif_get_default_pipe(struct ath6kl *ar, u8 *pipe_ul, u8 *pipe_dl);

int hif_map_service_pipe(struct ath6kl *ar, u16 service_id, u8 *pipe_ul,
			 u8 *pipe_dl);

u16 hif_get_free_queue_number(struct ath6kl *ar, u8 pipe);

void hif_detach_htc(struct ath6kl *ar);

#endif
