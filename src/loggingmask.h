/* -*- mode: C++; c-basic-offset: 3; tab-width: 3; -*-
 *
 * Copyright (c) 2012, Annai Systems, Inc.
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE
 *
 * Created under contract by Cardinal Peak, LLC.   www.cardinalpeak.com
 */

/*
 * loggingmasks.h
 *
 *  Created on: January 19, 2012
 *      Author: donavan
 */

#ifndef LOGGINGMASKS_H_
#define LOGGINGMASKS_H_

const uint32_t LOG_DEBUG_NOTIFICATION         = 0x00000001;       // S [alert::debug_notification]  peer_connect_alert: peer_disconnected_alert:

const uint32_t LOG_PEER_NOTIFICATION          = 0x00000002;       // S [alert::peer_notification]  url_seed_alert: incoming_connection_alert: 
                                                                  // lsd_peer_alert: peer_error_alert: invalid_request_alert: peer_ban_alert: 
                                                                  // peer_snubbed_alert: peer_unsnubbed_alert: unwanted_block_alert:

const uint32_t LOG_IP_BLOCK_NOTIFICATION      = 0x00000004;       // V [alert::ip_block_notification] peer_blocked_alert:

const uint32_t LOG_PERFORMANCE_WARNING        = 0x00000008;       // V [alert::performance_warning] performance_alert:

const uint32_t LOG_STATUS_NOTIFICATION        = 0x00000010;       // F [alert::status_notification] fastresume_rejected_alert: file_error_alert:
                                                                  // listen_failed_alert: add_torrent_alert: external_ip_alert: hash_failed_alert:
                                                                  // listen_succeeded_alert: metadata_received_alert: state_changed_alert:
                                                                  // torrent_added_alert: torrent_checked_alert: torrent_error_alert:
                                                                  // torrent_finished_alert: torrent_need_cert_alert: torrent_paused_alert:
                                                                  // torrent_removed_alert: torrent_resumed_alert: trackerid_alert:

const uint32_t LOG_STATS_NOTIFICATION         = 0x00000020;       // F [alert::stats_notification] stats_alert:

const uint32_t LOG_STORAGE_NOTIFICATION       = 0x00000040;       // V [alert::storage_notification] save_resume_data_failed_alert:
                                                                  // torrent_delete_failed_alert: cache_flushed_alert: file_rename_failed_alert:
                                                                  // file_renamed_alert: read_piece_alert: save_resume_data_alert:
                                                                  // storage_moved_alert: storage_moved_failed_alert: torrent_deleted_alert:

const uint32_t LOG_TRACKER_NOTIFICATION       = 0x00000080;       // S [alert::tracker_notification] scrape_failed_alert: tracker_error_alert:
                                                                  // tracker_warning_alert: dht_reply_alert: scrape_reply_alert:
                                                                  // tracker_announce_alert: tracker_reply_alert:

const uint32_t LOG_PROGRESS_NOTIFICATION      = 0x00000100;       // F [alert::progress_notification] block_timeout_alert: request_dropped_alert:
                                                                  // block_downloading_alert: block_finished_alert: file_completed_alert:
                                                                  // piece_finished_alert:


const uint32_t LOG_LT_CALL_BACK_LOGGER        = 0x40000000;       // S Messasge from the libtorrent minimal call back logger

const uint32_t LOG_UNIMPLEMENTED_ALERTS       = 0x80000000;       // F Unknown notification types in all notification handling functions:  
                                                                  // [alert::dht_notification] dht_announce_alert: dht_bootstrap_alert: dht_get_peers_alert,
                                                                  // [alert::port_mapping_notification] portmap_error_alert: portmap_alert: portmap_log_alert, 
                                                                  // [alert::rss_notification] rss_alert:,
                                                                  // [alert::error_notification] anonymous_mode_alert: metadata_failed_alert: udp_error_alert:,

// const uint32_t UNUSED                      = 0x00000200;
// const uint32_t UNUSED                      = 0x00000400;
// const uint32_t UNUSED                      = 0x00000800;

// const uint32_t UNUSED                      = 0x00001000;
// const uint32_t UNUSED                      = 0x00002000;
// const uint32_t UNUSED                      = 0x00004000;
// const uint32_t UNUSED                      = 0x00008000;

// const uint32_t UNUSED                      = 0x00010000;
// const uint32_t UNUSED                      = 0x00020000;
// const uint32_t UNUSED                      = 0x00040000;
// const uint32_t UNUSED                      = 0x00080000;

// const uint32_t UNUSED                      = 0x00100000;
// const uint32_t UNUSED                      = 0x00200000;
// const uint32_t UNUSED                      = 0x00400000;
// const uint32_t UNUSED                      = 0x00800000;

// const uint32_t UNUSED                      = 0x01000000;
// const uint32_t UNUSED                      = 0x02000000;
// const uint32_t UNUSED                      = 0x04000000;
// const uint32_t UNUSED                      = 0x08000000;

// const uint32_t UNUSED                      = 0x10000000;
// const uint32_t UNUSED                      = 0x20000000;

// These define the 3 logging levels offered via the command line.

const uint32_t LOGMASK_STANDARD = LOG_DEBUG_NOTIFICATION | LOG_PEER_NOTIFICATION | LOG_TRACKER_NOTIFICATION;

const uint32_t LOGMASK_VERBOSE = LOGMASK_STANDARD | LOG_IP_BLOCK_NOTIFICATION | LOG_PERFORMANCE_WARNING | LOG_STORAGE_NOTIFICATION | LOG_LT_CALL_BACK_LOGGER;

const uint32_t LOGMASK_FULL = LOGMASK_VERBOSE | LOG_STATUS_NOTIFICATION | LOG_PROGRESS_NOTIFICATION | LOG_STATS_NOTIFICATION | LOG_UNIMPLEMENTED_ALERTS;

#endif
