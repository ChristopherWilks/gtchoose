/* -*- mode: C++; c-basic-offset: 4; tab-width: 4; -*-
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

#ifndef GT_OPT_STRINGS_H
#define GT_OPT_STRINGS_H

//
// Strings used for long options.
//

// Common options:
#define OPT_HELP                   "help"
#define OPT_VERSION                "version"
#define OPT_CFG_FILE               "config-file"
#define OPT_BIND_IP                "bind-ip"
#define OPT_CRED_FILE              "credential-file"
#define OPT_CFG_DIR_DEPRECATED     "config-dir"                 // Keep this around to give the user a nice error message
#define OPT_RESOURCE_DIR           "resource-dir"
#define OPT_ADVERT_IP              "advertised-ip"
#define OPT_ADVERT_PORT            "advertised-port"
#define OPT_INTERNAL_PORT          "internal-port"
#define OPT_PATH                   "path"
#define OPT_RATE_LIMIT             "rate-limit"
#define OPT_INACTIVE_TIMEOUT       "inactivity-timeout"
#define OPT_PEER_TIMEOUT           "peer-timeout"
#define OPT_LOGGING                "log"
#define OPT_TIMESTAMP              "timestamps"
#define OPT_VERBOSE                "verbose"
#define OPT_VERBOSE_INCR           "verbose-incr"
#define OPT_SECURITY_API           "security-api"
#define OPT_CURL_NO_VERIFY_SSL     "ssl-no-verify-ca"
#define OPT_NO_USER_CFG_FILE       "disallow-user-config"
#define OPT_ALLOWED_MODES          "allowed-modes"
#define OPT_ALLOWED_SERVERS        "allowed-servers"
#define OPT_NULL_STORAGE           "null-storage"
#define OPT_ZERO_STORAGE           "zero-storage"

// Options for gtdownload:
#define OPT_DOWNLOAD               "download"
#define OPT_DOWNLOAD_GTO           "download-from-gto"
#define OPT_DOWNLOAD_XML           "download-from-xml"
#define OPT_DOWNLOAD_TSV           "download-from-tsv"
#define OPT_DOWNLOAD_LST           "download-from-lst"
#define OPT_MAX_CHILDREN           "max-children"
#define OPT_GTA_MODE               "gta"
#define OPT_WEBSERV_URL            "webservices-url"

// Options for gtupload:
#define OPT_UPLOAD                 "upload"
#define OPT_UPLOAD_GTO_PATH        "upload-gto-path"
#define OPT_GTO_ONLY               "gto-only"

// Options for gtserver:
#define OPT_SERVER                 "server"
#define OPT_QUEUE                  "queue"
#define OPT_FORCE_DL_MODE          "force-download-mode"
#define OPT_FOREGROUND             "foreground"
#define OPT_PIDFILE                "pidfile"

#endif  /* GT_OPT_STRINGS_H */
