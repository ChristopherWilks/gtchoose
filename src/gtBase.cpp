/* -*- mode: C++; c-basic-offset: 3; tab-width: 3; -*-
 *
 * Copyright (c) 2011-2012, Annai Systems, Inc.
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
 * geneTorrent.cpp
 *
 *  Created on: Aug 15, 2011
 *      Author: donavan
 */

#define _DARWIN_C_SOURCE 1

#include "gt_config.h"

#include <iostream>
#include <fstream>
#include <iomanip>
#include <cstdio>
#include <algorithm>

#ifdef __CYGWIN__
#include <sys/cygwin.h>
#endif /* __CYGWIN__ */

#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rand.h>

#include <boost/filesystem/path.hpp>
#include <boost/filesystem/operations.hpp>
#include <boost/regex.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/lexical_cast.hpp>

#include "libtorrent/entry.hpp"
#include "libtorrent/bencode.hpp"

#include "libtorrent/create_torrent.hpp"

#include "libtorrent/peer_info.hpp"
#include "libtorrent/ip_filter.hpp"
#include "libtorrent/alert_types.hpp"

#include <xqilla/xqilla-simple.hpp>

#include <curl/curl.h>

#include "gtBase.h"
#include "stringTokenizer.h"
#include "gtDefs.h"
#include "geneTorrentUtils.h"
#include "gtLog.h"
#include "loggingmask.h"

// global variable that used to point to GeneTorrent to allow
// libtorrent callback for file inclusion and logging.
// initialized in geneTorrent constructor, used in the free
// function file_filter to call member fileFilter.
void *geneTorrCallBackPtr; 

// Lock to prevent the callback logger from clearing a buffer
// at the saem time another thread is trying to add to a buffer
static pthread_mutex_t callBackLoggerLock;

gtBase::gtBase (gtBaseOpts &opts, opMode mode):
   _progName (opts.m_progName),
   _verbosityLevel (VERBOSE_1), 
   _devMode (false),
   _tmpDir (""), 
   _startUpComplete (false),
   _operatingMode (mode), 
   _successfulTrackerComms (false),

   // Protected members obtained from CLI or CFG.
   _version_msg( opts.m_version_msg),
   _addTimestamps (opts.m_addTimestamps),
   _allowedServersSet (opts.m_allowedServersSet),
   _authToken (""),
   _curlVerifySSL (opts.m_curlVerifySSL),
   _exposedPortDelta (opts.m_exposedPortDelta),
   _inactiveTimeout (opts.m_inactiveTimeout),
   _ipFilter (opts.m_ipFilter),
   _logDestination (opts.m_logDestination),
   _logToStdErr (opts.m_logToStdErr),
   _portEnd (opts.m_portEnd),
   _portStart (opts.m_portStart),
   _rateLimit (opts.m_rateLimit),
   _use_null_storage (opts.m_use_null_storage),
   _use_zero_storage (opts.m_use_zero_storage),

   // Private members obtained from CLI or CFG.
   _bindIP (opts.m_bindIP),
   _resourceDir (opts.m_resourceDir),
   _exposedIP (opts.m_exposedIP),
   _logMask (opts.m_logMask),
   _peerTimeout (opts.m_peerTimeout)
{
   geneTorrCallBackPtr = (void *) this;          // Set the global geneTorr pointer that allows fileFilter callbacks from libtorrent

   pthread_mutex_init (&callBackLoggerLock, NULL);

   char *envValue = getenv ("GENETORRENT_DEVMODE");
   if (envValue != NULL)
   {
      _tmpDir = sanitizePath (envValue) + "/";
      _devMode = true;
   }
   else
   {
      setTempDir();
      mkTempDir();
   }

   _verbosityLevel = global_verbosity;

   _dhParamsFile = _resourceDir + "/" + DH_PARAMS_FILE;
   if (statFile (_dhParamsFile) != 0)
   {
      gtError ("Failure opening SSL DH Params file:  " + _dhParamsFile, 202, ERRNO_ERROR, errno);
   }

   OpenSSL_add_all_algorithms();
   ERR_load_crypto_strings();
   initSSLattributes();

   if (4096 != RAND_load_file("/dev/urandom", 4096))
   {
      gtError ("Failure opening /dev/urandom to prime the OpenSSL PRNG", 202);
   }

   loadCredentialFile (opts.m_credentialPath);

   std::string gtTag;
   if (_operatingMode != SERVER_MODE)
   {
      gtTag = "GT";
   }
   else
   {
      gtTag = "Gt";
   }   

   strTokenize strToken (VERSION, ".", strTokenize::INDIVIDUAL_CONSECUTIVE_SEPARATORS);

   _gtFingerPrint = new libtorrent::fingerprint (gtTag.c_str(), strtol (strToken.getToken (1).c_str (), NULL, 10), strtol (strToken.getToken (2).c_str (), NULL, 10), strtol (strToken.getToken (3).c_str (), NULL, 10), 0);
}

void gtBase::startUpMessage()
{
   std::ostringstream msg;

   if (_devMode)
   {
      msg << "[devModeOverride] ";
   }

   msg << "Starting " << _version_msg;

   Log (PRIORITY_NORMAL, "%s (using tmpDir = %s)", msg.str().c_str(), _tmpDir.c_str());

   screenOutput ("Welcome to " << _version_msg << ".", VERBOSE_1);
}

void gtBase::initSSLattributes ()
{
   // If you add entries here you must adjust  CSR_ATTRIBUTE_ENTRY_COUNT in gtDefs.h
   attributes[0].key = "countryName";
   attributes[0].value = "US";

   attributes[1].key = "stateOrProvinceName";
   attributes[1].value = "CA";

   attributes[2].key = "localityName";
   attributes[2].value = "San Jose";

   attributes[3].key = "organizationName";
   attributes[3].value = "ploaders, Inc";

   attributes[4].key = "organizationalUnitName";
   attributes[4].value = "staff";

   attributes[5].key = "commonName";
   attributes[5].value = "www.uploadersinc.com";

   attributes[6].key = "emailAddress";
   attributes[6].value = "root@uploadersinc.com";
   // If you add entries here you must adjust  CSR_ATTRIBUTE_ENTRY_COUNT in gtDefs.h
}

// 
void gtBase::setTempDir ()     
{
   // Setup the static part of the Temp dir used to store ssl bits
   std::ostringstream pathPart;
   pathPart << "/GeneTorrent-" << getuid() << "-" << std::setfill('0') << std::setw(6) << getpid() << "-" << time(NULL);

   // On Uniux, returns environment's TMPDIR, TMP, TEMP, or TEMPDIR,
   //    or, failing that, /tmp
   // On Windows, return windows temp directory
   boost::filesystem::path p;
   try
   {
      p = boost::filesystem::temp_directory_path();
   }
   catch (boost::filesystem::filesystem_error e)
   {
      std::ostringstream errorStr;
      errorStr << "Could not find temp directory.  Set the TMPDIR "
         "environment variable to specify a temp directory for GeneTorrent. "
         "Error: ";
      errorStr << e.what ();

      gtError (errorStr.str (), 66);
   }

   std::string tempPath = p.string();

   _tmpDir = sanitizePath (tempPath + pathPart.str ());
}

// 
void gtBase::mkTempDir () 
{
   int retValue = mkdir (_tmpDir.c_str(), 0700);       
   if (retValue != 0 )
   {
      gtError ("Failure creating temporary directory " + _tmpDir, 202, ERRNO_ERROR, errno);
   }

   _tmpDir += "/";
}

// 
std::string gtBase::loadCSRfile (std::string csrFileName)
{
   std::string fileContent = "";
   
   std::ifstream csrFile;

   csrFile.open (csrFileName.c_str (), std::ifstream::in);

   if (!csrFile.good ())
   {
      if (_operatingMode != SERVER_MODE)
      {
         gtError ("Failure opening " + csrFileName + " for input.", 202, ERRNO_ERROR, errno);
      }
      else
      {
         gtError ("Failure opening " + csrFileName + " for input.", ERROR_NO_EXIT, ERRNO_ERROR, errno);
         return "";
      }
   }

   char inLine[100];

   while (csrFile.good())
   {
      std::istream &in = csrFile.getline (inLine, sizeof (inLine)-1);

      if (in.gcount() <= 0 || csrFile.eof())
      {
         break;
      }

      inLine[in.gcount()] = '\0';

      fileContent += std::string (inLine) + "\n";
   }

   csrFile.close ();

   return fileContent;
}

// 
gtBase::~gtBase ()
{
   cleanupTmpDir ();
   delete _gtFingerPrint;
   gtLogger::delete_globallog();
}

// 
void gtBase::gtError (std::string errorMessage, int exitValue, gtErrorType errorType, long errorCode, std::string errorMessageLine2, std::string errorMessageErrorLine)
{
   std::ostringstream logMessage;

   if (exitValue == NO_EXIT)      // exitValue = 0
   {
      logMessage << "Warning:  " << errorMessage;
   }
   else  // exitValue or ERROR_NO_EXIT = -1, the caller handles the error and this permits syslogging only
   {
      logMessage << errorMessage;
   }

   if (errorMessageLine2.size () > 0)
   {
      logMessage << ", " << errorMessageLine2;
   }

   switch (errorType)
   {
      case gtBase::HTTP_ERROR:
      {
         logMessage << "  Additional Info:  " << getHttpErrorMessage (errorCode) << " (HTTP status code = " << errorCode << ").";
      }
         break;

      case gtBase::CURL_ERROR:
      {
         logMessage << "  Additional Info:  " << curl_easy_strerror (CURLcode (errorCode)) << " (curl code = " << errorCode << ").";
      }
         break;

      case gtBase::ERRNO_ERROR:
      {
         logMessage << "  Additional Info:  " << strerror (errorCode) << " (errno = " << errorCode << ").";
      }
         break;

      case gtBase::TORRENT_ERROR:
      {
         logMessage << "  Additional Info:  " << errorMessageErrorLine << " (GT code = " << errorCode << ").";
      }
         break;

      default:
      {
         if (errorMessageErrorLine.size () > 0)
         {
            logMessage << ", " << errorMessageErrorLine;
         }
      }
         break;
   }

   if (exitValue == ERROR_NO_EXIT)   // ERRROR in server mode
   {
      Log (PRIORITY_HIGH, "%s", logMessage.str().c_str());
   }
   else if (exitValue == NO_EXIT)    // Warning message
   {
      Log (PRIORITY_NORMAL, "%s", logMessage.str().c_str());
   }
   else                              // Error and Exit
   {
      Log (PRIORITY_HIGH, "%s", logMessage.str().c_str());

      if (global_gtAgentMode)
      {
         std::cout << logMessage.str() << std::endl;
      }
      exit (exitValue);
   }
}

// 
std::string gtBase::getHttpErrorMessage (int code)
{
   switch (code)
   {
      case 505:
      {
         return "HTTP Version Not Supported";
      } break;

      case 504:
      {
         return "Gateway Timeout";
      } break;

      case 503:
      {
         return "Service Unavailable";
      } break;

      case 502:
      {
         return "Bad Gateway";
      } break;

      case 501:
      {
         return "Not Implemented";
      } break;

      case 500:
      {
         return "Internal Server Error";
      } break;

      case 400:
      {
         return "Bad Request";
      } break;

      case 401:
      {
         return "Unauthorized";
      } break;

      case 403:
      {
         return "Forbidden";
      } break;

      case 404:
      {
         return "Not Found";
      } break;

      case 409:
      {
         return "Request Timeout";
      } break;

      case 411:
      {
         return "Gone";
      } break;

      case 412:
      {
         return "Length Required";
      } break;

      default:
      {
         return "Unknown, research given code";
      } break;
   }

   return "Unknown, research given code";
}

// 
int gtBase::curlCallBackHeadersWriter (char *data, size_t size, size_t nmemb, std::string *buffer)
{
   int result = 0; // What we will return

   if (buffer != NULL) // Is there anything in the buffer?
   {
      buffer->append (data, size * nmemb); // Append the data to the buffer

      result = size * nmemb; // How much did we write?
   }

   return result;
}

// 
void gtBase::cleanupTmpDir()
{
   if (! _startUpComplete)
      return;

   if (!_devMode)
   {
      try
      {
         boost::filesystem::remove_all(_tmpDir);
      }
      catch (boost::filesystem::filesystem_error e)
      {
         Log (PRIORITY_NORMAL, "Failed to clean up temp directory");
      }
   }
}

libtorrent::session * gtBase::makeTorrentSession ()
{
   libtorrent::session *torrentSession = NULL;

   try
   {
      torrentSession = new libtorrent::session(*_gtFingerPrint, 0, libtorrent::alert::all_categories);
      optimizeSession (torrentSession);
      bindSession (torrentSession);
   }
   catch (boost::system::system_error e)  // thrown by boost::asio if a pthread_create
                                          // fails due to user/system process limits or OOM
   {
      gtError ("torrent session initialization error: " + std::string(e.what()), ERROR_NO_EXIT, DEFAULT_ERROR);
   }

   return torrentSession;
}

// 
void gtBase::bindSession (libtorrent::session *torrentSession)
{
   libtorrent::error_code torrentError;

   // the difference between the actual port used and the port to be advertised to the tracker
   if (_exposedPortDelta != 0) 
   {
      libtorrent::session_settings settings = torrentSession->settings ();
      settings.external_port_delta = _exposedPortDelta;
      torrentSession->set_settings (settings);
   }

   libtorrent::session_settings settings = torrentSession->settings ();

   // update the IP we bind on.  
   //

   if (_bindIP.size () > 0)
   {
      torrentSession->listen_on (std::make_pair (_portStart, _portEnd), torrentError, _bindIP.c_str (), 0);
   }
   else
   {
      torrentSession->listen_on (std::make_pair (_portStart, _portEnd), torrentError, NULL, 0);
   }

   if (torrentError)
   {
      Log (PRIORITY_NORMAL, "failure to set listen address or port in torrent session. (code %d) %s",
         torrentError.value(), torrentError.message().c_str());
   }

   // the ip address sent to the tracker with the announce
   if (_exposedIP.size () > 0) 
   {
      settings.announce_ip = _exposedIP;
   }

   if (_peerTimeout > 0)
      settings.peer_timeout = _peerTimeout;

   torrentSession->set_settings (settings);
}

// 
void gtBase::bindSession (libtorrent::session &torrentSession)
{
   bindSession (&torrentSession);
}

// 
void gtBase::optimizeSession (libtorrent::session *torrentSession)
{
   libtorrent::session_settings settings = torrentSession->settings ();

   settings.allow_multiple_connections_per_ip = true;
#ifdef TORRENT_CALLBACK_LOGGER
   settings.loggingCallBack = &gtBase::loggingCallBack;
#endif
   settings.max_allowed_in_request_queue = 1000;
   settings.max_out_request_queue = 1000;
   settings.mixed_mode_algorithm = libtorrent::session_settings::prefer_tcp;
   settings.enable_outgoing_utp = false;
   settings.enable_incoming_utp = false;

   if (_operatingMode != SERVER_MODE && _allowedServersSet)
      settings.apply_ip_filter_to_trackers = true;
   else
      settings.apply_ip_filter_to_trackers = false;

   settings.no_atime_storage = false;
   settings.max_queued_disk_bytes = 256 * 1024 * 1024;

   // when a connection fails, retry it more quickly than the libtorrent default.  Note that this is multiplied by the attempt
   // number, so the delay before the 2nd attempt is (min_reconnect_time * 2) and before the 3rd attempt is *3, and so on...
   settings.min_reconnect_time = 3;

   // This is the minimum interval that we will restatus the tracker.
   // The tracker itself tells us (via the interval parameter) when we
   // should restatus it.  However, if the value sent by the tracker
   // is less than the value below, then libtorrent follows the value
   // below.  So, setting this value low allows us to respond quickly
   // in the case where the tracker sends back a very low interval
   settings.min_announce_interval = 2;

   // prevent keepalives from being sent.  this will cause servers to
   // time out peers more rapidly.  
   //
   // TODO: probably a good idea to set this in ALL modes, but for now
   // we don't want to risk introducing a new bug to server mode
   if (_operatingMode != SERVER_MODE)
   { 
      settings.inhibit_keepalives = true;
   }

   settings.alert_queue_size = 10000;

   if (_operatingMode == SERVER_MODE)
   {
      settings.send_buffer_watermark = 256 * 1024 * 1024;

      // put 1.5 seconds worth of data in the send buffer this gives the disk I/O more heads-up on disk reads, and can maximize throughput
      settings.send_buffer_watermark_factor = 150;

      // don't retry peers if they fail once. Let them connect to us if they want to
      settings.max_failcount = 1;
   }

   overrideSettings( settings );

   torrentSession->set_settings (settings);

   if (_bindIP.size() || _exposedIP.size())
   {
      if (_bindIP.size())
      {
         try
         {
            _ipFilter.add_rule (boost::asio::ip::address::from_string(_bindIP), boost::asio::ip::address::from_string(_bindIP), libtorrent::ip_filter::blocked);
         }
         catch (boost::system::system_error e)
         {  
            std::ostringstream messageBuff;
            messageBuff << "invalid '--bind-ip' address of:  " << _bindIP << " caused an exception:  " << e.what();
            Log (PRIORITY_HIGH, "%s", messageBuff.str().c_str());
            exit(98);
         }
      }

      if (_exposedIP.size())
      {
         try
         {
            _ipFilter.add_rule (boost::asio::ip::address::from_string(_exposedIP), boost::asio::ip::address::from_string(_exposedIP), libtorrent::ip_filter::blocked);
         }
         catch (boost::system::system_error e)
         {  
            std::ostringstream messageBuff;
            messageBuff << "invalid '--advertised-ip' address of:  " << _exposedIP << " caused an exception:  " << e.what();
            Log (PRIORITY_HIGH, "%s", messageBuff.str().c_str());
            exit(98);
         }
      }

   }

   torrentSession->set_ip_filter(_ipFilter);
}

// 
void gtBase::optimizeSession (libtorrent::session &torrentSession)
{
   optimizeSession (&torrentSession);
}


void gtBase::overrideSettings( libtorrent::session_settings &settings )
{
   overrideSettingsNum( "GT_SESSION_VERSION", settings.version );
   overrideSettingsString( "GT_SESSION_USER_AGENT", settings.user_agent );
   overrideSettingsNum( "GT_SESSION_TRACKER_COMPLETION_TIMEOUT", settings.tracker_completion_timeout );
   overrideSettingsNum( "GT_SESSION_TRACKER_RECEIVE_TIMEOUT", settings.tracker_receive_timeout );
   overrideSettingsNum( "GT_SESSION_STOP_TRACKER_TIMEOUT", settings.stop_tracker_timeout );
   overrideSettingsNum( "GT_SESSION_TRACKER_MAXIMUM_RESPONSE_LENGTH", settings.tracker_maximum_response_length );
   overrideSettingsNum( "GT_SESSION_PIECE_TIMEOUT", settings.piece_timeout );
   overrideSettingsNum( "GT_SESSION_REQUEST_TIMEOUT", settings.request_timeout );
   overrideSettingsNum( "GT_SESSION_REQUEST_QUEUE_TIME", settings.request_queue_time );
   overrideSettingsNum( "GT_SESSION_MAX_ALLOWED_IN_REQUEST_QUEUE", settings.max_allowed_in_request_queue );
   overrideSettingsNum( "GT_SESSION_MAX_OUT_REQUEST_QUEUE", settings.max_out_request_queue );
   overrideSettingsNum( "GT_SESSION_WHOLE_PIECES_THRESHOLD", settings.whole_pieces_threshold );
   overrideSettingsNum( "GT_SESSION_PEER_TIMEOUT", settings.peer_timeout );
   overrideSettingsNum( "GT_SESSION_URLSEED_TIMEOUT", settings.urlseed_timeout );
   overrideSettingsNum( "GT_SESSION_URLSEED_PIPELINE_SIZE", settings.urlseed_pipeline_size );
   overrideSettingsNum( "GT_SESSION_URLSEED_WAIT_RETRY", settings.urlseed_wait_retry );
   overrideSettingsNum( "GT_SESSION_FILE_POOL_SIZE", settings.file_pool_size );
   overrideSettingsBool( "GT_SESSION_ALLOW_MULTIPLE_CONNECTIONS_PER_IP", settings.allow_multiple_connections_per_ip );
   overrideSettingsNum( "GT_SESSION_MAX_FAILCOUNT", settings.max_failcount );
   overrideSettingsNum( "GT_SESSION_MIN_RECONNECT_TIME", settings.min_reconnect_time );
   overrideSettingsNum( "GT_SESSION_PEER_CONNECT_TIMEOUT", settings.peer_connect_timeout );
   overrideSettingsBool( "GT_SESSION_IGNORE_LIMITS_ON_LOCAL_NETWORK", settings.ignore_limits_on_local_network );
   overrideSettingsNum( "GT_SESSION_CONNECTION_SPEED", settings.connection_speed );
   overrideSettingsBool( "GT_SESSION_SEND_REDUNDANT_HAVE", settings.send_redundant_have );
   overrideSettingsBool( "GT_SESSION_LAZY_BITFIELDS", settings.lazy_bitfields );
   overrideSettingsNum( "GT_SESSION_INACTIVITY_TIMEOUT", settings.inactivity_timeout );
   overrideSettingsNum( "GT_SESSION_UNCHOKE_INTERVAL", settings.unchoke_interval );
   overrideSettingsNum( "GT_SESSION_OPTIMISTIC_UNCHOKE_INTERVAL", settings.optimistic_unchoke_interval );
   overrideSettingsString( "GT_SESSION_ANNOUNCE_IP", settings.announce_ip );
   overrideSettingsNum( "GT_SESSION_NUM_WANT", settings.num_want );
   overrideSettingsNum( "GT_SESSION_INITIAL_PICKER_THRESHOLD", settings.initial_picker_threshold );
   overrideSettingsNum( "GT_SESSION_ALLOWED_FAST_SET_SIZE", settings.allowed_fast_set_size );
   overrideSettingsNum( "GT_SESSION_SUGGEST_MODE", settings.suggest_mode );
   overrideSettingsNum( "GT_SESSION_MAX_QUEUED_DISK_BYTES", settings.max_queued_disk_bytes );
   overrideSettingsNum( "GT_SESSION_MAX_QUEUED_DISK_BYTES_LOW_WATERMARK", settings.max_queued_disk_bytes_low_watermark );
   overrideSettingsNum( "GT_SESSION_HANDSHAKE_TIMEOUT", settings.handshake_timeout );
#ifndef TORRENT_DISABLE_DHT
   overrideSettingsBool( "GT_SESSION_USE_DHT_AS_FALLBACK", settings.use_dht_as_fallback );
#endif
   overrideSettingsBool( "GT_SESSION_FREE_TORRENT_HASHES", settings.free_torrent_hashes );
   overrideSettingsBool( "GT_SESSION_UPNP_IGNORE_NONROUTERS", settings.upnp_ignore_nonrouters );
   overrideSettingsNum( "GT_SESSION_SEND_BUFFER_WATERMARK", settings.send_buffer_watermark );
   overrideSettingsNum( "GT_SESSION_SEND_BUFFER_WATERMARK_FACTOR", settings.send_buffer_watermark_factor );
#ifndef TORRENT_NO_DEPRECATE
   overrideSettingsBool( "GT_SESSION_AUTO_UPLOAD_SLOTS", settings.auto_upload_slots );
   overrideSettingsBool( "GT_SESSION_AUTO_UPLOAD_SLOTS_RATE_BASED", settings.auto_upload_slots_rate_based );
#endif
   overrideSettingsNum( "GT_SESSION_CHOKING_ALGORITHM", settings.choking_algorithm );
   overrideSettingsNum( "GT_SESSION_SEED_CHOKING_ALGORITHM", settings.seed_choking_algorithm );
   overrideSettingsBool( "GT_SESSION_USE_PAROLE_MODE", settings.use_parole_mode );
   overrideSettingsNum( "GT_SESSION_CACHE_SIZE", settings.cache_size );
   overrideSettingsNum( "GT_SESSION_CACHE_BUFFER_CHUNK_SIZE", settings.cache_buffer_chunk_size );
   overrideSettingsNum( "GT_SESSION_CACHE_EXPIRY", settings.cache_expiry );
   overrideSettingsBool( "GT_SESSION_USE_READ_CACHE", settings.use_read_cache );
   overrideSettingsBool( "GT_SESSION_EXPLICIT_READ_CACHE", settings.explicit_read_cache );
   overrideSettingsNum( "GT_SESSION_EXPLICIT_CACHE_INTERVAL", settings.explicit_cache_interval );
   overrideSettingsNum( "GT_SESSION_DISK_IO_WRITE_MODE", settings.disk_io_write_mode );
   overrideSettingsNum( "GT_SESSION_DISK_IO_READ_MODE", settings.disk_io_read_mode );
   overrideSettingsBool( "GT_SESSION_COALESCE_READS", settings.coalesce_reads );
   overrideSettingsBool( "GT_SESSION_COALESCE_WRITES", settings.coalesce_writes );
#if 0 // TODO
   std::pair<int, int> outgoing_ports;
#endif
   overrideSettingsChar( "GT_SESSION_PEER_TOS", settings.peer_tos );
   overrideSettingsNum( "GT_SESSION_ACTIVE_DOWNLOADS", settings.active_downloads );
   overrideSettingsNum( "GT_SESSION_ACTIVE_SEEDS", settings.active_seeds );
   overrideSettingsNum( "GT_SESSION_ACTIVE_DHT_LIMIT", settings.active_dht_limit );
   overrideSettingsNum( "GT_SESSION_ACTIVE_TRACKER_LIMIT", settings.active_tracker_limit );
   overrideSettingsNum( "GT_SESSION_ACTIVE_LSD_LIMIT", settings.active_lsd_limit );
   overrideSettingsNum( "GT_SESSION_ACTIVE_LIMIT", settings.active_limit );
   overrideSettingsBool( "GT_SESSION_AUTO_MANAGE_PREFER_SEEDS", settings.auto_manage_prefer_seeds );
   overrideSettingsBool( "GT_SESSION_DONT_COUNT_SLOW_TORRENTS", settings.dont_count_slow_torrents );
   overrideSettingsNum( "GT_SESSION_AUTO_MANAGE_INTERVAL", settings.auto_manage_interval );
   overrideSettingsNum( "GT_SESSION_SHARE_RATIO_LIMIT", settings.share_ratio_limit );
   overrideSettingsNum( "GT_SESSION_SEED_TIME_RATIO_LIMIT", settings.seed_time_ratio_limit );
   overrideSettingsNum( "GT_SESSION_SEED_TIME_LIMIT", settings.seed_time_limit );
   overrideSettingsNum( "GT_SESSION_PEER_TURNOVER_INTERVAL", settings.peer_turnover_interval );
   overrideSettingsNum( "GT_SESSION_PEER_TURNOVER", settings.peer_turnover );
   overrideSettingsNum( "GT_SESSION_PEER_TURNOVER_CUTOFF", settings.peer_turnover_cutoff );
   overrideSettingsBool( "GT_SESSION_CLOSE_REDUNDANT_CONNECTIONS", settings.close_redundant_connections );
   overrideSettingsBool( "GT_SESSION_INHIBIT_KEEPALIVES", settings.inhibit_keepalives );
   overrideSettingsNum( "GT_SESSION_AUTO_SCRAPE_INTERVAL", settings.auto_scrape_interval );
   overrideSettingsNum( "GT_SESSION_AUTO_SCRAPE_MIN_INTERVAL", settings.auto_scrape_min_interval );
   overrideSettingsNum( "GT_SESSION_MAX_PEERLIST_SIZE", settings.max_peerlist_size );
   overrideSettingsNum( "GT_SESSION_MAX_PAUSED_PEERLIST_SIZE", settings.max_paused_peerlist_size );
   overrideSettingsNum( "GT_SESSION_MIN_ANNOUNCE_INTERVAL", settings.min_announce_interval );
   overrideSettingsBool( "GT_SESSION_PRIORITIZE_PARTIAL_PIECES", settings.prioritize_partial_pieces );
   overrideSettingsNum( "GT_SESSION_AUTO_MANAGE_STARTUP", settings.auto_manage_startup );
   overrideSettingsBool( "GT_SESSION_RATE_LIMIT_IP_OVERHEAD", settings.rate_limit_ip_overhead );
   overrideSettingsBool( "GT_SESSION_ANNOUNCE_TO_ALL_TRACKERS", settings.announce_to_all_trackers );
   overrideSettingsBool( "GT_SESSION_ANNOUNCE_TO_ALL_TIERS", settings.announce_to_all_tiers );
   overrideSettingsBool( "GT_SESSION_PREFER_UDP_TRACKERS", settings.prefer_udp_trackers );
   overrideSettingsBool( "GT_SESSION_STRICT_SUPER_SEEDING", settings.strict_super_seeding );
   overrideSettingsNum( "GT_SESSION_SEEDING_PIECE_QUOTA", settings.seeding_piece_quota );
   overrideSettingsNum( "GT_SESSION_MAX_SPARSE_REGIONS", settings.max_sparse_regions );
#ifndef TORRENT_DISABLE_MLOCK
   overrideSettingsBool( "GT_SESSION_LOCK_DISK_CACHE", settings.lock_disk_cache );
#endif
   overrideSettingsNum( "GT_SESSION_MAX_REJECTS", settings.max_rejects );
   overrideSettingsNum( "GT_SESSION_RECV_SOCKET_BUFFER_SIZE", settings.recv_socket_buffer_size );
   overrideSettingsNum( "GT_SESSION_SEND_SOCKET_BUFFER_SIZE", settings.send_socket_buffer_size );
   overrideSettingsBool( "GT_SESSION_OPTIMIZE_HASHING_FOR_SPEED", settings.optimize_hashing_for_speed );
   overrideSettingsNum( "GT_SESSION_FILE_CHECKS_DELAY_PER_BLOCK", settings.file_checks_delay_per_block );
   overrideSettingsEnum( "GT_SESSION_DISK_CACHE_ALGORITHM", settings.disk_cache_algorithm );
   overrideSettingsNum( "GT_SESSION_READ_CACHE_LINE_SIZE", settings.read_cache_line_size );
   overrideSettingsNum( "GT_SESSION_WRITE_CACHE_LINE_SIZE", settings.write_cache_line_size );
   overrideSettingsNum( "GT_SESSION_OPTIMISTIC_DISK_RETRY", settings.optimistic_disk_retry );
   overrideSettingsBool( "GT_SESSION_DISABLE_HASH_CHECKS", settings.disable_hash_checks );
   overrideSettingsBool( "GT_SESSION_ALLOW_REORDERED_DISK_OPERATIONS", settings.allow_reordered_disk_operations );
   overrideSettingsBool( "GT_SESSION_ALLOW_I2P_MIXED", settings.allow_i2p_mixed );
   overrideSettingsNum( "GT_SESSION_MAX_SUGGEST_PIECES", settings.max_suggest_pieces );
   overrideSettingsBool( "GT_SESSION_DROP_SKIPPED_REQUESTS", settings.drop_skipped_requests );
   overrideSettingsBool( "GT_SESSION_LOW_PRIO_DISK", settings.low_prio_disk );
   overrideSettingsNum( "GT_SESSION_LOCAL_SERVICE_ANNOUNCE_INTERVAL", settings.local_service_announce_interval );
   overrideSettingsNum( "GT_SESSION_DHT_ANNOUNCE_INTERVAL", settings.dht_announce_interval );
   overrideSettingsNum( "GT_SESSION_UDP_TRACKER_TOKEN_EXPIRY", settings.udp_tracker_token_expiry );
   overrideSettingsBool( "GT_SESSION_VOLATILE_READ_CACHE", settings.volatile_read_cache );
   overrideSettingsBool( "GT_SESSION_GUIDED_READ_CACHE", settings.guided_read_cache );
   overrideSettingsNum( "GT_SESSION_DEFAULT_CACHE_MIN_AGE", settings.default_cache_min_age );
   overrideSettingsNum( "GT_SESSION_NUM_OPTIMISTIC_UNCHOKE_SLOTS", settings.num_optimistic_unchoke_slots );
   overrideSettingsBool( "GT_SESSION_NO_ATIME_STORAGE", settings.no_atime_storage );
   overrideSettingsNum( "GT_SESSION_DEFAULT_EST_RECIPROCATION_RATE", settings.default_est_reciprocation_rate );
   overrideSettingsNum( "GT_SESSION_INCREASE_EST_RECIPROCATION_RATE", settings.increase_est_reciprocation_rate );
   overrideSettingsNum( "GT_SESSION_DECREASE_EST_RECIPROCATION_RATE", settings.decrease_est_reciprocation_rate );
   overrideSettingsBool( "GT_SESSION_INCOMING_STARTS_QUEUED_TORRENTS", settings.incoming_starts_queued_torrents );
   overrideSettingsBool( "GT_SESSION_REPORT_TRUE_DOWNLOADED", settings.report_true_downloaded );
   overrideSettingsBool( "GT_SESSION_STRICT_END_GAME_MODE", settings.strict_end_game_mode );
   overrideSettingsNum( "GT_SESSION_DEFAULT_PEER_UPLOAD_RATE", settings.default_peer_upload_rate );
   overrideSettingsNum( "GT_SESSION_DEFAULT_PEER_DOWNLOAD_RATE", settings.default_peer_download_rate );
   overrideSettingsBool( "GT_SESSION_BROADCAST_LSD", settings.broadcast_lsd );
   overrideSettingsBool( "GT_SESSION_ENABLE_OUTGOING_UTP", settings.enable_outgoing_utp );
   overrideSettingsBool( "GT_SESSION_ENABLE_INCOMING_UTP", settings.enable_incoming_utp );
   overrideSettingsBool( "GT_SESSION_ENABLE_OUTGOING_TCP", settings.enable_outgoing_tcp );
   overrideSettingsBool( "GT_SESSION_ENABLE_INCOMING_TCP", settings.enable_incoming_tcp );
   overrideSettingsNum( "GT_SESSION_MAX_PEX_PEERS", settings.max_pex_peers );
   overrideSettingsBool( "GT_SESSION_IGNORE_RESUME_TIMESTAMPS", settings.ignore_resume_timestamps );
   overrideSettingsBool( "GT_SESSION_NO_RECHECK_INCOMPLETE_RESUME", settings.no_recheck_incomplete_resume );
   overrideSettingsBool( "GT_SESSION_ANONYMOUS_MODE", settings.anonymous_mode );
   overrideSettingsNum( "GT_SESSION_TICK_INTERVAL", settings.tick_interval );
   overrideSettingsBool( "GT_SESSION_REPORT_WEB_SEED_DOWNLOADS", settings.report_web_seed_downloads );
   overrideSettingsNum( "GT_SESSION_SHARE_MODE_TARGET", settings.share_mode_target );
   overrideSettingsNum( "GT_SESSION_UPLOAD_RATE_LIMIT", settings.upload_rate_limit );
   overrideSettingsNum( "GT_SESSION_DOWNLOAD_RATE_LIMIT", settings.download_rate_limit );
   overrideSettingsNum( "GT_SESSION_LOCAL_UPLOAD_RATE_LIMIT", settings.local_upload_rate_limit );
   overrideSettingsNum( "GT_SESSION_LOCAL_DOWNLOAD_RATE_LIMIT", settings.local_download_rate_limit );
   overrideSettingsNum( "GT_SESSION_DHT_UPLOAD_RATE_LIMIT", settings.dht_upload_rate_limit );
   overrideSettingsNum( "GT_SESSION_UNCHOKE_SLOTS_LIMIT", settings.unchoke_slots_limit );
   overrideSettingsNum( "GT_SESSION_HALF_OPEN_LIMIT", settings.half_open_limit );
   overrideSettingsNum( "GT_SESSION_CONNECTIONS_LIMIT", settings.connections_limit );
   overrideSettingsNum( "GT_SESSION_UTP_TARGET_DELAY", settings.utp_target_delay );
   overrideSettingsNum( "GT_SESSION_UTP_GAIN_FACTOR", settings.utp_gain_factor );
   overrideSettingsNum( "GT_SESSION_UTP_MIN_TIMEOUT", settings.utp_min_timeout );
   overrideSettingsNum( "GT_SESSION_UTP_SYN_RESENDS", settings.utp_syn_resends );
   overrideSettingsNum( "GT_SESSION_UTP_FIN_RESENDS", settings.utp_fin_resends );
   overrideSettingsNum( "GT_SESSION_UTP_NUM_RESENDS", settings.utp_num_resends );
   overrideSettingsNum( "GT_SESSION_UTP_CONNECT_TIMEOUT", settings.utp_connect_timeout );
   overrideSettingsNum( "GT_SESSION_UTP_DELAYED_ACK", settings.utp_delayed_ack );
   overrideSettingsBool( "GT_SESSION_UTP_DYNAMIC_SOCK_BUF", settings.utp_dynamic_sock_buf );
   overrideSettingsNum( "GT_SESSION_MIXED_MODE_ALGORITHM", settings.mixed_mode_algorithm );
   overrideSettingsBool( "GT_SESSION_RATE_LIMIT_UTP", settings.rate_limit_utp );
   overrideSettingsNum( "GT_SESSION_LISTEN_QUEUE_SIZE", settings.listen_queue_size );
   overrideSettingsBool( "GT_SESSION_ANNOUNCE_DOUBLE_NAT", settings.announce_double_nat );
   overrideSettingsNum( "GT_SESSION_TORRENT_CONNECT_BOOST", settings.torrent_connect_boost );
   overrideSettingsBool( "GT_SESSION_SEEDING_OUTGOING_CONNECTIONS", settings.seeding_outgoing_connections );
   overrideSettingsBool( "GT_SESSION_NO_CONNECT_PRIVILEGED_PORTS", settings.no_connect_privileged_ports );
   overrideSettingsNum( "GT_SESSION_ALERT_QUEUE_SIZE", settings.alert_queue_size );
   overrideSettingsNum( "GT_SESSION_MAX_METADATA_SIZE", settings.max_metadata_size );
   overrideSettingsBool( "GT_SESSION_SMOOTH_CONNECTS", settings.smooth_connects );
   overrideSettingsBool( "GT_SESSION_ALWAYS_SEND_USER_AGENT", settings.always_send_user_agent );
   overrideSettingsBool( "GT_SESSION_APPLY_IP_FILTER_TO_TRACKERS", settings.apply_ip_filter_to_trackers );
   overrideSettingsNum( "GT_SESSION_READ_JOB_EVERY", settings.read_job_every );
   overrideSettingsBool( "GT_SESSION_USE_DISK_READ_AHEAD", settings.use_disk_read_ahead );
   overrideSettingsBool( "GT_SESSION_LOCK_FILES", settings.lock_files );
   overrideSettingsNum( "GT_SESSION_SSL_LISTEN", settings.ssl_listen );
   overrideSettingsNum( "GT_SESSION_EXTERNAL_PORT_DELTA", settings.external_port_delta );
}

template<typename T> void gtBase::overrideSettingsNum( const char* name, T &value )
{
   char *envValue = std::getenv( name );
   if( envValue != NULL ) {
      try {
         value = boost::lexical_cast<T>( std::string( envValue ) );
      } catch( boost::bad_lexical_cast &e) {
         overrideSettingsError( name, "Not a valid numeric value" );
      }
   }
}

template<typename T> void gtBase::overrideSettingsEnum( const char* name, T &value )
{
   overrideSettingsNum( name, *((int *) &value) );
}

void gtBase::overrideSettingsBool( const char* name, bool &value )
{
   char *envValue = std::getenv( name );
   if( envValue != NULL ) {
      try {
         switch( boost::lexical_cast<int>( std::string( envValue ) ) ) {
         case 0:
            value = false;
            break;
         case 1:
            value = true;
            break;
         default:
            overrideSettingsError( name, "Overrides of type 'bool' must be either '0' or '1'" );
         }
      } catch( boost::bad_lexical_cast &e ) {
         overrideSettingsError( name, "Overrides of type 'bool' must be either '0' or '1'" );
      }
   }
}

void gtBase::overrideSettingsChar( const char* name, char &value )
{
   char *envValue = std::getenv( name );
   if( envValue != NULL ) {
      if( std::strlen( envValue ) == 1 ) {
         value = envValue[0];
      } else {
         overrideSettingsError( name, "Overrides of type 'char' must be exactly one byte long" );
      }
   }
}

void gtBase::overrideSettingsString( const char* name, std::string &value )
{
   char *envValue = std::getenv( name );
   if( envValue != NULL ) {
      value = std::string( envValue );
   }
}

void gtBase::overrideSettingsError( const char* name, const char* message )
{
   gtError( std::string( name ) + ": " + message, COMMAND_LINE_OR_CONFIG_FILE_ERROR, DEFAULT_ERROR, 0 );
   abort(); // should not happen
}

// 
void gtBase::loggingCallBack (std::string message)
{
   pthread_mutex_lock (&callBackLoggerLock);

   static std::ostringstream messageBuff;
   messageBuff << message;

   if (std::string::npos != message.find ('\n'))
   {
      std::string logMessage = messageBuff.str().substr(0, messageBuff.str().size() - 1);
      messageBuff.str("");
      pthread_mutex_unlock (&callBackLoggerLock);

      boost::regex searchPattern ("[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]");

      if (regex_search (logMessage, searchPattern))
      {
         logMessage = logMessage.substr(12);
      }

      while (logMessage[0] == ' ' || logMessage[0] == '*' || logMessage[0] == '=' || logMessage[0] == '>')
      {
         logMessage.erase(0,1); 
      }

      if (logMessage.size() > 2)
      {
         if (((gtBase *)geneTorrCallBackPtr)->getLogMask() & LOG_LT_CALL_BACK_LOGGER)
         {
            Log (PRIORITY_NORMAL, "%s", logMessage.c_str());
         }
      }
      return;
   }
   pthread_mutex_unlock (&callBackLoggerLock);
}



void gtBase::processSSLError (std::string message)
{
   std::string errorMessage = message;

   unsigned long sslError;
   char sslErrorBuf[150];

   while (0 != ( sslError = ERR_get_error()))
   {
      ERR_error_string_n (sslError, sslErrorBuf, sizeof (sslErrorBuf));
      errorMessage += sslErrorBuf + std::string (", ");
   }

   if (_operatingMode != SERVER_MODE)
   {
      gtError (errorMessage, SSL_ERROR_EXIT_CODE);
   }
   else
   {
      gtError (errorMessage, ERROR_NO_EXIT);
   }
}

// 
bool gtBase::generateCSR (std::string uuid)
{
   RSA *rsaKey;

   // Generate RSA Key
   rsaKey =  RSA_generate_key(RSA_KEY_SIZE, RSA_F4, NULL, NULL);

   if (NULL == rsaKey)
   {
      processSSLError ("Failure generating OpenSSL Key:  ");   // if this returns server mode is active and we bail on this attempt
      return false;
   }

   EVP_PKEY *pKey;

   // Initialize private key store
   pKey = EVP_PKEY_new();

   if (NULL == pKey)
   {
      RSA_free(rsaKey);
      processSSLError ("Failure initializing OpenSSL EVP object:  ");   // if this returns server mode is active and we bail on this attempt
      return false;
   }    

   // Add key to private key store
   if (!(EVP_PKEY_set1_RSA (pKey, rsaKey)))
   {
      EVP_PKEY_free (pKey);
      RSA_free (rsaKey);
      processSSLError ("Failure adding OpenSSL key to EVP object:  ");   // if this returns server mode is active and we bail on this attempt
      return false;
   }    

   X509_REQ *csr;

   // Allocate a CSR
   csr = X509_REQ_new();

   if (NULL == csr)
   {
      EVP_PKEY_free (pKey);
      RSA_free(rsaKey);
      processSSLError ("Failure allocating OpenSSL CSR:  ");   // if this returns server mode is active and we bail on this attempt
      return false;
   }    

   // set the public key part of the SCR
   if (!(X509_REQ_set_pubkey (csr, pKey)))
   {
      X509_REQ_free (csr); 
      EVP_PKEY_free (pKey);
      RSA_free (rsaKey);
      processSSLError ("Failure adding public key to OpenSSL CSR:  ");   // if this returns server mode is active and we bail on this attempt
      return false;
   }    
  
   // allocate subject attribute structure 
   X509_NAME *subject;

   subject = X509_NAME_new();

   if (NULL == subject)
   {
      X509_REQ_free (csr); 
      EVP_PKEY_free (pKey);
      RSA_free(rsaKey);
      processSSLError ("Failure allocating OpenSSL X509 Name Structure:  ");   // if this returns server mode is active and we bail on this attempt
      return false;
   }    

   // Add attributes to subject
   for (int i = 0; i < CSR_ATTRIBUTE_ENTRY_COUNT; i++)
   {
      if (!X509_NAME_add_entry_by_txt(subject, attributes[i].key.c_str(), MBSTRING_ASC, (const unsigned char *)attributes[i].value.c_str(), -1, -1, 0))
      {
         X509_NAME_free (subject);
         X509_REQ_free (csr); 
         EVP_PKEY_free (pKey);
         RSA_free(rsaKey);
         processSSLError ("Failure adding " + attributes[i].key + " to OpenSSL X509 Name Structure:  ");   // if this returns server mode is active and we bail on this attempt
         return false;
      }
   }

   // Add the subject to the CSR
   if (!(X509_REQ_set_subject_name(csr, subject)))
   {
      X509_NAME_free (subject);
      X509_REQ_free (csr); 
      EVP_PKEY_free (pKey);
      RSA_free(rsaKey);
      processSSLError ("Failure adding X509 Name Structure to CSR:  ");   // if this returns server mode is active and we bail on this attempt
      return false;
   }

   EVP_MD *digest;

   digest = (EVP_MD *)EVP_sha1();

   if (NULL == digest)
   {
      X509_NAME_free (subject);
      X509_REQ_free (csr); 
      EVP_PKEY_free (pKey);
      RSA_free(rsaKey);
      processSSLError ("Failure allocating OpenSSL sha1 digest:  ");   // if this returns server mode is active and we bail on this attempt
      return false;
   }

   if (!(X509_REQ_sign(csr, pKey, digest)))
   {
      X509_NAME_free (subject);
      X509_REQ_free (csr); 
      EVP_PKEY_free (pKey);
      RSA_free(rsaKey);
      processSSLError ("Failure creating OpenSSL CSR:  ");   // if this returns server mode is active and we bail on this attempt
      return false;
   }

   FILE *outputFile;
   std::string csrPathAndFile = _tmpDir + uuid + ".csr";

   if (NULL == (outputFile = fopen(csrPathAndFile.c_str(), "w")))
   {
      X509_NAME_free (subject);
      X509_REQ_free (csr); 
      EVP_PKEY_free (pKey);
      RSA_free(rsaKey);
      processSSLError ("Failure opening " + csrPathAndFile + " for output.  Unable to write OpenSSL CSR.");   // if this returns server mode is active and we bail on this attempt
      return false;
   }
 
   if (PEM_write_X509_REQ(outputFile, csr) != 1)
   {
      fclose(outputFile);
      X509_NAME_free (subject);
      X509_REQ_free (csr); 
      EVP_PKEY_free (pKey);
      RSA_free(rsaKey);
      processSSLError ("Failure writing OpenSSL CSR to " + csrPathAndFile + ":  ");   // if this returns server mode is active and we bail on this attempt
      return false;
   }
   fclose(outputFile);

   std::string pKeyPathAndFile = _tmpDir + uuid + ".key";

   if (NULL == (outputFile = fopen(pKeyPathAndFile.c_str(), "w")))
   {
      X509_NAME_free (subject);
      X509_REQ_free (csr); 
      EVP_PKEY_free (pKey);
      RSA_free(rsaKey);
      processSSLError ("Failure opening " + pKeyPathAndFile + " for output.  Unable to write OpenSSL private key.");   // if this returns server mode is active and we bail on this attempt
      return false;
   }

   if (PEM_write_PrivateKey(outputFile, pKey, NULL, NULL, 0, 0, NULL) != 1)
   {
      fclose(outputFile);
      X509_NAME_free (subject);
      X509_REQ_free (csr); 
      EVP_PKEY_free (pKey);
      RSA_free(rsaKey);
      processSSLError ("Failure writing OpenSSL Private Key to " + pKeyPathAndFile + ":  ");   // if this returns server mode is active and we bail on this attempt
      return false;
   }
   fclose(outputFile);

   // Clean up memory allocated
   X509_NAME_free (subject);
   X509_REQ_free (csr); 
   EVP_PKEY_free (pKey);
   RSA_free (rsaKey);

   return true;
}

std::string gtBase::getFileName (std::string fileName)
{
   return boost::filesystem::path(fileName).filename().string();
}

std::string gtBase::getInfoHash (std::string torrentFile)
{
   libtorrent::error_code torrentError;
   libtorrent::torrent_info torrentInfo (torrentFile, torrentError);

   if (torrentError)
   {
      if (_operatingMode != SERVER_MODE)
      {
         gtError (".gto processing problem with " + torrentFile, 87, TORRENT_ERROR, torrentError.value (), "", torrentError.message ());
      }
      else
      {
         gtError (".gto processing problem with " + torrentFile, ERROR_NO_EXIT, TORRENT_ERROR, torrentError.value (), "", torrentError.message ());
         return "";
      }
   }

   return getInfoHash (&torrentInfo);
}

// 
std::string gtBase::getInfoHash (libtorrent::torrent_info *torrentInfo)
{
   libtorrent::sha1_hash const& info_hash = torrentInfo->info_hash();

   std::ostringstream infoHash;
   infoHash << info_hash;

   return infoHash.str();
}

// 
bool gtBase::generateSSLcertAndGetSigned(std::string torrentFile, std::string signUrl, std::string torrentUUID)
{
   std::string infoHash = getInfoHash(torrentFile);

   if (infoHash.size() < 20)
   {
      return false;
   }

   return acquireSignedCSR (infoHash, signUrl, torrentUUID);
}

FILE *gtBase::createCurlTempFile (std::string &tempFilePath)
{
   std::string t = _tmpDir + "gt-curl-response-XXXXXX";
   char tmpname[4096];
   FILE *curl_stderr_fp;

   strncpy (tmpname, t.c_str(), t.size() + 1);        // extra byte includes the NULL which eliminates the needs to bzero (tmpname, ....)

   int curl_stderr = mkstemp (tmpname);
   if (curl_stderr < 0)
   {
      Log (PRIORITY_HIGH, "Failed to create CURL temp file:  %s [%s (%d)]", tmpname, strerror (errno), errno);
      return NULL;
   }

   // fdopen Returns NULL on error
   curl_stderr_fp = fdopen (curl_stderr, "w+");

   tempFilePath = std::string (tmpname);
   return curl_stderr_fp;
}

void gtBase::finishCurlTempFile (FILE *curl_stderr_fp, std::string tempFilePath)
{
   if (curl_stderr_fp == NULL)
   {
      Log (PRIORITY_HIGH, "finishCurlTempFile called with NULL file pointer.");
      return;
   }

   if (fseek (curl_stderr_fp, 0, SEEK_END) < 0)
   {
      Log (PRIORITY_HIGH, "Failed to seek in CURL temp file.");
      return;
   }

   long size = ftell (curl_stderr_fp);
   rewind (curl_stderr_fp);

   char *curlMessage = (char *) malloc (size + 1);
   if (curlMessage == NULL)
   {
      fclose (curl_stderr_fp);
      if (unlink (tempFilePath.c_str()) < 0)
      {
         Log (PRIORITY_HIGH, "Failed to delete CURL temp file.");
      }
   }

   int count = fread(curlMessage, 1, size, curl_stderr_fp);
   // Add null-terminator
   curlMessage[size] = '\0';

   if (count)
   {
      screenOutput ("CURL library diagnostic information: " <<
         curlMessage << std::endl, VERBOSE_2);
   }
   else
   {
      Log (PRIORITY_HIGH, "Failed to read CURL temp file.");
   }

   free (curlMessage);

   fclose (curl_stderr_fp);
   if (unlink (tempFilePath.c_str()) < 0)
   {
      Log (PRIORITY_HIGH, "Failed to delete CURL temp file.");
   }
}

// 
bool gtBase::acquireSignedCSR (std::string info_hash, std::string CSRSignURL, std::string uuid)
{
   bool csrStatus = generateCSR (uuid);

   if (false == csrStatus)
   {
      return csrStatus;
   }

   std::string certFileName = _tmpDir + uuid + ".crt";
   std::string csrFileName = _tmpDir + uuid + ".csr";

   std::string csrData = loadCSRfile (csrFileName);

   if (csrData.size() == 0)  // only enounter this in SERVER_MODE, other modes exit.
   {
      gtError ("Operating in Server Mode, empty or missing CSR file encountered.  Discarding GTO from serving qeueue.", ERROR_NO_EXIT);
      return false;
   }

   FILE *signedCert;

   signedCert = fopen (certFileName.c_str (), "w");

   if (signedCert == NULL)
   {
      if (_operatingMode != SERVER_MODE)
      {
         gtError ("Failure opening " + certFileName + " for output.", 202, ERRNO_ERROR, errno);
      }
      else
      {
         gtError ("Failure opening " + certFileName + " for output.", ERROR_NO_EXIT, ERRNO_ERROR, errno);
         return false;
      }
   }

   char errorBuffer[CURL_ERROR_SIZE + 1];
   errorBuffer[0] = '\0';

   std::string curlResponseHeaders = "";

   checkIPFilter (CSRSignURL);

   CURL *curl;
   curl = curl_easy_init ();

   if (!curl)
   {
      if (_operatingMode != SERVER_MODE)
      {
         gtError ("libCurl initialization failure", 201);
      }
      else
      {
         gtError ("libCurl initialization failure", ERROR_NO_EXIT);
         return false;
      }
   }

   if (!_curlVerifySSL)
   {
      curl_easy_setopt (curl, CURLOPT_SSL_VERIFYPEER, 0);
      curl_easy_setopt (curl, CURLOPT_SSL_VERIFYHOST, 0);
   }

   curl_easy_setopt (curl, CURLOPT_ERRORBUFFER, errorBuffer);
   curl_easy_setopt (curl, CURLOPT_WRITEFUNCTION, NULL);
   curl_easy_setopt (curl, CURLOPT_HEADERFUNCTION, &curlCallBackHeadersWriter);
   curl_easy_setopt (curl, CURLOPT_MAXREDIRS, 15);
   curl_easy_setopt (curl, CURLOPT_WRITEDATA, signedCert);
   curl_easy_setopt (curl, CURLOPT_WRITEHEADER, &curlResponseHeaders);
   curl_easy_setopt (curl, CURLOPT_NOSIGNAL, (long)1);
   curl_easy_setopt (curl, CURLOPT_POST, (long)1);
#ifdef __CYGWIN__
	std::string winInst = getWinInstallDirectory () + "/cacert.pem";
	curl_easy_setopt (curl, CURLOPT_CAINFO, winInst.c_str ());
#endif /* __CYGWIN__ */

   struct curl_httppost *post=NULL;
   struct curl_httppost *last=NULL;

   curl_formadd (&post, &last, CURLFORM_COPYNAME, "token", CURLFORM_COPYCONTENTS, _authToken.c_str(), CURLFORM_END);
   curl_formadd (&post, &last, CURLFORM_COPYNAME, "cert_req", CURLFORM_COPYCONTENTS, csrData.c_str(), CURLFORM_END);
   curl_formadd (&post, &last, CURLFORM_COPYNAME, "info_hash", CURLFORM_COPYCONTENTS, info_hash.c_str(), CURLFORM_END);

   curl_easy_setopt (curl, CURLOPT_HTTPPOST, post);

   // CGHUBDEV-22: Set CURL timeouts to 20 seconds
   int timeoutVal = 20;
   int connTime = 20;

   curl_easy_setopt (curl, CURLOPT_URL, CSRSignURL.c_str());
   curl_easy_setopt (curl, CURLOPT_TIMEOUT, timeoutVal);
   curl_easy_setopt (curl, CURLOPT_CONNECTTIMEOUT, connTime);

   std::string tmppath;
   FILE *curl_stderr_fp = createCurlTempFile(tmppath);

   if (curl_stderr_fp)
   {
      curl_easy_setopt (curl, CURLOPT_VERBOSE, 1);
      curl_easy_setopt (curl, CURLOPT_STDERR, curl_stderr_fp);
   }
   else if (_verbosityLevel > VERBOSE_2)
   {
      curl_easy_setopt (curl, CURLOPT_VERBOSE, 1);
   }

   CURLcode res;
   int retries = 5;

   while (retries)
   {
      res = curl_easy_perform (curl);

      if (res != CURLE_SSL_CONNECT_ERROR && res != CURLE_OPERATION_TIMEDOUT)
      {
         // Only retry on SSL connect errors or timeouts in case the other end is temporarily overloaded.
         break;
      }

      // Give the other end time to become less loaded.
      sleep (2);

      retries--;

      if (retries)
      {
         screenOutput ("Retrying CSR signing for UUID: " + uuid, VERBOSE_1);
      }
   }

   fclose (signedCert);

   bool successfulPerform = processCurlResponse (curl, res, certFileName, CSRSignURL, uuid, "Problem communicating with GeneTorrent Executive while attempting a CSR signing transaction for UUID:", retries);

   curl_formfree (post);
   curl_easy_cleanup (curl);

   finishCurlTempFile (curl_stderr_fp, tmppath);
   screenOutput ("Headers received from the client:  '" << curlResponseHeaders << "'" << std::endl, VERBOSE_2);

   if (!successfulPerform)
   {
      if (_operatingMode != SERVER_MODE)
      {
         exit (1);
      }
   }

   return successfulPerform;
}

void gtBase::curlCleanupOnFailure (std::string fileName, FILE *gtoFile)
{
   fclose (gtoFile);
   int ret = unlink (fileName.c_str ());

   if (ret != 0)
   {
      gtError ("Unable to remove ", NO_EXIT, gtBase::ERRNO_ERROR, errno);
   }
}

void gtBase::removeFile (std::string fileName)
{
   int ret = unlink (fileName.c_str ());

   if (ret != 0)
   {
      gtError ("Unable to remove ", NO_EXIT, gtBase::ERRNO_ERROR, errno);
   }
}

std::string gtBase::makeTimeStamp ()
{
   const int BUFF_SIZE = 25;
   char buffer[BUFF_SIZE];
   char tail[BUFF_SIZE];
   char secBuff[BUFF_SIZE];
   struct timeval tp;

   gettimeofday (&tp, NULL);

   snprintf (secBuff, BUFF_SIZE, ".%03d", int (tp.tv_usec/1000));

   struct tm newTime;

   localtime_r (&tp.tv_sec, &newTime);
   strftime (buffer, BUFF_SIZE, "%m/%d-%T", &newTime);
   strftime (tail, BUFF_SIZE, "%z", &newTime);

   return buffer + std::string (secBuff) + tail;
}

bool gtBase::processHTTPError (std::string fileWithErrorXML, int retryCount, int optionalExitCode)
{
   XQilla xqilla;

   try
   {
      AutoDelete <XQQuery> query (xqilla.parse (X("//CGHUB_error/usermsg/text()|//CGHUB_error/effect/text()|//CGHUB_error/remediation/text()")));
      AutoDelete <DynamicContext> context (query->createDynamicContext ());

      // Disable schema validation. WS results don't contain schema references so validation is ineffective.
      context->getDocumentCache()->setDoPSVI( false );
      Sequence seq = context->resolveDocument (X(fileWithErrorXML.c_str()));

      if (!seq.isEmpty () && seq.first()->isNode ())
      {
         context->setContextItem (seq.first ());
         context->setContextPosition (1);
         context->setContextSize (1);
      }
      else
      {
         throw ("Empty set, likely invalid xml");
      }

      Result result = query->execute (context);
      Item::Ptr item;
   
      item = result->next (context);

      if (!item)
      {
         throw ("Empty item, no matching xml nodes");
      }

      std::string userMsg = UTF8(item->asString(context));
      item = result->next (context);

      if (!item)
      {
         throw ("Empty item, no matching xml nodes");
      }

      std::string effect = UTF8(item->asString(context));
      item = result->next (context);

      if (!item)
      {
         throw ("Empty item, no matching xml nodes");
      }

      std::string remediation = UTF8(item->asString(context));

      if (!(userMsg.size() && effect.size() && remediation.size()))
      {
         throw ("Incomplete message set.");
      }

      std::ostringstream logMessage;

      logMessage << userMsg << "  " << effect << "  " << remediation << std::endl;

      if (retryCount > 0)
      { 
         Log (PRIORITY_HIGH, "%s", logMessage.str().c_str());
      }
      else
      { 
         gtError ("Error:  " + logMessage.str(), 203);
      }

      if (GTO_FILE_DOWNLOAD_EXTENSION == fileWithErrorXML.substr (fileWithErrorXML.size() - 1))
      {
         removeFile (fileWithErrorXML);
      }
      
   }
   catch (...)
   {
      // Catch any error from parsing and return false to indicate processing is not complete, e.g., no xml, invalid xml, etc.
      if (GTO_FILE_DOWNLOAD_EXTENSION == fileWithErrorXML.substr (fileWithErrorXML.size() - 1))
      {
         std::string newFileName = fileWithErrorXML.substr (0, fileWithErrorXML.size() - 1) + GTO_ERROR_DOWNLOAD_EXTENSION;

         int result = rename (fileWithErrorXML.c_str(), newFileName.c_str());
         if (0 != result)
         {
            gtError ("Unable to rename " + fileWithErrorXML + " to " + newFileName, 203, ERRNO_ERROR, errno);
         }

         std::ostringstream logMessage;
         logMessage << "error processing failure with file:  " << newFileName <<  ", review the contents of the file.";
         Log (PRIORITY_HIGH, "%s", logMessage.str().c_str());

         std::ifstream errorFile;
         errorFile.open (newFileName.c_str ());
         while (errorFile.good ())
         {
            char line[200];
             errorFile.getline (line, sizeof (line) - 1);
            std::cerr << line << std::endl;
         }
         errorFile.close ();

      }
      return false;
   }

   if (ERROR_NO_EXIT == optionalExitCode)
   {
      return true;
   }

   exit (optionalExitCode);
}
 
bool gtBase::processCurlResponse (CURL *curl, CURLcode result, std::string fileName, std::string url, std::string uuid, std::string defaultMessage, int retryCount)
{
   if (result != CURLE_OK)
   {
      if (GTO_FILE_DOWNLOAD_EXTENSION == fileName.substr (fileName.size() -1))
      {
         removeFile (fileName);
      }
      
      gtError (defaultMessage + uuid, ERROR_NO_EXIT, gtBase::CURL_ERROR, result, "URL:  " + url);
      return false;
   }

   long code;
   result = curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);

   if (result != CURLE_OK)
   {
      if (GTO_FILE_DOWNLOAD_EXTENSION == fileName.substr (fileName.size() -1))
      {
         removeFile (fileName);
      }
      
      gtError (defaultMessage + uuid, ERROR_NO_EXIT, gtBase::DEFAULT_ERROR, 0, "URL:  " + url);
      return false;
   }

// TODO, use content type
   if (code != 200)
   {
      // returns true if successfully used the XML in the file,
      // otherwise log generic error with GTError
      if (!processHTTPError (fileName, retryCount, ERROR_NO_EXIT))
      {
         gtError (defaultMessage + uuid, ERROR_NO_EXIT, gtBase::HTTP_ERROR, code, "URL:  " + url);
      }
      return false;   // return false to indicate failed curl transaction
   }
   return true;    // success curl transaction
}

// Small wrapper around time () to initialize
// or update a time_t struct
time_t gtBase::timeout_update (time_t *timer)
{
   return time (timer);
}

// Check whether timeout is expired
// It is expired if all of the following:
//    this->_inactiveTimeout > 0
//    timer != NULL
//    time elapsed since last timer update
//       is > _inactiveTimeout (* 60 for seconds)
bool gtBase::timeout_check_expired (time_t *timer)
{
   if (_inactiveTimeout <= 0 || !timer)
      return false;

   if (time (NULL) - *timer > _inactiveTimeout * 60)
      return true;

   return false;
}

std::string gtBase::authTokenFromURI (std::string url)
{

   char errorBuffer[CURL_ERROR_SIZE + 1] = {'\0'};

   std::string curlResponseHeaders = "";
   std::string curlResponseData = "";

   checkIPFilter (url);

   CURL *curl;
   curl = curl_easy_init ();

   if (!curl)
      gtError ("libCurl initialization failure", 201);

   if (!_curlVerifySSL)
   {
      curl_easy_setopt (curl, CURLOPT_SSL_VERIFYPEER, 0);
      curl_easy_setopt (curl, CURLOPT_SSL_VERIFYHOST, 0);
   }

   curl_easy_setopt (curl, CURLOPT_ERRORBUFFER, errorBuffer);
   curl_easy_setopt (curl, CURLOPT_WRITEFUNCTION, &curlCallBackHeadersWriter);
   curl_easy_setopt (curl, CURLOPT_HEADERFUNCTION, &curlCallBackHeadersWriter);
   curl_easy_setopt (curl, CURLOPT_MAXREDIRS, 15);
   curl_easy_setopt (curl, CURLOPT_WRITEDATA, &curlResponseData);
   curl_easy_setopt (curl, CURLOPT_WRITEHEADER, &curlResponseHeaders);
   curl_easy_setopt (curl, CURLOPT_NOSIGNAL, (long)1);
   curl_easy_setopt (curl, CURLOPT_HTTPGET, (long)1);
#ifdef __CYGWIN__
	std::string winInst = getWinInstallDirectory () + "/cacert.pem";
	curl_easy_setopt (curl, CURLOPT_CAINFO, winInst.c_str ());
#endif /* __CYGWIN__ */

   // CGHUBDEV-22: Set CURL timeouts to 20 seconds
   int timeoutVal = 20;
   int connTime = 20;

   curl_easy_setopt (curl, CURLOPT_URL, url.c_str());
   curl_easy_setopt (curl, CURLOPT_TIMEOUT, timeoutVal);
   curl_easy_setopt (curl, CURLOPT_CONNECTTIMEOUT, connTime);

   std::string tmppath;
   FILE *curl_stderr_fp = createCurlTempFile(tmppath);

   if (curl_stderr_fp)
   {
      curl_easy_setopt (curl, CURLOPT_VERBOSE, 1);
      curl_easy_setopt (curl, CURLOPT_STDERR, curl_stderr_fp);
   }
   else if (_verbosityLevel > VERBOSE_2)
   {
      curl_easy_setopt (curl, CURLOPT_VERBOSE, 1);
   }

   CURLcode res;
   long code = -1;

   res = curl_easy_perform (curl);
   curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);

   if (res != CURLE_OK || code < 200 || code >= 300 ||
      curlResponseData.size() < 1)
   {
      std::ostringstream errormsg;
      errormsg << "Failed to download authentication token from provided URI.";
      if (code != 0)
         errormsg << " Response code = " << code << ".";
      if (strlen(errorBuffer))
         errormsg << " Error = " << errorBuffer;
      gtError (errormsg.str(), 65);
   }

   curl_easy_cleanup (curl);

   finishCurlTempFile (curl_stderr_fp, tmppath);
   screenOutput ("Headers received from the client:  '" << curlResponseHeaders << "'" << std::endl, VERBOSE_2);

   return curlResponseData;
}

// Checks whether a given (WSI) URL resolves to an IP address that is allowed
// by the filter, and exits with a command line error if not
void gtBase::checkIPFilter (std::string url)
{
   if (!_allowedServersSet)
      return;

   const std::string proto = "://";
   std::string hostName;
   size_t hostStart, hostEnd;
   if ((hostStart = url.find (proto)) != std::string::npos)
   {
      hostStart += proto.size();
      if ((hostEnd = url.find ("/", hostStart + 1)) !=
         std::string::npos)
         hostName = url.substr(hostStart, hostEnd - hostStart);
   }

   if (hostName.size() == 0)
      gtError ("Bad URL given for WSI call. Could not extract hostname"
               " from URL: " + url + ".", 59);

   boost::system::error_code ec;
   boost::asio::io_service io_service;
   boost::asio::ip::tcp::resolver resolver(io_service);
   boost::asio::ip::tcp::resolver::query query(hostName, "");
   for(boost::asio::ip::tcp::resolver::iterator i = resolver.resolve(query, ec);
                               i != boost::asio::ip::tcp::resolver::iterator();
                               ++i)
   {
      if (ec)
         continue;
       boost::asio::ip::tcp::endpoint end = *i;
       if (_ipFilter.access (end.address()))
          gtError ("IP address of server in WSI call is outside of"
                   " the allowed server range on this system.  Host: "
                   + hostName, 59);
   }
}

void gtBase::loadCredentialFile (std::string credsPathAndFile)
{
   if (credsPathAndFile.size() == 0)
      return;

   if (credsPathAndFile.find("http://")  == 0 ||
       credsPathAndFile.find("https://") == 0 ||
       credsPathAndFile.find("ftp://")   == 0 ||
       credsPathAndFile.find("ftps://")  == 0)
   {
      _authToken = authTokenFromURI (credsPathAndFile);
      return;
   }

   std::ifstream credFile;

   credFile.open (credsPathAndFile.c_str(), std::ifstream::in);

   if (!credFile.good ())
   {
      gtError ("credentials file not found (or is not readable):  "
               + credsPathAndFile, 55);
   }

   try
   {
      credFile >> _authToken;
   }
   catch (...)
   {
      gtError ("credentials file not found (or is not readable):  "
               + credsPathAndFile, 56);
   }

   credFile.close ();
}
