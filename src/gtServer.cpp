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
 * gtServer.cpp
 *
 *  Created on: Jan 27, 2012
 *      Author: donavan
 */

#define _DARWIN_C_SOURCE 1

#include "gt_config.h"

#include <iostream>
#include <fstream>
#include <iomanip>
#include <cstdio>

#include <boost/filesystem/path.hpp>
#include <boost/filesystem/operations.hpp>
#include <boost/regex.hpp>
#include <boost/algorithm/string.hpp>

#include "libtorrent/entry.hpp"
#include "libtorrent/bencode.hpp"

#include "libtorrent/create_torrent.hpp"

#include "libtorrent/peer_info.hpp"
#include "libtorrent/ip_filter.hpp"
#include "libtorrent/alert_types.hpp"

#include <xqilla/xqilla-simple.hpp>

// #include <curl/curl.h>

#include "gtServer.h"
#include "stringTokenizer.h"
#include "gtDefs.h"
#include "geneTorrentUtils.h"
#include "gtLog.h"
#include "loggingmask.h"
#include "gtNullStorage.h"
#include "gtZeroStorage.h"

static char const* server_state_str[] = {
   "checking (q)",                    // queued_for_checking,
   "checking",                        // checking_files,
   "dl metadata",                     // downloading_metadata,
   "receiving",                       // downloading,
   "finished",                        // finished,
   "serving",                         // seeding,
   "allocating",                      // allocating,
   "checking (r)"                     // checking_resume_data
};

extern void *geneTorrCallBackPtr; 

gtServer::gtServer (gtServerOpts &opts):
   gtBase (opts, SERVER_MODE),
   _serverQueuePath (opts.m_serverQueuePath),
   _serverDataPath (opts.m_serverDataPath),
   _serverModeCsrSigningUrl (opts.m_csrSigningUrl),
   _serverForceDownload(opts.m_serverForceDownload),
   _activeSessions (),

   // 1 port for SSL and 1 port for Non SSL per session
   // maximum sessions is 1/2 the allowed port range
   _maxActiveSessions ((opts.m_portEnd - opts.m_portStart + 1) / 2)
{
   startUpMessage();

   _startUpComplete = true;
}

void gtServer::getFilesInQueueDirectory (vectOfStr &files)
{
   boost::filesystem::path queueDir (_serverQueuePath);

   boost::regex searchPattern (std::string (".*" + GTO_FILE_EXTENSION));

   for (boost::filesystem::directory_iterator iter (queueDir), end; iter != end; iter++)
   {
      std::string fileName = iter->path().filename().string();
      if (regex_match (fileName, searchPattern))
      {
         files.push_back (_serverQueuePath + '/' + fileName);
      }
   }
}

void gtServer::checkSessions ()
{
   gtServer::activeSessionRec *workingSessionRec = NULL;

   while (_activeSessions.size () == 0) // Loop until a session is added
   {
      libtorrent::session *workingSession = addActiveSession ();

      if (workingSession)
      {
         workingSessionRec = new gtServer::activeSessionRec;
         workingSessionRec->torrentSession = workingSession;

         _activeSessions.push_back (workingSessionRec);
      }
      else
      {
         Log (PRIORITY_HIGH, "Unable to listen on any ports between %d and %d (system level ports).  GeneTorrent can not Serve data until at least one port is available.", _portStart, _portEnd);
         sleep (3); // give OS chance to clean up ports desired by this process
      }
   }

   if (_activeSessions.size () < _maxActiveSessions && workingSessionRec == NULL) // Try one time to add a new session
   {
      libtorrent::session *workingSession = addActiveSession ();

      if (workingSession)
      {
         workingSessionRec = new gtServer::activeSessionRec;
         workingSessionRec->torrentSession = workingSession;

         _activeSessions.push_back (workingSessionRec);
      }
   }
}

//
//  Managing torrents in Server mode is moderately complex
//
//  SessionRec->
//
//
//
void gtServer::run ()
{
   int cdRet = chdir (_serverDataPath.c_str ());

   if (cdRet != 0 )
   {
      gtError ("Failure changing directory to " + _serverDataPath, 202, ERRNO_ERROR, errno);
   }

   time_t nextMaintTime = time(NULL) + 30;         // next time stamp to perform maintenance -- shorten a bit for startup
   std::set <std::string> activeTorrentCollection; // list of active torrents, tracks if a GTO is being served
                                                   // This list is indirectly duplicated by the list of torrents being served
                                                   // that is maintained inside the list of activeSessions.
                                                   // This list is maintained here for simplicity and speed

   // determine location of stop file on this OS
   libtorrent::error_code ec;
   std::string stopPathAndFile;
   boost::filesystem::path stopFile = boost::filesystem::temp_directory_path(ec);
   if (!ec)
   {
      stopFile /= SERVER_STOP_FILE;
      stopPathAndFile = stopFile.string();
   }
   else
   {
      // An error occurred, use a default
      stopPathAndFile = "/tmp/" + SERVER_STOP_FILE;
   }

   bool isStarting = true;

   while (1)
   {
      if (!statFile (stopPathAndFile.c_str())) //statFile returns -1 on error
      {
         Log (PRIORITY_HIGH, "Exiting server due to existence of stop file %s",
            stopPathAndFile.c_str());
         break;
      }
      // Get the collection of .gto files in the queue directory
      vectOfStr filesInQueue;
      getFilesInQueueDirectory (filesInQueue);
      vectOfStr::iterator vectIter = filesInQueue.begin ();

      while (vectIter != filesInQueue.end ()) // check each .gto file to ensure GeneTorrent is "serving" the file
      {
         std::set <std::string>::iterator actTorrentIter;
         actTorrentIter = activeTorrentCollection.find (*vectIter);

         if (actTorrentIter == activeTorrentCollection.end ()) // gto is not in the set of active torrents
         {
            if (addTorrentToServingList (*vectIter, isStarting))  // Successfully added to a serving session
            {
               activeTorrentCollection.insert (*vectIter);
            }
         } 
         vectIter++;
      }

      isStarting = false;

      time_t timeNow = time(NULL);      

      if (nextMaintTime <= timeNow)
      {
         nextMaintTime = time(NULL) + 60;  // Set the time for the next maintenance window

         servedGtosMaintenance (timeNow, activeTorrentCollection);

         screenOutput ("", VERBOSE_1);
         continue;  // completed a maintenance cycle, skip the 2 second sleep cycle
      }

      processServerModeAlerts();
   }

   servedGtosMaintenance (time(NULL), activeTorrentCollection, true);

   // Note that remove_torrent does at least two things asynchronously: 1) it
   // sets in motion the deletion of this torrent object, and 2) it sends the
   // stopped event to the tracker and waits for a response.  So if we were to
   // exit immediately, two bad things happen.  First, the stopped event is
   // probably not sent.  Second, we end up doubly-deleting some objects
   // inside of libtorrent (because the deletion is already in progress and
   // then the call to exit() causes some cleanup as well), and we get nasty
   // complaints about malloc corruption printed to the console by glibc.
   //
   // The "proper" approached from a libtorrent perspective is to wait to
   // receive both the cache_flushed_alert and the tracker_reply_alert,
   // indicating that all is well.  However in the case of tearing down a
   // torrent, libtorrent appears to squelch the tracker_reply_alert so we
   // never get it (even though the tracker does in fact respond to the
   // stopped event sent to it by libtorrent).
   //
   // Therefore, ugly as it is, for the time being we will simply sleep here.
   // TODO: fix libtorrent so we ca do the proper thing of waiting to receive
   // the two events mentioned above.

   sleep(5);
}

void gtServer::processServerModeAlerts ()
{
   libtorrent::ptime endMonitoring = libtorrent::time_now_hires() + libtorrent::seconds(2);

   while (libtorrent::time_now_hires() < endMonitoring)
   {
      std::list <activeSessionRec *>::iterator listIter = _activeSessions.begin ();

      while (listIter != _activeSessions.end ())
      {
         checkAlerts (*(*listIter)->torrentSession);
         listIter++;
      }
      usleep(ALERT_CHECK_PAUSE_INTERVAL);
   }
}

void gtServer::servedGtosMaintenance (time_t timeNow, std::set <std::string> &activeTorrents, bool shutdownFlag)
{
   std::list <activeSessionRec *>::iterator listIter = _activeSessions.begin ();
   while (listIter != _activeSessions.end ())
   {
      std::map <std::string, activeTorrentRec *>::iterator mapIter = (*listIter)->mapOfSessionTorrents.begin (); //mapOfSessionTorrents

      while (mapIter != (*listIter)->mapOfSessionTorrents.end ())
      {
         libtorrent::torrent_status torrentStatus = mapIter->second->torrentHandle.status ();
         time_t torrentModTime = 0;
               
         if (statFile (mapIter->first, torrentModTime) < 0)
         {
            // The torrent has disappeared, stop serving it.
            Log (PRIORITY_NORMAL, " Stop serving:  GTO disappeared from queue:  %s info hash:  %s",  mapIter->first.c_str(), mapIter->second->infoHash.c_str());

            (*listIter)->torrentSession->remove_torrent (mapIter->second->torrentHandle);
            activeTorrents.erase (mapIter->first);
            delete (mapIter->second);
            (*listIter)->mapOfSessionTorrents.erase (mapIter++);

            continue;
         }

         if (torrentModTime != mapIter->second->mtime)   // Has the GTO on disk changed
         {
            if (getInfoHash (mapIter->first) != mapIter->second->infoHash)
            {
               Log (PRIORITY_HIGH, "Stop serving:  GTO InfoHash Changed while serving:  %s info hash:  %s (new GTO infoHash %s will not be served)", mapIter->first.c_str(), mapIter->second->infoHash.c_str(), getInfoHash (mapIter->first).c_str()); 

               (*listIter)->torrentSession->remove_torrent (mapIter->second->torrentHandle);
               deleteGTOfromQueue (mapIter->first);
               activeTorrents.erase (mapIter->first);
               delete (mapIter->second);
               (*listIter)->mapOfSessionTorrents.erase (mapIter++);

               continue;
            }
           
            mapIter->second->mtime = torrentModTime;
            mapIter->second->expires = getExpirationTime (mapIter->first);

            if (timeNow <  mapIter->second->expires)
            {
               mapIter->second->overTimeAlertIssued = false;
            }

            Log (PRIORITY_NORMAL, "Expiration Update:  GTO %s info hash:  %s has a new expiration time %d", mapIter->first.c_str(), mapIter->second->infoHash.c_str(), mapIter->second->expires);
         }

         // if an upload torrent and the current state is seeding, set the overtime flag to true on the first obversation of this stats
         // on the 2nd observation of this state, the gto will removed from the upload queue and removed from seeding
         // This gives the upload plenty of time to recognize that the upload has completed (I.E., the upload client recognizes
         // two seeders are present due to tracker scraping
         if (mapIter->second->downloadGTO == false && mapIter->second->torrentHandle.status().state == libtorrent::torrent_status::seeding)
         {
            if (!mapIter->second->overTimeAlertIssued)   // first pass set true
            {
               mapIter->second->overTimeAlertIssued = true;
               screenOutput (std::setw (41) << getFileName (mapIter->first) << " Status: " << server_state_str[torrentStatus.state] << "  expires in approximately:  00:01:00.", VERBOSE_1);
               mapIter++;
            }
            else                                         // second pass, remove the torrent from serving
            {
               Log (PRIORITY_NORMAL, "Stop serving:  upload complete %s info hash:  %s", mapIter->first.c_str(), getInfoHash (mapIter->first).c_str());

               (*listIter)->torrentSession->remove_torrent (mapIter->second->torrentHandle);
               deleteGTOfromQueue (mapIter->first);
               activeTorrents.erase (mapIter->first);
               delete (mapIter->second);
               (*listIter)->mapOfSessionTorrents.erase (mapIter++);
            }

            continue;
         }

         if (timeNow >= mapIter->second->expires || shutdownFlag)       // This GTO is expired or shutting down
         {
            std::vector <libtorrent::peer_info> peers;

            mapIter->second->torrentHandle.get_peer_info (peers);

            if (peers.size () == 0 || shutdownFlag)
            {
               Log (PRIORITY_NORMAL, "%s:  %s info hash:  %s", (shutdownFlag ? "Shutting Down (stop servering)" : "Expiring"), mapIter->first.c_str(), getInfoHash (mapIter->first).c_str());

               (*listIter)->torrentSession->remove_torrent (mapIter->second->torrentHandle);
               if (!shutdownFlag)        // If shutting down, keep the GTO files in the queue
               {
                  deleteGTOfromQueue (mapIter->first);
               }
               activeTorrents.erase (mapIter->first);
               delete (mapIter->second);
               (*listIter)->mapOfSessionTorrents.erase (mapIter++);
            }
            else
            {
               if (!mapIter->second->overTimeAlertIssued)
               {
                  Log (PRIORITY_NORMAL, "Overtime serving:  %s info hash:  %s (%d actor(s) connected)", mapIter->first.c_str(), getInfoHash (mapIter->first).c_str(), peers.size());
                  mapIter->second->overTimeAlertIssued = true;
               }
   
               screenOutput (std::setw (41) << getFileName (mapIter->first) << " Status: " << server_state_str[torrentStatus.state] << "  expired, but an actors continue to download", VERBOSE_1);
               mapIter++;
            }
         }
         else
         {
            mapIter++;
         }
      }
      listIter++;
   }
}

bool gtServer::isDownloadModeGetFromGTO (std::string torrentPathAndFileName)
{
   bool dlMode = false;

   if (_serverForceDownload)
      return true;

   FILE *data = popen (("gtoinfo --get-key gt_download_mode " + torrentPathAndFileName).c_str(), "r");

   if (data != NULL)
   {
      char vBuff[1024];

      if (NULL != fgets (vBuff, 1024, data))
      {
         std::string result = vBuff;

         std::size_t foundPos;
 
         if (std::string::npos != (foundPos = result.find ('\n')))
         {
            result.erase (foundPos);
         }

         if (boost::iequals (PYTHON_TRUE, result))
         {
            dlMode = true;
         }
      }
      else
      {
         Log (PRIORITY_HIGH, "Failure running gtoinfo on %s or no 'gt_download_mode' in GTO, defaulting to upload mode", torrentPathAndFileName.c_str());
      }
      pclose (data);
   }
   else
   {
      Log (PRIORITY_HIGH, "Failure running gtoinfo on %s, defaulting to upload mode", torrentPathAndFileName.c_str());
   }

   return dlMode;       
}

bool gtServer::addTorrentToServingList (std::string pathAndFileName, bool startUpMode)
{
   activeSessionRec *workSession = findSession ();

   activeTorrentRec *newTorrRec = new (activeTorrentRec);

   newTorrRec->expires = getExpirationTime (pathAndFileName);
   newTorrRec->overTimeAlertIssued = false;

   time_t torrentModTime = 0;
   if (statFile (pathAndFileName, torrentModTime) < 0)
   {
      Log (PRIORITY_HIGH, "Failure adding %s to Served GTOs, GTO file removed.  Error:  %s (%d)", pathAndFileName.c_str(), strerror (errno), errno);
      delete newTorrRec;
      deleteGTOfromQueue (pathAndFileName);
      return false;
   }

   newTorrRec->mtime = torrentModTime;
   newTorrRec->infoHash = getInfoHash (pathAndFileName);

   std::string uuid = pathAndFileName;

   uuid = uuid.substr (0, uuid.rfind ('.'));
   uuid = getFileName (uuid); 

   if (isDownloadModeGetFromGTO (pathAndFileName))
   {
      newTorrRec->torrentParams.seed_mode = true;
      newTorrRec->torrentParams.disable_seed_hash = true;
      newTorrRec->downloadGTO = true;
   }
   else
   {
      newTorrRec->downloadGTO = false;
   }

   // TODO: Might need _use_*_storage flags specific to D/L and U/L mode for
   // gtServer.

   if (_use_null_storage)
   {
      newTorrRec->torrentParams.storage = null_storage_constructor;
   }
   else if (_use_zero_storage)
   {
      newTorrRec->torrentParams.storage = zero_storage_constructor;
   }

   newTorrRec->torrentParams.auto_managed = false;
   newTorrRec->torrentParams.allow_rfc1918_connections = true;
   newTorrRec->torrentParams.save_path = "./";

   libtorrent::error_code torrentError;
   newTorrRec->torrentParams.ti = new libtorrent::torrent_info (pathAndFileName, torrentError);

   if (torrentError)
   {
      Log (PRIORITY_HIGH, "Failure adding %s to Served GTOs, GTO file removed.  Error: %s (%d)", pathAndFileName.c_str(), torrentError.message().c_str(), torrentError.value ());
      delete newTorrRec;
      deleteGTOfromQueue (pathAndFileName);
      return false;
   }

   newTorrRec->torrentHandle = workSession->torrentSession->add_torrent (newTorrRec->torrentParams, torrentError);

   if (torrentError)
   {
      Log (PRIORITY_HIGH, "Failure adding %s to Served GTOs, GTO file removed.  Error: %s (%d)", pathAndFileName.c_str(), torrentError.message().c_str(), torrentError.value ());
      delete newTorrRec;
      deleteGTOfromQueue (pathAndFileName);
      return false;
   }

   int sslCertSize = newTorrRec->torrentParams.ti->ssl_cert().size();

   if (sslCertSize > 0 && _devMode == false)
   {
      bool status = generateSSLcertAndGetSigned(pathAndFileName, _serverModeCsrSigningUrl, uuid); 

      if (status == false)
      {
         Log (PRIORITY_HIGH, "Failure adding %s to Served GTOs, GTO file removed.  Error:  unable to obtain a signed SSL Certificate.", pathAndFileName.c_str());
         delete newTorrRec;
         deleteGTOfromQueue (pathAndFileName);
         return false;
      }
   }

   if (sslCertSize > 0)
   {
      std::string sslCert = _tmpDir + uuid + ".crt";
      std::string sslKey = _tmpDir + uuid + ".key";
            
      newTorrRec->torrentHandle.set_ssl_certificate (sslCert, sslKey, _dhParamsFile);   // no passphrase
   }

   // The resume() causes the first announce of the torrent to be sent
   // to the tracker. If there are a lot of .gto files sitting in the
   // workqueue which are all added to the session at once, then we
   // will effectively DOS the tracker (looks like syn flood if N is
   // large, say 15K). Staggering the announcements with a delay
   // breaks the burstiness down into smaller groups.
   // Nov 2013, update to apply delays only during startup
   if (startUpMode)
   {
      static unsigned int stagger_announce_step = 0;
      const boost::int64_t delay_step_ms = 500;
      const int max_steps = 60; // gives max delay of 30s
      newTorrRec->torrentHandle.resume (delay_step_ms * (stagger_announce_step % max_steps));
      stagger_announce_step++;
   }
   else
   {
      newTorrRec->torrentHandle.resume(0);
   }

   screenOutput ("adding " << getFileName (pathAndFileName) << " to files being served", VERBOSE_1);

   Log (PRIORITY_NORMAL, "Begin serving:  %s info hash:  %s expires:  %d (%s)", pathAndFileName.c_str(), newTorrRec->infoHash.c_str(), newTorrRec->expires, (newTorrRec->torrentParams.seed_mode == true ? "download" : "upload"));
   workSession->mapOfSessionTorrents[pathAndFileName] = newTorrRec;

   return true;
}

gtServer::activeSessionRec *gtServer::findSession ()
{
   checkSessions (); // start or adds sessions if unused session slots exist

   std::list <activeSessionRec *>::iterator listIter = _activeSessions.begin ();
   unsigned int torrentsBeingServed = (*listIter)->mapOfSessionTorrents.size ();
   gtServer::activeSessionRec *workingSessionRec = *listIter;

   while (listIter != _activeSessions.end ())
   {
      if (torrentsBeingServed > (*listIter)->mapOfSessionTorrents.size ())
      {
         torrentsBeingServed = (*listIter)->mapOfSessionTorrents.size ();
         workingSessionRec = *listIter;
      }
      listIter++;
   }

   return workingSessionRec;;
}

void gtServer::deleteGTOfromQueue (std::string fileName)
{
   int ret = unlink (fileName.c_str ()); 
   if (ret != 0)
   {
      gtError ("Unable to remove ", NO_EXIT, gtServer::ERRNO_ERROR, errno);
   }
}

libtorrent::session *gtServer::addActiveSession ()
{
   libtorrent::session *sessionNew = makeTorrentSession ();

   if (!sessionNew)
      return NULL;

   int portUsed = sessionNew->listen_port ();
   int sslPortUsed = sessionNew->ssl_listen_port ();

   // verify both portUsed and sslPortUsed fall within the allowed pool
   if ((portUsed < _portStart + _exposedPortDelta || portUsed > _portEnd + _exposedPortDelta) ||
       (sslPortUsed < _portStart + _exposedPortDelta || sslPortUsed > _portEnd + _exposedPortDelta))
   {
      delete sessionNew;
      return NULL;
   }

   return sessionNew;
}

time_t gtServer::getExpirationTime (std::string torrentPathAndFileName)
{
   time_t expireTime = 2114406000;     // Default to 1/1/2037

   FILE *result = popen (("gtoinfo -x " + torrentPathAndFileName).c_str(), "r");

   if (result != NULL)
   {
      char vBuff[15];

      if (NULL != fgets (vBuff, 15, result))
      {
         expireTime = strtol (vBuff, NULL, 10);
         if (0 == expireTime)
         {
            expireTime = 2114406000;     // set back to 1/1/2037
            Log (PRIORITY_HIGH, "Failure running gtoinfo on %s or no 'expires on' in GTO, serving using default expiration of 1/1/2037", torrentPathAndFileName.c_str());
         }
      }
      else
      {
         Log (PRIORITY_HIGH, "Failure running gtoinfo on %s or no 'expires on' in GTO, serving using default expiration of 1/1/2037", torrentPathAndFileName.c_str());
      }
      pclose (result);
   }
   else
   {
      Log (PRIORITY_HIGH, "Failure running gtoinfo on %s, serving using default expiration of 1/1/2037", torrentPathAndFileName.c_str());
   }

   return expireTime;
}
