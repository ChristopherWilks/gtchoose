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
 * gtUpload.cpp
 *
 *  Created on: Jan 27, 2012
 *      Author: donavan
 */

#define _DARWIN_C_SOURCE 1

#include "gt_config.h"

#include <sys/statvfs.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <iostream>
#include <fstream>
#include <iomanip>
#include <cstdio>

#include <boost/filesystem/path.hpp>
#include <boost/filesystem/operations.hpp>
#include <boost/algorithm/string.hpp>

#include "libtorrent/entry.hpp"
#include "libtorrent/bencode.hpp"

#include "libtorrent/create_torrent.hpp"

#include "libtorrent/peer_info.hpp"
#include "libtorrent/ip_filter.hpp"
#include "libtorrent/alert_types.hpp"

#include <xqilla/xqilla-simple.hpp>

#include <curl/curl.h>

#include "gtUpload.h"
#include "stringTokenizer.h"
#include "gtDefs.h"
#include "geneTorrentUtils.h"
#include "gtLog.h"
#include "loggingmask.h"
#include "gtNullStorage.h"
#include "gtZeroStorage.h"

/*
static char const* upload_state_str[] = {
   "checking (q)",                     // queued_for_checking,
   "checking",                         // checking_files,
   "dl metadata",                      // downloading_metadata,
   "starting",                         // downloading,
   "finished",                         // finished,
   "uploading",                        // seeding,
   "allocating",                       // allocating,
   "checking (r)"                      // checking_resume_data
};
*/

extern void *geneTorrCallBackPtr; 

gtUpload::gtUpload (gtUploadOpts &opts):
   gtBase (opts, UPLOAD_MODE),
   _manifestFile (opts.m_manifestFile),
   _uploadUUID (""),
   _uploadSubmissionURL (""),
   _filesToUpload (),
   _pieceSize (4194304),
   _dataFilePath (opts.m_dataFilePath),
   _uploadGTODir (opts.m_uploadGTODir),
   _piecesInTorrent (0),
   _uploadGTOOnly(opts.m_uploadGTOOnly)
{
   startUpMessage();

   _startUpComplete = true;
}

void gtUpload::configureUploadGTOdir (std::string uuid)
{
   if (_uploadGTODir.size())      // User supplied something on the CLI
   {
      relativizePath (_uploadGTODir);
      _uploadGTODir +=  "/";
   }
   else
   {
      _uploadGTODir = getWorkingDirectory() + "/" + uuid + "/";
   }
}

void gtUpload::run ()
{
   std::string saveDir = getWorkingDirectory ();
   processManifestFile ();

   int64_t totalBytes = 0;
   unsigned totalFiles = 0;
   std::string torrentFileName = _uploadUUID + GTO_FILE_EXTENSION;
   bool inResumeMode = false;
   long resumeProgress = 0;

   if (!_devMode)        // devMode assumes the GTO is present, either from a previous run or manual assembly and is in the current directory
   {
      findDataAndSetWorkingDirectory ();
      configureUploadGTOdir (_uploadUUID);
      totalBytes = setPieceSize (totalFiles);

      time_t gtoTimeStamp;

      if (!statFile (_uploadGTODir + torrentFileName, gtoTimeStamp))
      {  // resume mode
         inResumeMode = true;
         resumeProgress = evaluateUploadResume(gtoTimeStamp, torrentFileName);
      }
      else
      {
         makeTorrent (_uploadUUID);
      }
      
      submitTorrentToGTExecutive (torrentFileName);
   }

   time_t startTime = time(NULL);
   std::ostringstream message;

   if (!inResumeMode)              // This message will not be accurate in dev mode
   {
      message << "Ready to upload 1 GTO with " << totalFiles << " file(s) comprised of " << add_suffix (totalBytes) << " of data"; 

      Log (PRIORITY_NORMAL, "%s", message.str().c_str());

      screenOutput (message.str(), VERBOSE_1);
   }

   if (!_uploadGTOOnly)
   {
      performGtoUpload (_uploadGTODir + torrentFileName, resumeProgress, inResumeMode);

      message.str("");

      if (!inResumeMode)     // This message will not be accurate in dev mode
      {
         time_t duration = time(NULL) - startTime;

         message << "Uploaded " << add_suffix (totalBytes) << " in " <<
            durationToStr (duration) << ".  Overall Rate " <<
            add_suffix (totalBytes/duration) << "/s";
      }
      else
      {
         message << "Resumed upload completed.  Total of " <<
            add_suffix (totalBytes) << " uploaded over multiple sessions.";
      }

      Log (PRIORITY_NORMAL, "%s", message.str().c_str());

      screenOutput (message.str(), VERBOSE_1);
   }
   else
   {
      // in gto-only mode
      std::string message = "GTO has been generated, but upload will be skipped";
      screenOutput (message, VERBOSE_0)
      Log (PRIORITY_NORMAL, "%s", message.c_str());
   }

   if (chdir (saveDir.c_str ()))
   {
      Log (PRIORITY_NORMAL, "Failed to chdir to saveDir");
   }
}

void gtUpload::submitTorrentToGTExecutive (std::string torrentFileName)
{
   screenOutput ("Submitting GTO to GT Executive...", VERBOSE_1);

   std::string uuidForErrors = _uploadUUID;

   FILE *gtoFile;

   gtoFile = fopen ((_uploadGTODir + torrentFileName + GTO_FILE_DOWNLOAD_EXTENSION).c_str (), "wb");

   if (gtoFile == NULL)
   {
      gtError ("Failure opening " + _uploadGTODir + torrentFileName + GTO_FILE_DOWNLOAD_EXTENSION + " for output.", 202, ERRNO_ERROR, errno);
   }

   char errorBuffer[CURL_ERROR_SIZE + 1];
   errorBuffer[0] = '\0';

   std::string curlResponseHeaders = "";

   checkIPFilter (_uploadSubmissionURL);

   CURL *curl;
   curl = curl_easy_init ();

   if (!curl)
   {
      gtError ("libCurl initialization failure", 201);
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
   curl_easy_setopt (curl, CURLOPT_WRITEDATA, gtoFile);
   curl_easy_setopt (curl, CURLOPT_WRITEHEADER, &curlResponseHeaders);
   curl_easy_setopt (curl, CURLOPT_NOSIGNAL, (long)1);
   curl_easy_setopt (curl, CURLOPT_POST, (long)1);
#ifdef __CYGWIN__
   std::string winInst = getWinInstallDirectory () + "/cacert.pem";
   curl_easy_setopt (curl, CURLOPT_CAINFO, winInst.c_str ());
#endif /* __CYGWIN__ */

   std::string data = "token=" + _authToken;

   struct curl_httppost *post=NULL;
   struct curl_httppost *last=NULL;

   curl_formadd (&post, &last, CURLFORM_COPYNAME, "token", CURLFORM_COPYCONTENTS, _authToken.c_str(), CURLFORM_END);

   curl_formadd (&post, &last, CURLFORM_COPYNAME, "file", CURLFORM_FILE, (_uploadGTODir + torrentFileName).c_str(), CURLFORM_FILENAME, torrentFileName.c_str(), CURLFORM_END);

   curl_easy_setopt (curl, CURLOPT_HTTPPOST, post);

   // CGHUBDEV-22: Set CURL timeouts to 20 seconds
   int timeoutVal = 20;
   int connTime = 20;

   curl_easy_setopt (curl, CURLOPT_URL, _uploadSubmissionURL.c_str());
   curl_easy_setopt (curl, CURLOPT_TIMEOUT, timeoutVal);
   curl_easy_setopt (curl, CURLOPT_CONNECTTIMEOUT, connTime);

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
         screenOutput ("Retrying to submit gto for UUID: " + _uploadUUID, VERBOSE_1);
      }
   }

   fclose (gtoFile);

   screenOutput ("Headers received from the client:  '" << curlResponseHeaders << "'" << std::endl, VERBOSE_2);

   processCurlResponse (curl, res, _uploadGTODir + torrentFileName + GTO_FILE_DOWNLOAD_EXTENSION, _uploadSubmissionURL, _uploadUUID, "Problem communicating with GeneTorrent Executive while trying to submit GTO for UUID:", 0);

   int result = rename ((_uploadGTODir + torrentFileName + GTO_FILE_DOWNLOAD_EXTENSION).c_str(), (_uploadGTODir + torrentFileName).c_str());
   
   if (0 != result)
   {
      gtError ("Unable to rename " + torrentFileName + GTO_FILE_DOWNLOAD_EXTENSION + " to " + torrentFileName, 203, ERRNO_ERROR, errno);
   }

   curl_formfree(post);
   curl_easy_cleanup (curl);
}

void gtUpload::findDataAndSetWorkingDirectory ()
{
   vectOfStr missingFiles;

   if (_dataFilePath.size () > 0) // User included a -p on the command line, move there
   {
      int cdRet = chdir (_dataFilePath.c_str ());

      if (cdRet != 0 )
      {
         gtError ("Failure changing directory to " + _dataFilePath, 202, ERRNO_ERROR, errno);
      }
   }

   // first look for files in the current directory
   if (verifyDataFilesExist (missingFiles))
   {
      return; // all data is present
   }

   if (missingFiles.size () != _filesToUpload.size ()) // only some of the files are missing, we have the correct directory, error
   {                                                   // if all files are missing presume wrong directory and continue
      displayMissingFilesAndExit (missingFiles);
   }

   missingFiles.clear ();

   int cdRet = chdir (".."); // move up one directory and try again

   if (cdRet != 0 )
   {
      gtError ("Failure changing directory to .. from " + getWorkingDirectory(), 202, ERRNO_ERROR, errno);
   }

   if (!verifyDataFilesExist (missingFiles))
   {
      displayMissingFilesAndExit (missingFiles); // Give up
   }
}

// This function verifies that all files specified in the manifest file exist in a
// directory named with the UUID in the manifest.
// the caller must be in the correct system directory when calling this function
// error check is the responsibility of the caller
bool gtUpload::verifyDataFilesExist (vectOfStr &missingFileList)
{
   bool missingFiles = false;
   std::string workingDataPath = _uploadUUID + "/";

   vectOfStr::iterator dupeIter = std::unique (_filesToUpload.begin(), _filesToUpload.end());

   _filesToUpload.resize (dupeIter - _filesToUpload.begin());


   vectOfStr::iterator vectIter = _filesToUpload.begin ();

   while (vectIter != _filesToUpload.end ())
   {
      if (statFile (workingDataPath + *vectIter) != 0 && statDirectory (workingDataPath + *vectIter) != 0)
      {
         missingFileList.push_back (*vectIter);
         missingFiles = true;
      }
      vectIter++;
   }

   return missingFiles ? false : true;
}

int64_t gtUpload::setPieceSize (unsigned &fileCount)
{
   struct stat fileStatus;
   int64_t totalDataSize = 0;

   vectOfStr::iterator vectIter = _filesToUpload.begin ();

   while (vectIter != _filesToUpload.end ())
   {
      int ret = stat ((_uploadUUID + "/" + *vectIter).c_str (), &fileStatus);

      if (ret == 0)
      {
         totalDataSize += fileStatus.st_size;
      }
      vectIter++;
      fileCount++;
   }

   while (totalDataSize / _pieceSize > 15000)
   {
      _pieceSize *= 2;
   }

   return totalDataSize;
}

void gtUpload::displayMissingFilesAndExit (vectOfStr &missingFiles)
{
   vectOfStr::iterator vectIter = missingFiles.begin ();

   while (vectIter != missingFiles.end ())
   {
      screenOutput ("Error:  " << strerror (errno) << " (errno = " << errno << ")  FileName:  " << _uploadUUID << "/" << *vectIter, VERBOSE_0);
      vectIter++;
   }

   gtError ("file(s) listed above were not found (or is (are) not readable)", 82, gtUpload::DEFAULT_ERROR);
}

long gtUpload::evaluateUploadResume (time_t gtoTimeStamp, std::string torrentName)
{
   screenOutput ("Evaluating " << torrentName << " for resume suitability...", VERBOSE_1);

   time_t fileTimeStamp;

   if (statFile (_manifestFile, fileTimeStamp))
   {
      gtError ("Unable to fstat " + _manifestFile + " for upload resume evaluation purposes.", 202, ERRNO_ERROR, errno);
   }

   if (fileTimeStamp > gtoTimeStamp)
   {
      gtError ("Unable to evaluate " + torrentName + " for upload resume purposes.  " + _manifestFile + " file is newer than GTO.", 217);
   }

   libtorrent::error_code torrentError;
   libtorrent::torrent_info torrentInfo (_uploadGTODir + torrentName, torrentError);

   if (torrentError)
   {
      gtError ("Unable to evaluate " + torrentName + " for upload resume purposes.", 217, TORRENT_ERROR, torrentError.value (), "", torrentError.message ());
   }

   for (libtorrent::torrent_info::file_iterator i = torrentInfo.begin_files(); i != torrentInfo.end_files(); ++i)
   {
      time_t fileTimeStamp;

      if (statFile (torrentInfo.files().file_path(*i), fileTimeStamp))
      {
         gtError ("Unable to evaluate contents of " + torrentName + " for upload resume purposes.  fstat failure on file:  " + torrentInfo.files().file_path(*i), 202, ERRNO_ERROR, errno);
      }

      if (fileTimeStamp > gtoTimeStamp)
      {
         gtError ("Unable to enable upload resume for " + torrentName + ".  Data files are newer than the .gto", 217);
      }
   }

   std::ifstream progressFile;
   long progress = 0;

   progressFile.open ((_uploadGTODir + torrentName + PROGRESS_FILE_EXT).c_str(), std::ifstream::in);

   if (!progressFile.good ())
   {
      gtError ("Unable to open previous upload progress file " + torrentName + PROGRESS_FILE_EXT + ".  The upload will resume, but % complete is not correct.", ERROR_NO_EXIT);
      return progress;
   }

   try
   {
      progressFile >> progress;
   }
   catch (...)
   {
      gtError ("Unable to read previous upload progress file " + torrentName + PROGRESS_FILE_EXT + ".  The upload will resume, but % complete is not correct.", ERROR_NO_EXIT);
   }

   return progress;
}

void gtUpload::makeTorrent (std::string uuid)
{
   std::string torrentName = uuid + GTO_FILE_EXTENSION;
 
   std::string torrentNameBuilding = uuid + GTO_FILE_BUILDING_EXTENSION;
 
   screenOutput ("Preparing " << torrentName << " for upload...", VERBOSE_1);
   screenOutputNoNewLine ("Computing checksums...", VERBOSE_1);

   std::string creator = std::string ("GeneTorrent-") + VERSION;
   std::string dataPath = libtorrent::complete (uuid);

   int flags = 0;

   try
   {
      libtorrent::file_storage fileStore;

      libtorrent::add_files (fileStore, dataPath, file_filter, flags);

      libtorrent::create_torrent torrent (fileStore, _pieceSize, -1, flags);

      torrent.add_tracker (DEFAULT_TRACKER_URL);

      _piecesInTorrent = torrent.num_pieces();

      libtorrent::set_piece_hashes (torrent, libtorrent::parent_path(dataPath), &hashCallback);
      torrent.set_creator (creator.c_str ());

      std::vector <char> finishedTorrent;
      bencode (back_inserter (finishedTorrent), torrent.generate ());

      FILE *output = fopen ((_uploadGTODir + torrentNameBuilding ).c_str (), "wb+");

      if (output == NULL)
      {
         gtError ("Failure opening " + _uploadGTODir + torrentNameBuilding + " for output.", 202, ERRNO_ERROR, errno);
      }

      fwrite (&finishedTorrent[0], 1, finishedTorrent.size (), output);
      fclose (output);
   }
   catch (...)
   {
      // TODO: better error handling here
      gtError ("Exception creating " + torrentName + " for output.", 232);
   }

   int result = rename ((_uploadGTODir + torrentNameBuilding).c_str(), (_uploadGTODir + torrentName).c_str());
   
   if (0 != result)
   {
      gtError ("Unable to rename " + torrentNameBuilding + " to " + torrentName, 203, ERRNO_ERROR, errno);
   }
}

void gtUpload::hashCallback (int piece)
{
   ((gtUpload *)geneTorrCallBackPtr)->hashCallbackImpl (piece);
}

void gtUpload::hashCallbackImpl (int piece)
{
   static time_t nextUpdate = 0;
 
   if (_verbosityLevel > VERBOSE_1 && piece > 0)   // Don't disply until we have something other than 0 to display
   {
      time_t timeNow = time(NULL); 
    
      if (timeNow > nextUpdate || piece + 1 == _piecesInTorrent)
      {
         std::ostringstream mess;
         if (nextUpdate > 0 )
         {
            mess << "\b\b\b\b\b\b\b";
         }
         mess << std::setw (6) << std::setprecision (2) << std::fixed << 100.0 * (piece + 1) / _piecesInTorrent << "%";

         if (_logToStdErr) 
         {
            std::cout << mess.str();
         }
         else
         {
            std::cerr << mess.str();
         }
         nextUpdate = timeNow + 1;
     
         // clean up screen as a new line is not printed 
         if (piece + 1 == _piecesInTorrent)
         {
            if (_logToStdErr) 
            {
               std::cout << std::endl;
            }
            else
            {
               std::cerr << std::endl;
            }
         }
      }
   }
}

void gtUpload::processManifestFile ()
{
   vectOfStr fileNames;

   XQilla xqilla;
   
   try
   {
      AutoDelete <XQQuery> query (xqilla.parse (X("for $variable in //SUBMISSION return //$variable/(SERVER_INFO/(@server_path|@submission_uri)|FILES/FILE/@filename)")));
      AutoDelete <DynamicContext> context (query->createDynamicContext ());
      // Disable schema validation. The XML in manifests is validated when it is ingested into GNOS.
      // There is no need to validate it again here. It is actually harmful since the SRA schema
      // references in the XML point at an unreliable server which, if it is down, causes validation
      // and hence the entire program to fail.
      context->getDocumentCache()->setDoPSVI( false );
      Sequence seq = context->resolveDocument (X(_manifestFile.c_str()));

      if (!seq.isEmpty () && seq.first ()->isNode ())
      {
         context->setContextItem (seq.first ());
         context->setContextPosition (1);
         context->setContextSize (1);
      }
      else
      {
         throw ("Empty set, invalid xml");
      }

      Result result = query->execute (context);

      Item::Ptr item;

      item = result->next (context);

      while (item != NULL)
      {
         strTokenize strToken (std::string (UTF8(item->asString(context))), "{}\"=", strTokenize::MERGE_CONSECUTIVE_SEPARATORS);

         std::string token1 = strToken.getToken (1);

         if (token1 == "server_path")
         {
            _uploadUUID = strToken.getToken (2);
         }
         else if (token1 == "submission_uri")
         {
            _uploadSubmissionURL = strToken.getToken (2);
         }
         else if (token1 == "filename")
         {
            std::string pathFileName = strToken.getToken (2);
 
            std::size_t foundPos = pathFileName.rfind ('/');
             
            if (std::string::npos != foundPos)
            { 
               std::string directory = pathFileName.substr (0, foundPos);
               _filesToUpload.push_back (directory);
            }
            _filesToUpload.push_back (strToken.getToken (2));
         }
         else
         {
            gtError ("Invalid manifest.xml file, unexpected attribute returned:  '" + token1 + "'", 201);
         }

         item = result->next (context); // Get the next node in the list from the xquery
      }
   }
   catch (...)
   {
      gtError ("Encountered an error attempting to process the file:  " + _manifestFile + ".  Review the contents of the file.", 97, gtBase::DEFAULT_ERROR, 0);
   }

   if (_uploadSubmissionURL.size () < 1)
   {
      gtError ("No Submission URL found in manifest file:  " + _manifestFile, 214, gtUpload::DEFAULT_ERROR);
   }

   if (_uploadUUID.size () < 1)
   {
      gtError ("No server_path (UUID) found in manifest file:  " + _manifestFile, 214, gtUpload::DEFAULT_ERROR);
   }

   if (_filesToUpload.size () < 1)
   {
      gtError ("No files found in manifest file:  " + _manifestFile, 214, gtUpload::DEFAULT_ERROR);
   }
}

void gtUpload::performGtoUpload (std::string torrentFileName, long previousProgress, bool inResumeMode)
{
   libtorrent::session *torrentSession = makeTorrentSession ();

   if (!torrentSession)
   {
      gtError ("unable to open a libtorrent session", 218, DEFAULT_ERROR);
   }

   libtorrent::add_torrent_params torrentParams;
   torrentParams.seed_mode = true;
   torrentParams.disable_seed_hash = true;
   torrentParams.allow_rfc1918_connections = true;
   // Upload mode, combined with auto_managed = false, should keep the libtorrent
   // session from ever requesting any pieces.
   torrentParams.upload_mode = true;
   torrentParams.auto_managed = false;
   torrentParams.save_path = "./";

   if (_use_null_storage)
   {
      torrentParams.storage = null_storage_constructor;
   }
   else if (_use_zero_storage)
   {
      torrentParams.storage = zero_storage_constructor;
   }

   libtorrent::error_code torrentError;

   torrentParams.ti = new libtorrent::torrent_info (torrentFileName, torrentError);

   if (torrentError)
   {
      gtError (".gto processing problem", 217, TORRENT_ERROR, torrentError.value (), "", torrentError.message ());
   }

   libtorrent::torrent_handle torrentHandle = torrentSession->add_torrent (torrentParams, torrentError);

   if (torrentError)
   {
      gtError ("problem adding .gto to session", 217, TORRENT_ERROR, torrentError.value (), "", torrentError.message ());
   }

   std::string uuid = torrentFileName;
   uuid = uuid.substr (0, uuid.rfind ('.'));
   uuid = getFileName (uuid); 

   int sslCertSize = torrentParams.ti->ssl_cert().size();

   std::string uri = _uploadSubmissionURL;

   if (sslCertSize > 0 && _devMode == false)
   {
      std::string pathToKeep = "/cghub/data/";
  
      std::size_t foundPos;
 
      if (std::string::npos == (foundPos = uri.find (pathToKeep)))
      {
         gtError ("Unable to find " + pathToKeep + " in the URL:  " + uri, 214, gtUpload::DEFAULT_ERROR);
      }

      std::string certSignURL = uri.substr(0, foundPos + pathToKeep.size()) + GT_CERT_SIGN_TAIL;

      generateSSLcertAndGetSigned(torrentFileName, certSignURL, uuid);
   }
      
   if (sslCertSize > 0)
   {
      std::string sslCert = _tmpDir + uuid + ".crt";
      std::string sslKey = _tmpDir + uuid + ".key";
            
      torrentHandle.set_ssl_certificate (sslCert, sslKey, _dhParamsFile);
   }

   if (_rateLimit > 0)
   {
      torrentHandle.set_upload_limit (_rateLimit);

      libtorrent::session_settings settings = torrentSession->settings ();
      settings.ignore_limits_on_local_network = false;
      torrentSession->set_settings (settings);
   }

   torrentHandle.resume();

   double percentComplete = 0.0;
   if (inResumeMode && previousProgress > 0)
   {
      percentComplete = 100.0 * previousProgress / torrentParams.ti->total_size();
      screenOutput ("Resuming upload that is approximately:  "  << std::fixed << std::setprecision(3) << percentComplete << "% complete.", VERBOSE_1);
   }

   bool displayed100Percent = false;

   libtorrent::session_status sessionStatus = torrentSession->status ();
   libtorrent::torrent_status torrentStatus = torrentHandle.status ();

   percentComplete = 0.0;
   time_t lastActivity = timeout_update ();
   int64_t lastScrapeTotalPayUp = 0;

   while (torrentStatus.uploaded < 1)
   {
      // Update session and torrent status as of last successful tracker scrape
      sessionStatus = torrentSession->status();
      torrentStatus = torrentHandle.status();

      if (torrentStatus.total_payload_upload > lastScrapeTotalPayUp)
         timeout_update (&lastActivity);

      lastScrapeTotalPayUp = torrentStatus.total_payload_upload;

      // Inactivity timeout check
      if (timeout_check_expired (&lastActivity))
      {
         // Timeout message and exit here
         std::ostringstream timeLenStr;
         timeLenStr << _inactiveTimeout;
         gtError ("Inactivity timeout triggered after " + timeLenStr.str() +
            " minute(s).  Shutting down upload client.", 206, gtBase::DEFAULT_ERROR, 0);
      }

      libtorrent::ptime endMonitoring = libtorrent::time_now_hires() + libtorrent::seconds (5);

      while (torrentStatus.uploaded < 1 && libtorrent::time_now_hires() < endMonitoring)
      {
         checkAlerts (torrentSession);
         usleep(ALERT_CHECK_PAUSE_INTERVAL);
      }

      // Warning - Asynchronous call does below not update our torrentStatus struct
      torrentHandle.scrape_tracker();

      FILE *gtoFile;

      gtoFile = fopen ((torrentFileName + PROGRESS_FILE_EXT).c_str (), "w");

      if (gtoFile != NULL)
      {
         fprintf (gtoFile, "%" PRId64, previousProgress + torrentStatus.total_payload_upload);
         fclose (gtoFile);
      }
      else // log error and continue
      {
         gtError ("Failure opening " + torrentFileName + PROGRESS_FILE_EXT + " for output.", ERROR_NO_EXIT, ERRNO_ERROR, errno);
      }

      if (_verbosityLevel > VERBOSE_1 && !displayed100Percent)
      {
         if (torrentStatus.state != libtorrent::torrent_status::queued_for_checking && torrentStatus.state != libtorrent::torrent_status::checking_files)
         {
            percentComplete = (previousProgress + torrentStatus.total_payload_upload) / (torrentParams.ti->total_size () * 1.0) * 100.0;

            if (percentComplete > 99.999999999)
            {
               percentComplete = 100.000000;
               displayed100Percent = true;
            }
            screenOutput ("Status:"  << std::setw(8) << (previousProgress + torrentStatus.total_payload_upload > 0 ? add_suffix(previousProgress + torrentStatus.total_payload_upload).c_str() : "0 bytes") <<
                                     " uploaded (" << std::fixed << std::setprecision(3) << percentComplete <<
                                     "% complete) current rate:  " << add_suffix (torrentStatus.upload_rate, "/s"), VERBOSE_1);
         }
      }
   }

   // It is possible to not display 100% based on the tracker scraping behavior.
   // test here and log 100
   if (!displayed100Percent)
   {
      percentComplete = 100.000000;
      screenOutput ("Status:"  << std::setw(8) << (previousProgress + torrentStatus.total_payload_upload > 0 ? add_suffix(previousProgress + torrentStatus.total_payload_upload).c_str() : "0 bytes") <<
                    " uploaded (" << std::fixed << std::setprecision(3) << percentComplete << "% complete) current rate:  " << add_suffix (torrentStatus.upload_rate, "/s"), 0);
   }

   checkAlerts (torrentSession);
   torrentSession->remove_torrent (torrentHandle);

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
   checkAlerts (torrentSession);

   delete torrentSession;
}

// do not include files that are not present in _filesToUpload
bool gtUpload::fileFilter (std::string const objectName)
{
   vectOfStr::iterator vectIter = _filesToUpload.begin ();

   while (vectIter != _filesToUpload.end ())
   {
      if (*vectIter == objectName)
      {
         return true;
      }
      vectIter++;
   }

   return false;
}

// do not include files and folders whose name starts with a ., based on file_filter from libtorrent
bool gtUpload::file_filter (boost::filesystem::path const& filename)
{
   static std::string workingDir = getWorkingDirectory () + "/" + ((gtUpload *)geneTorrCallBackPtr)->getUploadUUID();

   if (filename.string().size() == workingDir.size() && filename.string() == workingDir)  // this is the root of the data, e.g., the UUID directory
   {
      return true;
   }

   if (filename.string().size() < workingDir.size() + 1)
   {
      return false;
   }

   std::string targetObject = std::string (filename.string()).erase(0, workingDir.size() + 1);   // removes extra /

   if (targetObject[0] == '.')
   {
      return false;
   }

   return ((gtUpload *)geneTorrCallBackPtr)->fileFilter (targetObject);
}
