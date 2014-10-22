/* -*- mode: C++; c-basic-offset: 3; tab-width: 3; -*-
 *
 * Copyright (c) 2011, Annai Systems, Inc.
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

//============================================================================
// Name        : gtMain.cpp
//============================================================================

#include "gt_config.h"

#include <syslog.h>
#include <sys/file.h>

#include <iostream>
#include <fstream>
#include <algorithm>
#include <boost/algorithm/string.hpp>

#include <curl/curl.h>

#include "gtDefs.h"

#ifdef GENETORRENT_UPLOAD
#  include "gtUpload.h"
#  include "gtUploadOpts.h"
#  define GT_APP_CLASS gtUpload
#  define GT_OPT_CLASS gtUploadOpts
#endif

#ifdef GENETORRENT_DOWNLOAD
#  include "gtDownload.h"
#  include "gtDownloadOpts.h"
#  define GT_APP_CLASS gtDownload
#  define GT_OPT_CLASS gtDownloadOpts
#endif

#ifdef GENETORRENT_SERVER
#  include "gtServer.h"
#  include "gtServerOpts.h"
#  define GT_APP_CLASS gtServer
#  define GT_OPT_CLASS gtServerOpts
#endif

void miniErrorExit (std::string inputMessage, int errorNumber)
{
   std::ostringstream message;

   message << inputMessage << ", errno = " << errorNumber;
   std::cerr << message.str() << std::endl;
   exit (1);
}

void miniSyslogErrorExit (std::string inputMessage, int errorNumber)
{
   std::ostringstream message;

   message << inputMessage << ", errno = " << errorNumber;
   syslog (LOG_ERR, "%s", message.str().c_str());
   exit (1);
}

#ifdef GENETORRENT_SERVER
void daemonize (gtServerOpts *servOpts)
{
   pid_t pid;
   int fd = 0;

   pid = fork();

   if (pid < 0)       // system error
   {
      miniErrorExit ("fork() error deamonizing, errno = ", errno);
   }
   else if (pid > 0)  // parent process
   {
      exit (0);
   }
   else               // child process
   {
      // decouple from environment
      if (chdir ("/") < 0)
      {
         miniErrorExit ("chdir() error deamonizing, errno = ", errno);
      }

      if (setsid() < 0)
      {
         miniErrorExit ("setsid() error deamonizing, errno = ", errno);
      }

      umask (0);    // Can not fail.
 
      // fork again
      
      pid = fork();

      if (pid < 0)       // system error
      {
         miniErrorExit ("fork() error deamonizing (2nd fork), errno = ", errno);
      }
      else if (pid > 0)  // parent process
      {
         exit (0);
      }

      // 2nd child process

      int maxFD;

      maxFD = sysconf(_SC_OPEN_MAX); 
 
      if (maxFD < 0)
      {
         maxFD = 30000;   // Centos 6 ulimit default, 1024 might be more reasonable for a process at starup 
      }

      for (; fd < maxFD; fd++)
      {
          close (fd);   // ignore return code, failures will be caught below when ropening stdin, stdout, stderr.
      }

      servOpts->processOption_Log();   // Process hooks for logging purposes (typically syslog in server mode)

      fd = open ("/dev/null", O_RDWR);

      if (fd != STDIN_FILENO)
      {
         miniSyslogErrorExit ("open() error during deamonization, errno = ", errno);
      }

      if (dup2 (STDIN_FILENO, STDOUT_FILENO) != STDOUT_FILENO)
      {
         miniSyslogErrorExit ("dup2() error during deamonization (STDOUT call), errno = ", errno);
      }

      if (dup2 (STDIN_FILENO, STDERR_FILENO) != STDERR_FILENO)
      {
         miniSyslogErrorExit ("dup2() error during deamonization (STDERR call), errno = ", errno);
      }
   }

   // Deal with pid file
   std::string pidFileName = servOpts->m_serverPidFile;


   if (0 > (fd = open (pidFileName.c_str(), O_RDWR | O_CREAT, S_IRUSR | S_IWUSR)))
   {
      miniSyslogErrorExit ("open() error attempting to open " + pidFileName, errno); 
   }

   if (0 > lseek (fd, 0, SEEK_SET))
   {
      miniSyslogErrorExit ("lseek() error attempting to seek in " + pidFileName, errno); 
   }

   if (0 > lockf (fd, F_TLOCK, 0))
   {
      miniSyslogErrorExit ("flock() error attempting to lock " + pidFileName, errno); 
   }

   if (0 > ftruncate (fd, 0))
   {
      miniSyslogErrorExit ("ftruncate() error attempting to zero " + pidFileName, errno); 
   }

   std::ostringstream pidVal;

   pidVal << getpid();

   int pidSize = pidVal.str().size();

   if (write (fd, pidVal.str().c_str(), pidSize) != pidSize)
   {
      miniSyslogErrorExit ("write() error attempting to write pid file " + pidFileName, errno); 
   }
}
#endif

int main (int argc, char **argv)
{
#ifdef TORRENT_DEBUG
   std::cerr << "********************************************************" << std::endl
             << "*** D E B U G  B U I L D  O F  G E N E T O R R E N T ***" << std::endl
             << "********************************************************" << std::endl;
#endif

   GT_OPT_CLASS opts;
   opts.parse (argc, argv);

#ifdef GENETORRENT_SERVER
   if (!opts.m_serverForeground)
   {
      daemonize (&opts); 
   }
   else
#endif
   {
      opts.processOption_Log();   // daemonize handles this to get logging hooks in place (for daemonzing errors)
   }

   opts.log_options_used();

   curl_global_init(CURL_GLOBAL_ALL);
   gtBase *app = NULL;

   app = new GT_APP_CLASS (opts);

   if (app)
   {
      app->run();
      delete app;
   }

   return 0;
}
