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
 * gtLog.h
 *
 *  Created on: January 19, 2012
 *      Author: donavan
 */

#ifndef GT_LOG_H
#define GT_LOG_H

#ifndef WIN32
#include <inttypes.h>
#endif

#include <string>

#ifndef __STRING
#define __STRING(x) # x
#endif

// Function Log: This function works exactly like printf, except (a)
// the line is prepended with the time, source file name, and source
// file number; and (b) the text goes to wherever the log destination
// is set to
#define Log(lvl, fmt, ...) GlobalLog->__Log((lvl), (fmt), ## __VA_ARGS__)

//  TODO, This is out of date
// gtLogger parses the program's command line as follows:
//
//   By default, no log file whatsoever is used, unless the boolean
//   use_log_file is set to true, in which case the log file is
//   created as ~/logs/(argv[0]).(timestamp).log
// 
//   The user can override this behavior by specifying an argument 
//       --log destination
//   on the command line.  In which case the following destinations
//   are allowed:
//      none       No log file will be created
//      stdout     Log will be sent to stdout
//      stderr     Log will be sent to stderr
//      syslog     Log will be sent to syslog
//      filename   Log will be written to the specified file

enum gtLogLevel {
   PRIORITY_NORMAL,
   PRIORITY_HIGH,
   PRIORITY_DEBUG,
};


#define LogNormal(fmt, ...) Log(PRIORITY_NORMAL, (fmt), ## __VA_ARGS__)
#define LogDebug(fmt, ...)  Log(PRIORITY_DEBUG,  (fmt), ## __VA_ARGS__)

class gtLogger 
{
   public:
      static bool create_globallog (std::string, std::string, int childID = 0, std::string UUID = "");
      static void delete_globallog();

      void __Log (gtLogLevel priority, const char *string, ...);

      const char *log_file_name() { return m_filename; }
      bool logToStdErr() { return m_mode == gtLoggerOutputStderr; }
      int get_fd() { return m_fd ? fileno (m_fd) : -1; }

   private:
      enum OutputType 
      { 
         gtLoggerOutputNone,
         gtLoggerOutputSyslog,
         gtLoggerOutputStdout,
         gtLoggerOutputStderr,
         gtLoggerOutputFile, 
      };

      gtLogger (std::string progName, std::string log, int childID, std::string UUID);
      ~gtLogger();

      static int s_global_refcnt;

      OutputType m_mode;
      char *m_filename;
      char *m_progname;
      FILE *m_fd;

      int64_t m_last_timestamp;
};

extern gtLogger *GlobalLog;

#endif
