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

#include "gt_config.h"

#include "gtOptStrings.h"
#include "gtServerOpts.h"
#include "gtUtils.h"
#include "gt_scm_rev.h"

static const char usage_msg_hdr[] =
    "Usage:\n"
    "   gtserver [OPTIONS] -q <work-queue> -c <cred> --security-api <signing-URI> <path>\n"
    "\n"
    "For more detailed information on gtserver, see the manual pages.\n"
#if __CYGWIN__
    "The manual pages can be found as text files in the install directory.\n"
#else /* __CYGWIN__ */
    "Type 'man gtserver' to view the manual page.\n"
#endif /* __CYGWIN__ */
    "\n"
    "Where:\n"
    "\n"
    "  <path>  server data path\n"
    "\n"
    "Options"
    ;

gtServerOpts::gtServerOpts ():
    gtBaseOpts ("gtserver", usage_msg_hdr, "SERVER", 0),
    m_server_desc (),
    m_serverDataPath (""),
    m_serverForceDownload (false),
    m_serverQueuePath (""),
    m_serverForeground(false),
    m_serverPidFile (DEFAULT_PID_FILE)
{
}

void
gtServerOpts::add_options ()
{
    boost::program_options::options_description server_desc;
    server_desc.add_options ()
        (OPT_SERVER          ",s", opt_string(), "server data path")
        ;
    add_desc (server_desc, NOT_VISIBLE);

    m_server_desc.add_options ()
        (OPT_QUEUE           ",q", opt_string(), "input GTO directory")
        (OPT_FOREGROUND,                         "run in the foreground (do not deamonize)")
        (OPT_PIDFILE,              opt_string(), "full path and filename of the process's pid (ignored when --" OPT_FOREGROUND " is active")
        (OPT_FORCE_DL_MODE,                      "force added GTOs to download mode")
        ;
    add_desc (m_server_desc);

    gtBaseOpts::add_options ();

    add_options_hidden ('S');
}

void
gtServerOpts::add_positionals ()
{
    m_pos.add (OPT_SERVER, 1);
}

void
gtServerOpts::processOptions ()
{
    gtBaseOpts::processOptions ();

    processOption_Server ();
    processOption_Queue ();
    processOption_ServerForceDownload ();
    processOption_Foreground ();
    processOption_SecurityAPI ();

    checkCredentials ();
}

void gtServerOpts::processOption_Server ()
{
    if (m_vm.count (OPT_SERVER) == 0)
    {
        commandLineError ("Server command line or config file must "
                          "include a server data path argument.");
    }

    m_serverDataPath = sanitizePath (m_vm[OPT_SERVER].as<std::string>());

    if (m_serverDataPath.size() == 0)
    {
        commandLineError ("command line or config file contains no value for '"
                          OPT_SERVER "'");
    }

    relativizePath (m_serverDataPath);

    if (statDirectory (m_serverDataPath) != 0)
    {
        commandLineError ("unable to opening directory '" + m_serverDataPath + "'");
    }
}

void gtServerOpts::processOption_Queue ()
{
    if (m_vm.count (OPT_QUEUE) < 1)
    {
        commandLineError ("Must include a queue path when operating in server"
                          " mode, '-q' or '--queue'.");
    }

    m_serverQueuePath = sanitizePath (m_vm[OPT_QUEUE].as<std::string>());

    if (m_serverQueuePath.size() == 0)
    {
        commandLineError ("command line or config file contains no value for '"
                          OPT_QUEUE "'");
    }

    relativizePath (m_serverQueuePath);

    if (statDirectory (m_serverQueuePath) != 0)
    {
        commandLineError ("unable to opening directory '" + m_serverQueuePath + "'");
    }
}

void gtServerOpts::processOption_ServerForceDownload ()
{
    if (m_vm.count (OPT_FORCE_DL_MODE) > 0)
    {
        m_serverForceDownload = true;
    }
}

void gtServerOpts::processOption_Foreground ()
{

    if (m_vm.count (OPT_FOREGROUND) > 0)
    {
        m_serverForeground = true;
    }

}
