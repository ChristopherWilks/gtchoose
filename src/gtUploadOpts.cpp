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
#include "gtUploadOpts.h"
#include "gtUtils.h"
#include "gt_scm_rev.h"

static const char usage_msg_hdr[] =
    "Usage:\n"
    "   gtupload [OPTIONS] -c <cred> <manifest-file>\n"
    "\n"
    "For more detailed information on gtupload, see the manual pages.\n"
#if __CYGWIN__
    "The manual pages can be found as text files in the install directory.\n"
#else /* __CYGWIN__ */
    "Type 'man gtupload' to view the manual page.\n"
#endif /* __CYGWIN__ */
    "\n"
    "Where:\n"
    "\n"
    "  <manifest-file>    Path to manifest.xml file.\n"
    "\n"
    "Options"
    ;

gtUploadOpts::gtUploadOpts ():
    gtBaseOpts ("gtupload", usage_msg_hdr, "UPLOAD", 0),
    m_ul_desc (),
    m_dataFilePath (""),
    m_manifestFile (""),
    m_uploadGTODir (""),
    m_uploadGTOOnly (false)
{
}

void
gtUploadOpts::add_options ()
{
    boost::program_options::options_description ul_desc;
    ul_desc.add_options ()
        (OPT_UPLOAD            ",u", opt_string(), "Path to manifest.xml file.")
        ;
    add_desc (ul_desc, NOT_VISIBLE, CLI_ONLY);

    m_ul_desc.add_options ()
        (OPT_UPLOAD_GTO_PATH,        opt_string(), "Writable path for .GTO file during"
                                                   " creation and transmission.")
        (OPT_GTO_ONLY,                             "Only generate GTO, don't start upload.")
        ;
    add_desc (m_ul_desc);

    gtBaseOpts::add_options ();

    add_options_hidden ('U');
}

void
gtUploadOpts::add_positionals ()
{
    m_pos.add (OPT_UPLOAD, 1);
}

void
gtUploadOpts::processOptions ()
{
    gtBaseOpts::processOptions ();

    m_dataFilePath = processOption_Path ();
    processOption_Upload ();
    processOption_UploadGTODir ();
    processOption_InactiveTimeout ();
    processOption_UploadGTOOnly ();
    processOption_RateLimit();

    checkCredentials ();
}

void
gtUploadOpts::processOption_Upload ()
{
    if (m_vm.count (OPT_UPLOAD) == 0)
    {
        commandLineError ("Upload command line or config file must "
                          "include a manifest-file argument.");
    }

    if (m_vm.count (OPT_UPLOAD) == 1)
    {
        m_manifestFile = m_vm[OPT_UPLOAD].as<std::string>();
    }

    relativizePath (m_manifestFile);

    if (statFile (m_manifestFile) != 0)
    {
        commandLineError ("manifest file not found (or is not readable):  "
                          + m_manifestFile);
    }
}

void
gtUploadOpts::processOption_UploadGTODir ()
{
    if (m_vm.count (OPT_UPLOAD_GTO_PATH) == 1)
    {
        m_uploadGTODir = sanitizePath (m_vm[OPT_UPLOAD_GTO_PATH].as<std::string>());
    }
    else   // Option not present
    {
        m_uploadGTODir = "";   // Set to current directory
        return;
    }

    if (statDirectory (m_uploadGTODir) != 0)
    {
        commandLineError ("Unable to access directory '" + m_uploadGTODir + "'");
    }
}

void
gtUploadOpts::processOption_UploadGTOOnly ()
{
    if (m_vm.count (OPT_GTO_ONLY))
    {
        m_uploadGTOOnly = true;
    }
}
