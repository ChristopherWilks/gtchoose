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

#include "gtDownloadOpts.h"
#include "gtOptStrings.h"

#include "gtUtils.h"

static const char usage_msg_hdr[] =
    "Usage:\n"
    "   gtdownload [OPTIONS] -c <cred> <URL|UUID|.xml|.gto|.tsv|.lst>\n"
    "\n"
    "For more detailed information on gtdownload, see the manual pages.\n"
#if __CYGWIN__
    "The manual pages can be found as text files in the install directory.\n"
#else /* __CYGWIN__ */
    "Type 'man gtdownload' to view the manual page.\n"
#endif /* __CYGWIN__ */
    "\n"
    "Where:\n"
    "\n"
    "  URL  - the URL of a GTO file representing the file set to be downloaded\n"
    "  UUID - the UUID of the file set to be downloaded\n"
    "  .xml - the path of an XML file containing a cgquery result set referring to\n"
    "         the file sets to be downloaded\n"
    "  .gto - the path to a GTO file representing the file set to be downloaded\n"
    "  .tsv - the path to a tab-separated file whose 'analysis_id' column contains\n"
    "         the UUIDs of the file sets to be downloaded\n"
    "  .lst - the path to a file containing UUIDs or URLs of the file sets to be\n"
    "         downloaded\n"
    "\n"
    "The actual extension of the XML, GTO, TSV or list file is irrelevant. The file type\n"
    "will be detected automatically by examining the first 1000 bytes of the file. This\n"
    "heuristic can be overridden using the -X, -G, -T and -F options.\n"
    "\n"
    "Options"
    ;

gtDownloadOpts::gtDownloadOpts ():
    gtBaseOpts ("gtdownload", usage_msg_hdr, "DOWNLOAD", 3),
    m_dl_desc (),
    m_maxChildren (8),
    m_downloadSavePath (""),
    m_cliArgsDownload (),
    m_cliArgsDownloadFromGTO (),
    m_cliArgsDownloadFromXML (),
    m_cliArgsDownloadFromTSV (),
    m_cliArgsDownloadFromLST (),
    m_downloadModeCsrSigningUrl (),
    m_gtAgentMode (false),
    m_downloadModeWsiUrl (REPO_WSI_BASE_URL)
{
}

// Pass through constructor for use by derived classes.
gtDownloadOpts::gtDownloadOpts (std::string progName, std::string usage_hdr,
                                std::string mode, int inactiveTimeout):
    gtBaseOpts (progName, usage_hdr, mode, inactiveTimeout),
    m_dl_desc (),
    m_maxChildren (8),
    m_downloadSavePath (""),
    m_cliArgsDownload (),
    m_cliArgsDownloadFromGTO (),
    m_cliArgsDownloadFromXML (),
    m_cliArgsDownloadFromTSV (),
    m_cliArgsDownloadFromLST (),
    m_downloadModeCsrSigningUrl (),
    m_gtAgentMode (false),
    m_downloadModeWsiUrl (REPO_WSI_BASE_URL)
{
}

void
gtDownloadOpts::add_options ()
{
    // Download options
    boost::program_options::options_description dl_desc;
    dl_desc.add_options ()
        (OPT_DOWNLOAD            ",d", opt_vect_str()->composing())
        ;
    add_desc (dl_desc, NOT_VISIBLE, CLI_ONLY);

    m_dl_desc.add_options ()
        (OPT_MAX_CHILDREN,             opt_int(),    "number of download children")
        (OPT_WEBSERV_URL,           opt_string(),    "Full URL to Repository Web Services Interface")
        ;
    add_desc (m_dl_desc);

    boost::program_options::options_description gta_desc;
    gta_desc.add_options ()
        (OPT_GTA_MODE,          "Operating as a child of GTA, this option is hidden")
        ;
    add_desc (gta_desc, NOT_VISIBLE, CLI_ONLY);

    boost::program_options::options_description forced_dl_desc( "" );
    forced_dl_desc.add_options ()
        (OPT_DOWNLOAD_GTO        , opt_vect_str()->composing(), "see .gto above")
        (OPT_DOWNLOAD_XML        , opt_vect_str()->composing(), "see .xml above" )
        (OPT_DOWNLOAD_TSV        , opt_vect_str()->composing(), "see .tsv above")
        (OPT_DOWNLOAD_LST       , opt_vect_str()->composing(), "see .lst above")
        ;
    add_desc (forced_dl_desc, VISIBLE, CLI_ONLY);

    add_options_hidden ('D');

    gtBaseOpts::add_options ();
}

void
gtDownloadOpts::add_positionals ()
{
    m_pos.add (OPT_DOWNLOAD, -1);
}

void
gtDownloadOpts::processOptions ()
{
    gtBaseOpts::processOptions ();

    if( 0 == m_vm.count( OPT_DOWNLOAD )
          + m_vm.count( OPT_DOWNLOAD_GTO )
          + m_vm.count( OPT_DOWNLOAD_XML )
          + m_vm.count( OPT_DOWNLOAD_TSV )
          + m_vm.count( OPT_DOWNLOAD_LST ) ) {
        commandLineError( "Download command line or config file must specify what to download." );
    }

    processOption_MaxChildren ();
    processOption_DownloadList ();
    processOption_SecurityAPI ();
    processOption_InactiveTimeout ();
    processOption_RateLimit();
    processOption_WSI_URL();

    m_downloadSavePath = processOption_Path ();
}

void
gtDownloadOpts::processOption_MaxChildren ()
{
    if (m_vm.count (OPT_MAX_CHILDREN) == 1)
    {
        m_maxChildren = m_vm[OPT_MAX_CHILDREN].as< int >();
    }

    if (m_maxChildren < 1)
    {
        commandLineError ("Value for '--" OPT_MAX_CHILDREN
                          "' must be greater than 0");
    }
}

void
gtDownloadOpts::processOption_DownloadList ()
{
   if( m_vm.count( OPT_DOWNLOAD ) ) {
      m_cliArgsDownload = m_vm[ OPT_DOWNLOAD ].as<vectOfStr>();
   }
   if( m_vm.count( OPT_DOWNLOAD_GTO ) ) {
      m_cliArgsDownloadFromGTO = m_vm[ OPT_DOWNLOAD_GTO ].as<vectOfStr>();
   }
   if( m_vm.count( OPT_DOWNLOAD_XML ) ) {
      m_cliArgsDownloadFromXML = m_vm[ OPT_DOWNLOAD_XML ].as<vectOfStr>();
   }
   if( m_vm.count( OPT_DOWNLOAD_TSV ) ) {
      m_cliArgsDownloadFromTSV = m_vm[ OPT_DOWNLOAD_TSV ].as<vectOfStr>();
   }
   if( m_vm.count( OPT_DOWNLOAD_LST ) ) {
      m_cliArgsDownloadFromLST = m_vm[ OPT_DOWNLOAD_LST ].as<vectOfStr>();
   }
   checkCredentials();
}

/**
 * Should only be called by gtBaseOpts::processOption_Verbosity().
 *
 * This overrides the empty default in gtBaseOpts.
 */
void
gtDownloadOpts::processOption_GTAgentMode ()
{
    if (m_vm.count (OPT_GTA_MODE))
    {
        global_gtAgentMode = true;

        if (global_verbosity > 0)
        {
            commandLineError ("The '--gta' option may not be combined with either -v"
                              " or '--verbose' options.");
        }
    }
}

void gtDownloadOpts::processOption_WSI_URL ()
{
    // For now this is not mandatory
    if (m_vm.count (OPT_WEBSERV_URL))
    {
        m_downloadModeWsiUrl = sanitizePath (m_vm[OPT_WEBSERV_URL].as<std::string>());

        if (m_downloadModeWsiUrl.size() == 0)
        {
            commandLineError ("command line or config file contains no value for '" OPT_WEBSERV_URL "'");
        }

        if ((std::string::npos == m_downloadModeWsiUrl.find ("http")) || (std::string::npos == m_downloadModeWsiUrl.find ("://")))
        {
            commandLineError ("Invalid URI for '--" OPT_WEBSERV_URL "'");
        }
    }
}
