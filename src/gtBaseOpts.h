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

#ifndef BASE_OPTS_HPP
#define BASE_OPTS_HPP

#include <vector>

#include <boost/program_options.hpp>
#include <boost/filesystem.hpp>

#include "libtorrent/ip_filter.hpp"

#include "gtDefs.h"

typedef std::vector <std::string> vectOfStr;

#define opt_string   boost::program_options::value<std::string>
#define opt_int      boost::program_options::value<int>
#define opt_float    boost::program_options::value<float>
#define opt_vect_str boost::program_options::value<vectOfStr>

#define VISIBLE      true
#define NOT_VISIBLE  false

#define CLI_ONLY     true
#define NOT_CLI_ONLY false

extern bool global_gtAgentMode;
extern int global_verbosity;

class gtBaseOpts
{
public:
    gtBaseOpts (std::string progName, std::string usage_msg_hdr, std::string mode, int inactiveTimeout);
    virtual ~gtBaseOpts () {}

    static vectOfStr vmValueToStrings(boost::program_options::variable_value vv);

    void parse (int ac, char **av);

    // Make these public so they can be processed after everything else is initialized and the process has daemonized (if applicable).
    void processOption_Log ();
    void log_options_used ();

    std::string m_progName;

protected:
    boost::program_options::variables_map m_vm;
    boost::program_options::options_description m_base_desc;
    boost::program_options::positional_options_description m_pos;

    bool m_use_security_api_opt;
    bool m_use_alt_storage_opts;
    bool m_use_path_opt;

    std::string m_sys_cfg_file;
    std::string m_sys_restrict_cfg_file;

    void add_options_hidden (const char app);
    virtual void add_options ();
    virtual void add_positionals ();
    virtual void processOptions ();

    void commandLineError (std::string errMessage);

    void checkCredentials ();

    void add_desc (boost::program_options::options_description &desc,
                   bool is_visible=VISIBLE,
                   bool is_cli_only=NOT_CLI_ONLY);

    void processOption_RateLimit ();
    std::string processOption_Path ();
    void processOption_InactiveTimeout ();
    void processOption_SecurityAPI ();

private:
    void displayHelp ();
    void displayVersion ();

    void processConfigFile (const std::string& configFilename,
                            const boost::program_options::options_description& desc,
                            boost::program_options::variables_map &vm);
    void checkForIllegalOverrides (boost::program_options::variables_map& res_vm,
                                   boost::program_options::variables_map& final_vm);
    void checkIPAddress (std::string addr_string);

    void processOption_AdvertisedIP ();
    void processOption_AdvertisedPort ();
    void processOption_AllowedMode ();
    void processOption_AllowedServers ();
    void processOption_BindIP ();
    void processOption_ConfDirDeprecated ();
    void processOption_ResourceDir ();
    void processOption_CredentialFile ();
    void processOption_CurlNoVerifySSL ();
    void processOption_InternalPort ();
    void processOption_PeerTimeout ();
    void processOption_StorageFlags ();
    void processOption_Timestamps ();
    void processOption_Verbosity ();

    virtual void processOption_GTAgentMode () {}

    bool m_haveVerboseOnCli;

    std::string m_mode;
    boost::program_options::options_description m_all_desc;
    boost::program_options::options_description m_cfg_desc;
    boost::program_options::options_description m_cli_desc;
    boost::program_options::options_description m_vis_desc;

public:
    std::string m_version_msg;
    // Storage for processed option values
    bool m_addTimestamps;
    bool m_allowedServersSet;
    std::string m_bindIP;
    std::string m_resourceDir;
    std::string m_credentialPath;
    std::string m_csrSigningUrl;
    bool m_curlVerifySSL;
    std::string m_exposedIP;
    int m_exposedPortDelta;
    int m_inactiveTimeout;
    libtorrent::ip_filter m_ipFilter;
    std::string m_logDestination;
    int m_logMask;
    bool m_logToStdErr;
    int m_peerTimeout;
    int m_portEnd;
    int m_portStart;
    long m_rateLimit;
    bool m_use_null_storage;
    bool m_use_zero_storage;
};

#endif  // BASE_OPTS_HPP
