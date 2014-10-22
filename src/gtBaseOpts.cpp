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

#include <iostream>
#include <fstream>

#include "gtBaseOpts.h"
#include "gtOptStrings.h"
#include "gtLog.h"
#include "gtDefs.h"
#include "gtUtils.h"
#include "gt_scm_rev.h"

#include "accumulator.hpp"

#include "stringTokenizer.h"
#include "loggingmask.h"

#include <boost/algorithm/string.hpp>

namespace bpo = boost::program_options;
namespace bfs = boost::filesystem;

int global_verbosity = 0;    // Work around for boost:program_options
                             // not supporting -vvvvv type arguments
bool global_gtAgentMode = false;


gtBaseOpts::gtBaseOpts (std::string progName, std::string usage_msg_hdr, std::string mode, int inactiveTimeout):
    m_progName (progName),
    m_vm (),
    m_base_desc (),
    m_pos (),
    m_use_security_api_opt (true),
    m_use_alt_storage_opts (true),
    m_use_path_opt (true),
    m_sys_cfg_file ("/etc/GeneTorrent.conf"),
    m_sys_restrict_cfg_file ("/etc/GeneTorrent-restricted.conf"),
    m_haveVerboseOnCli (false),
    m_mode (mode),
    m_all_desc ("All Options"),
    m_cfg_desc ("Config File Options"),
    m_cli_desc ("Command Line Only Options"),
    m_vis_desc (usage_msg_hdr),
    m_version_msg(),
    // Storage for processed option values
    m_addTimestamps (false),
    m_allowedServersSet (false),
    m_bindIP (""),
    m_resourceDir (RESOURCE_DIR_DEFAULT),
    m_credentialPath (""),
    m_curlVerifySSL (true),
    m_exposedIP (""),
    m_exposedPortDelta (0),
    m_inactiveTimeout( inactiveTimeout ),
    m_ipFilter (),
    m_logDestination ("none"),
    m_logMask (0),
    m_logToStdErr (false),
    m_peerTimeout (0),
    m_portEnd (20900),
    m_portStart (20892),
    m_rateLimit (-1),
    m_use_null_storage (false),
    m_use_zero_storage (false)
{
   m_version_msg = std::string( "GeneTorrent " );
   m_version_msg.append( progName );
   m_version_msg.append( " release " VERSION ", " GT_SCM_REV_STR ", build: " GT_BUILD_NUMBER ", type: " GT_BUILD_TYPE ", target: " GT_BUILD_TARGET );
}

void
gtBaseOpts::parse (int ac, char **av)
{
    bool haveRestrictConfigFile = !statFile (m_sys_restrict_cfg_file.c_str ());
    bool haveDefaultConfigFile = !statFile (m_sys_cfg_file.c_str ());
    bool haveUserConfigFile = false;

    try
    {
        add_options ();
        add_positionals ();

        bpo::command_line_parser parser (ac, av);
        parser.options (m_all_desc);
        parser.positional (m_pos);

        bpo::variables_map cli_vm; // CLI and non-restricted Config File options.
        bpo::variables_map res_vm; // Restricted Config File options.

        bpo::store (parser.run(), cli_vm);

        if (cli_vm.count (OPT_VERBOSE))
            m_haveVerboseOnCli = true;

        if (cli_vm.count (OPT_CFG_FILE))
            haveUserConfigFile = true;

        if (haveRestrictConfigFile)
            processConfigFile (m_sys_restrict_cfg_file, m_cfg_desc, res_vm);

        // Store config file variables on cli variables map
        if (haveRestrictConfigFile &&
            res_vm.count (OPT_NO_USER_CFG_FILE))
        {
            // Restricted config disallows user-supplied config file
            if (haveUserConfigFile)
                commandLineError ("Restricted configuration file disallows the "
                                  "use of the '" OPT_CFG_FILE "' option.");

            if (haveDefaultConfigFile)
                processConfigFile (m_sys_cfg_file, m_cfg_desc, cli_vm);
        }
        else
        {
            // Prefer user-supplied config file over default config file
            if (haveUserConfigFile)
            {
                std::string cfgPath = cli_vm[OPT_CFG_FILE].as<std::string>();
                processConfigFile (cfgPath, m_cfg_desc, cli_vm);
            }
            else if (haveDefaultConfigFile)
            {
                processConfigFile (m_sys_cfg_file, m_cfg_desc, cli_vm);
            }
        }

        if (haveRestrictConfigFile)
        {
            processConfigFile (m_sys_restrict_cfg_file, m_cfg_desc, cli_vm);
            checkForIllegalOverrides(res_vm, cli_vm);
        }
        // This call signals that the variables_map is now "finalized"
        // and calls notifiers to set variables to option values
        // (which we don't currently use)
        bpo::notify (cli_vm);

        m_vm = cli_vm;
    }
    catch (bpo::error &e)
    {
        std::ostringstream msg ("Options Error: ");
        msg << e.what();
        commandLineError (msg.str());
    }

    if (m_vm.count (OPT_HELP))
        displayHelp ();

    if (m_vm.count (OPT_VERSION))
        displayVersion ();

    processOptions ();

//    log_options_used ();
}

void
gtBaseOpts::processConfigFile (const std::string& configFilename,
                               const bpo::options_description& desc,
                               bpo::variables_map &vm)
{
   if (statFile (configFilename) != 0)
   {
      commandLineError ("unable to open config file '" + configFilename + "'.");
   }

   std::ifstream inputFile (configFilename.c_str());

   if (!inputFile)
   {
      commandLineError ("unable to open config file '" + configFilename + "'.");
   }

   bpo::store (bpo::parse_config_file (inputFile, desc), vm);
}

void
gtBaseOpts::checkForIllegalOverrides (bpo::variables_map& res_vm,
                                      bpo::variables_map& final_vm)
{
   // Check if there are any variables in restrictedConfig that:
   // 1. Are in the final map (they all should be) -and-
   // 2. Have different values in the two maps
   // These values were overridden from the settings in the restricted
   // config file, which is not allowed

   for (bpo::variables_map::iterator it = res_vm.begin(); it != res_vm.end(); ++it)
   {
      vectOfStr restValues = gtBaseOpts::vmValueToStrings (it->second);

      // Get variable values from final var map
      bpo::variable_value finalVv = final_vm[it->first];
      vectOfStr finalValues = gtBaseOpts::vmValueToStrings (finalVv);

      // We don't care about order of vector elements
      std::sort(restValues.begin(), restValues.end());
      std::sort(finalValues.begin(), finalValues.end());

      if (restValues != finalValues)
         commandLineError ("Configuration file or CLI options may not"
                           " override the options present in "
                           + m_sys_restrict_cfg_file + ".  Please check "
                           "your settings for the program option \""
                           + it->first + "\".  You specified \""
                           + finalValues[0] + "\" " + "but the restricted "
                           "configuration value is \"" + restValues[0] + "\".");
   }
}

void
gtBaseOpts::displayHelp ()
{
    std::cout << m_vis_desc << std::endl;
    exit (0);
}

void
gtBaseOpts::displayVersion ()
{
    std::cout << "GTSNARF Modified " << m_version_msg << std::endl;
    exit (0);
}

void
gtBaseOpts::commandLineError (std::string errMessage)
{
    if (errMessage.size())
    {
        if (global_gtAgentMode)
        {
            std::cout << "error:  " << errMessage << std::endl;
            std::cout.flush();
        }
        else
        {
            std::cerr << "error:  " << errMessage << std::endl;
        }
    }
    exit (COMMAND_LINE_OR_CONFIG_FILE_ERROR);
}

vectOfStr
gtBaseOpts::vmValueToStrings(bpo::variable_value vv)
{
    vectOfStr value_strings;
    std::string value;

    if (vv.empty())
    {
        value_strings.push_back("UNSET");
    }
    else
    {
        const std::type_info &type = vv.value().type();

        if (type == typeid(std::string))
            value_strings.push_back(vv.as<std::string>());
        else if (type == typeid(int))
            value_strings.push_back(boost::lexical_cast<std::string>(vv.as<int>()));
        else if (type == typeid(float))
            value_strings.push_back(boost::lexical_cast<std::string>(vv.as<float>()));
        else if (type == typeid(vectOfStr))
            value_strings = vv.as<vectOfStr>();
        else
            assert (0);  // Need to handle new boost program_options argument type
    }

    return value_strings;
}

void
gtBaseOpts::log_options_used ()
{
    LogNormal ("Options:");

    for (bpo::variables_map::iterator it = m_vm.begin(); it != m_vm.end(); it++)
    {
        const char *prefix = (it->first.c_str()[0] == '-') ? "" : "--";
        vectOfStr values = gtBaseOpts::vmValueToStrings(it->second);

        for (vectOfStr::iterator vi = values.begin(); vi != values.end(); vi++)
        {
            LogNormal ("  %s%s = %s", prefix, it->first.c_str(), vi->c_str());
        }
    }
}

void
gtBaseOpts::checkCredentials ()
{
   if (m_credentialPath.size() == 0)
   {
      commandLineError ("Must include a credential file when attempting to"
                        " communicate with CGHub, use -c or --" OPT_CRED_FILE);
   }
}

void
gtBaseOpts::add_desc (bpo::options_description &desc, bool is_visible,
                    bool is_cli_only)
{
    m_all_desc.add (desc);

    if (is_visible)
    {
        m_vis_desc.add (desc);

        if (!is_cli_only)
            m_cfg_desc.add (desc);
    }
}

void
gtBaseOpts::add_options ()
{
    m_base_desc.add_options ()
        (OPT_BIND_IP           ",b", opt_string(), "Bind IP.")
        (OPT_CRED_FILE         ",c", opt_string(), "Path/file to credentials file.")
        (OPT_CFG_DIR_DEPRECATED  ",C", opt_string(), "Deprecated use " OPT_RESOURCE_DIR ".")
        (OPT_RESOURCE_DIR      ",R", opt_string(), "Full path to a directory containing static resource files (dhparam.pem).")
        (OPT_ADVERT_IP         ",e", opt_string(), "IP Address advertised.")
        (OPT_ADVERT_PORT       ",f", opt_int(),    "TCP Port advertised.")
        (OPT_INTERNAL_PORT     ",i", opt_string(), "Local IP port to bind on.")
        (OPT_LOGGING           ",l", opt_string(), "Path/file to log file, follow"
                                                   " by the log level.")
        (OPT_RATE_LIMIT        ",r", opt_float(),  "Transfer rate limiter in MB/s.")
        (OPT_TIMESTAMP         ",t",               "Add timestamps to messages"
                                                   " logged to the screen.")
        (OPT_VERBOSE,                opt_int(),    "Set on screen verbosity level.")
        (OPT_INACTIVE_TIMEOUT  ",k", opt_int(),    "Number of minutes of inactivity after which a"
                                                   " transfer times out and the program exits with "
                                                   " status code 206. The default is 3. Use 0 to "
                                                   " disable timeouts.")
        (OPT_CURL_NO_VERIFY_SSL,                   "Do not verify SSL certificates"
                                                   " of web services.")
        (OPT_PEER_TIMEOUT,           opt_int(),    "Set libtorrent peer timeout in seconds.")
        (OPT_NO_USER_CFG_FILE,                     "Do not allow users to specify a config file.")
        (OPT_ALLOWED_MODES,          opt_string(), "Allowed modes in this GeneTorrent"
                                                   " installation.")
        (OPT_ALLOWED_SERVERS,        opt_string(), "Allowed IP address ranges for WSI, tracker,"
                                                   " and peer traffic.")
        ;

    if (m_use_path_opt)
    {
        m_base_desc.add_options ()
            (OPT_PATH              ",p", opt_string(), "File system path used for"
                                                   " uploads and downloads.")
            ;
    }

    if (m_use_security_api_opt)
    {
        m_base_desc.add_options ()
            (OPT_SECURITY_API,           opt_string(), "SSL Key Signing URL")
            ;
    }
    add_desc (m_base_desc);

    m_cli_desc.add_options ()
        (OPT_CFG_FILE,               opt_string(), "Path/file to optional config file.")
        (OPT_HELP              ",h",               "Show help and exit.")
        (OPT_VERBOSE_INCR      ",v", accumulator<int>(&global_verbosity),
                                                   "Increase on screen verbosity level.")
        (OPT_VERSION,                              "Show version and exit.")
        ;
    if (m_use_alt_storage_opts)
    {
        m_cli_desc.add_options ()
            (OPT_NULL_STORAGE,                     "Enable use of null storage.")
            (OPT_ZERO_STORAGE,                     "Enable use of zero storage.")
            ;
    }
    add_desc (m_cli_desc, VISIBLE, CLI_ONLY);
}

/**
 * Add hidden options for those supplied by the app modes that are not
 * the calling app.
 *
 * For example, add the opts for gtdownload and gtupload if the caller
 * was gtserver.
 *
 * It's possible for the app to be none of gtserver, gtupload or
 * gtdownload.
 *
 * This allows the options to appear in the config file
 * without generating an error about them being unknown.
 *
 * @param app The mode of the app calling this: 'S', 'D', or 'U'
 */
void
gtBaseOpts::add_options_hidden (const char app)
{
    boost::program_options::options_description hidden_desc;

    if (app != 'D')
    {
        hidden_desc.add_options ()
            (OPT_MAX_CHILDREN,          opt_string(), "hidden, ignored")
            ;
    }

    if (app != 'S')
    {
        hidden_desc.add_options ()
            (OPT_SERVER,                opt_string(), "hidden, ignored")
            (OPT_QUEUE,                 opt_string(), "hidden, ignored")
            ;
    }

    add_desc (hidden_desc, NOT_VISIBLE);
}

void
gtBaseOpts::add_positionals ()
{
    // No positionals should be set here in gtBaseOpts. Classes
    // derived from gtBaseOpts will likely want to add their own
    // positionals, but that is completely optional.
}

/**
 * All derived class should provide an override for this and will need
 * to call this from within the override to have all the common
 * options processed.
 */
void
gtBaseOpts::processOptions ()
{
    // Must set verbosity first.
    processOption_Verbosity ();
    // processOption_Log ();

    processOption_ConfDirDeprecated ();
    processOption_ResourceDir ();
    processOption_CurlNoVerifySSL ();
    processOption_CredentialFile ();
    processOption_BindIP ();

    // Internal ports must be processed before the Advertised port
    processOption_InternalPort ();
    processOption_AdvertisedIP ();

    processOption_AdvertisedPort ();
    processOption_Timestamps ();
    processOption_StorageFlags ();
    processOption_PeerTimeout ();
    processOption_AllowedServers ();
    processOption_AllowedMode ();
}

void
gtBaseOpts::processOption_BindIP ()
{
    if (m_vm.count (OPT_BIND_IP) == 1)
    { 
        m_bindIP = m_vm[OPT_BIND_IP].as<std::string>();
    }
}

void
gtBaseOpts::processOption_Timestamps ()
{
    if (m_vm.count (OPT_TIMESTAMP))
    { 
        m_addTimestamps = true;
    }
}

void
gtBaseOpts::processOption_ConfDirDeprecated ()
{
    if (m_vm.count (OPT_CFG_DIR_DEPRECATED) == 1)
    {
        commandLineError (OPT_CFG_DIR_DEPRECATED " has been deprecated, use " OPT_RESOURCE_DIR " instead.");
    }
}

void
gtBaseOpts::processOption_ResourceDir ()
{
#ifdef __CYGWIN__
    m_resourceDir = getWinInstallDirectory ();
#endif /* __CYGWIN__ */

    if (m_vm.count (OPT_RESOURCE_DIR) == 1)
    {
        m_resourceDir = sanitizePath (m_vm[OPT_RESOURCE_DIR].as<std::string>());
    }
    else   // command line (or config file) option not present
    {
        char *envValue = getenv ("GT_RESOURCE_DIR");

        if (envValue != NULL)
        {
            m_resourceDir = sanitizePath (envValue) + "/";
        }
        else   // No environment variable for the resource path
        {
            return;
        }
    }

    if (statDirectory (m_resourceDir) != 0)
    {
        commandLineError ("unable to open resource directory '" + m_resourceDir + "'");
    }
}

void
gtBaseOpts::processOption_CredentialFile ()
{
    if (m_vm.count (OPT_CRED_FILE) == 1)
    { 
        m_credentialPath = m_vm[OPT_CRED_FILE].as<std::string>();
    }
}

void
gtBaseOpts::processOption_AdvertisedIP ()
{
    if (m_vm.count (OPT_ADVERT_IP) == 1)
    { 
        m_exposedIP = m_vm[OPT_ADVERT_IP].as<std::string>();
    }
    else   // Option not present
    {
        return;    
    }
}

void
gtBaseOpts::processOption_InternalPort ()
{
    std::string portList;

    if (m_vm.count (OPT_INTERNAL_PORT) == 1)
    { 
        portList = m_vm[OPT_INTERNAL_PORT].as<std::string>();
    }
    else   // Option not present
    {
        return;    
    }

    strTokenize strToken (portList, ":", strTokenize::MERGE_CONSECUTIVE_SEPARATORS);

    int lowPort = strtol (strToken.getToken (1).c_str (), NULL, 10);

    if (lowPort < 1024 || lowPort > 65535)
    {
        commandLineError ("-i (--internal-port) "
                          + strToken.getToken (1)
                          + " out of range (1024-65535)");
    }

    int highPort;
    bool highPortSet = false;

    if (strToken.size () > 1)
    {
        highPort = strtol (strToken.getToken (2).c_str (), NULL, 10);
        highPortSet = true;
    }

    if (highPortSet)
    {
        if (highPort < 1024 || highPort > 65535)
        {
            commandLineError ("-i (--internal-port) "
                              + strToken.getToken (2)
                              + " out of range (1024-65535)");
        }

        if (lowPort <= highPort)
        {
            m_portStart = lowPort;
            m_portEnd = highPort;
        }
        else
        {
            commandLineError ("when using -i (--internal-port) "
                              + strToken.getToken (1)
                              + " must be smaller than "
                              + strToken.getToken (2));
        }
    }
    else
    {
        m_portStart = lowPort;

        if (m_portStart + 8 > 65535)
        {
            commandLineError ("-i (--internal-port) implicit (add 8 ports)"
                              " end value exceeds 65535");
        }

        m_portEnd = m_portStart + 8; // default 8 ports
    }
}

void
gtBaseOpts::processOption_AdvertisedPort ()
{
    int exposedPort;

    if (m_vm.count (OPT_ADVERT_PORT) == 1)
    { 
        exposedPort = m_vm[OPT_ADVERT_PORT].as< int >();
    }
    else   // Option not present
    {
        return;    
    }

    if (exposedPort < 1024 || exposedPort > 65535)
    {
        commandLineError ("-f (--" OPT_ADVERT_PORT ") out of range (1024-65535)");
    }

    m_exposedPortDelta = exposedPort - m_portStart;
}

void
gtBaseOpts::processOption_Log ()
{
    if (m_vm.count (OPT_LOGGING))
    {
        std::string logArgument = m_vm[OPT_LOGGING].as<std::string>();

        strTokenize strToken (logArgument, ":",
                              strTokenize::MERGE_CONSECUTIVE_SEPARATORS);

        std::string level;

#ifdef __CYGWIN__
        if (std::count(logArgument.begin(), logArgument.end(), ':') > 1)
        {
            m_logDestination = strToken.getToken(1) + ":" + strToken.getToken(2);
            level = strToken.getToken(3);
        }
        else
        {
            m_logDestination = strToken.getToken(1);
            level = strToken.getToken(2);
        }
#else
        m_logDestination = strToken.getToken(1);
        level = strToken.getToken(2);
#endif

        if ("verbose" == level)
        {
            m_logMask  = LOGMASK_VERBOSE;
        }
        else if ("full" == level)
        {
            m_logMask  = LOGMASK_FULL;
        }
        else if ("standard" == level || level.size() == 0) // default to standard
        {
            m_logMask  = LOGMASK_STANDARD;
        }
        else
        {
            m_logMask = strtoul (level.c_str(), NULL, 0);
            if (0 == m_logMask)
            {
                commandLineError ("Unexpected logging level encountered.");
            }
        }
    }

    m_logToStdErr = gtLogger::create_globallog (m_progName, m_logDestination);
}

// Used by download and upload
void
gtBaseOpts::processOption_RateLimit ()
{
    if (m_vm.count (OPT_RATE_LIMIT) < 1)
    {
        return;    
    }

    // As MB (megabytes) per second
    float inRate = m_vm[OPT_RATE_LIMIT].as<float>();

    // convert to bytes per second, using SI units as that is what
    // libtorrent displays
    m_rateLimit = inRate * 1000 * 1000;

    if (m_rateLimit < 10000) // 10kB
    {
        commandLineError ("Configured rate limit is too low.  Please"
                          " specify a value larger than 0.01 for '"
                          OPT_RATE_LIMIT "'");
    }
}

// Used by download and upload
std::string
gtBaseOpts::processOption_Path ()
{
    if (m_vm.count (OPT_PATH) < 1)
    {
        return "";    
    }

    std::string path = sanitizePath (m_vm[OPT_PATH].as<std::string>());

    if (path.size() == 0)
    {
        commandLineError ("command line or config file contains no value for '"
                          OPT_PATH "'");
    }

    relativizePath (path);

    if (statDirectory (path) != 0)
    {
        commandLineError ("unable to opening directory '" + path + "'");
    }

    return path;
}

// Used by download and upload modes
void
gtBaseOpts::processOption_InactiveTimeout ()
{
    if (m_vm.count (OPT_INACTIVE_TIMEOUT) < 1)
    {
        return;
    }

    // As minutes
    int inactiveTimeout = m_vm[OPT_INACTIVE_TIMEOUT].as<int>();

    m_inactiveTimeout = inactiveTimeout;
}

void
gtBaseOpts::processOption_SecurityAPI ()
{
    if (m_mode == "UPLOAD")
        // Ignore sec api url for upload, it gets it from manifest file.
        return;

    if (m_mode == "SERVER" && (m_vm.count (OPT_SECURITY_API) < 1))
    {
        commandLineError ("Must include a full URL to the security API services in"
                          " server mode, --" OPT_SECURITY_API);
    }

    if (m_vm.count (OPT_SECURITY_API))
    {
        m_csrSigningUrl = m_vm[OPT_SECURITY_API].as<std::string>();

        if (m_csrSigningUrl.size() == 0)
        {
            commandLineError ("command line or config file contains no value for '"
                              OPT_SECURITY_API "'");
        }

        if ((std::string::npos == m_csrSigningUrl.find ("http"))
            || (std::string::npos == m_csrSigningUrl.find ("://")))
        {
            commandLineError ("Invalid URI for '--" OPT_SECURITY_API "'");
        }
    }
}

void
gtBaseOpts::processOption_CurlNoVerifySSL ()
{
    if (m_vm.count (OPT_CURL_NO_VERIFY_SSL))
        m_curlVerifySSL = false;
}

// Check the cli args for storage flags.
//
// Ensure that only one flag is set at a time.
//
void
gtBaseOpts::processOption_StorageFlags ()
{
    if (m_vm.count (OPT_NULL_STORAGE))
    {
        m_use_null_storage = true;
    }

    if (m_vm.count (OPT_ZERO_STORAGE))
    {
        m_use_zero_storage = true;
    }

    if (m_use_null_storage && m_use_zero_storage)
    {
        commandLineError ("Use of both '--" OPT_NULL_STORAGE "' and '--"
                          OPT_ZERO_STORAGE "' options at same time is not"
                          " allowed.");
    }
}

void
gtBaseOpts::processOption_PeerTimeout ()
{
    if (m_vm.count (OPT_PEER_TIMEOUT))
    {
        m_peerTimeout = m_vm[OPT_PEER_TIMEOUT].as<int> ();
    }
}

// Checks whether an IP address string is valid, exits with command line error
// if it is not
void
gtBaseOpts::checkIPAddress (std::string addr_string)
{
   boost::system::error_code ec;
   boost::asio::ip::address::from_string (addr_string, ec);
   if (ec)
      commandLineError ("Invalid IP address given on command line or in a "
         "config file: " + addr_string + ".");
}

// If allowed-modes is given with a list of IP ranges, construct an
// ip filter that will later be applied to the torrent session and
// checked prior to CURL calls
void
gtBaseOpts::processOption_AllowedServers ()
{
    if (m_vm.count (OPT_ALLOWED_SERVERS) < 1 ||
        m_mode == "SERVER")
        return;

    m_allowedServersSet = true;

    // By default, deny all
    m_ipFilter.add_rule (boost::asio::ip::address::from_string("0.0.0.0"),
                         boost::asio::ip::address::from_string("255.255.255.255"),
                         libtorrent::ip_filter::blocked);

    // allow IPs provided by allowed-servers option
    std::string serverList = m_vm[OPT_ALLOWED_SERVERS].as<std::string>();

    // Process comma- or colon-delimited lists of IPs or IP ranges
    // e.g., 192.168.1.1:192.168.2.1-192.168.2.255,192.168.3.1
    vectOfStr serverVec;
    boost::split (serverVec, serverList, boost::is_any_of (",:"));

    vectOfStr::iterator it;

    for (it = serverVec.begin(); it != serverVec.end(); ++it)
    {
        // Process range
        vectOfStr rangeVec;
        boost::split (rangeVec, *it, boost::is_any_of ("-"));

        // If '-' character, this is a range
        if (rangeVec.size() == 1)
        {
            // Check that IP string is valid
            checkIPAddress (rangeVec[0]);
            m_ipFilter.add_rule (boost::asio::ip::address::from_string(rangeVec[0]),
                                 boost::asio::ip::address::from_string(rangeVec[0]),
                                 0);
        }
        else if (rangeVec.size() == 2)
        {
            // Check that IP string is valid
            checkIPAddress (rangeVec[0]);
            checkIPAddress (rangeVec[1]);
            m_ipFilter.add_rule (boost::asio::ip::address::from_string(rangeVec[0]),
                                 boost::asio::ip::address::from_string(rangeVec[1]),
                                 0);
        }
        else
        {
            commandLineError("Invalid range given for " OPT_ALLOWED_SERVERS
                             " argument.");
        }
    }
}

void
gtBaseOpts::processOption_AllowedMode ()
{
    if (m_vm.count (OPT_ALLOWED_MODES))
    {
        std::string modes = m_vm[OPT_ALLOWED_MODES].as<std::string>();
        boost::to_upper(modes);

        vectOfStr modesVec;
        boost::split (modesVec, modes, boost::is_any_of(",:"));

        vectOfStr::iterator it;
        it = std::find (modesVec.begin(), modesVec.end(), "ALL");

        if (it == modesVec.end())
        {
            it = std::find (modesVec.begin(), modesVec.end(), m_mode);
            if (it == modesVec.end())
                commandLineError ("Restricted configuration file does not"
                                  " allow this mode of operation on this"
                                  " system.");
        }
    }
}

/**
 * Verify and configure global_verbosity level.
 *
 * For verbosity conversation, two different verbose settings are
 * available:
 *
 *   Short option: '-v' with increasing count
 *   Long option:  '--verbose=<level>'
 *
 * This is a rather ugly hack, but due to shortcomings in boost
 * program_options seems to be a workable solution.
 *
 * '-v' and '--verbose' are independent options due to boost
 * program_options, but work together.  Short options are not
 * permitted in config files, but '--verbose' is.
 *
 *   verbose       verbose       -v       Result
 *   ==================================================
 *   in config                            config value
 *                 on CLI                 cli value
 *                             on CLI     -v cli count
 *   in config     on CLI                 cli value
 *   in config                 on CLI     -v cli count
 *                 on CLI      on CLI     error
 *   in config     on CLI      on CLI     error
 */
void
gtBaseOpts::processOption_Verbosity ()
{
    if (global_verbosity > 0 && m_haveVerboseOnCli)
    {
        commandLineError ("Use of '-v' and '--verbose' are not permitted"
                          " on the command line at the same time.");
    }

    if (global_verbosity > 0)
    {
        // -v is present, -v overrides any possible --verbose
        if (global_verbosity >= 2)
        {
            // override out of range value from legacy -vvvv or -vvv
            global_verbosity = 2;
        }
    }
    else
    {
        // check if --verbosity available and set level if present
        if (m_vm.count (OPT_VERBOSE))
        {
            global_verbosity = m_vm[OPT_VERBOSE].as<int>();

            if (global_verbosity < 1 || global_verbosity > 2)
            {
                std::ostringstream errorMes;
                errorMes << "Value for '--verbose=" << global_verbosity
                         << "' is not valid, try 1 or 2.";
                commandLineError (errorMes.str());
            }
        }
    }

    processOption_GTAgentMode ();
}
