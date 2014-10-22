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
 * gtUtils.cpp
 *
 *  Created on: Feb 15, 2012
 *      Author: donavan
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <unistd.h>
#include <stdlib.h>

#include <cstdio>

#ifdef __CYGWIN__
#include <sys/cygwin.h>
#endif /* __CYGWIN__ */


#include "gtUtils.h"
#ifdef __CYGWIN__
#include <w32api/windows.h>
#include <sys/cygwin.h>
#endif /* __CYGWIN__ */

// 
int statDirectory (std::string dirFile)
{
   time_t dummyArg;
   return statFileOrDirectory (dirFile, DIR_TYPE, dummyArg);
}

// 
int statFile (std::string dirFile)
{
   time_t dummyArg;
   return statFileOrDirectory (dirFile, FILE_TYPE, dummyArg);
}

// 
int statFile (std::string dirFile, time_t &timeStamp)
{
   return statFileOrDirectory (dirFile, FILE_TYPE, timeStamp);
}

// Do not use this function directly
int statFileOrDirectory (std::string dirFile, statType sType, time_t &fileMtime)
{
   struct stat status;

   int statVal = stat (dirFile.c_str (), &status);

   if (statVal == 0 && S_ISDIR (status.st_mode))
   {
      if (sType != DIR_TYPE)  // Trying to stat a file and have a directory
      {
         return -1;
      }

      DIR *dir;

      dir = opendir (dirFile.c_str());
  
      if (dir != NULL)
      {
         closedir (dir);
         return 0;
      }
      else 
      {
         return -1;
      }
   }

   if (statVal == 0 && S_ISREG (status.st_mode))
   {
      if (sType != FILE_TYPE)  // Trying to stat a directory and have a file
      {
         return -1;
      }

      FILE *file;
   
      file = fopen (dirFile.c_str(), "r");
  
      if (file != NULL)
      {
         fileMtime = status.st_mtime;
         fclose (file);
         return 0;
      }
      else 
      {
         return -1;
      }
   }

   return -1;
}

void relativizePath (std::string &inPath)
{
#ifdef __CYGWIN__

   if (inPath[1] == ':')
   {
      // Convert windows path to posix-style path
      size_t size = cygwin_conv_path (CCP_WIN_A_TO_POSIX | CCP_ABSOLUTE,
         inPath.c_str (), NULL, 0);
      char *posixabspath = (char *) malloc (size);

      if (posixabspath &&
          cygwin_conv_path (CCP_WIN_A_TO_POSIX | CCP_ABSOLUTE,
          inPath.c_str (), posixabspath, size) == 0)
      {
         inPath = posixabspath;
      }

      free (posixabspath);
   }
   else if (inPath[0] != '/')
   {
      std::string wd = getWorkingDirectory();

      if (wd == "/")
        inPath = wd + inPath;
      else
        inPath = wd + "/" + inPath;
   }
#else /* __CYGWIN__ */
   if (inPath[0] != '/')
   {
      inPath = getWorkingDirectory() + "/" + inPath;
   }
#endif /* __CYGWIN__ */
}

std::string sanitizePath (std::string inPath)
{
   if (inPath[inPath.size () - 1] == '/' ||
       inPath[inPath.size () - 1] == '\\')
   {
      inPath.erase (inPath.size () - 1);
   }

   return inPath;
}

#ifdef __CYGWIN__
std::string getWinInstallDirectory ()
{
   // by default, look for dhparam.pem in the install dir on Windows
   char exeDir[MAX_PATH];
   std::string result;
   result = ".";

   if (GetModuleFileNameA (NULL, exeDir, MAX_PATH))
   {
      // Convert windows path to posix-style path
      std::string dirName = std::string (exeDir);
      dirName = dirName.substr (0, dirName.find_last_of ('\\'));

      size_t size = cygwin_conv_path (CCP_WIN_A_TO_POSIX | CCP_ABSOLUTE,
         dirName.c_str (), NULL, 0);
      char *posixabspath = (char *) malloc (size);

      if (posixabspath &&
          cygwin_conv_path (CCP_WIN_A_TO_POSIX | CCP_ABSOLUTE,
             dirName.c_str (), posixabspath, size) == 0)
      {
         result = posixabspath;
      }

      free (posixabspath);
   }

   return result;
}
#endif /* __CYGWIN__ */

std::string getWorkingDirectory ()
{
   std::string result = ".";

#ifdef __CYGWIN__
   // In cygwin, getcwd is broken if called from outside of the
   // cygwin environment.  Work around this by converting
   // the path returned by getcwd to an absolute posix path
   // via the cygwin library.
   char *getcwdpath;
   getcwdpath = (char *) malloc (MAX_PATH);

   if (!getcwdpath)
      return result;

   if (GetCurrentDirectoryA (MAX_PATH, getcwdpath))
   {

      ssize_t size = cygwin_conv_path (CCP_WIN_A_TO_POSIX | CCP_ABSOLUTE,
         getcwdpath, NULL, 0);
      if (size > 0)
      {
         char *posixabspath = (char *) malloc (size);
         if (!posixabspath)
         {
            free (getcwdpath);
            return result;
         }

         if (cygwin_conv_path (CCP_WIN_A_TO_POSIX | CCP_ABSOLUTE, getcwdpath,
            posixabspath, size) == 0)
         {
            result = posixabspath;
         }

         free (posixabspath);
      }
   }

   free (getcwdpath);
#else /* __CYGWIN__ */
   size_t size;

   size = (size_t) pathconf (".", _PC_PATH_MAX);

   char *buf;
   char *ptr;

   if ((buf = (char *) malloc ((size_t) size)) != NULL)
   {
      ptr = getcwd (buf, (size_t) size);

      if (ptr)
         result = buf;
   }

   free (buf);
#endif /* __CYGWIN__ */

   return result;
}
