/* -*- mode: C++; c-basic-offset: 3; tab-width: 3; -*- */
/*

Copyright (c) 2003, Arvid Norberg
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:

    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in
      the documentation and/or other materials provided with the distribution.
    * Neither the name of the author nor the names of its
      contributors may be used to endorse or promote products derived
      from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.

*/

/*
   Contents of this file are utility functions extracted from libtorrent-raster
   source code or examples.
*/

#include "gt_config.h"

#include <stdio.h>
#include <sstream>
#include <string.h>
#include <cmath>

#include "geneTorrentUtils.h"

// From libtorrent
std::string add_suffix (float val, char const* suffix)
{
   std::string ret;
   if (val == 0)
   {
      ret.resize (4 + 2, ' ');
      if (suffix)
         ret.resize (4 + 2 + strlen (suffix), ' ');
      return ret;
   }

   const char* prefix[] = { " kB", " MB", " GB", " TB" };
   const int num_prefix = sizeof(prefix) / sizeof(const char*);
   for (int i = 0; i < num_prefix; ++i)
   {
      val /= 1000.f;
      if (std::fabs (val) < 1000.f)
      {
         ret = to_string (val, 4);
         ret += prefix[i];
         if (suffix)
            ret += suffix;
         return ret;
      }
   }
   ret = to_string (val, 4);
   ret += " PB";
   if (suffix)
      ret += suffix;
   return ret;
}

// From libtorrent
std::string to_string (int v, int width)
{
   std::stringstream s;
   s.flags (std::ios_base::right);
   s.width (width);
   s.fill (' ');
   s << v;
   if (s.str().size())
   {
      return s.str()[s.str().size()-1] != '.' ? s.str() : ' ' + s.str().substr(0, s.str().size()-1);
   }
   return s.str();
}

std::string& to_string (float v, int width, int precision)
{
   // this is a silly optimization
   // to avoid copying of strings
   enum
   {
      num_strings = 20
   };
   static std::string buf[num_strings];
   static int round_robin = 0;
   std::string& ret = buf[round_robin];
   ++round_robin;
   if (round_robin >= num_strings)
      round_robin = 0;
   ret.resize (20);
   int size = snprintf (&ret[0], 20, "%*.*f", width, precision, v);
   ret.resize ((std::min) (size, width));
   if (ret.size())
   {
      if (ret[ret.size()-1] == '.')
      {
         ret.erase(ret.size()-1, 1);
      }
   }
   return ret;
}

// contributed by Cardinal Peak
std::string durationToStr(time_t duration)
{
	char buffer[1024];
	int hours;
	int minutes;
	int seconds;

	hours = duration / (60 * 60);
	duration -= hours * 60 * 60;
	minutes = duration / 60;
	duration -= minutes * 60;
	seconds = duration;

	snprintf(buffer, sizeof(buffer), "%02d:%02d:%02d", hours, minutes, seconds);
	return std::string(buffer);
}
