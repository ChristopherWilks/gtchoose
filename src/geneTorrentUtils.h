/* -*- mode: C++; c-basic-offset: 3; tab-width: 3; -*- */

/*
   Contents of this header file define utility functions extracted from 
   libtorrent-raster source code or examples.
*/

/*
 * geneTorrentUtils.h
 *
 *  Created on: Oct 1, 2011
 *      Author: donavan nelson
 */

#ifndef GENETORRENT_UTILS_H_
#define GENETORRENT_UTILS_H_

#include <pthread.h>

#include <string>

#include <boost/filesystem/path.hpp>

// helper functions for verbose output, from libtorrent
std::string add_suffix(float val, const char *suffix = 0);
std::string to_string(int v, int width);
std::string & to_string(float v, int width, int precision = 3);
std::string durationToStr(time_t duration);

bool file_filter (boost::filesystem::path const& filename);

#endif /* GENETORRENT_UTILS_H_ */
