/* -*- mode: C++; c-basic-offset: 2; tab-width: 2; -*-
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

#include "gtZeroStorage.h"

using namespace libtorrent;


class zero_storage : public storage_interface
{
public:
  bool has_any_file() { return false; }
  bool rename_file(int index, std::string const& new_filename) { return false; }
  bool release_files() { return false; }
  bool delete_files() { return false; }
  bool initialize(bool allocate_files) { return false; }
  bool move_storage(std::string const& save_path) { return true; }
  size_type physical_offset(int slot, int offset) { return 0; }
  bool move_slot(int src_slot, int dst_slot) { return false; }
  bool swap_slots(int slot1, int slot2) { return false; }
  bool swap_slots3(int slot1, int slot2, int slot3) { return false; }
  bool verify_resume_data(lazy_entry const& rd, error_code& error) { return false; }
  bool write_resume_data(entry& rd) const { return false; }

  // Reads fake the read by writing the requested number of bytes to zeros in
  // the buffer and then returning the number of bytes requested by caller.
  int read(char* buf, int slot, int offset, int size);
  int readv(file::iovec_t const* bufs, int slot, int offset, int num_bufs);

  // Writes do nothing but return success (i.e. the number of bytes written).
  int write(char const* buf, int slot, int offset, int size) { return size; }
  int writev(file::iovec_t const* bufs, int slot, int offset, int num_bufs);
};

int zero_storage::read(char* buf, int slot, int offset, int size)
{
  memset(buf, 0, size);
  return size;
}

int zero_storage::readv(file::iovec_t const* bufs, int slot, int offset, int num_bufs)
{
  int ret = 0;
  for (int i = 0; i < num_bufs; ++i)
  {
    memset(bufs[i].iov_base, 0, bufs[i].iov_len);
    ret += bufs[i].iov_len;
  }
  return ret;
}

int zero_storage::writev(file::iovec_t const* bufs, int slot, int offset, int num_bufs)
{
  int ret = 0;
  for (int i = 0; i < num_bufs; ++i)
    ret += bufs[i].iov_len;
  return ret;
}

storage_interface* zero_storage_constructor(file_storage const& fs,
	file_storage const* mapped, std::string const& path, file_pool& fp,
	std::vector<boost::uint8_t> const& file_prio)
{
  return new zero_storage;
}

