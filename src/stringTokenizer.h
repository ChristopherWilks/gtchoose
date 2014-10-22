/* -*- mode: C++; c-basic-offset: 3; tab-width: 3; -*-
 *
 * Copyright (c) 2011, Annai Systems, Inc.
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
 * stringTokenizer.h
 *
 *  Created on: Sep 15, 2011
 *      Author: dnelson
 */

#ifndef STRINGTOKENIZER_H_
#define STRINGTOKENIZER_H_

#include <pthread.h>

#include <string>
#include <map>

class strTokenize
{
   public:
      typedef enum separatorTreatment {MERGE_CONSECUTIVE_SEPARATORS=1, INDIVIDUAL_CONSECUTIVE_SEPARATORS} separatorTreatment;

      strTokenize (std::string toTokenize, const char *separator, separatorTreatment treatment);
      strTokenize (const char *toTokenize, const char *separator, separatorTreatment treatment);

      const std::string getToken (int index) {return _tokenMap[index-1]; }
      unsigned size () { return _tokenMap.size(); }
      void updateToken (const unsigned int index, std::string value) { _tokenMap[index-1] = value; }
      void display ();

   protected:

   private:
      std::map <unsigned int, std::string> _tokenMap;

      void process (const char *toTokenize, const char *separators, separatorTreatment treatment);
      void tokenizeSingle (std::string buff, const char *separators);
      void tokenizeMultiple (std::string buff, const char *separators);
};

#endif /* STRINGTOKENIZER_H_ */
