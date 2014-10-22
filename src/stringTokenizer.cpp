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
 * stringTokenizer.cpp
 *
 *  Created on: Sep 15, 2011
 *      Author: dnelson
 */

#include "gt_config.h"

#include <iostream>
#include <string.h>
#include <stdlib.h>

#include "stringTokenizer.h"

strTokenize::strTokenize (const char *toTokenize, const char *separators, separatorTreatment treatment) : _tokenMap()
{
   process (toTokenize, separators, treatment);
}

strTokenize::strTokenize (std::string toTokenize, const char *separators, separatorTreatment treatment) : _tokenMap()
{
   process (toTokenize.c_str(), separators, treatment);
}

void strTokenize::process (const char *toTokenize, const char *separators, separatorTreatment treatment)
{
   switch (treatment)
   {
      case strTokenize::MERGE_CONSECUTIVE_SEPARATORS:
      {
         tokenizeMultiple (toTokenize, separators);
      } break;

      case strTokenize::INDIVIDUAL_CONSECUTIVE_SEPARATORS:
      {
         tokenizeSingle (toTokenize, separators);
      } break;

      default:
      {
         std::cerr << "PANIC:  stringTokenizer::stringTokenizer():  unexpected case (treatment = " << treatment << ") in switch statement encountered. Programmer ERROR!" << std::endl;
         exit (254);
      } break;
   }
}

void strTokenize::display (void)
{
   for (unsigned int i = 0; i < _tokenMap.size(); i++)
   {
      std::cerr << "Token Map:  id = " << i << "    value  " << _tokenMap[i] << std::endl;
   }
}

void strTokenize::tokenizeSingle (std::string buff, const char *separators)
{
   char *token;
   int tokenCount = 0;
   char *strWalker;
   char *sepWalker;

   if (0 == buff.size())
   {
      return;
   }

   char *s = new char [buff.size()+1];

   strncpy (s, buff.c_str(), buff.size());
   s[buff.size()] = '\0';

   token=s;
   strWalker=s;

   while (*strWalker)
   {
      sepWalker = (char *)separators;
      while (*sepWalker)
      {
         if (*sepWalker == *strWalker)
         {
            *strWalker = '\0';
            _tokenMap[tokenCount++] = token;
            token = strWalker+1;
            break;
         }
         sepWalker++;
      }
      strWalker++;
   }

   _tokenMap[tokenCount++] = token;

   delete [] s;
}

void strTokenize::tokenizeMultiple (std::string buff, const char *separators)
{
   char *token;
   int tokenCount = 0;
   char *emptyBuff = NULL;

   char *s = new char [buff.size()+1];

   strncpy (s, buff.c_str(), buff.size());
   s[buff.size()] = '\0';

   token = strtok_r (s, separators, &emptyBuff);
   while (NULL != token)
   {
      _tokenMap[tokenCount++] = token;
      token = strtok_r (NULL, separators, &emptyBuff);
   }

   delete [] s;
}
