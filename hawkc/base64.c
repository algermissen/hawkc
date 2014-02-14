/*
 This file is based on base64 encode/decode code from
 https://github.com/superwills/NibbleAndAHalf.

 The code organization has been slightly modifies to match me own file structure.

 Original License of the base64 code below.

 https://github.com/superwills/NibbleAndAHalf
 base64.h -- Fast base64 encoding and decoding.
 version 1.0.0, April 17, 2013 143a

 Copyright (C) 2013 William Sherif

 This software is provided 'as-is', without any express or implied
 warranty.  In no event will the authors be held liable for any damages
 arising from the use of this software.

 Permission is granted to anyone to use this software for any purpose,
 including commercial applications, and to alter it and redistribute it
 freely, subject to the following restrictions:

 1. The origin of this software must not be misrepresented; you must not
 claim that you wrote the original software. If you use this software
 in a product, an acknowledgment in the product documentation would be
 appreciated but is not required.
 2. Altered source versions must be plainly marked as such, and must not be
 misrepresented as being the original software.
 3. This notice may not be removed or altered from any source distribution.

 William Sherif
 will.sherif@gmail.com

 YWxsIHlvdXIgYmFzZSBhcmUgYmVsb25nIHRvIHVz

 */
#include "base64.h"

const static char* b64="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/" ;

const static unsigned char unb64[]={
  0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
  0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
  0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
  0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
  0,   0,   0,  62,   0,   0,   0,  63,  52,  53,
 54,  55,  56,  57,  58,  59,  60,  61,   0,   0,
  0,   0,   0,   0,   0,   0,   1,   2,   3,   4,
  5,   6,   7,   8,   9,  10,  11,  12,  13,  14,
 15,  16,  17,  18,  19,  20,  21,  22,  23,  24,
 25,   0,   0,   0,   0,   0,   0,  26,  27,  28,
 29,  30,  31,  32,  33,  34,  35,  36,  37,  38,
 39,  40,  41,  42,  43,  44,  45,  46,  47,  48,
 49,  50,  51,   0,   0,   0,   0,   0,   0,   0,
  0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
  0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
  0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
  0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
  0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
  0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
  0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
  0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
  0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
  0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
  0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
  0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
  0,   0,   0,   0,   0,   0,
};



unsigned char* hawkc_base64_encode(const unsigned char* bin, size_t len, unsigned char *res, size_t *flen) {

  size_t rc = 0 ;
  size_t byteNo ;

  size_t modulusLen = len % 3 ;
  size_t pad = ((modulusLen&1)<<1) + ((modulusLen&2)>>1) ;

  *flen = 4*(len + pad)/3 ;

  for( byteNo = 0 ; byteNo+3 <= len ; byteNo+=3 )
  {
    unsigned char BYTE0=bin[byteNo];
    unsigned char BYTE1=bin[byteNo+1];
    unsigned char BYTE2=bin[byteNo+2];
    res[rc++]  = b64[ BYTE0 >> 2 ] ;
    res[rc++]  = b64[ ((0x3&BYTE0)<<4) + (BYTE1 >> 4) ] ;
    res[rc++]  = b64[ ((0x0f&BYTE1)<<2) + (BYTE2>>6) ] ;
    res[rc++]  = b64[ 0x3f&BYTE2 ] ;
  }

  if( pad==2 )
  {
    res[rc++] = b64[ bin[byteNo] >> 2 ] ;
    res[rc++] = b64[ (0x3&bin[byteNo])<<4 ] ;
    res[rc++] = '=';
    res[rc++] = '=';
  }
  else if( pad==1 )
  {
    res[rc++]  = b64[ bin[byteNo] >> 2 ] ;
    res[rc++]  = b64[ ((0x3&bin[byteNo])<<4)   +   (bin[byteNo+1] >> 4) ] ;
    res[rc++]  = b64[ (0x0f&bin[byteNo+1])<<2 ] ;
    res[rc++] = '=';
  }

  return res ;
}


unsigned char *hawkc_base64_decode(const unsigned char* safeAsciiPtr, size_t len,
		unsigned char *bin, size_t *flen) {

	  size_t cb=0;
	  size_t charNo;
	  size_t pad = 0 ;

	  if(len < 2) {
		  *flen =  0;
		  return bin;
	  }

	  if( safeAsciiPtr[ len-1 ]=='=' )  ++pad ;
	  if( safeAsciiPtr[ len-2 ]=='=' )  ++pad ;

	  *flen = 3*len/4 - pad ;

	  for( charNo=0; charNo + 4 + pad <= len; charNo+=4 )
	  {
	    size_t A=unb64[safeAsciiPtr[charNo]];
	    size_t B=unb64[safeAsciiPtr[charNo+1]];
	    size_t C=unb64[safeAsciiPtr[charNo+2]];
	    size_t D=unb64[safeAsciiPtr[charNo+3]];

	    bin[cb++] = (A<<2) | (B>>4) ;
	    bin[cb++] = (B<<4) | (C>>2) ;
	    bin[cb++] = (C<<6) | (D) ;
	  }

	  if( pad==1 )
	  {
	    size_t A=unb64[safeAsciiPtr[charNo]];
	    size_t B=unb64[safeAsciiPtr[charNo+1]];
	    size_t C=unb64[safeAsciiPtr[charNo+2]];

	    bin[cb++] = (A<<2) | (B>>4) ;
	    bin[cb++] = (B<<4) | (C>>2) ;
	  }
	  else if( pad==2 )
	  {
	    size_t A=unb64[safeAsciiPtr[charNo]];
	    size_t B=unb64[safeAsciiPtr[charNo+1]];

	    bin[cb++] = (A<<2) | (B>>4) ;
	  }

	  return bin ;

}
