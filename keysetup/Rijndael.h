#pragma once

typedef unsigned char word8;

void Encrypt256_256( const word8 in[ 32 ], word8 out[ 32 ], const word8 key[ 32 ] );
void Decrypt256_256( const word8 in[ 32 ], word8 out[ 32 ], const word8 key[ 32 ] );