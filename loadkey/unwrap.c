#include "loadkey.h"
#include <wmmintrin.h>
#include <emmintrin.h>
#include <smmintrin.h>

#define XMMLO( ymm )	( ( (__m128i *) &( ymm ) )[ 0 ] )
#define XMMHI( ymm )	( ( (__m128i *) &( ymm ) )[ 1 ] )

/*!
	\brief Performs a single block Rijndael 256 256 (key length, block length) encryption.
*/
void YK_Unwrap( block256_t *const pymmKey, const block256_t ymmKEK )
{
	__m128i tmp1, tmp2;
	const __m128i RIJNDAEL256_MASK = _mm_set_epi32( 0x03020d0c, 0x0f0e0908, 0x0b0a0504, 0x07060100 );
	const __m128i BLEND_MASK = _mm_set_epi32( 0x80000000, 0x80800000, 0x80800000, 0x80808000 );
	block256_t data = *pymmKey;

	//Round 0 (initial xor)
	XMMLO( data ) = _mm_xor_si128( XMMLO( data ), XMMLO( ymmKEK ) );
	XMMHI( data ) = _mm_xor_si128( XMMHI( data ), XMMHI( ymmKEK ) );

	for( unsigned uRound = 1;; ++uRound )
	{
		//Blend to compensate for the shift rows shifts bytes between two 128 bit blocks
		tmp1 = _mm_blendv_epi8( XMMLO( data ), XMMHI( data ), BLEND_MASK );
		tmp2 = _mm_blendv_epi8( XMMHI( data ), XMMLO( data ), BLEND_MASK );

		//Shuffle that compensates for the additional shift in rows 3 and 4 as opposed to Rijndael128 (AES)
		XMMLO( data ) = _mm_shuffle_epi8( tmp1, RIJNDAEL256_MASK );
		XMMHI( data ) = _mm_shuffle_epi8( tmp2, RIJNDAEL256_MASK );

		//Perform key expansion
		{
			switch( uRound )
			{
			case  1: tmp1 = _mm_aeskeygenassist_si128( XMMHI( ymmKEK ), 0x01 ); break;
			case  2: tmp1 = _mm_aeskeygenassist_si128( XMMHI( ymmKEK ), 0x02 ); break;
			case  3: tmp1 = _mm_aeskeygenassist_si128( XMMHI( ymmKEK ), 0x04 ); break;
			case  4: tmp1 = _mm_aeskeygenassist_si128( XMMHI( ymmKEK ), 0x08 ); break;
			case  5: tmp1 = _mm_aeskeygenassist_si128( XMMHI( ymmKEK ), 0x10 ); break;
			case  6: tmp1 = _mm_aeskeygenassist_si128( XMMHI( ymmKEK ), 0x20 ); break;
			case  7: tmp1 = _mm_aeskeygenassist_si128( XMMHI( ymmKEK ), 0x40 ); break;
			case  8: tmp1 = _mm_aeskeygenassist_si128( XMMHI( ymmKEK ), 0x80 ); break;
			case  9: tmp1 = _mm_aeskeygenassist_si128( XMMHI( ymmKEK ), 0x1B ); break;
			case 10: tmp1 = _mm_aeskeygenassist_si128( XMMHI( ymmKEK ), 0x36 ); break;
			case 11: tmp1 = _mm_aeskeygenassist_si128( XMMHI( ymmKEK ), 0x6C ); break;
			case 12: tmp1 = _mm_aeskeygenassist_si128( XMMHI( ymmKEK ), 0xD8 ); break;
			case 13: tmp1 = _mm_aeskeygenassist_si128( XMMHI( ymmKEK ), 0xAB ); break;
			case 14: tmp1 = _mm_aeskeygenassist_si128( XMMHI( ymmKEK ), 0x4D ); break;
			}

			tmp1 = _mm_shuffle_epi32( tmp1, 0xff );
			tmp2 = _mm_slli_si128( XMMLO( ymmKEK ), 0x4 );
			XMMLO( ymmKEK ) = _mm_xor_si128( XMMLO( ymmKEK ), tmp2 );
			tmp2 = _mm_slli_si128( tmp2, 0x4 );
			XMMLO( ymmKEK ) = _mm_xor_si128( XMMLO( ymmKEK ), tmp2 );
			tmp2 = _mm_slli_si128( tmp2, 0x4 );
			XMMLO( ymmKEK ) = _mm_xor_si128( XMMLO( ymmKEK ), tmp2 );
			XMMLO( ymmKEK ) = _mm_xor_si128( XMMLO( ymmKEK ), tmp1 );

			tmp2 = _mm_aeskeygenassist_si128( XMMLO( ymmKEK ), 0x0 );
			tmp1 = _mm_shuffle_epi32( tmp2, 0xaa );
			tmp2 = _mm_slli_si128( XMMHI( ymmKEK ), 0x4 );
			XMMHI( ymmKEK ) = _mm_xor_si128( XMMHI( ymmKEK ), tmp2 );
			tmp2 = _mm_slli_si128( tmp2, 0x4 );
			XMMHI( ymmKEK ) = _mm_xor_si128( XMMHI( ymmKEK ), tmp2 );
			tmp2 = _mm_slli_si128( tmp2, 0x4 );
			XMMHI( ymmKEK ) = _mm_xor_si128( XMMHI( ymmKEK ), tmp2 );
			XMMHI( ymmKEK ) = _mm_xor_si128( XMMHI( ymmKEK ), tmp1 );
		}

		if( uRound >= 14 )
			break;

		//This is the encryption step that includes sub bytes, shift rows, mix columns, xor with round key
		XMMLO( data ) = _mm_aesenc_si128( XMMLO( data ), XMMLO( ymmKEK ) );
		XMMHI( data ) = _mm_aesenc_si128( XMMHI( data ), XMMHI( ymmKEK ) );
	}

	//Last AES round
	XMMLO( *pymmKey ) = _mm_aesenclast_si128( XMMLO( data ), XMMLO( ymmKEK ) );
	XMMHI( *pymmKey ) = _mm_aesenclast_si128( XMMHI( data ), XMMHI( ymmKEK ) );
}