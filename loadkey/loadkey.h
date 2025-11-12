#pragma once
#include <stdbool.h>

typedef __attribute__((aligned (16))) struct
{
	unsigned char ab[ 32 ];
} block256_t;

bool LoadKey( block256_t *pymmKey );