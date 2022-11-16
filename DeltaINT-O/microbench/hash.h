#ifndef HASH_H
#define HASH_H

#include <stdint.h>
#include <stdlib.h>

uint32_t EcmpHash(const uint8_t* key, size_t len, uint32_t seed);
uint32_t mmh3(const uint8_t * key, size_t len, uint32_t seed);

#endif
