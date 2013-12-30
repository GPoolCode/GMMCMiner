#ifndef __MOMENTUM__
#define __MOMENTUM__
#include "uint256.h"
#include <vector>
#include "main.h"

extern unsigned int memorySize;

void SHA512Filler(char *mainMemoryPsuedoRandomData, int threadNumber, int totalThreads, uint256 midHash);
void aesSearch(char *mainMemoryPsuedoRandomData, int threadNumber, int totalThreads, uint256 midHash, WorkThread*, bool *quitFlag);

#endif
