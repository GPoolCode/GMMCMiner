#pragma once
#include "uint256.h"
#include <vector>
#include "main.h"

void SHA512Filler(char *mainMemoryPsuedoRandomData, int threadNumber, int totalThreads, uint256 midHash);
void aesSearch(char *mainMemoryPsuedoRandomData, int threadNumber, int totalThreads, WorkThread*, bool *quitFlag);
