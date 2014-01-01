#include <iostream>
#include <openssl/sha.h>
#include "momentum.h"
#include <openssl/aes.h>
#include <openssl/evp.h>
#include "main.h"

#define PSUEDORANDOM_DATA_SIZE 30 //2^30 = 1GB
#define PSUEDORANDOM_DATA_CHUNK_SIZE 6 //2^6 = 64 bytes
#define L2CACHE_TARGET 16 // 2^16 = 64K
#define AES_ITERATIONS 50

// useful constants
#define  psuedoRandomDataSize (1<<PSUEDORANDOM_DATA_SIZE)
#define  cacheMemorySize   (1<<L2CACHE_TARGET)
#define chunks (1<<(PSUEDORANDOM_DATA_SIZE-PSUEDORANDOM_DATA_CHUNK_SIZE))
#define chunkSize (1<<(PSUEDORANDOM_DATA_CHUNK_SIZE))
#define comparisonSize (1<<(PSUEDORANDOM_DATA_SIZE-L2CACHE_TARGET))

void SHA512Filler(char *mainMemoryPsuedoRandomData, int threadNumber, int totalThreads, uint256 midHash){
	unsigned char hash_tmp[sizeof(midHash)];
	memcpy((char*)&hash_tmp[0], (char*)&midHash, sizeof(midHash) );
	uint32_t* index = (uint32_t*)hash_tmp;

	uint32_t chunksToProcess = (memorySize >> PSUEDORANDOM_DATA_CHUNK_SIZE) / totalThreads;
	uint32_t startChunk = threadNumber * chunksToProcess;
	uint32_t endChunk = startChunk + chunksToProcess;
	if (threadNumber == totalThreads - 1) {
		endChunk = (memorySize >> PSUEDORANDOM_DATA_CHUNK_SIZE);
	}
	for( uint32_t i = startChunk; i < endChunk; i++) {
		*index = i;
		SHA512((unsigned char*)hash_tmp, sizeof(hash_tmp), (unsigned char*)&(mainMemoryPsuedoRandomData[i*chunkSize]));
	}
}

void aesSearch(char *mainMemoryPsuedoRandomData, int threadNumber, int totalThreads, uint256 midHash, WorkThread *parentThread, bool *quitFlag) {
	unsigned char hash_tmp[sizeof(midHash)];
	memcpy((char*)&hash_tmp[0], (char*)&midHash, sizeof(midHash) );
	uint32_t* index = (uint32_t*)hash_tmp;

	unsigned char cacheMemoryOperatingData[cacheMemorySize+16];
	unsigned char cacheMemoryOperatingData2[cacheMemorySize];
	uint32_t* cacheMemoryOperatingData32 = (uint32_t*)cacheMemoryOperatingData;
	uint32_t* cacheMemoryOperatingData322 = (uint32_t*)cacheMemoryOperatingData2;
	unsigned char key[32] = {0};
	unsigned char iv[AES_BLOCK_SIZE];
	int outlen1, outlen2;
	uint32_t searchNumber=comparisonSize/totalThreads;
	uint32_t startLoc = threadNumber*searchNumber;
	uint32_t endLoc = startLoc + searchNumber;
	if (threadNumber == totalThreads - 1) {
		endLoc = comparisonSize;
	}
	for(uint32_t k=startLoc;k<endLoc;k++){
		if (*quitFlag) return;
		if ((k + 1) * cacheMemorySize <= memorySize) {
			memcpy((char*)&cacheMemoryOperatingData[0], (char*)&mainMemoryPsuedoRandomData[k*cacheMemorySize], cacheMemorySize);
		}
		else {
			int i = k*cacheMemorySize / chunkSize;
			for (int j = 0; j < cacheMemorySize / chunkSize; j++) {
				*index = i;
				SHA512((unsigned char*)hash_tmp, sizeof(hash_tmp), (unsigned char*)&(cacheMemoryOperatingData[j*chunkSize]));
				i++;
			}
		}
		for(int j=0;j<AES_ITERATIONS;j++){
			uint32_t nextLocation = cacheMemoryOperatingData32[(cacheMemorySize/4)-1]%comparisonSize;
			if ((nextLocation + 1) * cacheMemorySize <= memorySize) {
				memcpy((char*)&cacheMemoryOperatingData2[0], (char*)&mainMemoryPsuedoRandomData[nextLocation*cacheMemorySize], cacheMemorySize);
			}
			else {
				int i = nextLocation*cacheMemorySize / chunkSize;
				for (int j = 0; j < cacheMemorySize / chunkSize; j++) {
					*index = i;
					SHA512((unsigned char*)hash_tmp, sizeof(hash_tmp), (unsigned char*)&(cacheMemoryOperatingData2[j*chunkSize]));
					i++;
				}
			}
			for(uint32_t i = 0; i < cacheMemorySize/4; i++){
				cacheMemoryOperatingData322[i] ^= cacheMemoryOperatingData32[i];
			}
			EVP_CIPHER_CTX ctx;
			memcpy(key,(unsigned char*)&cacheMemoryOperatingData2[cacheMemorySize-32],32);
			memcpy(iv,(unsigned char*)&cacheMemoryOperatingData2[cacheMemorySize-AES_BLOCK_SIZE],AES_BLOCK_SIZE);
			EVP_EncryptInit(&ctx, EVP_aes_256_cbc(), key, iv);
			EVP_EncryptUpdate(&ctx, cacheMemoryOperatingData, &outlen1, cacheMemoryOperatingData2, cacheMemorySize);
			EVP_EncryptFinal(&ctx, cacheMemoryOperatingData + outlen1, &outlen2);
			EVP_CIPHER_CTX_cleanup(&ctx);
		}
		uint32_t solution=cacheMemoryOperatingData32[(cacheMemorySize/4)-1]%comparisonSize;
		if (solution == 1968) {
			uint32_t proofOfCalculation=cacheMemoryOperatingData32[(cacheMemorySize/4)-2];
			parentThread->submit(k, proofOfCalculation);
		}
	}
}

