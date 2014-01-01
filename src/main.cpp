#include <iostream>
#include <QDateTime>
#include <QDebug>
#include <QCoreApplication>
#include <QEventLoop>
#include <openssl/sha.h>
#include <string>
#include <QThread>
#include "uint256.h"
#include "main.h"
#include <QTime>
#include <QThread>
#include "momentum.h"
#include <QCoreApplication>
#include <QTime>
using std::string;

uint32_t rej_num = 0;
uint32_t sub_num = 0;
unsigned int memorySize = (1<<30);
long long hash_num = 0;
long long t_total = 0; 

double getDifficulty(unsigned int nBits) {
	int nShift = (nBits >> 24) & 0xff;
	double dDiff =
		(double)0x0000ffff / (double)(nBits & 0x00ffffff);
	while (nShift < 29) {   
		dDiff *= 256.0;
		nShift++;
	}   
	while (nShift > 29) {   
		dDiff /= 256.0;
		nShift--;
	}   
	return dDiff;
}

void GSleep(int gap) {
	QTime t;
	t.start();
	while (t.elapsed() < gap) {
		QCoreApplication::processEvents();
	}
}

void customMessageHandler(QtMsgType type, const char *msg)
{
	if (type == QtDebugMsg) {
		printf("[%s %s] %s\n", (QDate::currentDate()).toString("MM-dd").toStdString().c_str(), (QTime::currentTime()).toString("hh:mm:ss").toStdString().c_str(), msg);
	}
}

void MiningThreadStep1::run() {
	SHA512Filler(mainMemory, threadNumber, totalThreads, midHash);
}

void MiningThreadStep2::run() {
	aesSearch(mainMemory, threadNumber, totalThreads, midHash, parentThread, quitFlag);
}


void WorkThread::run() {
	qDebug("Start new work thread.");
	qDebug("Height = %u Difficulty = %.10f", nHeight, getDifficulty(nBits));

	getShareHash();

	QTime t;
	t.start();
	unsigned int originTime = nTime;

	while (!quitFlag) {
		QTime t_hash;
		t_hash.start();

		nNonce++;
		getMidHash();

		//qDebug("Step1");	
		for (int i = 0; i < workerCount; i++) {
			workerStep1[i].mainMemory = mainMemory;
			workerStep1[i].threadNumber = i;
			workerStep1[i].totalThreads = workerCount;
			workerStep1[i].midHash = midHash; 
			workerStep1[i].start();
		}
		for (int i = 0; i < workerCount; i++) {
			workerStep1[i].wait();
		}
		//qDebug("Step2");	
		for (int i = 0; i < workerCount; i++) {
			workerStep2[i].mainMemory = mainMemory;
			workerStep2[i].threadNumber = i;
			workerStep2[i].totalThreads = workerCount;
			workerStep2[i].midHash = midHash;
			workerStep2[i].parentThread = this;
			workerStep2[i].quitFlag = &quitFlag;
			workerStep2[i].start();
		}
		for (int i = 0; i < workerCount; i++) {
			workerStep2[i].wait();
		}
		//qDebug("Over");

		if (quitFlag) break;	
		hash_num++;
		t_total += t_hash.elapsed();
		qDebug("%.5f Hashes / min", hash_num * 60000. / t_total);
		nTime = originTime + t.elapsed() / 1000;
	}
}


GPoolClient::GPoolClient() {
	//    QObject::connect(this, SIGNAL( readyRead()), this, SLOT(onRead()) );
}

void GPoolClient::submit(const char* data, const int len) {
	if (state() != QAbstractSocket::ConnectedState || workThread.quitFlag) {
		return;
	}
	this->write((const char*)data, len);
	if (!this->flush()) {
		this->abort();
	}
}

void WorkThread::submit(unsigned int nBirthdayA, unsigned int nBirthdayB) {
	uint256 fullHash = getFullHash(nBirthdayA, nBirthdayB);
	if (fullHash > shareHash) {
		qDebug("Found a solution but not share");
		return;
	}

	qDebug("Share found! I will submit now!!");
	unsigned char data[92];
	data[0] = 4;
	data[1] = 88;
	data[2] = data[3] = 0;
	memcpy(data + 4, &hashMerkleRoot, 32);
	memcpy(data + 36, &hashPrevBlock, 32);
	memcpy(data + 68, &nVersion, 4);
	memcpy(data + 72, &nTime, 4);
	memcpy(data + 76, &nNonce, 4);
	memcpy(data + 80, &nBits, 4);
	memcpy(data + 84, &nBirthdayA, 4);
	memcpy(data + 88, &nBirthdayB, 4);

	client->submit((const char*)data, 92);
}

bool GPoolClient::login() {
	unsigned char data[10000];
	data[0] = 1;
	data[1] = (11 + user.length()) & 0xff;
	data[2] = ((11 + user.length()) >> 8) & 0xff;
	data[3] = ((11 + user.length()) >> 16) & 0xff;
	memcpy(data + 4, &MINER_VERSION, 4);
	data[8] = user.length();
	memcpy(data + 9, user.c_str(), user.length());
	data[9 + user.length()] = 1;
	data[10 + user.length()] = 'x';
	data[11 + user.length()] = 1;
	data[12 + user.length()] = 0;
	data[13 + user.length()] = 0;
	data[14 + user.length()] = 0;

	int len = this->write((const char*)data, 15 + user.length());
	this->flush();
	if (len == 15 + (int)user.length()) {
		return true;
	} else {
		return false;
	}
}

void WorkThread::getShareHash() {
	shareHash = (nBitsShare & 0xffffff);
	shareHash = shareHash << ((((nBitsShare >> 24) & 0xff) - 3) * 8);
}

void WorkThread::getMidHash() {
	unsigned char data[80];
	memcpy(data, &nVersion, sizeof(nVersion));
	memcpy(data + 4, &hashPrevBlock, sizeof(hashPrevBlock));
	memcpy(data + 36, &hashMerkleRoot, sizeof(hashMerkleRoot));
	memcpy(data + 68, &nTime, sizeof(nTime));
	memcpy(data + 72, &nBits, sizeof(nBits));
	memcpy(data + 76, &nNonce, sizeof(nNonce));

	unsigned char hash[32];
	SHA256((unsigned char*)data, sizeof(data), (unsigned char*)hash);
	SHA256((unsigned char*)hash, sizeof(hash), (unsigned char*)&midHash);
}

uint256 WorkThread::getFullHash(unsigned int nBirthdayA, unsigned int nBirthdayB) {
	unsigned char data[88];
	memcpy(data, &nVersion, sizeof(nVersion));
	memcpy(data + 4, &hashPrevBlock, sizeof(hashPrevBlock));
	memcpy(data + 36, &hashMerkleRoot, sizeof(hashMerkleRoot));
	memcpy(data + 68, &nTime, sizeof(nTime));
	memcpy(data + 72, &nBits, sizeof(nBits));
	memcpy(data + 76, &nNonce, sizeof(nNonce));
	memcpy(data + 80, &nBirthdayA, sizeof(nBirthdayA));
	memcpy(data + 84, &nBirthdayB, sizeof(nBirthdayB));

	unsigned char hash[32];
	uint256 fullHash;
	SHA256((unsigned char*)data, sizeof(data), (unsigned char*)hash);
	SHA256((unsigned char*)hash, sizeof(hash), (unsigned char*)&fullHash);
	return fullHash;
}

void GPoolClient::onRead() {
	unsigned char buffer[10000];
	unsigned char *data = buffer;
	int dataLen = readData((char *)buffer, 10000);

	while (dataLen >= 4) {
		int opCode = data[0];
		int opLen = data[1] + (int(data[2]) << 8) + (int(data[3]) << 16);
		if (opLen + 4 > dataLen) {
			return;
		}
		if (opCode == 2) {
			unsigned int err_no;
			memcpy(&err_no, data + 4, 4);
			if (err_no != 0) {
				data[10 + int(data[8]) + int(data[9]) * 16] = 0;
				qDebug("%s", data + 10);
				exit(0);
			} else {
				qDebug("Login Success!");
			}
		}
		else if (opCode == 3) {
			workThread.quitFlag = true;
			workThread.wait();

			workThread.client = this;
			memcpy(&workThread.nVersion, data + 4, 4);
			memcpy(&workThread.nHeight, data + 8, 4);
			memcpy(&workThread.nBits, data + 12, 4);
			memcpy(&workThread.nBitsShare, data + 16, 4);
			memcpy(&workThread.nTime, data + 20, 4);
			memcpy(&workThread.hashPrevBlock, data + 24, 32);
			memcpy(&workThread.hashMerkleRoot, data + 56, 32);

			workThread.quitFlag = false;
			workThread.start();
		}
		else if (opCode == 5) {
			unsigned int err_no;
			memcpy(&err_no, data + 4, 4);
			if (err_no == 0) {
				qDebug("Share ACCEPTED");
			}
			else {
				data[10 + int(data[8]) + int(data[9]) * 16] = 0;
				qDebug("Share rejected: %s", data + 10);
				rej_num++;
			}
			sub_num++;
			qDebug("Acc %u Rej %u Sub %u AccRate %.3f%%", sub_num - rej_num, rej_num, sub_num, (sub_num - rej_num) * 100. / sub_num);
		}
		else if (opCode == 8) {

		}
		else {
			//qDebug("Unkown OpCode %d, Ignore Data Length %d", opCode, opLen);
		}

		data += 4 + opLen;
		dataLen -= opLen + 4;
	}
}

int main(int argc, char**argv) {
	qInstallMsgHandler(customMessageHandler);

	qDebug("Welcome to GPool.net");
	qDebug("This is beta version of GMMCMiner.");
	qDebug("Release date : %s", __DATE__);


	QString ip = "162.243.223.123";
	int port = 10031;

	GPoolClient *client = new GPoolClient();
	client->workThread.nNonce = 0;
	client->workThread.workerCount = 1;
	client->user = "M9PrLnpQamdxBY1E6NCQ1SmkHXyXu1iyQm";

	for (int i = 1; i < argc - 1; i++) {
		if (strcmp(argv[i], "-u") == 0) {
			client->user = argv[++i];
		}
		else if (strcmp(argv[i], "-t") == 0) {
			sscanf(argv[++i], "%d", &client->workThread.workerCount);
		}
		else if (strcmp(argv[i], "-h") == 0) {
			ip = argv[++i];
		}
		else if (strcmp(argv[i], "-p") == 0) {
			sscanf(argv[++i], "%d", &port);
		}
		else if (strcmp(argv[i], "-m") == 0) {
			if (strcmp(argv[i + 1], "512") == 0) {
				memorySize = (1<<29);
			}
			else if (strcmp(argv[i + 1], "256") == 0) {
				memorySize = (1<<28);
			}
		}
	}

	if (client->workThread.workerCount > MAX_THREADS) {
		client->workThread.workerCount = MAX_THREADS;
	} else if (client->workThread.workerCount < 1) {
		client->workThread.workerCount = 1;
	}

	qDebug("@Host : %s", ip.toStdString().c_str());
	qDebug("@Port : %d", port);
	qDebug("@User : %s", client->user.c_str());
	qDebug("@Thread : %d", client->workThread.workerCount);
	qDebug("@Memory : %d MB", memorySize >> 20);

	char *mainMemory = new char[memorySize];
	if (mainMemory == NULL) {
		qDebug("I cannot allocate enough memory. Exit.");
		return 0;
	}
	client->workThread.mainMemory = mainMemory;

	while (true) {
		if (client->state() != QAbstractSocket::ConnectedState) {
			client->workThread.quitFlag = true;
			client->abort();
			client->connectToHost(ip, port);
			if (client->waitForConnected(2000)) {
				qDebug("Connected to pool");
				if (!client->login()) {
					qDebug("Login error, I will try later.");
					GSleep(3000);
				}
			} else {
				qDebug("Failed to connect, I will try later.");
				GSleep(3000);
			}
		}
		else {
			if (client->waitForReadyRead(300)) {
				client->onRead();
			}
		}
	}

	delete []mainMemory;
	delete client;

	return 0;
}

