#pragma once
#include <QTcpSocket>
#include <string>
#include <QObject>
#include "uint256.h"
#include <QThread>
#include <QMutex>
using std::string;
const int MAX_THREADS = 256;
const int MINER_VERSION = 2;

class GPoolClient;
class WorkThread;

class MiningThreadStep1: public QThread {
public:
    int threadNumber;
    int totalThreads;
    char *mainMemory;
    uint256 midHash;
    void run();
};

class MiningThreadStep2: public QThread {
public:
    int threadNumber;
    int totalThreads;
    char *mainMemory;
    bool *quitFlag;
    WorkThread *parentThread;
    void run();
};

class WorkThread: public QThread {
public:
    GPoolClient *client;
    MiningThreadStep1 workerStep1[MAX_THREADS];
    MiningThreadStep2 workerStep2[MAX_THREADS];
    int workerCount;
    char *mainMemory;
    bool quitFlag;
    
    unsigned int nVersion;
    uint256 hashPrevBlock;
    uint256 hashMerkleRoot;
    unsigned int nTime;
    unsigned int nBits;
    unsigned int nHeight;
    unsigned int nBitsShare;
    unsigned int nNonce;
    uint256 midHash;
    uint256 shareHash;
    
    void getMidHash();
    void getShareHash();
    uint256 getFullHash(unsigned int, unsigned int);
    
    void run();
    void submit(unsigned int, unsigned int);
};

class GPoolClient : public QTcpSocket {
    Q_OBJECT
public:
    string user;
    
    WorkThread workThread;
    QMutex submitMutex;

    GPoolClient();
    bool login();
    void submit(const char *, const int);

public slots:
    void onRead();
};


