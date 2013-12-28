TEMPLATE = app
CONFIG += console
TARGET = 
DEPENDPATH += .
INCLUDEPATH += .
QT += network
LIBS += -L. -lssl -lcrypto 
#DEFINES += QT_NO_DEBUG_OUTPUT
# Input
HEADERS += main.h momentum.h  uint256.h
SOURCES += main.cpp  momentum.cpp

