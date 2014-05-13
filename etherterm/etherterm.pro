#-------------------------------------------------
#
# Project created by QtCreator 2014-05-12T18:13:17
#
#-------------------------------------------------

QT       += core gui

TARGET = etherterm
TEMPLATE = app

LIBS += -lpcap
QT += network

SOURCES += main.cpp\
        mainwindow.cpp

HEADERS  += mainwindow.h

FORMS    += mainwindow.ui

