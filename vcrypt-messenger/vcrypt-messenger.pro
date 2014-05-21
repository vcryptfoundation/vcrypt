 HEADERS       = \
    inputsender.h \
    outputreceiver.h \
    mainwindow.h \
    settingsdialog.h \
    qmainwindowtray.h \
    addbuddydialog.h \
    notifysound.h \
    calldialog.h \
    audiooutputfiller.h \
    contactlist.h \
    messagingdialog.h \
    messagingtab.h \
    message.h \
    messagelog.h \
    vreg.h \
    calldialogs.h \
    asklogin.h \
    passwordchange.h \
    vcryptsettings.h
 SOURCES       = \
                 main.cpp \
    inputsender.cpp \
    outputreceiver.cpp \
    mainwindow.cpp \
    settingsdialog.cpp \
    qmainwindowtray.cpp \
    addbuddydialog.cpp \
    notifysound.cpp \
    calldialog.cpp \
    audiooutputfiller.cpp \
    contactlist.cpp \
    messagingdialog.cpp \
    messagingtab.cpp \
    message.cpp \
    messagelog.cpp \
    vreg.cpp \
    calldialogs.cpp \
    asklogin.cpp \
    passwordchange.cpp \
    vcryptsettings.cpp

QT           +=  gui
CONFIG += mobility
MOBILITY = multimedia

#INCLUDEPATH += /usr/include/QtMobility
#INCLUDEPATH += /usr/include/QtMultimediaKit
INCLUDEPATH += ../opus-1.1/installed/include/
#INCLUDEPATH += ../server/
INCLUDEPATH += ../vcrypt_libclient/
INCLUDEPATH += ../polarssl-1.2.8/include

android: {
LIBS += ../vcrypt_libclient/ndk/obj/local/armeabi/libvcrypt_libclient.a
LIBS += -lm ../ndk-opus-codec/obj/local/armeabi/libopus-static.a
LIBS += -lm ../polarssl-1.2.8/ndk/obj/local/armeabi/libpolarssl.a
}

!android {
LIBS += ../vcrypt_libclient/Debug/libvcrypt_libclient.a
LIBS += -lm ../opus-1.1/installed/lib/libopus.a
LIBS += ../polarssl-1.2.8/library/libpolarssl.a

PRE_TARGETDEPS += ../vcrypt_libclient/Debug/libvcrypt_libclient.a
PRE_TARGETDEPS += ../opus-1.1/installed/lib/libopus.a
PRE_TARGETDEPS += ../polarssl-1.2.8/library/libpolarssl.a

DEPENDPATH += ../vcrypt_libclient/
DEPENDPATH += ../polarssl-1.2.8/include
}

win32: {
LIBS += -lpthread -lws2_32
lessThan(QT_MAJOR_VERSION, 5): QT += multimedia
}

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets multimedia gui

lessThan(QT_MAJOR_VERSION, 5): {
QT += phonon
DEFINES += __PHONON__
}


 # install
 target.path = $$[QT_INSTALL_EXAMPLES]/multimedia/audiooutput
 sources.files = $$SOURCES *.h $$RESOURCES $$FORMS audiooutput.pro
 sources.path = $$[QT_INSTALL_EXAMPLES]/multimedia/audiooutput
 INSTALLS += target sources

FORMS += \
    callform.ui \
    mainwindow.ui \
    settingsdialog.ui \
    addbuddydialog.ui \
    calldialog.ui \
    messagingdialog.ui \
    asklogin.ui \
    passwordchange.ui

RESOURCES += \
    resources.qrc
