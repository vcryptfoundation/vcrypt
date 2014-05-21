#include "notifysound.h"
#include "settingsdialog.h"
#include <QDebug>

const QString NotifySound::soundRinger = ":/resources/CallRingingIn.wav";
const QString NotifySound::soundCallInProgress = ":/resources/CallRingingOut.wav";
const QString NotifySound::soundHangUp = ":/resources/CallHangup.wav";
const QString NotifySound::soundMessageIn = ":/resources/ChatIncomingInitial.wav";

NotifySound::NotifySound()
{
#if __PHONON__
    currentSound = NULL;
#endif
}

void NotifySound::start(QString sound, bool loop)
{
#if __PHONON__
    if (currentSound != NULL) {
        if (currentSound->state() == Phonon::PlayingState) {
            currentSound->stop();
        }

        delete currentSound;
        currentSound = NULL;
    }

    currentSound = Phonon::createPlayer(Phonon::MusicCategory, Phonon::MediaSource(sound));

    if (loop)
        connect(currentSound, SIGNAL(aboutToFinish()), this, SLOT(aboutToFinish1()));

    currentSound->play();
#endif
}

void NotifySound::aboutToFinish1()
{
#if __PHONON__
    currentSound->enqueue(currentSound->currentSource());
#endif
}

void NotifySound::stop()
{
#if __PHONON__
    if (currentSound == NULL)
        return;

    currentSound->stop();
    delete currentSound;
    currentSound = NULL;
#endif
}

