#ifndef NOTIFYSOUND_H
#define NOTIFYSOUND_H


#include <QSound>
#if __PHONON__
#include <phonon/phonon>
#endif

class NotifySound : public QObject
{
    Q_OBJECT
public:
    NotifySound();
    void start(QString stop, bool loop=false);
    void stop();

    static const QString soundRinger;
    static const QString soundCallInProgress;
    static const QString soundHangUp;
    static const QString soundMessageIn;
private:
#if __PHONON__
    Phonon::MediaObject *currentSound;
#endif

private slots:
    void aboutToFinish1();
};

#endif // NOTIFYSOUND_H
