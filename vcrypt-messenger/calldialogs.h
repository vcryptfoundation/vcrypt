#ifndef CALLDIALOLGS_H
#define CALLDIALOLGS_H

#include <QObject>
#include <QList>
#include "calldialog.h"

class CallDialogs : public QObject
{
    Q_OBJECT
public:
    explicit CallDialogs();
    CallDialog* showDialog(QString buddy);
    int findDialog(QString buddy);
private:
    QList<CallDialog*> callDialogs;
    QAudioDeviceInfo findDevice(QAudio::Mode mode, QString name);
    QAudioOutput*    m_audioOutput;
    QAudioInput*     m_audioInput;
    QIODevice*       m_output;
    InputSender *input_sender;

    void stopAudio();
signals:
    
public slots:
    void cbCallStatusChanged(QString username, int status, int reason);
    int cbStartAudio();
    void cbReceiveAudio(char *data, int data_size);
private slots:
    void removeDialog(QString buddy);
    
};

#endif // CALLDIALOLGS_H
