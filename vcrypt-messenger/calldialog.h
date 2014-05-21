#ifndef CALLDIALOG_H
#define CALLDIALOG_H

#include <QMainWindow>
#include <QPushButton>
#include <QLineEdit>
#include <QAudioOutput>
#include <QAudioInput>
#include <QFile>
#include "audiooutputfiller.h"
#include "notifysound.h"
#include "inputsender.h"
#include "outputreceiver.h"
#include "client.h"


namespace Ui {
class CallDialog;
}

class CallDialog : public QMainWindow
{
    Q_OBJECT
    
public:
    explicit CallDialog(QString buddy);
    ~CallDialog();

    void setStatus(int status);
    void closeCall();
    void callAnswered();
    void callStatusChanged(int status, int reason);
    QString getBuddy() const;

    void callEnded(int reason);
private slots:

    void closeEvent(QCloseEvent *event);
    void reject();
    void on_buttonAnswer_released();
    void on_buttonHangUp_released();

    void on_buttonCall_released();

    void on_buttonReject_released();

private:
    Ui::CallDialog *ui;
    QString buddy;

    QAudioDeviceInfo m_play_device;
    QAudioDeviceInfo m_rec_device;
    QAudioOutput*    m_audioOutput;
    QAudioInput*     m_audioInput;
    QIODevice*       m_output; // not owned
    QIODevice*       m_input; // not owned
    InputSender *input_sender;
    OutputReceiver *output_receiver;
    AudioOutputFiller *audio_input_filler;
    bool audio_initialized;

    void startAudio();
    void stopAudio();
    QAudioDeviceInfo findDevice(QAudio::Mode type, QString name);
signals:
    void wndClosed(QString buddy);
};

#endif // CALLDIALOG_H
