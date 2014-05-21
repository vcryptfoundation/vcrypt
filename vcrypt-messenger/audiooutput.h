
#ifndef AUDIOOUTPUT_H
#define AUDIOOUTPUT_H


#include <QObject>
#include <QMainWindow>

#include <QTimer>
#include <QPushButton>
#include <QComboBox>
#include <QByteArray>

#include <QIODevice>
#include <QAudioOutput>
#include <QAudioInput>
#include <QUdpSocket>

#include "generator.h"
#include "inputsender.h"

class AudioTest : public QMainWindow
{
    Q_OBJECT
public:
    AudioTest();
    ~AudioTest();




private:
    void initializeWindow();
    void initializeAudio();
    void createAudioOutput();
    void createAudioInput();
     void DeviceChanged();

private:
    QTimer*          m_pullTimer;

    // Owned by layout
    QPushButton*     m_play_modeButton;
    QPushButton*     m_play_suspendResumeButton;
    QComboBox*       m_play_device_Box;
    QComboBox*       m_rec_device_Box;

    QAudioDeviceInfo m_play_device;
    QAudioDeviceInfo m_rec_device;
    Generator*       m_generator;
    QAudioOutput*    m_audioOutput;
    QAudioInput*     m_audioInput;
    QIODevice*       m_output; // not owned
    QIODevice*       m_input; // not owned
    QAudioFormat     m_format;

    bool             m_pullMode;
    QByteArray       m_buffer;
    InputSender *input_sender;

    static const QString PushModeLabel;
    static const QString PullModeLabel;
    static const QString SuspendLabel;
    static const QString ResumeLabel;

private slots:
    void notified();
    void pullTimerExpired();
    void toggleMode();
    void toggleSuspendResume();
    //void play_stateChanged(QAudio::State state);
    void playDeviceChanged(int index);
    void rec_stateChanged(QAudio::State state);
    void recDeviceChanged(int index);
    //void readPendingDatagrams();
};

#endif
