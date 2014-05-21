#include <QDebug>
#include <QVBoxLayout>

#include <QAudioOutput>
#include <QAudioInput>
#include <QAudioDeviceInfo>
#include <QtCore/qmath.h>
#include <QtCore/qendian.h>
#include <QUdpSocket>
#include "audiooutput.h"
#include "generator.h"
#include "inputsender.h"

const QString AudioTest::PushModeLabel(tr("Enable push mode"));
const QString AudioTest::PullModeLabel(tr("Enable pull mode"));
const QString AudioTest::SuspendLabel(tr("Suspend playback"));
const QString AudioTest::ResumeLabel(tr("Resume playback"));

const int DurationSeconds = 100;
const int ToneFrequencyHz = 440;
const int DataFrequencyHz = 8000;
const int BufferSize      = 32768;

AudioTest::AudioTest()
    :   m_pullTimer(new QTimer(this))
    ,   m_play_modeButton(0)
    ,   m_play_suspendResumeButton(0)
    ,   m_play_device_Box(0)
    ,   m_rec_device_Box(0)
    ,   m_play_device(QAudioDeviceInfo::defaultOutputDevice())
    ,   m_rec_device(QAudioDeviceInfo::defaultInputDevice())
    ,   m_generator(0)
    ,   m_audioOutput(0)
    ,   m_audioInput(0)
    ,   m_output(0)
    ,   m_input(0)
    ,   m_buffer(BufferSize, 0)
{
    initializeWindow();

    initializeAudio();
}

void AudioTest::initializeWindow()
{
    QScopedPointer<QWidget> window(new QWidget);
    QScopedPointer<QVBoxLayout> layout(new QVBoxLayout);

    m_rec_device_Box = new QComboBox(this);
    foreach (const QAudioDeviceInfo &deviceInfo, QAudioDeviceInfo::availableDevices(QAudio::AudioInput))
        m_rec_device_Box->addItem(deviceInfo.deviceName(), qVariantFromValue(deviceInfo));
    connect(m_rec_device_Box,SIGNAL(activated(int)),SLOT(recDeviceChanged(int)));
    layout->addWidget(m_rec_device_Box);

    m_play_device_Box = new QComboBox(this);
    foreach (const QAudioDeviceInfo &deviceInfo, QAudioDeviceInfo::availableDevices(QAudio::AudioOutput))
        m_play_device_Box->addItem(deviceInfo.deviceName(), qVariantFromValue(deviceInfo));
    connect(m_play_device_Box,SIGNAL(activated(int)),SLOT(playDeviceChanged(int)));
    layout->addWidget(m_play_device_Box);

    m_play_modeButton = new QPushButton(this);
    m_play_modeButton->setText(PushModeLabel);
    connect(m_play_modeButton, SIGNAL(clicked()), SLOT(toggleMode()));
    layout->addWidget(m_play_modeButton);

    m_play_suspendResumeButton = new QPushButton(this);
    m_play_suspendResumeButton->setText(SuspendLabel);
    connect(m_play_suspendResumeButton, SIGNAL(clicked()), SLOT(toggleSuspendResume()));
    layout->addWidget(m_play_suspendResumeButton);

    window->setLayout(layout.data());
    layout.take(); // ownership transferred

    setCentralWidget(window.data());
    QWidget *const windowPtr = window.take(); // ownership transferred
    windowPtr->show();
}

void AudioTest::initializeAudio()
{
    connect(m_pullTimer, SIGNAL(timeout()), SLOT(pullTimerExpired()));

    m_pullMode = true;

    m_format.setSampleRate(DataFrequencyHz);
    m_format.setChannelCount(1);
    m_format.setSampleSize(8);
    m_format.setCodec("audio/pcm");
    m_format.setByteOrder(QAudioFormat::LittleEndian);
    m_format.setSampleType(QAudioFormat::UnSignedInt);

    QAudioDeviceInfo info(QAudioDeviceInfo::defaultOutputDevice());
    if (!info.isFormatSupported(m_format)) {
        qWarning() << "Default format not supported - trying to use nearest";
        m_format = info.nearestFormat(m_format);
    }

    m_generator = new Generator(m_format, DurationSeconds*1000000, ToneFrequencyHz, this);
    //input_sender = new InputSender(this, udpSocket, "127.0.0.1" , 60000);

    createAudioOutput();
    createAudioInput();
}

void AudioTest::createAudioOutput()
{
    delete m_audioOutput;
    m_audioOutput = 0;
    m_audioOutput = new QAudioOutput(m_play_device, m_format, this);
    //m_audioOutput->setBufferSize(32);
    //connect(m_audioOutput, SIGNAL(notify()), SLOT(notified()));
    //connect(m_audioOutput, SIGNAL(play_stateChanged(QAudio::State)), SLOT(play_stateChanged(QAudio::State)));

    //m_generator->start();
    //m_audioOutput->start(m_generator);
}

void AudioTest::createAudioInput()
{
    delete m_audioInput;
    m_audioInput = 0;
    m_audioInput = new QAudioInput(m_rec_device, m_format, this);
    //m_audioInput->setBufferSize();
    input_sender->start();
    m_audioInput->start(input_sender);
    //m_audioOutput->start(m_input);
}

AudioTest::~AudioTest()
{

}

void AudioTest::playDeviceChanged(int index)
{
    m_play_device = m_play_device_Box->itemData(index).value<QAudioDeviceInfo>();
    DeviceChanged();
}

void AudioTest::recDeviceChanged(int index)
{
    m_rec_device = m_rec_device_Box->itemData(index).value<QAudioDeviceInfo>();
    DeviceChanged();
}

void AudioTest::DeviceChanged()
{
//    m_pullTimer->stop();
//    m_generator->stop();
//    m_audioOutput->stop();
//    m_audioOutput->disconnect(this);
//    m_audioInput->stop();
//    m_audioInput->disconnect(this);
//    createAudioOutput();
//    createAudioInput();
}


void AudioTest::notified()
{
//    qWarning() << "bytesFree = " << m_audioOutput->bytesFree()
//               << ", " << "elapsedUSecs = " << m_audioOutput->elapsedUSecs()
//               << ", " << "processedUSecs = " << m_audioOutput->processedUSecs();
}

void AudioTest::pullTimerExpired()
{
//    if (m_audioOutput && m_audioOutput->state() != QAudio::StoppedState) {
//        int chunks = m_audioOutput->bytesFree()/m_audioOutput->periodSize();
//        while (chunks) {
//            const qint64 len = m_generator->read(m_buffer.data(), m_audioOutput->periodSize());
//            //const qint64 len = m_input->read(m_buffer.data(), m_audioOutput->periodSize());
//            if (len)
//                m_output->write(m_buffer.data(), len);
//            if (len != m_audioOutput->periodSize())
//                break;
//            --chunks;
//        }
//    }
}

void AudioTest::toggleMode()
{
    m_pullTimer->stop();
    m_audioOutput->stop();
    m_audioInput->stop();

    if (m_pullMode) {
        m_play_modeButton->setText(PullModeLabel);
        m_output = m_audioOutput->start();
        m_input = m_audioInput->start();
        m_pullMode = false;
        m_pullTimer->start(20);
        qDebug() << "push mode";
    } else {
        m_play_modeButton->setText(PushModeLabel);
        m_pullMode = true;
        qDebug() << "pull mode";
        m_audioOutput->start();
        m_audioInput->start(input_sender);
        //m_audioOutput->start(m_input);
    }

    m_play_suspendResumeButton->setText(SuspendLabel);
}

void AudioTest::toggleSuspendResume()
{
    if (m_audioOutput->state() == QAudio::SuspendedState) {
        qWarning() << "status: Suspended, resume()";
        m_audioOutput->resume();
        m_play_suspendResumeButton->setText(SuspendLabel);
    } else if (m_audioOutput->state() == QAudio::ActiveState) {
        qWarning() << "status: Active, suspend()";
        m_audioOutput->suspend();
        m_play_suspendResumeButton->setText(ResumeLabel);
    } else if (m_audioOutput->state() == QAudio::StoppedState) {
        qWarning() << "status: Stopped, resume()";
        m_audioOutput->resume();
        m_play_suspendResumeButton->setText(SuspendLabel);
    } else if (m_audioOutput->state() == QAudio::IdleState) {
        qWarning() << "status: IdleState";
    }
}

//void AudioTest::play_stateChanged(QAudio::State state)
//{
//    qWarning() << "play state = " << state;
//}

void AudioTest::rec_stateChanged(QAudio::State state)
{
    qWarning() << "rec state = " << state;
}
