#include "calldialogs.h"
#include "vreg.h"
#include <assert.h>

void callback_call_status_change(const char *username, int status, int reason)
{
    QString q_username = username;
    QMetaObject::invokeMethod(Vreg::callDialogs(), "cbCallStatusChanged", Qt::QueuedConnection,
                                  Q_ARG(QString, q_username), Q_ARG(int, status), Q_ARG(int, reason));

//    dolog(D_CALLBACK, "CALLBACK: Call status for %s changed to: %s / %s\n",
//            username, vcrypt_get_error(status), vcrypt_get_error(reason));

//    if (status == -ERR_CALL_HANGUP) {
//        audio_sending = 2; // initiate end

//        if (f_audiorec) {
//            fclose(f_audiorec);
//            f_audiorec = NULL;
//        }

//        alsa_close(alsa_play);
//        alsa_play = NULL;
//    }
}

int callback_start_audio_sending()
{
    QMetaObject::invokeMethod(Vreg::callDialogs(), "cbStartAudio", Qt::QueuedConnection);
    return 0;
}

void callback_audio(char *data, int data_size)
{
    Vreg::callDialogs()->cbReceiveAudio(data, data_size);
}

CallDialogs::CallDialogs() :
    QObject()
  , m_audioOutput(0)
  , m_audioInput(0)
  , m_output(0)
{
    Vreg::vcrypt()->callback_call_status_change = callback_call_status_change;
    Vreg::vcrypt()->callback_start_audio_sending = callback_start_audio_sending;
    Vreg::vcrypt()->callback_audio = callback_audio;
    callDialogs.clear();
}

QAudioDeviceInfo CallDialogs::findDevice(QAudio::Mode mode, QString name)
{
    if (name != "default") {
        foreach (const QAudioDeviceInfo &deviceInfo, QAudioDeviceInfo::availableDevices(mode))
            if (deviceInfo.deviceName() == name)
                return deviceInfo;

        qDebug() << "Coudln't find the device" << name << "using default";
    }

    return mode == QAudio::AudioInput ? QAudioDeviceInfo::defaultInputDevice() : QAudioDeviceInfo::defaultOutputDevice();
}

void CallDialogs::cbReceiveAudio(char *data, int data_size)
{
    if (m_output && m_output->isOpen()) {
        qint64 r = m_output->write(data, data_size);
        if (r != data_size)
            qDebug() << "AUDIO OUTPUT: tried" << data_size << r;
    }
}

int CallDialogs::cbStartAudio()
{
    QAudioFormat m_format;
    m_format.setSampleRate(24000);
    m_format.setChannelCount(VCRYPT_AUDIO_CHANNELS);
    m_format.setSampleSize(16);
    m_format.setCodec("audio/pcm");
    m_format.setByteOrder(QAudioFormat::LittleEndian);
    m_format.setSampleType(QAudioFormat::SignedInt);

    // TODO: check input supported format
    QAudioDeviceInfo outputDevInfo = findDevice(QAudio::AudioOutput, Vreg::settings()->value("audiooutput").toString());

    if (!outputDevInfo.isFormatSupported(m_format)) {
        m_format = outputDevInfo.nearestFormat(m_format);
        qWarning() << "Default format not supported - trying to use nearest";
    }

    qDebug() << "using samplerate: " << m_format.sampleRate() << m_format.sampleSize();
    assert (outputDevInfo.isFormatSupported(m_format));

    // TODO: change thsi function to use vcrypt context
    int ret = audio_ctx_init(&Vreg::vcrypt()->call_ctx.audio_ctx, m_format.sampleRate(),
                             m_format.sampleRate());
    if (ret)
        return ret;

    m_audioOutput = new QAudioOutput(outputDevInfo, m_format);
    int bsmsec = 1000.0 * Vreg::vcrypt()->call_ctx.audio_ctx.packet_frames_play / m_format.sampleRate() * 2;
    qDebug() << "will use buff of " << bsmsec << "msec";
    m_audioOutput->setBufferSize(bsmsec);
    m_output = m_audioOutput->start();

    m_audioInput = new QAudioInput(findDevice(QAudio::AudioInput, Vreg::settings()->value("audioinput").toString()), m_format);

    input_sender = new InputSender(this, Vreg::vcrypt()->call_ctx.audio_ctx.packet_frames_rec * sizeof(qint16) * VCRYPT_AUDIO_CHANNELS);
    input_sender->start();
    m_audioInput->start(input_sender);

    return 0;
}

void CallDialogs::cbCallStatusChanged(QString username, int status, int reason)
{
    CallDialog *cd = this->showDialog(username);
    assert(cd);
    cd->callStatusChanged(status, reason);

    if (status == -ERR_CALL_HANGUP) {
       stopAudio();
    }
}

int CallDialogs::findDialog(QString buddy)
{
    for(int i=0; i<callDialogs.count(); i++) {
        if (callDialogs.at(i)->getBuddy() == buddy)
            return i;
    }

    return -1;
}

void CallDialogs::removeDialog(QString buddy)
{
    int i = findDialog(buddy);
    if (i>= 0)
        callDialogs.removeAt(i);
}

CallDialog* CallDialogs::showDialog(QString buddy)
{
    CallDialog *cd;

    int i = findDialog(buddy);

    if (i >= 0) {
        cd = callDialogs.at(i);
    } else {
        cd = new CallDialog(buddy);
        connect(cd, SIGNAL(wndClosed(QString)), this, SLOT(removeDialog(QString)));
        callDialogs << cd;
    }

    cd->activateWindow();
    return cd;
}

void CallDialogs::stopAudio()
{
//    if (audio_input_filler) {
//        audio_input_filler->stop();
//        delete audio_input_filler;
//        audio_input_filler = NULL;
//    }

    if (m_audioInput)
    {
        m_audioInput->stop();
        delete m_audioInput;
        m_audioInput = 0;
    }

    if (m_audioOutput)
    {
        m_audioOutput->stop();
        delete m_audioOutput;
        m_audioOutput = 0;

        // this is just a pointer
        m_output = 0;
    }

    if (input_sender)
    {
        input_sender->stop();
        delete input_sender;
        input_sender = 0;
    }

//    if (output_receiver)
//    {
//        output_receiver->stop();
//        delete output_receiver;
//        output_receiver = 0;
//    }
}
