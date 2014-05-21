#include <QDebug>
#include <QAudioOutput>
#include <QAudioInput>
#include <assert.h>

#include "calldialog.h"
#include "ui_calldialog.h"
#include "inputsender.h"
#include "profiler.h"
#include "audiooutputfiller.h"
#include "vreg.h"
#include "call.h"

CallDialog::CallDialog(QString buddy) :
    QMainWindow(),
    ui(new Ui::CallDialog)
  , m_audioOutput (0)
  , m_audioInput (0)
  , input_sender (0)
  , output_receiver(0)
  , audio_input_filler(0)
  , audio_initialized(false)
{
    setAttribute(Qt::WA_DeleteOnClose);
    ui->setupUi(this);
    show();
    restoreGeometry(Vreg::settings()->value("call_geometry").toByteArray());

    this->buddy = buddy;
    ui->callBuddy->setText(buddy);
}

CallDialog::~CallDialog()
{
    delete ui;
    //stopAudio();
}

void CallDialog::callStatusChanged(int status, int reason)
{
    QString add;
    add.append(vcrypt_get_error(status));
    add.append("; ");
    add.append(vcrypt_get_error(reason));
    ui->status->addItem(add);
    ui->status->scrollToBottom();

    if (reason != 0 || status == -ERR_CALL_HANGUP) {
        if (status == -ERR_CALL_HANGUP)
            Vreg::notifySound()->start(NotifySound::soundHangUp, 0);
    } else {
        switch(status) {
        case -ERR_CALL_SENT:
            Vreg::notifySound()->start(NotifySound::soundCallInProgress, 1);
            break;
        case -ERR_CALL_RECEIVED:
            Vreg::notifySound()->start(NotifySound::soundRinger, 1);
            break;
        case -ERR_CALL_ANSWERED:
            Vreg::notifySound()->stop();
            break;
        }
    }
}

void CallDialog::closeEvent(QCloseEvent *event)
{
    Q_UNUSED(event);
    Vreg::settings()->setValue("call_geometry", saveGeometry());
    emit wndClosed(buddy);
}


void CallDialog::reject()
{
    close();
}

void CallDialog::startAudio()
{
//    QAudioFormat m_format;

//    QString device_in = Vreg::settings()->value("audioinput").toString();
//    QString device_out = Vreg::settings()->value("audiooutput").toString();

//    m_format.setSampleRate(48000);
//    m_format.setChannelCount(1);
//    m_format.setSampleSize(16);
//    m_format.setCodec("audio/pcm");
//    m_format.setByteOrder(QAudioFormat::LittleEndian);
//    m_format.setSampleType(QAudioFormat::SignedInt);

//    QAudioDeviceInfo outputDevInfo = findDevice(QAudio::AudioOutput, device_out);

//    if (!outputDevInfo.isFormatSupported(m_format)) {
//        m_format = outputDevInfo.nearestFormat(m_format);
//        qWarning() << "Default format not supported - trying to use nearest";
//    }

//    qDebug() << "using samplerate: " << m_format.sampleRate() << m_format.sampleSize();

//    assert (outputDevInfo.isFormatSupported(m_format));

//    m_audioOutput = new QAudioOutput(outputDevInfo, m_format);
//    //m_audioInput = new QAudioInput(findDevice(QAudio::AudioInput, device_in), m_format);

//    m_audioOutput->setBufferSize(Vreg::vcrypt()->call_ctx.audio_ctx.packet_frames_play * 2 * 2); // TODO: check this

//    if (callType == call_test) {
//        m_output = m_audioOutput->start();
//        m_audioInput->start(m_output);
//        qDebug() << "sample rate: " << m_audioOutput->format().sampleRate();
//    } else {
//        input_sender = new InputSender(this);
//        input_sender->start();
//        m_audioInput->start(input_sender);

//        //        output_receiver = new OutputReceiver(vcrypt->audio_fifo_receive);
//        //        output_receiver->start();
//        //        m_audioOutput->start(output_receiver);
//        //m_audioOutput->suspend();

//        //m_output = m_audioOutput->start();

//        m_output = m_audioOutput->start();
//        //audio_input_filler = new AudioOutputFiller(m_output, m_audioOutput, Vreg::vcrypt()->audio_fifo_receive);
//        //audio_input_filler->start();
//    }

//    qDebug() << "recommended write bytes is: " << m_audioOutput->periodSize()
//             << "but we writing: " << m_format.sampleRate() * packet_duration * m_format.channelCount() * 2
//             << "real buffer size is: " << m_audioOutput->bufferSize();

//    audio_initialized = true;
}


QString CallDialog::getBuddy() const
{
    return buddy;
}

void CallDialog::on_buttonCall_released()
{
    vcrypt_call(Vreg::vcrypt(), (const char*)this->buddy.toLocal8Bit().data());
}

void CallDialog::on_buttonHangUp_released()
{
    vcrypt_call_hangup(Vreg::vcrypt(), this->buddy.toLocal8Bit().data());
}

void CallDialog::on_buttonAnswer_released()
{
    vcrypt_call_accept(Vreg::vcrypt(), this->buddy.toLocal8Bit().data(), 0);
}

void CallDialog::on_buttonReject_released()
{
    vcrypt_call_accept(Vreg::vcrypt(), this->buddy.toLocal8Bit().data(), 1);
}
