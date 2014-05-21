#include "callform.h"
#include "inputsender.h"
#include "ui_callform.h"
#include <QDebug>
#include <QSystemTrayIcon>
#include <QMessageBox>
#include "client.h"


//CallForm *formobj = NULL;
/* CALLBACK PROXY FUNCTIONS */
//void callback_notify_error(int reason)
//{
//    QMetaObject::invokeMethod(formobj, "vcryptSetError", Qt::QueuedConnection, Q_ARG(int, reason));
//    if (reason == -ERR_CALL_STARTED)
//        QMetaObject::invokeMethod(formobj, "startAudio", Qt::QueuedConnection);
//}

//void callback_ringer(char *username)
//{
//    QMetaObject::invokeMethod(formobj, "RingerControl", Qt::QueuedConnection, Q_ARG(char*, username));
//}

//void callback_call_wait(char *username)
//{
//    QMetaObject::invokeMethod(formobj, "AnswerWaitNotifierControl", Qt::QueuedConnection, Q_ARG(char*, username));
//}

//void callback_call_close()
//{
//    QMetaObject::invokeMethod(formobj, "closeCall", Qt::QueuedConnection);
//}

//void callback_call_open()
//{
//    QMetaObject::invokeMethod(formobj, "openCall", Qt::QueuedConnection);
//}

//void callback_audio(char *data, int size)
//{
//    formobj->receiveAudio(data, size);
//}

CallForm::CallForm(QWidget *parent)
    : QWidget(parent)
    , ui(new Ui::CallForm)
    , m_audioOutput (0)
    , m_audioInput (0)
    , input_sender (0)
    , output_receiver(0)
    , ringTimer(new QTimer(this))
    , vcrypt(0)
{
    ui->setupUi(this);
//    formobj = this;

    vcrypt = vcrypt_create();
    // TODO: check the outcome

    qRegisterMetaType<char*>("char*");

    //vcrypt->callback_notify_error = callback_notify_error;
//    vcrypt->callback_call_ring = callback_ringer;
//    vcrypt->callback_call_wait_answer = callback_call_wait;
//    vcrypt->callback_call_close = callback_call_close;
//    vcrypt->callback_call_open = callback_call_open;
//    vcrypt->callback_audio = callback_audio;

    foreach (const QAudioDeviceInfo &deviceInfo, QAudioDeviceInfo::availableDevices(QAudio::AudioInput))
        ui->m_rec_device_Box->addItem(deviceInfo.deviceName(), qVariantFromValue(deviceInfo));

    foreach (const QAudioDeviceInfo &deviceInfo, QAudioDeviceInfo::availableDevices(QAudio::AudioOutput))
        ui->m_play_device_Box->addItem(deviceInfo.deviceName(), qVariantFromValue(deviceInfo));

    m_format.setSampleRate(16000);
    m_format.setChannelCount(1);
    m_format.setSampleSize(16);
    m_format.setCodec("audio/pcm");
    m_format.setByteOrder(QAudioFormat::LittleEndian);
    m_format.setSampleType(QAudioFormat::UnSignedInt);

    //vcrypt_codec_setup(vcrypt, m_format.sampleRate(), m_format.sampleRate()/50);

    QAudioDeviceInfo info(QAudioDeviceInfo::defaultOutputDevice());
    if (!info.isFormatSupported(m_format)) {
        qWarning() << "Default format not supported - trying to use nearest";
        m_format = info.nearestFormat(m_format);
    }

    connect(
        ui->logWidget->model(),
        SIGNAL(rowsInserted ( const QModelIndex &, int, int ) ),
        ui->logWidget,
        SLOT(scrollToBottom ())
    );

    connect(ringTimer, SIGNAL(timeout()), SLOT(RingerFlash()));

    ui->btnAnswer->setEnabled(false);
    ui->btnReject->setEnabled(false);

    setWindowTitle("Vcrypt");
}


CallForm::~CallForm()
{
    vcrypt_close(vcrypt);
    delete ui;
}

void CallForm::startAudio()
{
    m_play_device = ui->m_play_device_Box->itemData(ui->m_play_device_Box->currentIndex()).value<QAudioDeviceInfo>();
    m_rec_device = ui->m_rec_device_Box->itemData(ui->m_rec_device_Box->currentIndex()).value<QAudioDeviceInfo>();

    m_audioOutput = new QAudioOutput(m_play_device, m_format, this);
    m_audioInput = new QAudioInput(m_rec_device, m_format, this);
    input_sender = new InputSender(this, this->vcrypt);
    input_sender->start();
    m_audioInput->start(input_sender);

    //output_receiver = new OutputReceiver(this);
    //output_receiver->start();
    m_output = m_audioOutput->start();
}

void CallForm::receiveAudio(char *data, int size)
{
    if (m_output)
        m_output->write(data, size);
}

void CallForm::stopAudio()
{
    if (m_audioOutput)
    {
        delete m_audioOutput;
        m_audioOutput = 0;
        m_output = 0;
    }

    if (m_audioInput)
    {
        delete m_audioInput;
        m_audioInput = 0;
    }

    if (input_sender)
    {
        delete input_sender;
        input_sender = 0;
    }

    if (output_receiver)
    {
        delete output_receiver;
        output_receiver = 0;
    }
}

void CallForm::enableServerSettings(bool enabled)
{
    ui->server_addr->setEnabled(enabled);
    ui->server_port->setEnabled(enabled);
    ui->username->setEnabled(enabled);
    ui->password->setEnabled(enabled);
}

void CallForm::RingerFlash()
{
    static int ishighlighted;
    if (ishighlighted)
    {
        ui->callerInfo->setStyleSheet("QLineEdit{background: white;}");
        ishighlighted = 0;
    }
    else
    {
        ui->callerInfo->setStyleSheet("QLineEdit{background: red;}");
        ishighlighted = 1;
    }
}

void CallForm::closeCall()
{
    stopAudio();
    ui->callButton_2->setText("Call");
}

void CallForm::openCall()
{
    ui->callButton_2->setText("Hang-up");
}

void CallForm::AnswerWaitNotifierControl(char *username)
{
    if (username)
    {
        QString temp;
        temp.sprintf("Wating for answer from user '%s'", username);
        ui->callerInfo->setText(username);
        ui->logWidget->addItem(temp);
        ringTimer->start(500);
    }
    else
    {
        ringTimer->stop();
        ui->callerInfo->setText("");
        ui->callerInfo->setStyleSheet("QLineEdit{background: white;}");
    }
}

void CallForm::RingerControl(char *username)
{
    if (username)
    {
        QString temp;
        temp.sprintf("User '%s' is calling", username);
        ui->callerInfo->setText(username);
        ui->logWidget->addItem(temp);
        ringTimer->start(500);
        ui->btnAnswer->setEnabled(true);
        ui->btnReject->setEnabled(true);
    }
    else
    {
        ringTimer->stop();
        ui->callerInfo->setText("");
        ui->callerInfo->setStyleSheet("QLineEdit{background: white;}");
        ui->btnAnswer->setEnabled(false);
        ui->btnReject->setEnabled(false);
    }
}

void CallForm::vcryptSetError(int reason)
{
    if (!vcrypt_is_connected(vcrypt))
         vcryptDisconnect();

//    if (reason  != -ERR_SUCCESS &&
//            reason != -ERR_MSG_QUEUED)
//        ui->callButton_2->setText("Call");

    //ui->status->setText(vcrypt_get_error(reason));
    ui->logWidget->addItem(vcrypt_get_error(reason));

    if (reason == -ERR_REGISTER_AUTH_FAILURE)
        ui->password->setText(ui->username->text());

    if (reason == -ERR_REGISTER_ALREADY_LOGGED)
    {
        ui->username->setText("user0002");
        ui->password->setText(ui->username->text());
    }

    if (ui->username->text() == "user0001")
        ui->calee->setText("user0002");
    else
        ui->calee->setText("user0001");
}

void CallForm::vcryptDisconnect()
{
    ui->connectButton->setText("Connect");
    enableServerSettings(true);
}

void CallForm::on_connectButton_released()
{
    //static int i;
    if (!vcrypt_is_connected(vcrypt))
    {
        ui->connectButton->setEnabled(false);
        qApp->processEvents();
        enableServerSettings(false);
        qApp->processEvents();

        QByteArray address = ui->server_addr->text().toLocal8Bit();
        QByteArray username = ui->username->text().toLocal8Bit();
        QByteArray password = ui->password->text().toLocal8Bit();

        int res = vcrypt_connect_auth( vcrypt,
                        address.data(), ui->server_port->text().toInt(),
                        username.data(), password.data());

        //qDebug() << i++ << " ------------------------------ " << res;

        if (res == ERR_SUCCESS)
        {
            ui->connectButton->setText("Disconnect");
            ui->logWidget->addItem("SUCCESS: Connection established");
        }
        else
        {
            vcrypt_close(vcrypt);
            vcryptSetError(res);
        }

        ui->connectButton->setEnabled(true);
    }
    else
    {
        vcrypt_close(vcrypt);
        vcryptSetError(ERR_SUCCESS);
    }
}

void CallForm::on_callButton_2_released()
{
    if (!vcrypt_call_inprogress(vcrypt))
    {
        QByteArray calee = ui->calee->text().toLocal8Bit();
        int res = vcrypt_call(vcrypt, calee.data());
        ui->logWidget->addItem(vcrypt_get_error(res));
    }
    else
    {
        int res = vcrypt_caller_call_hangup(vcrypt);
        ui->logWidget->addItem(vcrypt_get_error(res));
    }
}

void CallForm::on_pingBtn_released()
{
    int res = vcrypt_ping_server(vcrypt);
    ui->logWidget->addItem(vcrypt_get_error(res));
}

void CallForm::on_pingClient_released()
{
    QByteArray calee = ui->calee->text().toLocal8Bit();
    int res = vcrypt_ping_client(vcrypt, calee.data());
    ui->logWidget->addItem(vcrypt_get_error(res));
}

void CallForm::on_btnAnswer_released()
{
    vcrypt_call_accept(vcrypt, 0);
}

void CallForm::on_btnReject_released()
{
    vcrypt_call_accept(vcrypt, 1);
}


