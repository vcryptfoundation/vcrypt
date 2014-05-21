#include <QDebug>
#include "inputsender.h"
#include <assert.h>
#include "client.h"
#include "vreg.h"

InputSender::InputSender(QObject *parent, int send_bytes) :
    QIODevice(parent)
  , send_bytes(send_bytes)
{
    fifo = fifo_new(send_bytes * 3);
}

InputSender::~InputSender()
{
    fifo_close(fifo);
}

qint64 InputSender::readData(char *data, qint64 len)
{
    Q_UNUSED(data);
    Q_UNUSED(len);
    return 0;
}

qint64 InputSender::writeData(const char *data, qint64 len)
{
    fifo_write(fifo, data, len);
    char buff[send_bytes];

    while (fifo_bytes_available(fifo) >= send_bytes) {
        fifo_read(fifo, buff, send_bytes);
        int ret = vcrypt_queue_audio(Vreg::vcrypt(), buff, send_bytes);
        if (ret < 0)
            qDebug() << "error sending audio: "  << vcrypt_get_error(ret);
    }

    return len;
}

void InputSender::start()
{
    open(QIODevice::WriteOnly);
}

void InputSender::stop()
{
    close();
}

qint64 InputSender::bytesAvailable() const
{
    assert(false && "ERROR: bytesAvailable called");
    return 0;
}
