#include "outputreceiver.h"
#include <QDebug>
#include <qmath.h>
#include <QtCore/qendian.h>
#include <assert.h>

OutputReceiver::OutputReceiver(FIFO *fifo) :
    QIODevice()
{
    this->fifo = fifo;
}

OutputReceiver::~OutputReceiver()
{
}

void OutputReceiver::start()
{
    open(QIODevice::ReadOnly);
}

void OutputReceiver::stop()
{
    close();
}

qint64 OutputReceiver::readData(char *data, qint64 len)
{
    if (len > 1024)
        len = 1024;

    if (fifo_bytes_available(fifo) >= len) {
        return fifo_read(fifo, data, len);
    } else {
        memset(data, 0, len);
        return len;
    }
}

qint64 OutputReceiver::writeData(const char *data, qint64 len)
{
    Q_UNUSED(data);
    Q_UNUSED(len);
    return 0;
}

qint64 OutputReceiver::bytesAvailable() const
{
    qDebug() << "bytes available called";
    return 0;
}

