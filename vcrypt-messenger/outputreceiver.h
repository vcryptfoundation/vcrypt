#ifndef OUTPUTRECEIVER_H
#define OUTPUTRECEIVER_H

#include <QIODevice>
#include <QQueue>
#include <QMutex>
#include "fifo.h"

class OutputReceiver : public QIODevice
{
    Q_OBJECT
public:
    explicit OutputReceiver(FIFO *fifo);
    ~OutputReceiver();
    qint64 readData(char *data, qint64 maxlen);
    qint64 writeData(const char *data, qint64 len);
    qint64 bytesAvailable() const;
    void start();
    void stop();
    FIFO* fifo;
    
signals:

private:

    
public slots:
    
};

#endif // OUTPUTRECEIVER_H
