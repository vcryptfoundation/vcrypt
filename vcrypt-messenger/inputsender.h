#ifndef INPUTSENDER_H
#define INPUTSENDER_H

#include <QIODevice>
#include "client.h"
#include "fifo.h"


class InputSender : public QIODevice
{
    Q_OBJECT
private:
    int send_bytes;
    FIFO* fifo;
public:
    explicit InputSender(QObject *parent, int send_bytes);
     ~InputSender();
    qint64 readData(char *data, qint64 maxlen);
    qint64 writeData(const char *data, qint64 len);
    qint64 bytesAvailable() const;
    void start();
    void stop();
    
signals:
    
public slots:
    
};

#endif // INPUTSENDER_H
