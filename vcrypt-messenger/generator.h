#ifndef GENERATOR_H
#define GENERATOR_H

#include <QObject>
#include <QIODevice>
#include <QAudioOutput>
#include <QAudioInput>
#include <math.h>
#include <QtCore/qmath.h>
#include <QtCore/qendian.h>


class Generator : public QIODevice
{
    Q_OBJECT
public:
    Generator(const QAudioFormat &format, qint64 durationUs, int frequency, QObject *parent);
    ~Generator();

    void start();
    void stop();

    qint64 readData(char *data, qint64 maxlen);
    qint64 writeData(const char *data, qint64 len);
    qint64 bytesAvailable() const;

private:
    void generateData(const QAudioFormat &format, qint64 durationUs, int frequency);

private:
    qint64 m_pos;
    QByteArray m_buffer;
};

#endif // GENERATOR_H
