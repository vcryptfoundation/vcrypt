#ifndef AUDIOOUTPUTFILLER_H
#define AUDIOOUTPUTFILLER_H

#include <QThread>
#include <QIODevice>
#include <QAudioOutput>
#include "fifo.h"

class AudioOutputFiller : public QThread
{
    Q_OBJECT
public:
    explicit AudioOutputFiller(QIODevice *output, QAudioOutput *audio_output, FIFO *fifo);
    void stop();
signals:
    
public slots:

private:
    QIODevice *output;
    QAudioOutput *audio_output;
    FIFO *fifo;
    int running;
    void run();
};

#endif // AUDIOOUTPUTFILLER_H
