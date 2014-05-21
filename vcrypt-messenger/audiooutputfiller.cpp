#include "audiooutputfiller.h"
#include <qmath.h>
#include <QDebug>

AudioOutputFiller::AudioOutputFiller(QIODevice *output, QAudioOutput *audio_output, FIFO *fifo) :
    QThread()
{
    this->output = output;
    this->audio_output = audio_output;
    this->fifo = fifo;
}

void AudioOutputFiller::run()
{
    int size = 256;
    char data[size];

    running = 1;

    while(running) {
        if (fifo_bytes_available(fifo) < size) {
            usleep(10000);
            continue;
        }

        if (audio_output->bytesFree() < size) {
            usleep(10000);
            continue;
        }

        fifo_read(fifo, data, size);

        int res = output->write(data, size);

        if (res != size) {
            qDebug() << "write size mismatch! " << size << res;
        }
    }
}

void AudioOutputFiller::stop()
{
    running = 0;
    wait();
}
