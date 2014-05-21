#ifndef MESSAGELOG_H
#define MESSAGELOG_H

#include <QPlainTextEdit>
#include "message.h"

class MessageLog : private QPlainTextEdit
{
public:
    explicit MessageLog(QWidget *parent = 0);
    using QPlainTextEdit::QWidget;
    using QPlainTextEdit::installEventFilter;
    void addMessage(QString username, QString message, int type, int id = 0);
    void updateMessage(int id, int type, QString error);
private:
    QList<Message> pendingMessages;
    int findPending(qint64 id);
};

#endif // MESSAGELOG_H
