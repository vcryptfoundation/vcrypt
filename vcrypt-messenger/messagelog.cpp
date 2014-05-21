#include "messagelog.h"
#include <QtGui>

MessageLog::MessageLog(QWidget *parent) :
    QPlainTextEdit(parent)
{
    setReadOnly(true);
    setFocusPolicy(Qt::NoFocus);
    pendingMessages.clear();
}

void MessageLog::addMessage(QString username, QString message, int type, int id)
{
    Message msg(username, id, type, message);

    if (type == Message::OutgoingPending)
        pendingMessages.append(msg);

    appendHtml(msg.toHtml());
    ensureCursorVisible();
}

int MessageLog::findPending(qint64 id)
{
    for(int i=0; i<pendingMessages.count(); i++)
        if (pendingMessages.at(i).getQid() == id)
            return i;

    return -1;
}

void MessageLog::updateMessage(int id, int type, QString error)
{
    QTextCursor cursor = textCursor();

    QTextBlock block = cursor.block();
    while (block.isValid()) {
        QTextCursor cur(block);
        cur.select(QTextCursor::BlockUnderCursor);

        // check if the line has pending ID
        QRegExp regexp("<a name=\"([0-9]+)\">");

        if (cur.selection().toHtml().contains(regexp)) {
            if (regexp.capturedTexts().at(1).toInt() == id) {
                int idx = findPending(id);
                if (idx >= 0) {
                    Message msg = pendingMessages.at(idx);
                    msg.setType(type);
                    msg.setError(error);

                    if (block.previous().isValid())
                        cur.insertBlock();

                    cur.insertHtml(msg.toHtml());
                    if (type != Message::OutgoingStored)
                        pendingMessages.removeAt(idx);
                    return;
                } else {
                    qDebug() << "error while updating message " << id << "was not found in pending list";
                }
            }
        }

        block = block = block.previous();
    }

    qDebug() << "error while updating message " << id << "was not found in message log";
}

