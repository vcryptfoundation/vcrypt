#ifndef MESSAGINGTAB_H
#define MESSAGINGTAB_H

#include <QWidget>
#include <QTextEdit>
#include <QPlainTextEdit>
#include <QTimer>
#include <QtGui>
#include "messagelog.h"
#include "client.h"

class MessagingTab : public QWidget
{
    Q_OBJECT
public:
    explicit MessagingTab(QWidget  *parent, QString username);
    ~MessagingTab();

    QString getUsername() const;
    char getStatus() const;
    void setStatus(char value);

    void receiveMessage(QString message, int msg_type);
    void updateMessageStatus(int32_t id, int status);
    void enableSending(int result);
    void refocus();
    int getUnread() const;
    void setHasUnread(int value);
    private:
    QString username;
    char status;
    MessageLog *messageLog;
    QTextEdit *input;
    QWidget *parent;
    int unreadMessages;
    void logMessageOutgoing(QString message, int msg_id);

signals:
    void unreadChanged();
    
public slots:
    void msgTimeout(int id);

private slots:
    void sendMessage();

    
protected:
    bool eventFilter(QObject *obj, QEvent *event);
    bool event(QEvent *event);

};


#endif // MESSAGINGTAB_H
