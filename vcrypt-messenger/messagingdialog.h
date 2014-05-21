#ifndef MESSAGINGDIALOG_H
#define MESSAGINGDIALOG_H

#include <QMainWindow>
#include <QEvent>
#include "contactlist.h"
#include "client.h"
#include "messagingtab.h"

namespace Ui {
class MessagingDialog;
}

class MessagingDialog : public QMainWindow
{
    Q_OBJECT
    
public:
    explicit MessagingDialog(QWidget *parent=0);
    ~MessagingDialog();

    void updateStatus(char status, QString username);
    void receiveMessage(const QString &username, const QString &message, int msg_type);
    void updateMessageStatus(const QString &username, int32_t id, int result);
    void updateStatuses(ContactList *clist);
    void enableSending(const QString &username, int result);

    int getUnreadMessages() const;
    void setUnreadMessages(int value);

    void showWindow();
private:
    Ui::MessagingDialog *ui;
    QTabWidget *tabWidget;
    int findTab(QString username);
    MessagingTab *getTabClass(int tab);
    int startMessaging(char status, QString username, bool set_current);
    int unreadMessages;
public slots:


    int startMessagingSlot(char status, QString username);
protected:
    bool event(QEvent *event);
    void closeEvent(QCloseEvent *event);

    void focusInEvent(QFocusEvent *e);
private slots:
    void closeTab(int index);
    void tabChanged(int i);
    void unreadChangedSlot();
signals:
    void unreadChanged();
};

#endif // MESSAGINGDIALOG_H
