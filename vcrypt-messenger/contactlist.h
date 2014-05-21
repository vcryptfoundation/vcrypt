#ifndef CONTACTLIST_H
#define CONTACTLIST_H

#include "client.h"
#include <QListWidget>

class ContactList : public QListWidget
{
    Q_OBJECT

public:
    ContactList(QWidget *parent);
    static ContactList* singleton(QWidget *parent = 0);
    void loadContacts(const QString &data);
    void addBuddy(char status, QString username, bool sort=true);
    void addBuddy(QString status_username, bool sort=true);
    bool buddyExists(QString buddy);
    void delBuddy(QString username);
    void changeStatus(char status, QString username);
    char getStatus(QString username);
    static QIcon getStatusIcon(char status);

private:
    void callBuddy(QString buddy);
    QListWidgetItem* findBuddy(QString username);
    void changeStatus(QListWidgetItem *item, char status);
    char getItemStatus(QListWidgetItem *item);
private slots:
    void showContactlistContextMenu(const QPoint &pos);
    void contactClicked(QListWidgetItem *item);

signals:
    void startMessaging(char status, QString username);
};

#endif // CONTACTLIST_H
