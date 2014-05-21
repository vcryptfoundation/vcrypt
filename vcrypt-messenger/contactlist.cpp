#include <QMenu>
#include <QMessageBox>
#include <QDebug>
#include <assert.h>
#include "contactlist.h"
#include "vreg.h"
#include "calldialog.h"
#include "calldialogs.h"
#include "call.h"

ContactList::ContactList(QWidget *parent) :
    QListWidget(parent)
{
    setContextMenuPolicy(Qt::CustomContextMenu);
    connect(this, SIGNAL(customContextMenuRequested(const QPoint &)),
            SLOT(showContactlistContextMenu(const QPoint &)));

    connect(this, SIGNAL(itemActivated(QListWidgetItem*)), SLOT(contactClicked(QListWidgetItem*)));
}

ContactList* ContactList::singleton(QWidget *parent)
{
    static ContactList *cl = 0;

    if (cl == 0) {
        assert(parent);
        cl = new ContactList(parent);
    }

    return cl;
}

// TODO: this needs some optimization
void ContactList::loadContacts(const QString &data)
{
    clear();

    foreach(QString contact_raw, data.split("\n", QString::SkipEmptyParts)) {
        addBuddy(contact_raw, false);
    }

    sortItems();
}

QListWidgetItem* ContactList::findBuddy(QString username)
{
    QList<QListWidgetItem*> items = findItems(username, Qt::MatchFixedString);
    if (items.count() == 0)
        return NULL;

    return items.at(0);
}

void ContactList::changeStatus(QListWidgetItem *item, char status)
{
    QBrush col;

    switch(status) {
    case '0': // offline
        col = Qt::gray;
        break;
    case '1': // online
        col = Qt::black;
        break;
    default: // error
        col = Qt::red;
        break;
    }

    item->setForeground(col);
    item->setIcon(getStatusIcon(status));
}

QIcon ContactList::getStatusIcon(char status)
{
    return QIcon( status == '1' ?
                      ":/resources/icon-online.svg" : ":/resources/icon-offline.svg");
}

void ContactList::changeStatus(char status, QString username)
{
    QListWidgetItem *item = findBuddy(username);
    if (item)
        changeStatus(item, status);
}

// TODO: this must be done properly
char ContactList::getItemStatus(QListWidgetItem *item)
{
    if (item == NULL)
        return '0';

    return item->foreground() == Qt::black ? '1' : '0';
}

char ContactList::getStatus(QString username)
{
    QListWidgetItem *item = findBuddy(username);
    return getItemStatus(item);
}

void ContactList::delBuddy(QString username)
{
    QListWidgetItem *item = findBuddy(username);
    if (item)
        delete item;
}


void ContactList::addBuddy(QString status_username, bool sort)
{
    addBuddy(status_username.at(0).toLatin1(),
             status_username.right(status_username.length() - 1),
             sort);
}

void ContactList::addBuddy(char status, QString username, bool sort)
{
    QListWidgetItem *item = new QListWidgetItem(username);
    changeStatus(item, status);
    addItem(item);

    if (sort)
        sortItems();
}

bool ContactList::buddyExists(QString buddy)
{
    return findItems(buddy, Qt::MatchFixedString).count() > 0;
}

void ContactList::showContactlistContextMenu(const QPoint &pos)
{
    enum {
        MN_CALL,
        MN_MESSAGE,
        MN_DELETE,
        MN_PING
    };

    if (this->itemAt(pos) == NULL)
        return;

    QMenu contextMenu(tr("Context menu"), this);

    QList<int> *action_ids = new QList<int>();
    QList<QAction*> *actions = new QList<QAction*>();

    actions->append(new QAction(tr("Call"), this));
    action_ids->append(MN_CALL);

    actions->append(new QAction(tr("Message"), this));
    action_ids->append(MN_MESSAGE);

    actions->append(new QAction(tr("Delete"), this));
    action_ids->append(MN_DELETE);

    actions->append(new QAction(tr("Ping"), this));
    action_ids->append(MN_PING);

    contextMenu.addActions(*actions);
    QAction *action = contextMenu.exec(mapToGlobal(pos));

    if (action) {
        QString buddy = this->itemAt(pos)->text();

        switch(action_ids->at(actions->indexOf(action))) {
        case MN_CALL:
            callBuddy(buddy);
            break;
        case MN_MESSAGE:
            emit startMessaging(getItemStatus(this->itemAt(pos)), buddy);
            break;
        case MN_DELETE:
            if (QMessageBox::question(this, "Confirmation",
                                      "Are you sure you want to delete buddy \""
                                      + buddy +"\"?",
                                      "No", "Yes",
                                      0, 1 ) ) {
                vcrypt_contact_del(Vreg::vcrypt(), buddy.toLatin1().data());
            }
            break;
        case MN_PING:
            vcrypt_ping_client(Vreg::vcrypt(), buddy.toLatin1().data());
            break;
        default:
            qDebug() << "ERROR: wrong menu action id!";
            break;
        }
    }
}

void ContactList::contactClicked(QListWidgetItem *item)
{
    //callBuddy(item->text());
    emit startMessaging(getItemStatus(item), item->text());
}


void ContactList::callBuddy(QString buddy)
{
    vcrypt_call(Vreg::vcrypt(), buddy.toLocal8Bit().data());
}

