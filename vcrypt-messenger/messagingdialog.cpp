#include "messagingdialog.h"
#include "messagingtab.h"
#include "contactlist.h"
#include "ui_messagingdialog.h"
#include <QDebug>
#include <QKeyEvent>
#include "vreg.h"

MessagingDialog::MessagingDialog(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MessagingDialog) ,
    unreadMessages(0)
{
    ui->setupUi(this);
    setWindowIcon(QIcon (":/resources/icon-online.svg"));
    restoreGeometry(Vreg::settings()->value("messaging_geometry").toByteArray());

    tabWidget = new QTabWidget(this);
    tabWidget->setTabsClosable(true);

    tabWidget->installEventFilter(this);

    setCentralWidget(tabWidget);

    connect(tabWidget, SIGNAL(tabCloseRequested(int)), this, SLOT(closeTab(int)));
    connect(tabWidget, SIGNAL(currentChanged(int)), this, SLOT(tabChanged(int)));
}

MessagingDialog::~MessagingDialog()
{
    delete tabWidget;
    delete ui;
}

bool MessagingDialog::event(QEvent *event)
{
    if (event->type() == QEvent::KeyPress) {
        QKeyEvent *ke = static_cast<QKeyEvent *>(event);

        if (ke->key() == Qt::Key_Escape) {
            closeTab(tabWidget->currentIndex());
            return true;
        }
    }

    return QWidget::event(event);
}

void MessagingDialog::unreadChangedSlot()
{
    int unread = 0;
    for(int i = 0; i<tabWidget->count(); i++) {
        MessagingTab *tab = getTabClass(i);
        if (tab) {
            int u = tab->getUnread();
            unread += u;

            // TODO: optimize this
            if (u) {
                tabWidget->setTabIcon(i, QIcon(":/resources/icon-unread.svg"));
            } else {
                tabWidget->setTabIcon(i, ContactList::getStatusIcon(ContactList::singleton()->getStatus(tab->getUsername())));
            }
        }
    }

    if (unread != unreadMessages) {
        setUnreadMessages(unread);
        emit unreadChanged();
    }

    qDebug() << "there are " << unread << " messages";
}

void MessagingDialog::tabChanged(int i)
{
    Q_UNUSED(i);
    if (tabWidget->currentWidget()) {
        tabWidget->currentWidget()->setFocus();

        getTabClass(i)->refocus();
    }
}

void MessagingDialog::focusInEvent(QFocusEvent *e)
{
    Q_UNUSED(e);

    if (tabWidget->currentWidget())
        tabWidget->currentWidget()->setFocus();
}

int MessagingDialog::findTab(QString username)
{
    for(int i = 0; i<tabWidget->count(); i++) {
        if (tabWidget->tabText(i).compare(username) == 0)
            return i;
    }

    return -1;
}

MessagingTab *MessagingDialog::getTabClass(int tab)
{
    return (MessagingTab*)tabWidget->widget(tab);
}

int MessagingDialog::getUnreadMessages() const
{
    return unreadMessages;
}

void MessagingDialog::setUnreadMessages(int value)
{
    unreadMessages = value;
}

void MessagingDialog::updateStatus(char status, QString username)
{
    int tab = findTab(username);

    if (tab >= 0) {
        MessagingTab *tc = getTabClass(tab);

        tc->setStatus(status);

        if (tc->getUnread() == 0)
            tabWidget->setTabIcon(tab, ContactList::getStatusIcon(status));
    }
}

void MessagingDialog::receiveMessage(const QString &username, const QString &message, int msg_type)
{
    if (msg_type != 1) {
        Vreg::notifySound()->start(NotifySound::soundMessageIn);
    }

    int tab = startMessaging(ContactList::singleton()->getStatus(username), username, false);
    getTabClass(tab)->receiveMessage(message, msg_type);
}

void MessagingDialog::enableSending(const QString &username, int result)
{
    int tab = findTab(username);

    if (tab >= 0) {
        getTabClass(tab)->enableSending(result);
    }
}

void MessagingDialog::updateMessageStatus(const QString &username, int32_t id, int result)
{
    int tabIndex = findTab(username);

    if (tabIndex >= 0) {
        getTabClass(tabIndex)->updateMessageStatus(id, result);
    }
}

void MessagingDialog::updateStatuses(ContactList *clist)
{
    for(int i = 0; i<tabWidget->count(); i++) {
        char status = clist->getStatus(tabWidget->tabText(i));

        getTabClass(i)->setStatus(status);
        tabWidget->setTabIcon(i, ContactList::getStatusIcon(status));
    }
}

int MessagingDialog::startMessagingSlot(char status, QString username)
{
    return startMessaging(status, username, true);
}

int MessagingDialog::startMessaging(char status, QString username, bool set_current)
{
    if (set_current)
        showWindow();

    int tabIndex = findTab(username);

    if (tabIndex >= 0) {
        tabWidget->setTabIcon(tabIndex, ContactList::getStatusIcon(status));

        if (set_current)
            tabWidget->setCurrentIndex(tabIndex);
    } else {
        QWidget *temp = new MessagingTab(tabWidget, username);
        connect(temp, SIGNAL(unreadChanged()), this, SLOT(unreadChangedSlot()));

        tabIndex = tabWidget->addTab(temp, ContactList::getStatusIcon(status), username);

        if (set_current)
            tabWidget->setCurrentWidget(temp);
    }

    return tabIndex;
}

void MessagingDialog::closeTab(int index)
{
    delete tabWidget->widget(index);

    if (tabWidget->count() == 0) {
        hide();
        setVisible(false);
        return;
    }

    tabWidget->currentWidget()->setFocus();
}

void MessagingDialog::closeEvent(QCloseEvent *event)
{
    Q_UNUSED(event);

    Vreg::settings()->setValue("messaging_geometry", saveGeometry());

    int n = tabWidget->count();
    for(int i = 0; i<n; i++) {
        delete tabWidget->widget(0);
    }

    QWidget::closeEvent(event);
}


void MessagingDialog::showWindow()
{
    qDebug() << "trying to show messaging window";

    // these are necessary and enough for windows
    showNormal();
    activateWindow();
    // these are necessary and enough for windows

    // needed for linux
    raise();
}
