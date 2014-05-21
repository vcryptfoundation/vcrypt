#include "messagingtab.h"
#include <QVBoxLayout>
#include <QSplitter>
#include <QDebug>
#include <QSizePolicy>
#include <QKeyEvent>
#include <QPlainTextEdit>
#include <QTimer>
#include <QtGui>
#include <QMessageBox>
#include "messagelog.h"
#include "client.h"
#include "contactlist.h"
#include "vreg.h"


/* this filters the events on the input box, also it sends the message */
bool MessagingTab::eventFilter(QObject *obj, QEvent *event)
{
    QKeyEvent *keyEvent = static_cast<QKeyEvent *>(event);
    if (event->type() == QEvent::KeyPress) {
        if (keyEvent->key() == Qt::Key_Return) {
            if (keyEvent->modifiers() & Qt::ControlModifier) {
                keyEvent->setModifiers(Qt::NoModifier);
                return QObject::eventFilter(obj, event);
            } else {
                sendMessage();
                return true;
            }
        }

        if (keyEvent->key() == Qt::Key_Tab) {
            if (keyEvent->modifiers() & Qt::ControlModifier) {
                keyPressEvent(keyEvent);
                return true;
            }
        }
    }

    if (event->type() == QEvent::FocusIn) {
        qDebug() << "got focus in INPUT event ";
        unreadMessages = 0;
        emit unreadChanged();
        return true;
    }

    return QObject::eventFilter(obj, event);
}

bool MessagingTab::event(QEvent *event)
{
    static int d;
    if (event->type() == QEvent::FocusIn) {
        qDebug() << "got focus in event " << d++;
        input->setFocus();
        unreadMessages = 0;
        emit unreadChanged();
        return true;
    }

    return QWidget::event(event);
}

MessagingTab::MessagingTab(QWidget  *parent, QString username) :
    QWidget(parent),
    username(username),
    parent(parent),
    unreadMessages(0)
{
    QSplitter *splitter = new QSplitter(Qt::Vertical, this);
    splitter->setChildrenCollapsible(false);

    messageLog = new MessageLog(this);

    input = new QTextEdit(this);
    input->setMinimumHeight(40);
    input->installEventFilter(this);

    //connect(filter, SIGNAL(enterPressed()), this, SLOT(sendMessage()));
    //connect(input, SIGNAL())

    splitter->addWidget(messageLog);
    splitter->addWidget(input);

    splitter->setStretchFactor(0, 1);
    splitter->setStretchFactor(1, 0);

    QList<int> sizes;
    sizes << 1000 << 0;
    splitter->setSizes(sizes);

    QVBoxLayout *layout = new QVBoxLayout();
    layout->addWidget(splitter);

    int ret = 0;//vcrypt_message_send_prepare(Vreg::vcrypt(), username.toLatin1().data());
    enableSending(ret);

    setLayout(layout);
}

MessagingTab::~MessagingTab()
{
    delete messageLog;
    delete input;
}

void MessagingTab::msgTimeout(int id)
{
    messageLog->updateMessage(id, Message::OutgoingSent, "");
}

void MessagingTab::receiveMessage(QString message, int msg_type)
{
    int type;

    switch(msg_type) {
    case 0:
        type = Message::Incoming;
        break;
    case 1:
        type = Message::System;
        break;
    case 3:
        type = Message::IncomingOffline;
        break;
    default:
        type = Message::OutgoingError;
        break;
    }

    if (!input->hasFocus()) {
        unreadMessages++;
        emit unreadChanged();
    }

    messageLog->addMessage(username, message, type);
}

void MessagingTab::updateMessageStatus(int32_t id, int status)
{
    int type;
    switch(status) {
    case 0:
        type = Message::OutgoingSent;
        break;
    case -ERR_MESSAGE_STORED:
        type = Message::OutgoingStored;
        break;
    default:
        type = Message::OutgoingError;
        break;
    }

    messageLog->updateMessage(id, type, status ? vcrypt_get_error(status) : "");
}

void MessagingTab::enableSending(int result)
{
    if (result == 0) {
        input->clear();
        input->setEnabled(1);

        if (hasFocus())
            input->setFocus();
    } else {
        input->setEnabled(0);
        input->setText(vcrypt_get_error(result));
    }
}

void MessagingTab::refocus()
{
    input->setFocus();
}

int MessagingTab::getUnread() const
{
    return unreadMessages;
}


void MessagingTab::sendMessage()
{
    if (input->toPlainText().trimmed().length() == 0) {
        input->clear();
        return;
    }

    int32_t msg_id = vcrypt_message_send(Vreg::vcrypt(), username.toLocal8Bit().data(),
                                         input->toPlainText().trimmed().toLocal8Bit().data());

    if (msg_id > 0) {
        messageLog->addMessage(username, input->toPlainText(), Message::OutgoingPending, msg_id);
        input->clear();
    } else if (msg_id == 0) {
        input->clear();
    } else {
        QMessageBox::critical(this, tr("Vcrypt"), vcrypt_get_error(msg_id));
    }
}


QString MessagingTab::getUsername() const
{
    return username;
}

char MessagingTab::getStatus() const
{
    return status;
}

void MessagingTab::setStatus(char value)
{
    status = value;
}
