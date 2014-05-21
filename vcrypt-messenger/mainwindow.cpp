#include <QMenu>
#include <QDebug>
#include <QMessageBox>
#include <assert.h>

#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "addbuddydialog.h"
#include "contactlist.h"
#include "vreg.h"
#include "asklogin.h"

MainWindow *formobj;
/* CALLBACK PROXY FUNCTIONS */
void callback_server_disconnect(int reason)
{
    QMetaObject::invokeMethod(formobj, "cbServerDisconnect", Qt::QueuedConnection, Q_ARG(int, reason));
}


void callback_load_contacts(const char *data)
{
    QString tstr = data;
    QMetaObject::invokeMethod(formobj, "cbLoadContacts", Qt::QueuedConnection, Q_ARG(QString, tstr));
}

void callback_contact_add_del_response(int command, int response, const char *username)
{
    QString tstr = username;
    QMetaObject::invokeMethod(formobj, "cbProcessContactAddDelResponse", Qt::QueuedConnection,
                              Q_ARG(int, command),
                              Q_ARG(int, response),
                              Q_ARG(QString, tstr));
}

void callback_contact_status_notify(const char *username, int status)
{
    QString tstr = username;
    QMetaObject::invokeMethod(formobj, "cbContactStatusNotify", Qt::QueuedConnection,
                              Q_ARG(QString, tstr), Q_ARG(int, status));

}

void callback_message_received(const char *username, char *message_f, int msg_type)
{
    QString tstr = username;
    QString tstr_msg = message_f;
    free(message_f);

    QMetaObject::invokeMethod(formobj, "cbMessageReceived", Qt::QueuedConnection,
                              Q_ARG(QString, tstr),
                              Q_ARG(QString, tstr_msg),
                              Q_ARG(int, msg_type));
}

void callback_message_sent_status_update(const char *username, int32_t id, int res)
{
    QString tstr = username;
    QMetaObject::invokeMethod(formobj, "cbMessageSentStatusNotify", Qt::QueuedConnection,
                              Q_ARG(QString, tstr),
                              Q_ARG(qint32, id),
                              Q_ARG(int, res));
}

void callback_message_enable_sending(const char *username, int res)
{
    QString tstr = username;
    QMetaObject::invokeMethod(formobj, "cbMessageEnableSending", Qt::QueuedConnection,
                              Q_ARG(QString, tstr),
                              Q_ARG(int, res));
}


void callback_ping_response(const char *username, int result)
{
    QString tstr;

    if (username)
        tstr = username;

    QMetaObject::invokeMethod(formobj, "cbPingResponse", Qt::QueuedConnection,
                              Q_ARG(QString, tstr), Q_ARG(int, result));
}

void callback_password_change_response(int result)
{
    QMetaObject::invokeMethod(formobj, "cbPasswordChange", Qt::QueuedConnection,
                              Q_ARG(int, result));
}

void callback_key_generate_response(int result, char *checksum_f)
{
    QString tstr;

    if (checksum_f) {
        tstr = checksum_f;
        free(checksum_f);
    }

    QMetaObject::invokeMethod(formobj, "cbKeyGenerateResponse", Qt::QueuedConnection,
                              Q_ARG(int, result),
                              Q_ARG(QString, tstr));
}

/* END OF CALLBACK PROXY FUNCTIONS */

MainWindow::MainWindow(QWidget *parent) :
    QMainWindowTray(parent),
    ui(new Ui::VcryptMain),
    settingsDialog(0),
    addBuddy(NULL)
{
    formobj = this;
    ui->setupUi(this);

    QString kfname = Vreg::settings()->value("private_key").toString();
    Vreg::vcrypt(&kfname);

    QMainWindow::restoreGeometry(Vreg::settings()->value("wndgeometry").toByteArray());

    // TODO: check the outcome

    messaging = new MessagingDialog();
    connect(messaging, SIGNAL(unreadChanged()), this, SLOT(unreadChanged()));

    Vreg::vcrypt()->callback_server_disconnect = callback_server_disconnect;
    Vreg::vcrypt()->callback_load_contacts = callback_load_contacts;
    Vreg::vcrypt()->callback_contact_add_del_response = callback_contact_add_del_response;
    Vreg::vcrypt()->callback_contact_status_notify = callback_contact_status_notify;
    Vreg::vcrypt()->callback_message_received = callback_message_received;
    Vreg::vcrypt()->callback_message_sent_status_update = callback_message_sent_status_update;
    Vreg::vcrypt()->callback_ping_response = callback_ping_response;
    Vreg::vcrypt()->callback_password_change_response = callback_password_change_response;
    Vreg::vcrypt()->callback_key_generate_response = callback_key_generate_response;

    Vreg::callDialogs(); // ths will setup the rest of the callbacks;

    statusBar()->showMessage("Offlne");

    buttonConnect= new QPushButton("Connect");
    connect(buttonConnect, SIGNAL(released()), this, SLOT(connectButtonTrigered()));

    QPushButton *buttonTest = new QPushButton("Test");
    connect(buttonTest, SIGNAL(released()), this, SLOT(testButtonTrigered()));

    contactList = ContactList::singleton(this);
    connect(contactList, SIGNAL(startMessaging(char, QString)), messaging, SLOT(startMessagingSlot(char, QString)));

    layout = new QVBoxLayout();
    centralWidget = new QWidget(this);

    layout->addWidget(contactList);
    layout->addWidget(buttonConnect);
    //layout->addWidget(buttonTest);

    centralWidget->setLayout(layout);
    setCentralWidget(centralWidget);

    connectToServer(0);
}

MainWindow::~MainWindow()
{
    vcrypt_close(Vreg::vcrypt(), 1);
    delete ui;
}


void MainWindow::unreadChanged()
{
    setTrayIcon(vcrypt_is_connected(Vreg::vcrypt()), messaging->getUnreadMessages());
}

void MainWindow::testButtonTrigered()
{
//    callDialog = new CallDialog(0, notifySound, call_test, "test", settingsDialog->storage);
//    callDialog->show();
    vcrypt_ping_server(Vreg::vcrypt());
}

void MainWindow::connectToServer(int suppress_ask)
{
    if (!vcrypt_is_connected(Vreg::vcrypt()))
    {
        QString password;

        if (!Vreg::settings()->hasSettings()) {
            if (!suppress_ask) {
                AskLogin al(this, Vreg::settings());
                if (al.exec() == QDialog::Rejected)
                    return;

                password = al.getPassword();
            } else {
                return;
            }
        } else {
            password = Vreg::settings()->getPassword();
        }

        buttonConnect->setEnabled(false);
        qApp->processEvents();
        vcrypt_connect_auth( Vreg::vcrypt(),
                             Vreg::settings()->getServer().toLocal8Bit().data(),
                             Vreg::settings()->getUsername().toLocal8Bit().data(),
                             password.toLocal8Bit().data());
    }
    else
    {
        buttonConnect->setEnabled(false);
        qApp->processEvents();
        vcrypt_close(Vreg::vcrypt(), 1);
        vcryptSetError(ERR_SUCCESS);
        statusBar()->showMessage("Offline");
        setTrayIcon(false, messaging->getUnreadMessages());
    }
}


void MainWindow::connectButtonTrigered()
{
    connectToServer(0);
}

void MainWindow::cbServerDisconnect(int reason)
{
    if (reason == 0)
    {
        buttonConnect->setText("Disconnect");
        setTrayIcon(1, messaging->getUnreadMessages());
        statusBar()->showMessage("Online");
    } else {
        buttonConnect->setText("Connect");
        setTrayIcon(0, messaging->getUnreadMessages());
        contactList->clear();
        messaging->updateStatuses(contactList);
        statusBar()->showMessage(vcrypt_get_error(reason));

        if (reason == -ERR_REGISTER_AUTH_FAILURE) {
            Vreg::settings()->clearPassword();
            connectToServer(0);
        }
    }

    buttonConnect->setEnabled(true);
}

void MainWindow::vcryptSetError(int reason)
{
    statusBar()->showMessage(vcrypt_get_error(reason));
    qDebug() << "SET ERROR:" << vcrypt_get_error(reason);
}


void MainWindow::on_actionQuit_triggered()
{
    QApplication::quit();
}

// TODO: this needs some optimization
void MainWindow::cbLoadContacts(QString data)
{
    contactList->loadContacts(data);
    messaging->updateStatuses(contactList);
}

void MainWindow::cbProcessContactAddDelResponse(int command, int response, QString username)
{
    if (response < 0) {
        QMessageBox::critical(this, tr("Vcrypt"), vcrypt_get_error(response));
        return;
    }

    if (command == REQ_CONTACT_DEL) {
        contactList->delBuddy(username);
    } else if (command == REQ_CONTACT_ADD){
        if (addBuddy != NULL)
            addBuddy->serverResponse(response, username);
    }
}

void MainWindow::cbContactStatusNotify(QString username, int status)
{
    contactList->changeStatus(status, username);
    messaging->updateStatus(status, username);
}

void MainWindow::cbMessageReceived(QString username, QString message, int msg_type)
{
    messaging->receiveMessage(username, message, msg_type);
}

void MainWindow::cbMessageSentStatusNotify(QString username, qint32 id, int result)
{
    messaging->updateMessageStatus(username, id, result);
}

void MainWindow::cbMessageEnableSending(QString username, int result)
{
    qDebug() << "username is " << username;
    messaging->enableSending(username, result);
}

void MainWindow::cbPingResponse(QString username, int result)
{
    QString msg = "Ping response from ";
    if (username.length()) {
        msg.append(username);
    } else {
        msg.append("SERVER");
    }

    msg.append(": \n");
    msg.append(vcrypt_get_error(result));

    QMessageBox::critical(this, "Vcrypt - Ping", msg);
}

void MainWindow::cbPasswordChange(int result)
{
    if (settingsDialog)
        settingsDialog->cbPasswordChange(result);
}

void MainWindow::cbKeyGenerateResponse(int result, QString checksum)
{
    if (settingsDialog) {
        settingsDialog->cbKeyGenerateResult(result, checksum);
    } else {
        QString msg;
        if (result == 0) {
            msg.append("Keys generated successfully:<br>");
            msg.append(checksum);
            Vreg::settings()->setValue("private_key", Vreg::settings()->value("private_key_temp").toString());
        } else {
            msg.append("Key generation:<br>");
            msg.append(vcrypt_get_error(result));
        }

        showMessage(msg);
    }
}

void MainWindow::closeEvent(QCloseEvent *event)
{
    Q_UNUSED(event);
    Vreg::settings()->setValue("wndgeometry", QMainWindow::saveGeometry()); //TODO: move this to settingsdialog
    QMainWindowTray::closeEvent(event);
}

void MainWindow::on_actionSettings_triggered()
{
    settingsDialog = new SettingsDialog(this, Vreg::settings());
    settingsDialog->exec();
    delete settingsDialog;
    settingsDialog = NULL;
}

void MainWindow::afterSettingsClose()
{
    settingsDialog->hide();
}

void MainWindow::on_actionAdd_buddy_triggered()
{
    if (addBuddy != NULL)
        return;

    addBuddy = new addBuddyDialog(this, contactList);
    addBuddy->exec();
    delete addBuddy;
    addBuddy = NULL;
}


void MainWindow::showWindow()
{
    if (messaging->getUnreadMessages())
        messaging->showWindow();
    else
        QMainWindowTray::showWindow();
}

//void MainWindow::iconActivated(QSystemTrayIcon::ActivationReason reason)
//{
//    qDebug() << "window activated";
//#if not __ANDROID__
//    switch (reason) {
//    case QSystemTrayIcon::Trigger:
//    case QSystemTrayIcon::DoubleClick:
//        if (messaging->getUnreadMessages())
//            messaging->showWindow();
//        else
//            showWindow();
//        break;
//    default:
//        break;
//    }
//#endif
//}
