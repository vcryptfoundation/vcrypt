#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QSettings>
#include <QPushButton>
#include <QListWidget>
#include <QVBoxLayout>
#include <qmainwindowtray.h>
#include "settingsdialog.h"
#include "addbuddydialog.h"
#include "messagingdialog.h"
#include "notifysound.h"
#include "calldialog.h"
#include "client.h"
#include "contactlist.h"

namespace Ui {
class VcryptMain;
}

class MainWindow : public QMainWindowTray
{
    Q_OBJECT
    
public:
    explicit MainWindow(QWidget *parent = 0);
    ~MainWindow();
private:
    Ui::VcryptMain *ui;
    SettingsDialog *settingsDialog;
    void createMenu();

    QPushButton *buttonConnect;
    ContactList *contactList;
    QVBoxLayout *layout;
    QWidget *centralWidget;

    addBuddyDialog *addBuddy;
    MessagingDialog *messaging;
    void connectToServer(int noask);
private slots:
    void on_actionQuit_triggered();
    void on_actionSettings_triggered();
    void afterSettingsClose();
    void connectButtonTrigered();
    void on_actionAdd_buddy_triggered();
    void testButtonTrigered();
    void cbLoadContacts(QString data);
    void cbProcessContactAddDelResponse(int command, int response, QString username);
    void cbContactStatusNotify(QString username, int status);
    void cbMessageReceived(QString username, QString message, int msg_type);
    void cbMessageSentStatusNotify(QString username, qint32 id, int result);
    void cbServerDisconnect(int reason);
    void cbPingResponse(QString username, int result);
    void cbPasswordChange(int result);
    void unreadChanged();
public slots:
    void vcryptSetError(int reason);

    void cbMessageEnableSending(QString username, int result);
    void cbKeyGenerateResponse(int result, QString checksum);
protected:
     void closeEvent(QCloseEvent *event);
     void showWindow();
};

#endif // MAINWINDOW_H
