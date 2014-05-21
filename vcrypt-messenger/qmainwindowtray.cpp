#include "qmainwindowtray.h"
#include <QSystemTrayIcon>
#include <QMessageBox>
#include <QStatusBar>
#include <QDebug>
#include "qapplication.h"

QMainWindowTray::QMainWindowTray(QWidget *parent) :
    QMainWindow(parent)
  , icon_online(QIcon (":/resources/icon-online.svg"))
  , icon_offline(QIcon (":/resources/icon-offline.svg"))
  , icon_unread(QIcon (":/resources/icon-unread.svg"))
{
#if not __ANDROID__
    if (QSystemTrayIcon::isSystemTrayAvailable()) {

        createActions();
        createTrayIcon();
        setMainWindowIcon();

        connect(trayIcon, SIGNAL(messageClicked()), this, SLOT(messageClicked()));
        connect(trayIcon, SIGNAL(activated(QSystemTrayIcon::ActivationReason)),
                this, SLOT(iconActivated(QSystemTrayIcon::ActivationReason)));

        trayIcon->setIcon(QIcon(":/resources/icon-offline.svg"));
        trayIcon->setToolTip(tr("Vcrypt messanger"));
        trayIcon->show();
    }

    qDebug() << "windows state: " << 0 + windowState();
#endif
}

void QMainWindowTray::closeEvent(QCloseEvent *event)
{
    Q_UNUSED(event);

    if (trayIcon->isVisible()) {
        //         QMessageBox::information(this, tr("Systray"),
        //                                  tr("The program will keep running in the "
        //                                     "system tray. To terminate the program, "
        //                                     "choose <b>Quit</b> in the context menu "
        //                                     "of the system tray entry."));

        hide();
        event->ignore();
    }

    qDebug() << "windows state: " << 0 + windowState();
}

void QMainWindowTray::showWindow()
{
//      setWindowState( (windowState() & ~Qt::WindowMinimized) | Qt::WindowActive);
//    setWindowFlags(windowFlags() | Qt::WindowStaysOnTopHint);
//    setWindowFlags(windowFlags() & ~Qt::WindowStaysOnTopHint);
//    showNormal();


    // these are necessary and enough for windows
    //setWindowFlags(windowFlags() | Qt::Popup);
    show();
    raise();
    activateWindow();
//    setWindowState( (windowState() & ~Qt::WindowMinimized) | Qt::WindowActive);
    // these are necessary and enough for windows

      //raise();
//      setFocus();

//    lower();
//    raise();
//    setFocus();

    //if (!isVisible())
    //setWindowState( (windowState() & ~Qt::WindowMinimized) | Qt::WindowActive);
//    setFocus();
}

void QMainWindowTray::createActions()
{
#if not __ANDROID__
    activateAction = new QAction(tr("Activate"), this);
    connect(activateAction, SIGNAL(triggered()), this, SLOT(menuActivated()));

    quitAction = new QAction("&Quit", this);
    connect(quitAction, SIGNAL(triggered()), qApp, SLOT(quit()));
#endif
}

void QMainWindowTray::createTrayIcon()
{
#if not __ANDROID__
    trayIconMenu = new QMenu(this);
    trayIconMenu->addAction(activateAction);
    trayIconMenu->addSeparator();
    trayIconMenu->addAction(quitAction);

    trayIcon = new QSystemTrayIcon(this);
    trayIcon->setContextMenu(trayIconMenu);
#endif
}

void QMainWindowTray::menuActivated()
{
    iconActivated(QSystemTrayIcon::Trigger);
}

void QMainWindowTray::iconActivated(QSystemTrayIcon::ActivationReason reason)
{
#if not __ANDROID__
    switch (reason) {
    case QSystemTrayIcon::Trigger:
    case QSystemTrayIcon::DoubleClick:
        showWindow();
        break;
    default:
        break;
    }
#endif
}

void QMainWindowTray::showMessage(QString message)
{
#if not __ANDROID__
        QSystemTrayIcon::MessageIcon icon = QSystemTrayIcon::MessageIcon(0);
        trayIcon->showMessage("Vcrypt Messenger", message, icon,
                              10*1000);
#endif
}

void QMainWindowTray::messageClicked()
{
#if not __ANDROID__
    //    QMessageBox::information(0, tr("Systray"),
    //                             tr("Sorry, I already gave what help I could.\n"
    //                                "Maybe you should try asking a human?"));
#endif
}

QIcon* QMainWindowTray::getStatusIcon(bool online, int unread)
{
    if (unread) {
        return &icon_unread;
    } else {
        return online ? &icon_online : &icon_offline;
    }
}

void QMainWindowTray::setTrayIcon(bool online, int unread)
{
    trayIcon->setIcon(*getStatusIcon(online, unread));
}

void QMainWindowTray::setMainWindowIcon()
{
#if not __ANDROID__
    setWindowIcon(icon_online);
#endif
}
