#ifndef QMAINWINDOWTRAY_H
#define QMAINWINDOWTRAY_H

#include <QMainWindow>
#include <QSystemTrayIcon>
#include <QMenu>
#include <QCloseEvent>


class QMainWindowTray : public QMainWindow
{
    Q_OBJECT
public:
    explicit QMainWindowTray(QWidget *parent = 0);
    QIcon icon_online;
    QIcon icon_offline;
    QIcon icon_unread;

    QIcon *getStatusIcon(bool online, int unread);
    void setTrayIcon(bool online, int unread);
    void showMessage(QString message);
signals:


private:
    void createActions();
    void createTrayIcon();

    QSystemTrayIcon *trayIcon;
    QMenu *trayIconMenu;
    QAction *activateAction;
    QAction *minimizeAction;
    QAction *maximizeAction;
    QAction *restoreAction;
    QAction *quitAction;
    void setMainWindowIcon();
public slots:

private slots:
    void messageClicked();
    void menuActivated();
    void iconActivated(QSystemTrayIcon::ActivationReason reason);

protected:
    void closeEvent(QCloseEvent *event);
    virtual void showWindow();

};

#endif // QMAINWINDOWTRAY_H
