#ifndef ASKLOGIN_H
#define ASKLOGIN_H

#include <QDialog>
#include "vcryptsettings.h"

namespace Ui {
class AskLogin;
class VcryptSettings;
}

class AskLogin : public QDialog
{
    Q_OBJECT

public:
    explicit AskLogin(QWidget *parent, VcryptSettings *settings);
    ~AskLogin();

    QString getServer();
    QString getUser();
    QString getPassword();
    bool savePass();
    void saveAll();
protected:
    void accept();
private:
    Ui::AskLogin *ui;
    VcryptSettings *settings;
};

#endif // ASKLOGIN_H
