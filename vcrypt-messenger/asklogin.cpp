#include "asklogin.h"
#include "ui_asklogin.h"

AskLogin::AskLogin(QWidget *parent, VcryptSettings *settings) :
    QDialog(parent),
    ui(new Ui::AskLogin),
    settings(settings)
{
    ui->setupUi(this);

    QString server = settings->value("server").toString();
    QString server_port = settings->value("server_port").toString();

    if (server_port > 0)
        ui->server->setText(server + ":" + server_port);
    else
        ui->server->setText(server);

    ui->username->setText(settings->value("username").toString());
    ui->password->setText(settings->value("password").toString());

    ui->password->setFocus();
}

void AskLogin::saveAll()
{
    settings->setValue("server", getServer());
    settings->setValue("username", getUser());

    settings->setValue("savepassword", savePass());
    if (savePass()) {
        settings->setValue("password", getPassword());
    } else {
        settings->setValue("password", "");
    }
}

QString AskLogin::getServer()
{
    return ui->server->text();
}

QString AskLogin::getUser()
{
    return ui->username->text();
}

QString AskLogin::getPassword()
{
    return ui->password->text();
}

bool AskLogin::savePass()
{
    return ui->savePassword->isChecked();
}

AskLogin::~AskLogin()
{
    delete ui;
}

void AskLogin::accept()
{
    saveAll();
    QDialog::accept();
}

