#include "passwordchange.h"
#include "ui_passwordchange.h"
#include "vreg.h"
#include "client.h"

#include <QCloseEvent>
#include <qmessagebox.h>


PasswordChange::PasswordChange(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::PasswordChange)
{
    ui->setupUi(this);
}

PasswordChange::~PasswordChange()
{
    delete ui;
}

void PasswordChange::cbPasswordChange(int result)
{
    QMessageBox::critical(this, tr("Vcrypt"), vcrypt_get_error(result));
    ui->pushButton->setEnabled(true);
    ui->pushButton_2->setEnabled(true);

    if (result == 0)
        close();
}

void PasswordChange::on_pushButton_released()
{
    ui->pushButton->setEnabled(false);
    ui->pushButton_2->setEnabled(false);

    vcrypt_password_change(Vreg::vcrypt(),
                           ui->old_pw->text().toLatin1().data(),
                           ui->new_pw->text().toLatin1().data(),
                           ui->new_pwr->text().toLatin1().data());
}

void PasswordChange::on_pushButton_2_released()
{
    // cancel button
    close();
}

void PasswordChange::closeEvent(QCloseEvent *event)
{
    if (!ui->pushButton->isEnabled())
        event->ignore();
}

void PasswordChange::reject()
{
    if (ui->pushButton->isEnabled())
        close();
}

