#include <QMessageBox>
#include "ui_addbuddydialog.h"
#include "addbuddydialog.h"
#include "vreg.h"

addBuddyDialog::addBuddyDialog(QWidget *parent, ContactList *list) :
    QDialog(parent),
    ui(new Ui::addBuddyDialog),
    list(list)
{
    ui->setupUi(this);
}

addBuddyDialog::~addBuddyDialog()
{
    delete ui;
}

void addBuddyDialog::serverResponse(int response, const QString &username)
{
    Q_UNUSED(response);
    // TODO: make server return user status
    list->addBuddy('0', username);
    close();
    accept();
}

void addBuddyDialog::on_buttonBox_clicked(QAbstractButton *button)
{
    QString buddy = ui->buddyID->text().toLower();

    if ((QPushButton*)button == ui->buttonBox->button(QDialogButtonBox::Ok)) {
        if (buddy.length() == 0) {
            QMessageBox::critical(this, tr("Vcrypt - Add budy"), tr("Buddy ID can not be empty!"));
        } else if (list->buddyExists(buddy)) {
            QMessageBox::critical(this, tr("Vcrypt - Add budy"), tr("This buddy is already in your list!"));
        } else {
            // TODO: disable controls here
            vcrypt_contact_add(Vreg::vcrypt(), buddy.toLocal8Bit().data());
        }
    }
}
