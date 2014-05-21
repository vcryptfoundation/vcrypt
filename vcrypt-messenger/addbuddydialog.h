#ifndef ADDBUDDYDIALOG_H
#define ADDBUDDYDIALOG_H

#include <QDialog>
#include <QListWidget>
#include <QAbstractButton>
#include "client.h"
#include "contactlist.h"

namespace Ui {
class addBuddyDialog;
}

class addBuddyDialog : public QDialog
{
    Q_OBJECT
    
public:
    explicit addBuddyDialog(QWidget *parent, ContactList *list);
    ~addBuddyDialog();
    
    void serverResponse(int response, const QString &username);
private slots:
    void on_buttonBox_clicked(QAbstractButton *button);

private:
    Ui::addBuddyDialog *ui;
    ContactList *list;
};

#endif // ADDBUDDYDIALOG_H
