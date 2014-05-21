#ifndef PASSWORDCHANGE_H
#define PASSWORDCHANGE_H

#include <QDialog>

namespace Ui {
class PasswordChange;
}

class PasswordChange : public QDialog
{
    Q_OBJECT

public:
    explicit PasswordChange(QWidget *parent = 0);
    ~PasswordChange();
    void cbPasswordChange(int result);
protected:
    void reject();
    void closeEvent(QCloseEvent *event);
private slots:
    void on_pushButton_released();
    void on_pushButton_2_released();

private:
    Ui::PasswordChange *ui;
};

#endif // PASSWORDCHANGE_H
