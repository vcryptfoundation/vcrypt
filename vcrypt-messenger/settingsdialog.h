#ifndef SETTINGSDIALOG_H
#define SETTINGSDIALOG_H

#include "passwordchange.h"
#include "vcryptsettings.h"

#include <QDialog>
#include <QSettings>
#include <QAbstractButton>
#include <QComboBox>
#include <QAudioDeviceInfo>
#include <asklogin.h>
#include "client.h"

namespace Ui {
class SettingsDialog;
}

class SettingsDialog : public QDialog
{
    Q_OBJECT
    
public:
    explicit SettingsDialog(QWidget *parent, VcryptSettings* settings);
    ~SettingsDialog();

    void fillAudioCombo(QComboBox *combo, QAudio::Mode mode, QString setstr);
    void loadFromAsk(AskLogin &dlg);
    void saveAll();
    void clearPassword();
    void cbPasswordChange(int result);
    QString getServer();
    QString getUsername();
    QString getPassword();
    QString getRingerOutput();
    QString getAudioInput();
    QString getAudioOutput();
    bool getSavePass();
    void cbKeyGenerateResult(int result, QString &checksum);
private:
    Ui::SettingsDialog *ui;
    PasswordChange *pwchangeDlg;
    QSettings* settings;

    void restoreAll();
    void fillAudioDevices();

    QString audioInputDevice;
    QString audioOutputDevice;
    QString ringerDevice;
protected:
     void closeEvent(QCloseEvent *event);
     void showEvent(QShowEvent *event);
private slots:
     void on_buttonBox_clicked(QAbstractButton *button);

     void on_genKeys_released();

     void generateKeys();
     void on_loadKeys_released();

     void on_changeButton_released();

     void on_savePassword_toggled(bool checked);

signals:
     void closed();
};

#endif // SETTINGSDIALOG_H
