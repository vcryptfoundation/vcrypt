#include <QSettings>
#include <QDebug>
#include <QAudioDeviceInfo>
#include <QMessageBox>
#include <QFileDialog>
#include <assert.h>

#include "asklogin.h"
#include "passwordchange.h"
#include "settingsdialog.h"
#include "ui_settingsdialog.h"
#include "vcryptsettings.h"
#include "vreg.h"

SettingsDialog::SettingsDialog(QWidget *parent, VcryptSettings* settings) :
    QDialog(parent),
    ui(new Ui::SettingsDialog) ,
    pwchangeDlg(0),
    settings(settings)
{
    ui->setupUi(this);
    connect(this, SIGNAL(closed()), parent, SLOT(afterSettingsClose()));

    fillAudioDevices();
    restoreAll();
}

SettingsDialog::~SettingsDialog()
{
    delete ui;
}

void SettingsDialog::fillAudioCombo(QComboBox *combo, QAudio::Mode mode, QString setSelected)
{
    int index = 0;

    combo->clear();
    combo->addItem("default", "default");
    foreach (const QAudioDeviceInfo &deviceInfo, QAudioDeviceInfo::availableDevices(mode)) {
        combo->addItem(deviceInfo.deviceName());
        //deviceInfo.

        index++;
        if (settings->value(setSelected).toString() == deviceInfo.deviceName())
            combo->setCurrentIndex(index);
    }
}

void SettingsDialog::fillAudioDevices()
{
    fillAudioCombo(ui->audioInput, QAudio::AudioInput, "audioinput");
    fillAudioCombo(ui->audioOutput, QAudio::AudioOutput, "audiooutput");
    fillAudioCombo(ui->ringerOutput, QAudio::AudioOutput, "ringeroutput");
}

void SettingsDialog::restoreAll()
{
    QString server = settings->value("server").toString();

    ui->server->setText(server);
    ui->username->setText(settings->value("username").toString());
    ui->password->setText(settings->value("password").toString());
    ui->savePassword->setChecked(settings->value("savepassword").toBool());

    char checksum[FLETCHER_SIZE_STR];
    if (vcrypt_get_key_fingerprint_ctx(Vreg::vcrypt(), checksum) != 0) {
        ui->keyFp->setText("No valid keys");
    } else {
        ui->keyFp->setText(checksum);
    }

    emit on_savePassword_toggled(settings->value("savepassword").toBool());
}

void SettingsDialog::closeEvent(QCloseEvent *event)
{
    Q_UNUSED(event);
    emit closed();
}

void SettingsDialog::showEvent(QShowEvent *event)
{
    Q_UNUSED(event);
    fillAudioDevices();
    restoreAll();
}

void SettingsDialog::on_buttonBox_clicked(QAbstractButton *button)
{
    if ((QPushButton*)button == ui->buttonBox->button(QDialogButtonBox::Ok)) {
        saveAll();
    } else {
        restoreAll();
    }

    close();
}

void SettingsDialog::generateKeys()
{
    ui->genKeys->setEnabled(false);
    ui->loadKeys->setEnabled(false);
    qApp->processEvents();

    QString keyfile = QFileDialog::getSaveFileName(this, "Private key file location", "",
                                                   "Private key files *.der (*.der);; All files(*)");
    qApp->processEvents(QEventLoop::AllEvents, 1000);

    if (keyfile.length() == 0) {
        ui->genKeys->setEnabled(true);
        return;
    }

    QRegExp regex("\\.der$");
    if (regex.indexIn(keyfile) == -1) {
        keyfile.append(".der");
    }

    vcrypt_generate_keys(Vreg::vcrypt(), keyfile.toLatin1().data());
    settings->setValue("private_key_temp", keyfile);

    QMessageBox::information(this, tr("Vcrypt"),
                             "Keys are generated in background, you can close this window. You will be notified when this is done.");
}

void SettingsDialog::on_genKeys_released()
{
    emit generateKeys();
}

void SettingsDialog::on_loadKeys_released()
{
    QString keyfile = QFileDialog::getOpenFileName(this, "Private key file location", "",
                                                   "Private key files *.der (*.der);; All files(*)");

    if (keyfile.length() == 0)
        return;

    char checksum[FLETCHER_SIZE_STR];
    int ret;
    if ((ret=vcrypt_load_keys(Vreg::vcrypt(), keyfile.toLatin1().data(), checksum)) < 0 ) {
        ui->keyFp->setText("No valid keys");
        QMessageBox::critical(this, tr("Vcrypt"), vcrypt_get_error(ret));
    } else {
        ui->keyFp->setText(checksum);
        settings->setValue("private_key", keyfile);
    }
}

void SettingsDialog::on_changeButton_released()
{
    assert(pwchangeDlg == NULL);

    pwchangeDlg = new PasswordChange(this);
    pwchangeDlg->exec();
    delete pwchangeDlg;
    pwchangeDlg = NULL;
}

void SettingsDialog::cbPasswordChange(int result)
{
    if (pwchangeDlg)
        pwchangeDlg->cbPasswordChange(result);
}

void SettingsDialog::cbKeyGenerateResult(int result, QString &checksum)
{
    QMessageBox::critical(this, tr("Vcrypt"),
                          result == 0 ? "Keys generated successfully: " + checksum : vcrypt_get_error(result));
    ui->genKeys->setEnabled(true);
    ui->loadKeys->setEnabled(true);
}


void SettingsDialog::saveAll()
{
    settings->setValue("server", ui->server->text());
    settings->setValue("username", ui->username->text());
    settings->setValue("savepassword", ui->savePassword->isChecked());

    if (ui->savePassword->isChecked()) {
        settings->setValue("password", ui->password->text());
    } else {
        settings->setValue("password", "");
    }

    settings->setValue("audioinput", ui->audioInput->currentText());
    settings->setValue("audiooutput", ui->audioOutput->currentText());
    settings->setValue("ringeroutput", ui->ringerOutput->currentText());
}

void SettingsDialog::on_savePassword_toggled(bool checked)
{
    if (!checked)
        ui->password->setText("");
    ui->password->setEnabled(checked);
}
