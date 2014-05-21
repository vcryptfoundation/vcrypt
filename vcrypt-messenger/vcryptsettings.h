#ifndef VCRYPTSETTINGS_H
#define VCRYPTSETTINGS_H

#include <QSettings>

class VcryptSettings : public QSettings
{
    Q_OBJECT
public:
    explicit VcryptSettings(const QString &organization, const QString &application, QObject *parent = 0);
    QString getServer();
    QString getUsername();
    QString getPassword();
    QString getRingerOutput();
    int hasSettings();
    void clearPassword();
signals:

public slots:

};

#endif // VCRYPTSETTINGS_H
