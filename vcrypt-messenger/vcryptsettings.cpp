#include "asklogin.h"
#include "settingsdialog.h"
#include "vcryptsettings.h"

VcryptSettings::VcryptSettings(const QString &organization, const QString &application, QObject *parent) :
    QSettings(organization, application, parent)
{
}

int VcryptSettings::hasSettings()
{
    return value("username").toString().length() &&
            value("server").toString().length() &&
            value("password").toString().length();
}

void VcryptSettings::clearPassword()
{
    setValue("password", "");
}


QString VcryptSettings::getServer()
{
    return value("server").toString();
}

QString VcryptSettings::getUsername()
{
    return value("username").toString();
}

QString VcryptSettings::getPassword()
{
    return value("password").toString();
}

QString VcryptSettings::getRingerOutput()
{
    return value("ringeroutput").toString();
}
