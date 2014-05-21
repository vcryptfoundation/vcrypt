#ifndef VREG_H
#define VREG_H

#include "client.h"
#include "notifysound.h"
#include "calldialogs.h"
#include "vcryptsettings.h"
#include <QSettings>

class Vreg
{
public:
    Vreg();
    static VCRYPT_CTX *vcrypt(QString *fname = 0);
    static NotifySound *notifySound();
    static VcryptSettings *settings();
    static CallDialogs *callDialogs();
};

#endif // VREG_H
