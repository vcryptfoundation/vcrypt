#include "vreg.h"
#include "client.h"
#include <QDebug>
#include "notifysound.h"
#include "calldialogs.h"

Vreg::Vreg()
{
}

VCRYPT_CTX *Vreg::vcrypt(QString *fname)
{
    static VCRYPT_CTX* vcrypt;

    if (vcrypt == NULL) {
        vcrypt = vcrypt_create(fname->toLatin1().data());
        qDebug() << "created vcrypt context: " << vcrypt;
    }

    return vcrypt;
}

VcryptSettings *Vreg::settings()
{
    static VcryptSettings* ss;

    if (ss == NULL) {
        ss = new VcryptSettings("manager", "Vcrypt");
    }

    return ss;
}

NotifySound *Vreg::notifySound()
{
    static NotifySound* ns;

    if (ns == NULL) {
        ns = new NotifySound();
    }

    return ns;
}

CallDialogs *Vreg::callDialogs()
{
    static CallDialogs* cds;

    if (cds == NULL) {
        cds = new CallDialogs();
    }

    return cds;
}
