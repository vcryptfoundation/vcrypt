#include "message.h"
#include <QtGui>

const int Message::Incoming = 0;
const int Message::IncomingOffline = 1;
const int Message::OutgoingPending = 2;
const int Message::OutgoingSent = 3;
const int Message::OutgoingStored = 4;
const int Message::OutgoingError = 5;
const int Message::System = 6;

Message::Message(QString username, qint64 qid, int type, QString message, QDateTime date)
    : username(username)
    , qid(qid)
    , type(type)
    , message(message)
    , error("")
    , date(date)
{
}

QString Message::formatDate(QDateTime date)
{
    return date.toString("yyyy-MM-dd hh:mm:ss");
}

QString Message::escape(QString str)
{
#if QT_VERSION < QT_VERSION_CHECK(5, 0, 0)
    return Qt::escape(str);
#else
    return str.toHtmlEscaped();
#endif
}

QString Message::toHtml()
{
    QString result;

    switch(type) {
    case Incoming:
        result = QString("<span style=\"color:green; font-size: small;\">(%1)</span> "
                         "<span style=\"color:green; font-weight: bold;\">%2:</span> "
                         "<span style=\"color:black;\">%3</span>")
                .arg(formatDate(date))
                .arg(username)
                .arg(Message::escape(message));
        break;
    case IncomingOffline:
        result = QString("<span style=\"color:grey; font-size: small;\">(%1)</span> "
                         "<span style=\"color:grey; font-weight: bold;\">%2:</span> "
                         "<span style=\"color:black;\">%3</span>")
                .arg(formatDate(date))
                .arg(username)
                .arg(Message::escape(message));
        break;
    case OutgoingPending:
        result = QString("<a name=\"%1\"></a>"
                         "<span style=\"color:grey; font-style:italic; font-size: small;\">... (%2)</span> "
                         "<span style=\"color:grey; font-style:italic; font-weight: bold;\">me:</span> "
                         "<span style=\"color:grey; font-style:italic;\">%3</span>")
                .arg(qid)
                .arg(formatDate(date))
                .arg(Message::escape(message));
        break;
    case OutgoingStored:
        result = QString("<span  title=\"%3\">"
                         "<a name=\"%1\"></a>"
                         "<span style=\"color:grey; font-size: small;\">(%2)</span> "
                         "<span style=\"color:grey; font-weight: bold;\">me:</span> "
                         "<span style=\"color:grey; \">%4</span>"
                         "</span>")
                .arg(qid)
                .arg(formatDate(date))
                .arg(Message::escape(error))
                .arg(Message::escape(message));
        break;
    case OutgoingError:
        result = QString("<span  title=\"%3\">"
                         "<a name=\"%1\"></a>"
                         "<span style=\"color:red; font-style:italic; font-size: small;\">(%2)</span> "
                         "<span style=\"color:red; font-style:italic; font-weight: bold;\">me:</span> "
                         "<span style=\"color:red; font-style:italic;\">%4</span>"
                         "</span>")
                .arg(qid)
                .arg(formatDate(date))
                .arg(Message::escape(error))
                .arg(Message::escape(message));
        break;
    case OutgoingSent:
        result = QString("<span style=\"color:blue; font-size: small;\">(%1)</span> "
                         "<span style=\"color:blue; font-weight: bold;\">me</span>: "
                         "<span style=\"color:black;\">%2</span>")
                .arg(formatDate(date))
                .arg(Message::escape(message));
        break;
    case System:
        result = QString("<span style=\"color:black; font-size: small;\">(%1)</span> "
                         "<span style=\"color:black; font-weight: bold;\">system</span>: "
                         "<span style=\"color:black; font-weight: bold;\">%2</span>")
                .arg(formatDate(date))
                .arg(Message::escape(message));
        break;
    default:
        result = "error";
        break;
    }

    return result;
}

qint64 Message::getQid() const
{
    return qid;
}

int Message::getType() const
{
    return type;
}

void Message::setType(int value)
{
    type = value;
}

void Message::setError(const QString &value)
{
    error = value;
}
