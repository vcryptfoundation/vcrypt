#ifndef MESSAGE_H
#define MESSAGE_H

#include <QDateTime>

class Message
{
public:
   static const int Incoming;
   static const int IncomingOffline;
   static const int OutgoingPending;
   static const int OutgoingSent;
   static const int OutgoingStored;
   static const int OutgoingError;
   static const int System;

   explicit Message(QString username, qint64 qid, int type, QString message, QDateTime date = QDateTime::currentDateTime());
   QString toHtml();
   QString formatDate(QDateTime date);
   qint64 getQid() const;

   int getType() const;
   void setType(int value);

   QString escape(QString str);
   void setError(const QString &value);

private:
   QString username;
   qint64 qid;
   int type; // incoming/outgoing
   QString message;
   QString error;
   QDateTime date;
};


#endif // MESSAGE_H
