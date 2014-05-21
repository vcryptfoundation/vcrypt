#include <QtGui>
#include <QApplication>

#include "mainwindow.h"

int main(int argv, char **args)
{
    QApplication app(argv, args);
    app.setApplicationName("Vcrypt Messenger");

    //app.setStyleSheet(":focus { border : 2px solid black; border-radius: 4px;}");

    QDir pluginsDir(qApp->applicationDirPath());
    pluginsDir.setPath( pluginsDir.absolutePath() + "/plugins");

    if ( pluginsDir.exists() )
    {
        QStringList libPaths;
        libPaths << pluginsDir.absolutePath() << qApp->libraryPaths();
        qApp->setLibraryPaths(libPaths);
    }

    MainWindow mainwnd;
    mainwnd.show();

    return app.exec();
}
