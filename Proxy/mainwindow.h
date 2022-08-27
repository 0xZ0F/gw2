#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <thread>

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

    void DbgPrint(QString str);
    void Output(QString str);
    void ClearDbg();
    void ClearOut();

private slots:
    void on_menu_Inject_triggered();

private:
    void HandlePipe();
    Ui::MainWindow *ui;
    QThread *pipeThread;
};
#endif // MAINWINDOW_H
