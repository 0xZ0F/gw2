#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <TlHelp32.h>
#include <commdlg.h>

#include <QMainWindow>
#include <QThread>
#include <QFileDialog>
#include <QApplication>
#include <QLocale>
#include <QTranslator>

#include <memory>

#include "ManualMap.hpp"

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

private:
    void HandlePipe();
    Ui::MainWindow* ui;
    QThread* pipeThread;

private slots:
    void on_menu_Load_triggered();
    void on_menu_Unload_triggered();

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

    void DbgPrint(QString str);
    void Output(QString str);
    void ClearDbg();
    void ClearOut();

    std::unique_ptr<ManualMap> m_pMMData;
};
#endif // MAINWINDOW_H
