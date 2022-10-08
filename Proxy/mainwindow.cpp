#include "mainwindow.h"
#include "./ui_mainwindow.h"

#include <thread>
#include <Windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <QThread>
#include <QFileDialog>

#include "Packet.h"
#include "ManualMap.h"

#define PIPE_NAME L"\\\\.\\pipe\\Z0F_Pipe"

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    pipeThread = QThread::create(&MainWindow::HandlePipe, this);
    pipeThread->start();
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::DbgPrint(QString str){
    QMetaObject::invokeMethod(ui->txt_Dbg, "appendPlainText", Qt::QueuedConnection, Q_ARG(QString, str));
}

void MainWindow::Output(QString str){
    QMetaObject::invokeMethod(ui->txt_Out, "appendPlainText", Qt::QueuedConnection, Q_ARG(QString, str));
}

void MainWindow::ClearDbg(){
    QMetaObject::invokeMethod(ui->txt_Dbg, "clear", Qt::QueuedConnection);
}

void MainWindow::ClearOut(){
    QMetaObject::invokeMethod(ui->txt_Out, "clear", Qt::QueuedConnection);
}

void MainWindow::HandlePipe(){
    PACKET packet;
    HANDLE hPipe;

    // Create Pipe
    hPipe = SetupPipe(PIPE_NAME, PIPE_ACCESS_DUPLEX, PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT);
    if (hPipe == INVALID_HANDLE_VALUE) {
        DbgPrint("main() SetupPipe() err: " + QString::number(::GetLastError()));
        goto __exit;
    }

    DbgPrint("Server Started");

    // Read from client
    for (;;) {
        memset(&packet, 0, sizeof(packet));
        DbgPrint("Waiting to get packet...");
        if(!RecvPacket(hPipe, &packet)){
            DbgPrint("Failed to get packet.");
            break;
        }
        DbgPrint("Got Connection");

        packet.buf[packet.size - 1] = '\0';
        ClearOut();
        Output(packet.buf);

        if(ui->chk_Intercept->checkState() == Qt::Checked){
            QEventLoop loop;
            QObject::connect(ui->btn_Send, SIGNAL(clicked()), &loop, SLOT(quit()));
            loop.exec();
        }

        if(!SendPacket(hPipe, &packet)){
            DbgPrint("Failed to send packet.");
            break;
        }
    }

__exit:
    if (hPipe) {
        ::DisconnectNamedPipe(hPipe);
    }
    if (hPipe) {
        ::CloseHandle(hPipe);
    }
    DbgPrint("Pipe server quit.");
}

void MainWindow::on_menu_Inject_triggered()
{
    OPENFILENAMEW ofn;
    WCHAR szFile[260] = {0};

    ZeroMemory(&ofn, sizeof(ofn));
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = NULL;
    ofn.lpstrFile = szFile;
    ofn.nMaxFile = sizeof(szFile);
    ofn.lpstrFilter = L"\0";
    ofn.nFilterIndex = 1;
    ofn.lpstrFileTitle = NULL;
    ofn.nMaxFileTitle = 0;
    ofn.lpstrInitialDir = NULL;
    ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;

    // Display the Open dialog box.
    if (FALSE == GetOpenFileName(&ofn)) {
        DbgPrint("Failed to open file.");
        return;
    }

    DbgPrint("Injecting:" + QString::fromStdWString(ofn.lpstrFile));

    PROCESSENTRY32W PE32{ 0 };
    PE32.dwSize = sizeof(PE32);
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE)
    {
        DbgPrint("CreateToolhelp32Snapshot() " + QString::number(GetLastError()));
        return;
    }

    DWORD PID = 0;
    BOOL bRet = Process32FirstW(hSnap, &PE32);
    while (bRet)
    {
        if (0 == wcsncmp(PE32.szExeFile, L"Gw2-64.exe", sizeof(PE32.szExeFile)))
        {
            PID = PE32.th32ProcessID;
            break;
        }
        bRet = Process32NextW(hSnap, &PE32);
    }

    CloseHandle(hSnap);

    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);
    if (!hProc)
    {
        DbgPrint("Failed to open process: " + QString::number(GetLastError()));
        return;
    }

    if (!IsCorrectTargetArchitecture(hProc))
    {
        DbgPrint("Invalid target proccess architecture.");
        CloseHandle(hProc);
        return;
    }

    CustomMap(hProc, ofn.lpstrFile);
    CloseHandle(hProc);
    return;
}

