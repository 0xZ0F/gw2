#include "mainwindow.h"
#include "./ui_mainwindow.h"

#include <thread>
#include <Windows.h>
#include <iostream>
#include <QThread>


#include "Packet.h"

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    pipeThread = QThread::create(&MainWindow::HandlePipe, this);
    pipeThread->start();
//    pipeThread.detach(); // Find a better way than doing this.
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
    hPipe = ::SetupPipe(L"\\\\.\\pipe\\Z0F_Pipe", PIPE_ACCESS_DUPLEX, PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT);
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
