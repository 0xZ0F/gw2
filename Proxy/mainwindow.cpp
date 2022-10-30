#include "mainwindow.h"
#include "./ui_mainwindow.h"

#include "PipeManager.hpp"
#include "ManualMap.hpp"

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    m_pMMData = std::make_unique<ManualMap>();

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
    HANDLE hPipe;
    PipeManager manager;
    
    DbgPrint("Waiting...\n");

    hPipe = manager.SetupPipe();
    if (hPipe == INVALID_HANDLE_VALUE) {
        DbgPrint("main() SetupPipe() err: " + QString::number(::GetLastError()));
        goto __exit;
    }

    DbgPrint("Client Connected");

    // Read from client
    for (;;) {
        memset(&manager, 0, sizeof(manager));
        if(!manager.RecvPacket(hPipe)){
            DbgPrint("Failed to get packet.");
            break;
        }
        
        ClearOut();
        Output(manager.GetBuf());

        // If intercept is checked...
        if(ui->chk_Intercept->checkState() == Qt::Checked){
            QEventLoop loop;
            QObject::connect(ui->btn_Send, SIGNAL(clicked()), &loop, SLOT(quit()));
        
            // Wait until button is pressed
            loop.exec();
            
            // Send modified packet
            std::string text = ui->txt_Out->toPlainText().toStdString();
            manager.SetPacketSize(text.length());
            DbgPrint("New length: " + QString::number(text.length()));
            CopyMemory(manager.GetBuf(), text.c_str(), text.length());
        }

        if(!manager.SendPacket(hPipe)){
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

void MainWindow::on_menu_Load_triggered()
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

    DbgPrint("Injecting: " + QString::fromStdWString(ofn.lpstrFile));
    
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE)
    {
        DbgPrint("CreateToolhelp32Snapshot() " + QString::number(GetLastError()));
        return;
    }

    DWORD PID = 0;    
    PROCESSENTRY32W PE32{ 0 };
    PE32.dwSize = sizeof(PE32);
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

    if (!m_pMMData->IsCorrectTargetArchitecture(hProc))
    {
        DbgPrint("Invalid target proccess architecture.");
        CloseHandle(hProc);
        return;
    }

    if (!m_pMMData->CustomMap(hProc, ofn.lpstrFile)) {
        DbgPrint("Failed to inject DLL.\n");
        CloseHandle(hProc);
        return;
    }
    m_pMMData->m_PID = PID;

    CloseHandle(hProc);

    DbgPrint("DLL Injected.\n");    
    
    return;
}

void MainWindow::on_menu_Unload_triggered()
{
    if (!m_pMMData->m_pDllInMemory) {
        DbgPrint("No DLL injected.\n");
        return;
    }

    DbgPrint("Unloading DLL...\n");
    if (!m_pMMData->FreeDLL()) {
        DbgPrint("FreeAll() failed: " + QString::number(GetLastError()));
    }
}