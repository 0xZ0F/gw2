#include "mainwindow.h"
#include "./ui_mainwindow.h"

MainWindow::MainWindow(QWidget* parent)
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

void MainWindow::DbgPrint(QString str) {
	QMetaObject::invokeMethod(ui->txt_Dbg, "appendPlainText", Qt::QueuedConnection, Q_ARG(QString, str));
}

void MainWindow::Output(QString str) {
	QMetaObject::invokeMethod(ui->txt_Out, "appendPlainText", Qt::QueuedConnection, Q_ARG(QString, str));
}

void MainWindow::ClearDbg() {
	QMetaObject::invokeMethod(ui->txt_Dbg, "clear", Qt::QueuedConnection);
}

void MainWindow::ClearOut() {
	QMetaObject::invokeMethod(ui->txt_Out, "clear", Qt::QueuedConnection);
}

void MainWindow::HandlePipe() {
	Comms comms;
	PipePacket packet;

	RPC_STATUS status = 0;

	if (!comms.CreatePipe()) {
		DbgPrint("CreatePipe(): " + QString::number(::GetLastError()));
		goto __exit;
	}

	// Wait for pipe connection
	DbgPrint("Waiting for DLL to connect...");
	if (!comms.ConnectPipe()) {
		DbgPrint("ConnectPipe(): " + QString::number(::GetLastError()));
		goto __exit;
	}
	
	// Connect RPC
	status = m_rpc.Start();
	if (status) {
		DbgPrint("Failed to start RPC.\n");
		goto __exit;
	}
	
	DbgPrint("Client Connected");

	// Read from client
	for (;;) {
		if (!comms.RecvPacket(packet)) {
			DbgPrint("RecvPacket(): " + QString::number(::GetLastError()));
			break;
		}

		ClearOut();

		// Add NULL for the output
		packet.m_data.push_back('\0');
		Output(packet.m_data.data());
		packet.m_data.pop_back();

		///
		/// TODO: This intercept is broken.
		/// Intercepting and sending causes issue.
		///

		// If intercept is checked...
		if (ui->chk_Intercept->checkState() == Qt::Checked) {
			QEventLoop loop;
			QObject::connect(ui->btn_Send, SIGNAL(clicked()), &loop, SLOT(quit()));

			// Wait until button is pressed
			loop.exec();

			// Get modified packet
			std::string text = ui->txt_Out->toPlainText().toStdString();
			if (!text.empty()) {
				// Remove the previously added NULL
				text.pop_back();
			}

			// Assign packet to the modified version
			packet.m_size = text.length();
			packet.m_data.assign(text.begin(), text.end());

			DbgPrint("New length: " + QString::number(text.length()));
		}

		if (!comms.SendPacket(packet)) {
			DbgPrint("Failed to send packet.");
			break;
		}
	}

__exit:
	DbgPrint("Pipe server quit.");
}

void MainWindow::on_menu_Load_triggered()
{
	OPENFILENAMEW ofn;
	WCHAR szFile[260] = { 0 };

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

	DbgPrint("DLL Injected.");

	return;
}

void MainWindow::on_menu_Unload_triggered()
{
	if (!m_pMMData->m_pDllInMemory) {
		DbgPrint("No DLL injected.");
		return;
	}

	DbgPrint("Unloading DLL...");
	if (!m_pMMData->FreeDLL()) {
		DbgPrint("FreeAll() failed: " + QString::number(GetLastError()));
	}
}

void MainWindow::on_chk_Fishing_clicked()
{
	unsigned long exception = 0;
	if (!SetFishing(ui->chk_Fishing->isChecked(), exception)) {
		DbgPrint(QString("Failed to ") + (ui->chk_Fishing->isChecked() ? "enable" : "disable") + " easy fishing. Error: " + QString::fromStdString(std::to_string(exception)));
	}
	else {
		DbgPrint(QString("Easy fishing ") + (ui->chk_Fishing->isChecked() ? "enabled" : "disabled") + ".");
	}
}

