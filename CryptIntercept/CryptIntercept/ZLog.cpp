#include "ZLog.hpp"

ZLog::ZLog() {
	dbgFile.open(ZLog::txt_dbgFile, std::ios::app);
	GUIFile.open(ZLog::txt_GUIFile, std::ios::app);
	tradeFile.open(ZLog::txt_tradeFile, std::ios::app);
}

ZLog::~ZLog() {
	dbgFile.close();
	GUIFile.close();
	tradeFile.close();
}

bool ZLog::AnyFilesFailed() {
	return dbgFile.fail() || GUIFile.fail() || tradeFile.fail();
}

void ZLog::DbgBox(LPCWSTR str) {
	MessageBoxW(NULL, str, L"Z0F", MB_ICONINFORMATION);
}