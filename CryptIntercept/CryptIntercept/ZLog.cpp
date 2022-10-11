#include "pch.h"

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

BOOL ZLog::AnyFilesFailed() {
	return dbgFile.fail() || GUIFile.fail() || tradeFile.fail();
}

VOID ZLog::DbgBox(LPCWSTR str) {
	MessageBox(NULL, str, L"Z0F", MB_ICONINFORMATION);
}