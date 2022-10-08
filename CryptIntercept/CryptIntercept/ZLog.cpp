#include "pch.h"

#include "ZLog.hpp"

ZLog::ZLog() {
	ZLog::dbgFile.open(ZLog::txt_dbgFile, std::ios::app);
	ZLog::GUIFile.open(ZLog::txt_GUIFile, std::ios::app);
	ZLog::tradeFile.open(ZLog::txt_tradeFile, std::ios::app);
}

ZLog::~ZLog() {
	ZLog::dbgFile.close();
	ZLog::GUIFile.close();
	ZLog::tradeFile.close();
}

BOOL ZLog::AnyFilesFailed() {
	return ZLog::dbgFile.fail() || ZLog::GUIFile.fail() || ZLog::tradeFile.fail();
}

void ZLog::DbgBox(LPCWSTR str) {
	MessageBox(NULL, str, L"Z0F", MB_ICONINFORMATION);
}