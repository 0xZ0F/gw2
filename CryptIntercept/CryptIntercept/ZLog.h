#pragma once
#include <string>

class ZLog {
private:
	const std::string txt_dbgFile = "_Z0F_DBG.txt";
	const std::string txt_GUIFile = "_GUI_LOG.txt";
	const std::string txt_tradeFile = "_TRADE_LOG.txt";
public:
	std::ofstream dbgFile;
	std::ofstream GUIFile;
	std::ofstream tradeFile;
	ZLog();
	~ZLog();
	BOOL AnyFilesFailed();
	void DbgBox(LPCWSTR);
};