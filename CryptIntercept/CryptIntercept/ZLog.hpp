#pragma once

#include <fstream>

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

	/// <summary>
	/// Check if there was a failure to create or open any files.
	/// </summary>
	/// <returns>TRUE on success, FALSE otherwise.</returns>
	BOOL AnyFilesFailed();
	
	/// <summary>
	/// Show a message box with.
	/// </summary>
	/// <param name="str">String to put in the message box.</param>
	VOID DbgBox(LPCWSTR str);
};