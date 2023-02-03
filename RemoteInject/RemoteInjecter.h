#pragma once

#include <QtWidgets/QMainWindow>
#include "ui_RemoteInjecter.h"

#include <QTextEdit>

#include <windows.h>

class RemoteInjecter : public QMainWindow
{
    Q_OBJECT

public:
    RemoteInjecter(QWidget *parent = Q_NULLPTR);

private:
    Ui::RemoteInjecterClass ui;
	QTextEdit* mTextEdit_log;

public slots:
	void SelectTargetFile();
	void SelectWorkingDir();
	void SelectDLL();
	void LaunchEXE();

private:
	void LogError(const std::string& msg);
	void LogInfo(const std::string& msg);
	void LogSuccess(const std::string& msg);

	bool GetProceeIDfromParentID(DWORD& dwParentProcessId, std::vector<DWORD>& childProcess);
	bool Inject(LPCTSTR DLLPath, DWORD ProcessID);
};
