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
	bool Inject(LPCTSTR DLLPath, DWORD ProcessID);
};
