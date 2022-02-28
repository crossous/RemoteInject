#include "RemoteInjecter.h"

#include <QFileDialog>
#include <QMessageBox>

#include <tchar.h>

#include <sstream>

RemoteInjecter::RemoteInjecter(QWidget* parent)
	: QMainWindow(parent)
{
	ui.setupUi(this);
	QWidget* centralWidget = this->findChild<QWidget*>("centralWidget");
	mTextEdit_log = centralWidget->findChild<QTextEdit*>("textEdit_log");
}

void RemoteInjecter::SelectTargetFile()
{
	static QString prePath;

	if (prePath == "")
	{
		prePath = "./";
	}

	QWidget* centralWidget = this->findChild<QWidget*>("centralWidget");

	QLineEdit* lineEdit_targetFile = centralWidget->findChild<QLineEdit*>("lineEdit_targetFile");
	QString filepath = QFileDialog::getOpenFileName(this, "选择启动文件", prePath, "exe File(*.exe)");
	if (filepath != "")
	{
		prePath = filepath;
		lineEdit_targetFile->setText(filepath);

		std::filesystem::path fullpath(filepath.toStdString());
		std::filesystem::path defaultWorkDir = fullpath.parent_path();

		QLineEdit* lineEdit_workingDir = centralWidget->findChild<QLineEdit*>("lineEdit_workingDir");
		lineEdit_workingDir->setText(QString::fromStdString(defaultWorkDir.string()));

		mTextEdit_log->setTextColor(Qt::black);
		mTextEdit_log->append(QString::fromStdString("[info]已选择exe路径：" +defaultWorkDir.string()));
	}
	else
	{
		mTextEdit_log->setTextColor(Qt::red);
		mTextEdit_log->append("[error]未选择路径");
	}
}

void RemoteInjecter::SelectWorkingDir()
{
	QWidget* centralWidget = this->findChild<QWidget*>("centralWidget");
	QLineEdit* lineEdit_targetFile = centralWidget->findChild<QLineEdit*>("lineEdit_targetFile");
	QLineEdit* lineEdit_workingDir = centralWidget->findChild<QLineEdit*>("lineEdit_workingDir");

	QString filepath = lineEdit_targetFile->text();
	QString workingDir;
	if (filepath != "")
	{
		std::filesystem::path fullpath(filepath.toStdString());
		std::filesystem::path defaultWorkDir = fullpath.parent_path();

		workingDir = QString::fromStdString(defaultWorkDir.string());
	}
	else
	{
		if (lineEdit_workingDir->text() != "")
		{
			workingDir = lineEdit_workingDir->text();
		}
		else
		{
			workingDir = "./";
		}
	}

	QString res = QFileDialog::getExistingDirectory(this, "选择工作目录", workingDir, QFileDialog::ShowDirsOnly);
	if (res != "")
	{
		lineEdit_workingDir->setText(res);
		mTextEdit_log->setTextColor(Qt::black);
		mTextEdit_log->append(QString::fromStdString("[info]已选择工作目录：") + res);
	}
	else
	{
		mTextEdit_log->setTextColor(Qt::red);
		mTextEdit_log->append("[error]未选择工作目录");
	}
}

void RemoteInjecter::SelectDLL()
{
	static QString prePath;

	if (prePath == "")
	{
		prePath = "./";
	}

	QWidget* centralWidget = this->findChild<QWidget*>("centralWidget");

	QLineEdit* lineEdit_dll = centralWidget->findChild<QLineEdit*>("lineEdit_dll");
	QString filepath = QFileDialog::getOpenFileName(this, "选择dll路径", prePath, "dll File(*.dll)");
	if (filepath != "")
	{
		prePath = filepath;
		lineEdit_dll->setText(filepath);

		mTextEdit_log->setTextColor(Qt::black);
		mTextEdit_log->append(QString::fromStdString("[info]已选择DLL：") + filepath);
	}
	else
	{
		mTextEdit_log->setTextColor(Qt::red);
		mTextEdit_log->append("[error]未选择DLL");
	}
}

void RemoteInjecter::LaunchEXE()
{
	QWidget* centralWidget = this->findChild<QWidget*>("centralWidget");
	QLineEdit* lineEdit_targetFile = centralWidget->findChild<QLineEdit*>("lineEdit_targetFile");
	QLineEdit* lineEdit_workingDir = centralWidget->findChild<QLineEdit*>("lineEdit_workingDir");
	QLineEdit* lineEdit_cmdLineArgs = centralWidget->findChild<QLineEdit*>("lineEdit_cmdLineArgs");

	QLineEdit* lineEdit_dll = centralWidget->findChild<QLineEdit*>("lineEdit_dll");

	QString targetFile = lineEdit_targetFile->text();
	if (targetFile == "")
	{
		mTextEdit_log->setTextColor(Qt::red);
		mTextEdit_log->append("[error]没有目标程序");

		return;
	}

	QString workingDir = lineEdit_workingDir->text();
	QString cmdLineArgs = lineEdit_cmdLineArgs->text();

	std::wstring targetFileWStr = targetFile.toStdWString();
	const TCHAR* szExePath = targetFileWStr.c_str();

	const TCHAR* szWorkspace = nullptr;
	std::wstring workingDirWStr = workingDir.toStdWString();
	if (workingDir != "")
	{
		szWorkspace = workingDirWStr.c_str();
	}

	TCHAR* szCmdline = nullptr;
	std::wstring cmdLineArgsWStr = cmdLineArgs.toStdWString();
	if (cmdLineArgs != "")
	{
		szCmdline = new TCHAR[cmdLineArgsWStr.size() + 1];
		memcpy(szCmdline, cmdLineArgsWStr.c_str(), sizeof(TCHAR) * cmdLineArgsWStr.size());
		szCmdline[cmdLineArgsWStr.size()] = TEXT('\0');
		//szCmdline = dllPathWStr.c_str();
	}

	//CreateProcess的返回值
	BOOL bSuccess = FALSE;
	//CreateProcess传出的进程信息
	PROCESS_INFORMATION pi;
	STARTUPINFO si;
	ZeroMemory(&pi, sizeof(PROCESS_INFORMATION));
	ZeroMemory(&si, sizeof(STARTUPINFO));
	si.cb = sizeof(STARTUPINFO);
	si.dwFlags |= STARTF_USESTDHANDLES;

	bSuccess = CreateProcess(
		szExePath,//exe路径
		szCmdline,//命令行参数
		NULL,
		NULL,
		TRUE,
		0,
		NULL,
		szWorkspace,//工作路径
		&si,
		&pi
	);

	if (szCmdline != nullptr)
	{
		delete[] szCmdline;
	}

	if (!bSuccess)
	{
		DWORD errorCode = GetLastError();
		std::stringstream ss;
		ss << "[error]进程开启错误，错误为：";
		ss << "0x" << std::hex << errorCode;

		std::string errorStr;
		if (errorCode == 0x2e4)
		{
			ss << "，请用管理员权限启动程序";
		}

		ss >> errorStr;

		mTextEdit_log->setTextColor(Qt::red);
		mTextEdit_log->append(QString::fromStdString(errorStr));
		return;
	}
	else
	{
		mTextEdit_log->setTextColor(Qt::green);
		mTextEdit_log->append("[success]开启进程成功");
	}

	QString dllPath = lineEdit_dll->text();

	if (dllPath != "")
	{
		std::wstring cmdLineArgsWStr = dllPath.toStdWString();
		const TCHAR* RenderDocDll = cmdLineArgsWStr.c_str();
		if (!Inject(RenderDocDll, pi.dwProcessId))
		{
			mTextEdit_log->setTextColor(Qt::red);
			mTextEdit_log->append("[error]Inject函数创建远程线程失败");
		}
		else
		{
			mTextEdit_log->setTextColor(Qt::green);
			mTextEdit_log->append("[success]创建远程线程成功");
		}

		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
	}
}


bool RemoteInjecter::Inject(LPCTSTR DLLPath, DWORD ProcessID)
{
	HANDLE hProcess = nullptr;
	hProcess = OpenProcess(PROCESS_ALL_ACCESS, TRUE, ProcessID);
	if (!hProcess)
	{
		mTextEdit_log->setTextColor(Qt::red);
		mTextEdit_log->append("[error]打开目标进程句柄失败");
		return false;
	}

	SIZE_T PathSize = (_tcslen(DLLPath) + 1) * sizeof(TCHAR);

	LPVOID StartAddress = VirtualAllocEx(hProcess, NULL, PathSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	if (!StartAddress)
	{
		mTextEdit_log->setTextColor(Qt::red);
		mTextEdit_log->append("[error]申请路径地址空间失败");
		return false;
	}

	if (!WriteProcessMemory(hProcess, StartAddress, DLLPath, PathSize, NULL))
	{
		mTextEdit_log->setTextColor(Qt::red);
		mTextEdit_log->append("[error]传入路径地址空间失败");
		return false;
	}

	PTHREAD_START_ROUTINE pfnStartAddress = (PTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle(_T("kernel32.dll")), "LoadLibraryW");

	if (!pfnStartAddress)
	{
		mTextEdit_log->setTextColor(Qt::red);
		mTextEdit_log->append("[error]获取LoadLibraryW函数地址失败");
		return false;
	}

	HANDLE hThread = CreateRemoteThreadEx(hProcess, NULL, NULL, pfnStartAddress, StartAddress, NULL, NULL, NULL);
	if (!hThread)
	{
		mTextEdit_log->setTextColor(Qt::red);
		mTextEdit_log->append("[error]打开远程线程失败");
		return false;
	}

	WaitForSingleObject(hThread, INFINITE);
	CloseHandle(hThread);
	CloseHandle(hProcess);

	return TRUE;
}