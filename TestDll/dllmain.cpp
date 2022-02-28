#define _CRT_SECURE_NO_WARNINGS
#include <Windows.h>
#include <iostream>
#include <process.h>

bool OpenConsole()
{
	if (AllocConsole()) {
		freopen("CONOUT$", "w", stdout);
		SetConsoleTitle(L"Debug Console");
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_RED);
		std::cout << "Hello Inject!" << std::endl;
		return true;
	}

	return false;
}

unsigned int __stdcall init(void* data)
{
	OpenConsole();
	return 0;
}

BOOL WINAPI DllMain(HINSTANCE hInstance, DWORD fdwReason, LPVOID)
{
	DisableThreadLibraryCalls(hInstance);

	switch (fdwReason)
	{
	case DLL_PROCESS_ATTACH:
		_beginthreadex(nullptr, 0, init, nullptr, 0, nullptr);
		break;
	}

	return TRUE;
}