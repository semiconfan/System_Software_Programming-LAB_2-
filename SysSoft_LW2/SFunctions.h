#pragma once

#include <Windows.h>
#include <TlHelp32.h>
#include <WbemIdl.h>
#include <iostream>
#include <string>
#include <cwchar>
#include <ctime>

using namespace std;

// Прототипи допоміжних функцій 
HRESULT CheckResult(HRESULT hRes, IWbemServices* pSvc, IWbemLocator* pLoc);
wstring WMIDateStringToDate(const wstring& wmiDate);
DWORD GetProcId(const wchar_t* procName);
void TerminateLowPriorityNotepadProcess();
void TerminateChildProcess(DWORD parentProcessID);