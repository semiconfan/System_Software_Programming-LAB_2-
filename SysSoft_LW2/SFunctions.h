#pragma once

#include <Windows.h>
#include <WbemIdl.h>
#include <iostream>
#include <string>
#include <cwchar>
#include <ctime>

using namespace std;

// Прототипи допоміжних функцій 
HRESULT checkResult(HRESULT hRes, IWbemServices* pSvc, IWbemLocator* pLoc);
wstring WMIDateStringToDate(const wstring& wmiDate);