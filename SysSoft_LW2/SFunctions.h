#pragma once

#include <Windows.h>
#include <WbemIdl.h>
#include <iostream>
#include <string>
#include <cwchar>
#include <ctime>

using namespace std;

// ��������� ��������� ������� 
HRESULT checkResult(HRESULT hRes, IWbemServices* pSvc, IWbemLocator* pLoc);
wstring WMIDateStringToDate(const wstring& wmiDate);