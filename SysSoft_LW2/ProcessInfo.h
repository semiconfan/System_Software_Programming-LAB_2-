#pragma once

#include <iostream>
#include <string>
#include <Windows.h>
using namespace std;

class ProcessInfo
{
public:
	wstring Name;
	UINT32 ProcessId;
	UINT64 WriteTransferCount;

	void PrintFields();
};

