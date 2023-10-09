#include "ProcessInfo.h"

void ProcessInfo::PrintFields()
{
	wcout << "Ім'я процесу: " << Name << '.' << endl;
	wcout << "ID процесу: " << ProcessId << '.' << endl;
	wcout << "Обсяг записаних процесом даних: " << WriteTransferCount << " байт." << endl << endl;
}
