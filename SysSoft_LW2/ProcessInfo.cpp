#include "ProcessInfo.h"

void ProcessInfo::PrintFields()
{
	wcout << "��'� �������: " << Name << '.' << endl;
	wcout << "ID �������: " << ProcessId << '.' << endl;
	wcout << "����� ��������� �������� �����: " << WriteTransferCount << " ����." << endl << endl;
}
