#include "SFunctions.h"

HRESULT CheckResult(HRESULT hRes, IWbemServices* pSvc, IWbemLocator* pLoc)
{
    if (FAILED(hRes))
    {
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        cout << "Помилковий запит до WMI. Код помилки: 0x"
            << hex << hRes << endl;
        return hRes;
    }
    return S_OK;
}

wstring WMIDateStringToDate(const wstring& wmiDate)
{
    // Створення структури, яка використовується для зберігання дати і часу
    struct tm tm = { 0 };
    
    // Розбір рядка на окремі компоненти (рік, місяць, день та ін.)
    swscanf_s(wmiDate.c_str(), L"%4d%2d%2d%2d%2d%2d",
        &tm.tm_year, &tm.tm_mon, &tm.tm_mday, &tm.tm_hour,
        &tm.tm_min, &tm.tm_sec);
    
    // Коригування значення року та місяця для функції wcsftime
    tm.tm_year -= 1900;
    tm.tm_mon--;
    
    // Форматування структури tm у рядок у звичайному форматі дати
    const unsigned int buffSize = 256;
    wchar_t buffer[buffSize];
    wcsftime(buffer, sizeof(buffer), L"%Y-%m-%d %H:%M:%S", &tm);
    buffer[buffSize - 1] = '\0';

    // Повернення отриманого рядка у форматі "РРРР-ММ-ДД ГГ:ХХ:СС"
    return wstring(buffer);
}

DWORD GetProcId(const wchar_t* procName)
{
    DWORD procId = 0;
    HANDLE hSnap =
        CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (hSnap != INVALID_HANDLE_VALUE)
    {
        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(pe32);

        if (Process32First(hSnap, &pe32))
        {
            do
            {
                if (!_wcsicmp(pe32.szExeFile, procName))
                {
                    procId = pe32.th32ProcessID;
                    break;
                }
            } while (Process32Next(hSnap, &pe32));
        }
    }
    CloseHandle(hSnap);
    return procId;
}

void TerminateLowPriorityNotepadProcess()
{
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot) {
        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);
        if (Process32First(hSnapshot, &pe32))
        {
            do
            {
                if (wstring(pe32.szExeFile) == L"notepad.exe") 
                {
                    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE,
                        pe32.th32ProcessID);
                    if (hProcess)
                    {
                        DWORD priorityClass = GetPriorityClass(hProcess);
                        if (priorityClass == IDLE_PRIORITY_CLASS)
                            TerminateProcess(hProcess, 0);
                        CloseHandle(hProcess);
                    }
                }
            } while (Process32Next(hSnapshot, &pe32));
        }
        CloseHandle(hSnapshot);
    }
}

void TerminateChildProcess(DWORD parentProcessID)
{
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot) {
        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);
        if (Process32First(hSnapshot, &pe32))
        {
            do
            {
                if (pe32.th32ParentProcessID == parentProcessID)
                {
                    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE,
                        pe32.th32ProcessID);
                    if (hProcess)
                    {
                        TerminateProcess(hProcess, 0);
                        CloseHandle(hProcess);
                    }
                }
            } while (Process32Next(hSnapshot, &pe32));
        }
        CloseHandle(hSnapshot);
    }
}
