#define _WIN32_DCOM

#include <iostream>
#include <cstring>
#include <vector>
#include <algorithm>
#include <wbemidl.h>I
#include <Windows.h>

#include "ProcessInfo.h"
#include "SFunctions.h"

#pragma comment(lib, "wbemuuid.lib")

using namespace std;

bool CmpProcByWTC(const ProcessInfo& proc1, const ProcessInfo& proc2) {
    return proc1.WriteTransferCount > proc2.WriteTransferCount;
}

int main()
{
    // Український шрифт
    SetConsoleCP(1251);
    SetConsoleOutputCP(1251);

    // Ініціалізація COM
    HRESULT hRes;
    hRes = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hRes))
    {
        cout << "Помилка ініціалізації бібліотеки COM. Код помилки: 0x"
            << hex << hRes << endl;
        return hRes; // Аварійне завершення програми
    }

    // Встановка загальних рівнів безпеки COM
    hRes = CoInitializeSecurity(
        NULL,
        -1,
        NULL,
        NULL,
        RPC_C_AUTHN_LEVEL_DEFAULT,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        NULL,
        EOAC_NONE,
        NULL);
    if (FAILED(hRes))
    {
        cout << "Помилка встановки загальних рівнів безпеки COM. "
            << "Код помилки: 0x" << hex << hRes << endl;
        CoUninitialize();
        return hRes; // Аварійне завершення програми
    }

    // Отримання з'єднання з простором імен WMI

    // Ініціалізація IWbemLocator-інтерфейса
    IWbemLocator* pLoc = 0;
    hRes = CoCreateInstance(CLSID_WbemLocator, 0,
        CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID*)&pLoc);

    if (FAILED(hRes))
    {
        cout << "Помилка створення об'єкту IWbemLocator. " <<
            "Код помилки: 0x" << hex << hRes << endl;
        return hRes; // Аварійне завершення програми
    }

    // Підключення до WMI через IWbemLocator
    IWbemServices* pSvc = 0;

    // Підключення до простору імен root\cimv2 з поточним користувачем
    hRes = pLoc->ConnectServer(
        BSTR(L"ROOT\\CIMV2"),
        NULL,
        NULL,
        0,
        NULL,
        0,
        0,
        &pSvc);

    if (FAILED(hRes))
    {
        cout << "Не вдалося під'єднатись. Код помилки: 0x"
            << hex << hRes << endl;
        pLoc->Release();
        CoUninitialize();
        return hRes; // Аварійне завершення програми
    }
    cout << "Програму під'єднано до WMI." << endl << endl;

    /*
    * 1. Отримано та виведено список властивостей класу Win32_NetworkAdapter (MSFT_NetAdapter)
    */

    cout << "Завдання 1." << endl;

    // Задання запиту до WMI
    IEnumWbemClassObject* pEnumerator = NULL;
    hRes = pSvc->ExecQuery(
        BSTR(L"WQL"),
        BSTR(L"SELECT Name, Adaptertype, MacAddress FROM Win32_NetworkAdapter"),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        NULL,
        &pEnumerator);

    if (checkResult(hRes, pSvc, pLoc) != S_OK)
        return 1; // Аварійне завершення програми

    // Отримання даних з запиту
    IWbemClassObject* pclsObj = 0;
    ULONG uReturn = 0;

    // Кількість об'єктів класу Win32_NetworkAdapter
    int NetDeviceNum = 0;

    while (pEnumerator)
    {
        hRes = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);

        if (checkResult(hRes, pSvc, pLoc) != S_OK)
            return 1; // Аварійне завершення програми

        if (0 == uReturn)
        {
            break;
        }

        VARIANT vtProp;
        VariantInit(&vtProp);

        NetDeviceNum++;
        // Вивід заданого списку властивостей класу Win32_NetworkAdapter
        hRes = pclsObj->Get(L"Name", 0, &vtProp, 0, 0);
        if (SUCCEEDED(hRes))
        {
            wcout << "Інформація про пристрій з номером " <<
                NetDeviceNum << '.' << endl;
            if (SysStringLen(vtProp.bstrVal))
            {
                wcout << "Ім'я мережевого адаптера: " <<
                    vtProp.bstrVal << endl;
                VariantClear(&vtProp);
            }
            else
                wcout << "Ім'я мережевого адаптера: " <<
                "" << endl;
        }

        hRes = pclsObj->Get(L"AdapterType", 0, &vtProp, 0, 0);
        if (SUCCEEDED(hRes))
        {
            if (SysStringLen(vtProp.bstrVal))
            {
                wcout << "Тип мережевого адаптера: " <<
                    vtProp.bstrVal << endl;
                VariantClear(&vtProp);
            }
            else
                wcout << "Тип мережевого адаптера: " <<
                "" << endl;
        }

            hRes = pclsObj->Get(L"MACAddress", 0, &vtProp, 0, 0);
        if (SUCCEEDED(hRes))
        {
            if (SysStringLen(vtProp.bstrVal))
            {
                wcout << "MAC-адреса мережевого адаптера: " <<
                    vtProp.bstrVal << endl << endl;
                VariantClear(&vtProp);
            }
            else
                wcout << "MAC-адреса мережевого адаптера: " <<
                "" << endl << endl;
        }
        pclsObj->Release();

    }

    /*
    * 2. Отримано та виведено збір деяких відомостей про підключені пристрої, згідно з варіантом
    */

    cout << "Завдання 2." << endl;

    HKEY hKey;
    LPCWSTR lpSubKey = L"SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces";
    LSTATUS lResult = RegOpenKeyEx(HKEY_LOCAL_MACHINE, lpSubKey, 0, KEY_READ, &hKey);
    if (lResult != ERROR_SUCCESS)
    {
        if (lResult == ERROR_FILE_NOT_FOUND)
        {
            cout << "Ключ не знайдено." << endl;
            return TRUE;
        }
        else
        {
            cout << "Помилка відкриття ключа." << endl;
            return FALSE;
        }
    }

    DWORD index = 0;
    TCHAR subkeyName[MAX_PATH];
    DWORD subkeyNameSize = MAX_PATH;

    while (RegEnumKeyEx(hKey, index, subkeyName, &subkeyNameSize,
        NULL, NULL, NULL, NULL) == ERROR_SUCCESS)
    {
        // Отримано ідентифікатор мережевого адаптера (GUID)
        wstring adapterGuid = subkeyName;
        
        // Відкрито ключ адаптера за його GUID
        HKEY adapterKey;
        lResult = RegOpenKeyEx(hKey, adapterGuid.c_str(), 0,
            KEY_READ, &adapterKey);
        if (lResult == ERROR_SUCCESS)
        {
            TCHAR macAddress[MAX_PATH];
            DWORD macAddressSize = MAX_PATH;

            // Отримано MAC-адресу через ключ "DhcpIPAddress"
            lResult = RegQueryValueExW(adapterKey, L"DhcpIPAddress", NULL, NULL,
                (LPBYTE)macAddress, &macAddressSize);
            if (lResult == ERROR_SUCCESS)
            {
                // Виведено інформацію про мережевий адаптер, включаючи MAC-адресу
                wcout << L"Network interface GUID: " << adapterGuid << endl;
                wcout << L"DhcpIPAddress: " << macAddress << endl << endl;
            }
            else
            {
                wcout << "Не вдалося запитати інформацію про адаптер: " 
                    << adapterGuid << endl << endl;
            }

            // Закрити ключ адаптера
            RegCloseKey(adapterKey);
        }
        else
        {
            wcout << "Не вдалося відкрити ключ адаптера для GUID: " 
                << adapterGuid << endl;
        }

        // Перехід до наступного підкаталогу (GUID)
        index++;
        subkeyNameSize = MAX_PATH;
    }

    RegCloseKey(hKey);

    /*
    * 3. Запущено процес згідно із варіантом
    */

    wcout << "Завдання 3." << endl
        << "Інформація про запущений процес згідно із варіантом (WINWORD.EXE):\n";

    STARTUPINFO si;
    PROCESS_INFORMATION pi;

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    
    // Встановлення параметрів процесу при його запуску
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_NORMAL; // Встановлення стану вікна на Normal

    ZeroMemory(&pi, sizeof(pi));

    // Запуск дочірнього процесу
    if (!CreateProcess(
        L"C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",// Шлях до виконуваного файлу
        NULL,   // Аргументи командного рядка (NULL, якщо не використовуються)
        NULL,   // Дескриптор процесу не успадковується
        NULL,   // Дескриптор потоку не успадковується
        FALSE,  // Не успадковувати дескриптори
        0,      // Прапор створення процесу
        NULL,   // Середовище виконання (NULL для успадкування середовища поточного процесу)
        NULL,   // Поточний каталог (NULL для каталогу поточного процесу)
        &si,    // Покажчик на структуру STARTUPINFO
        &pi     // Покажчик на структуру PROCESS_INFORMATION
    ))
    {
        cout << "Не вдалося створити процес. Код помилки: "
            << GetLastError() << endl;
        return 1;
    }

    // Зміна пріоритету процесса
    SetPriorityClass(pi.hProcess,
        NORMAL_PRIORITY_CLASS);

    Sleep(4000);

    // Виконання запиту до WMI, для отримання даних про процес

    // Формування запиту WQL
    wstring WQL_Porc_Querry = L"SELECT * FROM Win32_Process WHERE NAME = 'WINWORD.EXE' AND ParentProcessId = ";
    DWORD currProcID = GetCurrentProcessId();
    DWORD winWordProcId = 0;
    WQL_Porc_Querry += to_wstring(currProcID);

    hRes = pSvc->ExecQuery(
        BSTR(L"WQL"),
        BSTR(WQL_Porc_Querry.c_str()),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        NULL,
        &pEnumerator
    );

    if (checkResult(hRes, pSvc, pLoc) != S_OK)
        return 1; // Аварійне завершення програми

    // Отримання результатів запиту та вилучення даних про процес
    while (pEnumerator)
    {
        hRes = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);

        if (checkResult(hRes, pSvc, pLoc) != S_OK)
            return 1; // Аварійне завершення програми

        if (uReturn == 0)
            break;

        VARIANT vtEntity;

        hRes = pclsObj->Get(L"ExecutablePath", 0, &vtEntity, 0, 0);
        wcout << "Шлях до виконуваного файлу процесу: " << vtEntity.bstrVal << endl;
        VariantClear(&vtEntity);

        hRes = pclsObj->Get(L"CreationDate", 0, &vtEntity, 0, 0);
        wcout << "Час початку процесу: " << WMIDateStringToDate(vtEntity.bstrVal) << endl;
        VariantClear(&vtEntity);

        hRes = pclsObj->Get(L"Priority", 0, &vtEntity, 0, 0); 
        wcout << "Пріоритет процесу: " << vtEntity.uintVal << endl;
        VariantClear(&vtEntity);

        hRes = pclsObj->Get(L"ProcessId", 0, &vtEntity, 0, 0); 
        winWordProcId = vtEntity.uintVal;
        wcout << "Ідентифікатор процесу: " << vtEntity.uintVal << endl;
        VariantClear(&vtEntity);

        hRes = pclsObj->Get(L"ThreadCount", 0, &vtEntity, 0, 0);
        wcout << "Кількість активних потоків процесу: " << vtEntity.uintVal << endl << endl;
        VariantClear(&vtEntity);

        pclsObj->Release();
    }

    // Формування запиту про потоки батьківського процеса

    cout << "Інформація про активні потоки запущеного процесу: " << endl;
    wstring WQL_Thread_Querry = L"SELECT * FROM Win32_Thread WHERE ProcessHandle = ";
    WQL_Thread_Querry += to_wstring(winWordProcId);

    // Кількість процесів
    unsigned int numOfThreads = 0;

    hRes = pSvc->ExecQuery(
        BSTR(L"WQL"),
        BSTR(WQL_Thread_Querry.c_str()),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        NULL,
        &pEnumerator
    );

    if (checkResult(hRes, pSvc, pLoc) != S_OK)
        return 1; // Аварійне завершення програми

    while (pEnumerator)
    {
        hRes = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);

        if (checkResult(hRes, pSvc, pLoc) != S_OK)
            return 1; // Аварійне завершення програми

        if (uReturn == 0)
            break;

        VARIANT vtThProp;
        VariantInit(&vtThProp);
        ULONGLONG  threadUMT, theradKMT;

        hRes = pclsObj->Get(L"ProcessHandle", 0, &vtThProp, 0, 0);

        numOfThreads++;
        wcout << "Інформація про поток з номером " << numOfThreads << ": \n";

        wcout << "Ідентифікатор процесу, що створив потік: " << vtThProp.bstrVal << endl;
        VariantClear(&vtThProp);

        hRes = pclsObj->Get(L"DynamicPriority", 0, &vtThProp, 0, 0);
        wcout << "Динамічний пріоритет потоку: " << vtThProp.uintVal << endl;
        VariantClear(&vtThProp);

        hRes = pclsObj->Get(L"Priority", 0, &vtThProp, 0, 0);
        wcout << "Базовий пріоритет потоку: " << vtThProp.uintVal << endl;
        VariantClear(&vtThProp);

        hRes = pclsObj->Get(L"UserModeTime", 0, &vtThProp, 0, 0);
        threadUMT = vtThProp.ullVal;
        VariantClear(&vtThProp);

        hRes = pclsObj->Get(L"KernelModeTime", 0, &vtThProp, 0, 0);
        theradKMT = vtThProp.ullVal;
        VariantClear(&vtThProp);

        wcout << "Загальний час виконання потоку (Kernel Mode Time + User Mode Time): "
            << threadUMT + theradKMT << endl;

        hRes = pclsObj->Get(L"ThreadState", 0, &vtThProp, 0, 0);
        wcout << "Стан потоку: " << vtThProp.uintVal << endl << endl;
        VariantClear(&vtThProp);

        pclsObj->Release();
    }

    /*
    * 4. Отримано та виведено збір інформації про процеси згідно з варіантом
    */

    cout << "Завдання 4." << endl;

    vector<ProcessInfo> processList;
    ProcessInfo process;

    hRes = pSvc->ExecQuery(
        BSTR(L"WQL"),
        BSTR(L"SELECT Name, ProcessId, WriteTransferCount FROM Win32_Process WHERE Name <> '_Total' AND Name <> 'Idle'"),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        NULL,
        &pEnumerator
    );

    if (checkResult(hRes, pSvc, pLoc) != S_OK)
        return 1; // Аварійне завершення програми

    // Отримання результатів запиту та вилучення даних
    while (pEnumerator)
    {
        hRes = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);

        if (checkResult(hRes, pSvc, pLoc) != S_OK)
            return 1; // Аварійне завершення програми

        if (uReturn == 0)
            break;

        VARIANT vtName, vtProcessId, vtWriteTransferCount;

        // Вилучення даних з запиту в об'єкт process
        // 
        // Ім'я процесу
        hRes = pclsObj->Get(L"Name", 0, 
            &vtName, 0, 0);
        if (SUCCEEDED(hRes))
        {
            process.Name = vtName.bstrVal;
            VariantClear(&vtName);
        }

        // ID процесу
        hRes = pclsObj->Get(L"ProcessId", 0, 
            &vtProcessId, 0, 0);
        if (SUCCEEDED(hRes))
        {
            process.ProcessId = vtProcessId.uintVal;
            VariantClear(&vtProcessId);
        }

        // Обсяг записаних процесом даних 
        hRes = pclsObj->Get(L"WriteTransferCount", 0, 
            &vtWriteTransferCount, 0, 0);
        if (SUCCEEDED(hRes))
        {
            process.WriteTransferCount = vtWriteTransferCount.uintVal;
            VariantClear(&vtWriteTransferCount);
        }

        // Занесення даних про процес у список процесів
        processList.push_back(process);

        pclsObj->Release();
    }

    // Сортування списку процесів за обсягом записаних даних
    sort(processList.begin(), processList.end(), CmpProcByWTC);

    // Вивід в консоль інформації про процес, що має найбільший обсяг записаних даних
    cout << "Інформація про процес, що має найбільший обсяг записаних даних: \n";
    processList[0].PrintFields();
    // Очікування, поки дочірній процес завершиться
    WaitForSingleObject(pi.hProcess, INFINITE);

    // Закриття дескрипторів процесу та основного потоку
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    // Звільнення ресурсів
    pSvc->Release();
    pLoc->Release();
    pEnumerator->Release();
    CoUninitialize();
}