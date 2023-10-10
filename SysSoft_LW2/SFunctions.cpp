#include "SFunctions.h"

HRESULT checkResult(HRESULT hRes, IWbemServices* pSvc, IWbemLocator* pLoc)
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
