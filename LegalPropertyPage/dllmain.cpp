/*******************************************************************************
    Device Property Page for Bus Filter Framework Sample Driver
    Copyright (C) 2026 Yang Yuanzhi <yangyuanzhi@gmail.com>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*******************************************************************************/
#include "pch.h"

// Global variables
HINSTANCE g_hInstance = NULL;
HMODULE g_hRichEditDll = NULL;
const wchar_t *GPL_V3_TEXT = L"Bus Filter Framework (BFF)\r\n"
                             L"Bus Filter Framework Sample Driver\r\n"
                             L"Device Property Page for Bus Filter Framework Sample Driver\r\n\r\n"
                             L"https://github.com/abysdom/bus-filter-framework\r\n\r\n"
                             L"Copyright (C) 2026 Yang Yuanzhi <yangyuanzhi@gmail.com>\r\n\r\n"
                             L"This program is free software: you can redistribute it and/or modify "
                             L"it under the terms of the GNU General Public License as published by "
                             L"the Free Software Foundation, either version 3 of the License, or "
                             L"(at your option) any later version.\r\n\r\n"
                             L"This program is distributed in the hope that it will be useful, "
                             L"but WITHOUT ANY WARRANTY; without even the implied warranty of "
                             L"MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the "
                             L"GNU General Public License for more details.\r\n\r\n"
                             L"You should have received a copy of the GNU General Public License "
                             L"along with this program.  If not, see <https://www.gnu.org/licenses/>.";

// Dialog procedure for the property page
INT_PTR CALLBACK GPLNoticeDlgProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg)
    {
        case WM_INITDIALOG: {
            HWND hRichEdit = GetDlgItem(hwnd, IDC_RICHEDIT21);
            SetWindowText(hRichEdit, GPL_V3_TEXT);
            return TRUE;
        }
        case WM_NOTIFY: {
            NMHDR *nmhdr = (NMHDR *)lParam;
            if (nmhdr->code == PSN_APPLY)
            {
                SetWindowLongPtr(hwnd, DWLP_MSGRESULT, PSNRET_NOERROR);
            }
            break;
        }
        case WM_COMMAND:
            if (LOWORD(wParam) == IDC_VIEW_LICENSE)
            {
                ShellExecute(NULL, L"open", L"https://www.gnu.org/licenses/gpl-3.0.html", NULL, NULL, SW_SHOW);
            }
            break;
    }
    return FALSE;
}

// Entry point for the property page provider
extern "C" __declspec(dllexport) BOOL APIENTRY LegalPropertyPageProvider(PSP_PROPSHEETPAGE_REQUEST pRequest,
                                                                         LPFNADDPROPSHEETPAGE pAddSheetFunc, LPARAM lParam)
{
    if (pRequest->PageRequested != SPPSR_ENUM_ADV_DEVICE_PROPERTIES)
    {
        return FALSE;
    }

    // Create property page
    PROPSHEETPAGE psp = {0};
    psp.dwSize = sizeof(PROPSHEETPAGE);
    psp.dwFlags = PSP_USECALLBACK | PSP_USETITLE;
    psp.hInstance = g_hInstance;
    psp.pszTemplate = MAKEINTRESOURCE(IDD_GPL_DIALOG);
    psp.pszTitle = L"GPL v3 Notice";
    psp.pfnDlgProc = GPLNoticeDlgProc;
    psp.pfnCallback = NULL;

    HPROPSHEETPAGE hPage = CreatePropertySheetPage(&psp);
    if (hPage)
    {
        if (pAddSheetFunc(hPage, lParam))
        {
            return TRUE;
        }
        DestroyPropertySheetPage(hPage);
    }
    return FALSE;
}

// DLL entry point
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    if (ul_reason_for_call == DLL_PROCESS_ATTACH)
    {
        g_hInstance = hModule;
        DisableThreadLibraryCalls(hModule);
        g_hRichEditDll = LoadLibraryW(L"riched20.dll");
    }
    else if (ul_reason_for_call == DLL_PROCESS_DETACH && g_hRichEditDll)
    {
        FreeLibrary(g_hRichEditDll);
    }
    return TRUE;
}
