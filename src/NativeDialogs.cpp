#ifdef USE_QT_UI

#include "NativeDialogs.hpp"

#include <windows.h>

#include <commdlg.h>
#include <shlobj.h>
#include <shobjidl.h>

#include <string>

namespace seal
{

QString OpenFileDialog(const QString& title, const QString& filter)
{
    wchar_t fileName[MAX_PATH] = {};
    std::wstring wTitle = title.toStdWString();
    std::wstring wFilter = filter.toStdWString();

    // convert pipe-separated filters to Win32 double-NUL form.
    for (auto& c : wFilter)
    {
        if (c == L'|')
        {
            c = L'\0';
        }
    }

    OPENFILENAMEW ofn = {};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = nullptr;
    ofn.lpstrFilter = wFilter.c_str();
    ofn.lpstrFile = fileName;
    ofn.nMaxFile = MAX_PATH;
    ofn.lpstrTitle = wTitle.c_str();
    // preserve CWD for relative vault discovery.
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR;

    if (GetOpenFileNameW(&ofn))
    {
        return QString::fromWCharArray(fileName);
    }
    return {};
}

QString SaveFileDialog(const QString& title, const QString& filter)
{
    // lpstrFile also seeds the filename field.
    wchar_t fileName[MAX_PATH] = L".seal";
    std::wstring wTitle = title.toStdWString();
    std::wstring wFilter = filter.toStdWString();
    for (auto& c : wFilter)
    {
        if (c == L'|')
        {
            c = L'\0';
        }
    }

    OPENFILENAMEW ofn = {};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = nullptr;
    ofn.lpstrFilter = wFilter.c_str();
    ofn.lpstrFile = fileName;
    ofn.nMaxFile = MAX_PATH;
    ofn.lpstrTitle = wTitle.c_str();
    ofn.lpstrDefExt = L"seal";
    ofn.Flags = OFN_OVERWRITEPROMPT | OFN_NOCHANGEDIR;

    if (GetSaveFileNameW(&ofn))
    {
        return QString::fromWCharArray(fileName);
    }
    return {};
}

QString OpenFolderDialog(const QString& title)
{
    // COM must be initialized on the GUI thread.
    IFileDialog* pfd = nullptr;
    HRESULT hr =
        CoCreateInstance(CLSID_FileOpenDialog, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&pfd));
    if (FAILED(hr))
    {
        return {};
    }

    // exclude virtual shell locations so SIGDN_FILESYSPATH can return a path.
    DWORD opts = 0;
    pfd->GetOptions(&opts);
    pfd->SetOptions(opts | FOS_PICKFOLDERS | FOS_FORCEFILESYSTEM | FOS_NOCHANGEDIR);
    pfd->SetTitle(title.toStdWString().c_str());

    QString result;
    if (SUCCEEDED(pfd->Show(nullptr)))
    {
        IShellItem* psi = nullptr;
        if (SUCCEEDED(pfd->GetResult(&psi)))
        {
            PWSTR path = nullptr;
            if (SUCCEEDED(psi->GetDisplayName(SIGDN_FILESYSPATH, &path)))
            {
                result = QString::fromWCharArray(path);
                CoTaskMemFree(path);
            }
            psi->Release();
        }
    }
    pfd->Release();
    return result;
}

}  // namespace seal

#endif  // USE_QT_UI
