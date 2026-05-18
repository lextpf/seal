#include "Win32StyleProbe.hpp"

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <array>
#include <string>
#include <string_view>

namespace seal
{

namespace
{

HWND drillDown(HWND parent, POINT screenPt)
{
    HWND current = parent;
    while (current != nullptr)
    {
        POINT clientPt = screenPt;
        ScreenToClient(current, &clientPt);
        HWND child = RealChildWindowFromPoint(current, clientPt);
        if ((child == nullptr) || child == current)
        {
            break;
        }
        current = child;
    }
    return current;
}

HWND resolveDeepestChild(POINT screenPt)
{
    HWND root = WindowFromPoint(screenPt);
    if (root == nullptr)
    {
        return nullptr;
    }
    return drillDown(root, screenPt);
}

bool isEditLikeClass(std::wstring_view cls)
{
    static constexpr std::array<std::wstring_view, 6> kEditClasses = {
        L"Edit",
        L"RichEdit",
        L"RichEdit20A",
        L"RichEdit20W",
        L"RICHEDIT50W",
        L"TEdit",  // Delphi VCL
    };
    for (const auto& candidate : kEditClasses)
    {
        if (cls == candidate)
        {
            return true;
        }
    }
    return false;
}

std::string narrowAscii(std::wstring_view input)
{
    std::string out;
    out.reserve(input.size());
    for (wchar_t character : input)
    {
        out.push_back((character < 0x80) ? static_cast<char>(character) : '?');
    }
    return out;
}

}  // namespace

ProbeResult Win32StyleProbe::run(const ProbeContext& ctx)
{
    ProbeResult result;
    result.m_ProbeName = name();

    HWND hwnd = ctx.m_TargetWindow;
    if (hwnd == nullptr)
    {
        hwnd = resolveDeepestChild(ctx.m_ClickPoint);
    }
    else
    {
        hwnd = drillDown(hwnd, ctx.m_ClickPoint);
    }

    if (hwnd == nullptr)
    {
        return result;
    }

    std::array<wchar_t, 64> classBuf{};
    GetClassNameW(hwnd, classBuf.data(), static_cast<int>(classBuf.size()));
    const std::wstring_view classView{classBuf.data()};

    if (!isEditLikeClass(classView))
    {
        result.m_Evidence = "class=" + narrowAscii(classView);
        return result;
    }

    const LONG_PTR style = GetWindowLongPtrW(hwnd, GWL_STYLE);
    if ((style & ES_PASSWORD) != 0)
    {
        result.m_Verdict = Verdict::Password;
        result.m_Confidence = 0.98F;
        result.m_Evidence = "class=" + narrowAscii(classView) + " style=ES_PASSWORD";
        return result;
    }

    const LRESULT mask = SendMessageW(hwnd, EM_GETPASSWORDCHAR, 0, 0);
    if (mask != 0)
    {
        result.m_Verdict = Verdict::Password;
        result.m_Confidence = 0.95F;
        result.m_Evidence = "class=" + narrowAscii(classView) + " mask_char_set";
        return result;
    }

    result.m_Verdict = Verdict::Username;
    result.m_Confidence = 0.55F;
    result.m_Evidence = "class=" + narrowAscii(classView) + " no_password_style";
    return result;
}

}  // namespace seal
