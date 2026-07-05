#pragma once

#ifdef USE_QT_UI

#include <QtCore/QString>

namespace seal
{

/**
 * @brief Win32 native file-open, file-save, and folder-picker dialogs.
 * @author Alex (https://github.com/lextpf)
 * @ingroup NativeDialogs
 *
 * Thin blocking wrappers over the classic common-dialog APIs
 * (`GetOpenFileNameW` / `GetSaveFileNameW`) and the Vista-era `IFileDialog`
 * folder picker. Each returns the chosen path as a `QString`, or an empty
 * string when the user cancels. All three pass a no-change-directory flag
 * (`OFN_NOCHANGEDIR` / `FOS_NOCHANGEDIR`) so the process working directory
 * stays put; relative-path vault auto-discovery depends on it. Compiled only
 * under `USE_QT_UI`.
 *
 * @par Distinguishing Options
 * | Function           | Options beyond the shared `*_NOCHANGEDIR`  |
 * |--------------------|--------------------------------------------|
 * | `OpenFileDialog`   | `OFN_FILEMUSTEXIST`, `OFN_PATHMUSTEXIST`   |
 * | `SaveFileDialog`   | `OFN_OVERWRITEPROMPT`, default ext `.seal` |
 * | `OpenFolderDialog` | `FOS_PICKFOLDERS`, `FOS_FORCEFILESYSTEM`   |
 *
 * @par Filter Encoding
 * `OPENFILENAMEW` wants NUL-separated, double-NUL-terminated filter pairs.
 * Callers pass a '|'-separated string ending in '|'; each '|' is rewritten to
 * '\0' in place and `c_str()`'s implicit terminator supplies the closing NUL:
 * @verbatim
 * caller : "Text (*.txt)|*.txt|All (*)|*.*|"
 *              | replace every '|' with '\0'   (+ implicit trailing '\0')
 *              v
 * buffer : Text (*.txt)\0*.txt\0All (*)\0*.*\0\0
 * @endverbatim
 */

/**
 * @brief Open a Win32 file-open dialog.
 * @ingroup NativeDialogs
 * @param title  Dialog title.
 * @param filter Pipe-separated file type filter (e.g. "Vault Files (*.seal)|*.seal|All Files
 * (*)|*.*|").
 * @return Selected file path, or empty string if cancelled.
 */
[[nodiscard]] QString OpenFileDialog(const QString& title, const QString& filter);

/**
 * @brief Open a Win32 file-save dialog.
 * @ingroup NativeDialogs
 * @param title  Dialog title.
 * @param filter Pipe-separated file type filter.
 * @return Selected file path, or empty string if cancelled.
 */
[[nodiscard]] QString SaveFileDialog(const QString& title, const QString& filter);

/**
 * @brief Open a Win32 folder picker dialog.
 * @ingroup NativeDialogs
 * @param title Dialog title.
 * @return Selected folder path, or empty string if cancelled.
 */
[[nodiscard]] QString OpenFolderDialog(const QString& title);

}  // namespace seal

#endif  // USE_QT_UI
