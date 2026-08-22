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
 * Thin blocking wrappers over `GetOpenFileNameW`, `GetSaveFileNameW` and the
 * `IFileDialog` folder picker. Each returns the chosen path, or an empty string
 * when the user cancels. All three pass a no-change-directory flag
 * (`OFN_NOCHANGEDIR` / `FOS_NOCHANGEDIR`) so the process working directory stays
 * put; relative-path vault auto-discovery depends on it. Compiled only under
 * `USE_QT_UI`.
 *
 * @par Blocking and threading
 * Each function runs the shell's own modal message loop and returns only when
 * the user closes the dialog, so call it on the GUI thread, never from a worker.
 * Qt's event loop is suspended for that whole time, although the dialog's pump
 * still delivers window messages to the seal window.
 *
 * @warning No owner window is supplied (`hwndOwner` is null, and `Show` receives
 * null). Nothing disables the seal window while a dialog is open, so the dialog
 * is not modal to the application and can be pushed behind it.
 *
 * @par Distinguishing options
 * | Function           | Options beyond the shared `*_NOCHANGEDIR`  |
 * |--------------------|--------------------------------------------|
 * | `OpenFileDialog`   | `OFN_FILEMUSTEXIST`, `OFN_PATHMUSTEXIST`   |
 * | `SaveFileDialog`   | `OFN_OVERWRITEPROMPT`, default ext `.seal` |
 * | `OpenFolderDialog` | `FOS_PICKFOLDERS`, `FOS_FORCEFILESYSTEM`   |
 *
 * @par Result limits
 * The two file dialogs write into a fixed `wchar_t[MAX_PATH]` buffer, so the API
 * rejects a selection longer than 259 characters and reports it like a cancel.
 * Multi-select is off, so at most one path comes back. An empty return never
 * distinguishes a cancel from a failed call; callers treat both as "do nothing".
 *
 * @par Filter encoding
 * `OPENFILENAMEW` wants NUL-separated, double-NUL-terminated filter pairs.
 * Callers pass a '|'-separated string ending in '|'. The functions copy that
 * string, rewrite every '|' in the copy to '\0', and let `c_str()`'s implicit
 * terminator supply the closing NUL. The caller's `QString` is unchanged:
 * @verbatim
 * caller : "Text (*.txt)|*.txt|All (*)|*.*|"
 *              | copy, then replace every '|' with '\0'
 *              v   (+ implicit trailing '\0' from c_str())
 * buffer : Text (*.txt)\0*.txt\0All (*)\0*.*\0\0
 * @endverbatim
 * The trailing '|' is mandatory: without it the copy ends in one NUL, the list
 * carries no empty terminating entry, and the dialog reads past the end of the
 * copy. Both call sites in `AppViewModel` supply it.
 */

/**
 * @brief Open a Win32 file-open dialog.
 * @ingroup NativeDialogs
 *
 * `OFN_FILEMUSTEXIST` and `OFN_PATHMUSTEXIST` make the dialog refuse anything
 * that is not an existing file, so a non-empty result named an existing file at
 * the moment the dialog closed. Nothing keeps it existing afterwards, so the
 * caller still handles an open failure.
 *
 * @param title  Dialog title.
 * @param filter Pipe-separated file type filter, terminated by '|'
 *               (e.g. "Vault Files (*.seal)|*.seal|All Files (*)|*.*|").
 * @return Selected file path, or an empty string when the user cancels or the
 *         call fails.
 */
[[nodiscard]] QString OpenFileDialog(const QString& title, const QString& filter);

/**
 * @brief Open a Win32 file-save dialog.
 * @ingroup NativeDialogs
 *
 * The file-name field opens pre-filled with ".seal", and `lpstrDefExt` appends
 * "seal" when the user types a name without an extension. `OFN_OVERWRITEPROMPT`
 * confirms before an existing file is chosen. The dialog only returns a path: it
 * never creates or truncates the file, and a caller that needs the ".seal"
 * suffix guaranteed appends it itself.
 *
 * @param title  Dialog title.
 * @param filter Pipe-separated file type filter, terminated by '|'.
 * @return Selected file path, or an empty string when the user cancels or the
 *         call fails.
 */
[[nodiscard]] QString SaveFileDialog(const QString& title, const QString& filter);

/**
 * @brief Open a Win32 folder picker dialog.
 * @ingroup NativeDialogs
 *
 * Creates the shell `CLSID_FileOpenDialog` object through its `IFileDialog`
 * interface and adds `FOS_PICKFOLDERS` to the options it already carries; a
 * failed `GetOptions` leaves only the three added flags. `FOS_FORCEFILESYSTEM`
 * keeps virtual shell locations out of the result, so the returned string is
 * always a real filesystem path. The shell allocates it, so no `MAX_PATH` limit
 * applies.
 *
 * The dialog object and the shell item are released on every path, and the path
 * string is freed with `CoTaskMemFree`.
 *
 * @pre COM is initialized on the calling thread. Qt does this for the GUI
 *      thread, so GUI-thread callers need no extra setup.
 *
 * @param title Dialog title.
 * @return Selected folder path, or an empty string when the user cancels, when
 *         the dialog object cannot be created, or when the selection exposes no
 *         filesystem path.
 */
[[nodiscard]] QString OpenFolderDialog(const QString& title);

}  // namespace seal

#endif  // USE_QT_UI
