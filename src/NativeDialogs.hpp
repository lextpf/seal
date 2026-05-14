#pragma once

#ifdef USE_QT_UI

#include <QtCore/QString>

namespace seal
{

/**
 * @brief Open a Win32 file-open dialog.
 * @author Alex (https://github.com/lextpf)
 * @ingroup NativeDialogs
 * @param title  Dialog title.
 * @param filter Pipe-separated file type filter (e.g. "Vault Files (*.seal)|*.seal|All Files
 * (*)|*.*|").
 * @return Selected file path, or empty string if cancelled.
 */
[[nodiscard]] QString OpenFileDialog(const QString& title, const QString& filter);

/**
 * @brief Open a Win32 file-save dialog.
 * @author Alex (https://github.com/lextpf)
 * @ingroup NativeDialogs
 * @param title  Dialog title.
 * @param filter Pipe-separated file type filter.
 * @return Selected file path, or empty string if cancelled.
 */
[[nodiscard]] QString SaveFileDialog(const QString& title, const QString& filter);

/**
 * @brief Open a Win32 folder picker dialog.
 * @author Alex (https://github.com/lextpf)
 * @ingroup NativeDialogs
 * @param title Dialog title.
 * @return Selected folder path, or empty string if cancelled.
 */
[[nodiscard]] QString OpenFolderDialog(const QString& title);

}  // namespace seal

#endif  // USE_QT_UI
