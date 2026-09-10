#pragma once

#ifdef USE_QT_UI

#include <QtCore/QString>

namespace seal
{

/**
 * @brief blocking Win32 path pickers that preserve the working directory.
 * @author Alex (https://github.com/lextpf)
 * @ingroup NativeDialogs
 *
 * call on the GUI thread. the shell message loop still delivers window messages.
 * no owner HWND is supplied, so seal remains enabled and can cover the dialog.
 *
 * returns one path, or empty for cancellation or failure. file dialogs use
 * MAX_PATH buffers and reject paths longer than 259 characters; the folder picker
 * has no fixed buffer limit.
 *
 * file filters require pipe-separated pairs with a final pipe. conversion adds
 * the required double NUL without changing the input:
 *
 * @verbatim
 * caller : "Text (*.txt)|*.txt|All (*)|*.*|"
 *              | copy, then replace every '|' with '\0'
 *              v   (+ implicit trailing '\0' from c_str())
 * buffer : Text (*.txt)\0*.txt\0All (*)\0*.*\0\0
 * @endverbatim
 *
 * @warning omitting the trailing pipe lets Win32 read past the filter buffer.
 */

/**
 * @brief select an existing file; the caller must still handle later open failure.
 * @ingroup NativeDialogs
 *
 * @param filter pipe-separated pairs ending in a pipe.
 * @return selected path; empty on cancellation or failure.
 */
[[nodiscard]] QString OpenFileDialog(const QString& title, const QString& filter);

/**
 * @brief choose a save path and confirm an existing target without writing it.
 * @ingroup NativeDialogs
 *
 * the initial name is `.seal`; extensionless input gains that suffix. callers
 * that require `.seal` for every name must enforce it themselves.
 *
 * @param filter pipe-separated pairs ending in a pipe.
 * @return selected path; empty on cancellation or failure.
 */
[[nodiscard]] QString SaveFileDialog(const QString& title, const QString& filter);

/**
 * @brief choose a filesystem folder; exclude virtual shell locations.
 * @ingroup NativeDialogs
 *
 * @return selected path; empty on cancellation or failure.
 * @pre COM is initialized on the GUI thread.
 */
[[nodiscard]] QString OpenFolderDialog(const QString& title);

}  // namespace seal

#endif  // USE_QT_UI
