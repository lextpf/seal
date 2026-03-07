#pragma once

#ifdef USE_QT_UI

#include <QAbstractListModel>
#include <QString>

#include <vector>

#include "Cryptography.h"
#include "Vault.h"

namespace seal
{

/**
 * @class VaultListModel
 * @brief QAbstractListModel subclass that provides filtered vault records
 *        to the QML view layer.
 * @author Alex (https://github.com/lextpf)
 * @ingroup VaultModel
 *
 * Presents the in-memory vault as a flat, filterable list that QML
 * `ListView` / `Repeater` can bind to directly. Each row exposes
 * the cleartext platform name, masked username/password placeholders,
 * and the real index into the backing `std::vector<VaultRecord>`.
 *
 * ## :material-filter: Filtering
 *
 * setFilter() applies a case-insensitive substring match on the
 * platform name.  Matching is performed in rebuildFilteredIndices(),
 * which rebuilds a compact index vector so QML only sees the rows
 * that pass the filter. An empty filter string shows all non-deleted
 * records.
 *
 * ## :material-sync: Model Updates
 *
 * The model does not own the record data; it holds a non-owning
 * pointer set via setRecords(). Call refresh() after any mutation
 * (add, edit, delete, load) to trigger a full `beginResetModel` /
 * `endResetModel` cycle, which re-filters and notifies all attached
 * views.
 *
 * ## :material-format-list-numbered: Roles
 *
 * Custom roles are defined in the `Roles` enum class and exposed
 * to QML via roleNames():
 * - **Platform** - cleartext service name
 * - **MaskedUsername** - fixed asterisk placeholder
 * - **MaskedPassword** - fixed asterisk placeholder
 * - **RecordIndex** - real index for decrypt-on-demand lookups
 */
class VaultListModel : public QAbstractListModel
{
    Q_OBJECT
    Q_PROPERTY(int count READ count NOTIFY countChanged)

public:
    /// @brief Custom data roles for vault record display.
    enum class Roles
    {
        Platform = Qt::UserRole + 1,  ///< Cleartext service/platform name.
        MaskedUsername,               ///< Fixed asterisk placeholder for username.
        MaskedPassword,               ///< Fixed asterisk placeholder for password.
        RecordIndex                   ///< Real index for decrypt-on-demand lookups.
    };

    explicit VaultListModel(QObject* parent = nullptr);

    int rowCount(const QModelIndex& parent = QModelIndex()) const override;
    QVariant data(const QModelIndex& index, int role = Qt::DisplayRole) const override;
    QHash<int, QByteArray> roleNames() const override;

    /// @brief Set the backing record store (non-owning pointer).
    void setRecords(const std::vector<seal::VaultRecord>* records);

    /// @brief Set the current platform-name filter text.
    void setFilter(const QString& filter);

    /// @brief Force a full model reset (re-filter + notify views).
    void refresh();

    /// @brief Number of visible (filtered) records.
    int count() const;

    /// @brief Map a filtered-model row to the real record index.
    Q_INVOKABLE int recordIndexForRow(int row) const;

signals:
    void countChanged();

private:
    void rebuildFilteredIndices();

    const std::vector<seal::VaultRecord>* m_Records = nullptr;
    QString m_Filter;
    std::vector<int> m_FilteredIndices;
};

}  // namespace seal

#endif  // USE_QT_UI
