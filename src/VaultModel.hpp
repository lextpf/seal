#pragma once

#ifdef USE_QT_UI

#include <QAbstractListModel>
#include <QString>

#include <vector>

#include "Cryptography.hpp"
#include "Vault.hpp"

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
 *
 * @see Backend
 */
class VaultListModel : public QAbstractListModel
{
    Q_OBJECT
    Q_PROPERTY(int count READ count NOTIFY countChanged)

public:
    /// @enum Roles
    /// @brief Custom data roles for vault record display.
    enum class Roles
    {
        Platform = Qt::UserRole + 1,  ///< Cleartext service/platform name.
        MaskedUsername,               ///< Fixed asterisk placeholder for username.
        MaskedPassword,               ///< Fixed asterisk placeholder for password.
        RecordIndex                   ///< Real index for decrypt-on-demand lookups.
    };

    /// @brief Construct the model with no backing data.
    explicit VaultListModel(QObject* parent = nullptr);

    /// @brief Return the number of visible (filtered) rows.
    int rowCount(const QModelIndex& parent = QModelIndex()) const override;

    /// @brief Return data for a given role at the specified model index.
    QVariant data(const QModelIndex& index, int role = Qt::DisplayRole) const override;

    /// @brief Map custom Roles enum values to QML role name strings.
    QHash<int, QByteArray> roleNames() const override;

    /// @brief Set the backing record store (non-owning pointer).
    /// @param records         Pointer to the vault record vector (must outlive this model, may be
    /// null).
    /// @param ownerGeneration Pointer to owner's monotonic mutation counter (may be null).
    void setRecords(const std::vector<seal::VaultRecord>* records,
                    const uint64_t* ownerGeneration = nullptr);

    /// @brief Set the current platform-name filter text.
    /// @param filter Substring to match (empty shows all non-deleted records).
    void setFilter(const QString& filter);

    /// @brief Force a full model reset (re-filter + notify views).
    void refresh();

    /// @brief Number of visible (filtered) records.
    int count() const;

    /// @brief Map a filtered-model row to the real record index.
    /// @param row Row index in the filtered view.
    /// @return Index into the backing `std::vector<VaultRecord>`, or -1 if out of range.
    Q_INVOKABLE int recordIndexForRow(int row) const;

signals:
    void countChanged();

private:
    void rebuildFilteredIndices();

    const std::vector<seal::VaultRecord>* m_Records = nullptr;
    const uint64_t* m_OwnerGeneration = nullptr;  ///< Owner's mutation counter (null = unchecked).
    uint64_t m_SnapshotGeneration = 0;  ///< Generation at last setRecords(); stale = skip.
    QString m_Filter;
    std::vector<int> m_FilteredIndices;
};

}  // namespace seal

#endif  // USE_QT_UI
