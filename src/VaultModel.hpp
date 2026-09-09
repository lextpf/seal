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
 * @brief Present borrowed vault records as filtered, sorted, non-secret QML rows.
 * @author Alex (<https://github.com/lextpf>)
 * @ingroup VaultModel
 *
 * @verbatim
 *   backing vector        rebuildFilteredIndices()        QML rows
 *   +------------------+  +--------------------+  +---------------------+
 *   | 0 github.com     |  | drop deleted       |  | row 0 -> record 2   |
 *   | 1 (deleted)      |->| drop filter misses |->| row 1 -> record 0   |
 *   | 2 aws.amazon.com |  | order per SortMode |  +---------------------+
 *   +------------------+  +--------------------+   m_FilteredIndices
 * @endverbatim
 *
 * Filtering matches stored platform names, so `com` matches a chip labeled `github`.
 * Refresh after every mutation, including save: erasing soft deletes shifts record
 * indices without a generation bump. Refresh invalidates all QModelIndex and row values.
 * Until refreshed, a changed generation makes `data()` return invalid values.
 * Row counts and mapping helpers still use the last snapshot; they do not validate
 * the generation. Refresh before using a mapped index to select or mutate a record.
 *
 * | Role            | QML key           | Value                            |
 * |-----------------|-------------------|----------------------------------|
 * | Platform        | `platform`        | Plaintext platform label         |
 * | MaskedUsername  | `maskedUsername`  | 8 U+2022 bullets                 |
 * | MaskedPassword  | `maskedPassword`  | 12 U+2022 bullets                |
 * | RecordIndex     | `recordIndex`     | Full record index                |
 * | BrandIconPath   | `brandIconPath`   | Resource path or empty           |
 * | SiteBinding     | `siteBinding`     | Strict browser host or empty     |
 * | DisplayPlatform | `displayPlatform` | Registrable label without suffix |
 *
 * Masks do not depend on secret length. The model exposes no invokable methods
 * and never decrypts or mutates credentials.
 *
 * @pre Call only on the view's owning thread.
 */
class VaultListModel : public QAbstractListModel
{
    Q_OBJECT
    Q_PROPERTY(int count READ count NOTIFY countChanged)

public:
    /**
     * @enum Roles
     * @brief Custom roles start at Qt::UserRole + 1; standard Qt roles are unsupported.
     */
    enum class Roles
    {
        Platform = Qt::UserRole + 1,
        MaskedUsername,
        MaskedPassword,
        RecordIndex,
        BrandIconPath,  ///< Resource path for the resolved brand icon, or empty.
        SiteBinding,
        DisplayPlatform
    };

    /**
     * @enum SortMode
     * @brief Ordering of the filtered rows.
     *
     * GroupedByBrand resolves both compared labels during sorting. The resource
     * index is built once; subsequent lookups perform no file I/O.
     */
    enum class SortMode
    {
        Alphabetical = 0,    ///< Platform name A to Z (case-insensitive).
        ReverseAlpha = 1,    ///< Platform name Z to A (case-insensitive).
        GroupedByBrand = 2,  ///< Branded records first; each group sorts alphabetically.
    };

    explicit VaultListModel(QObject* parent = nullptr);

    /**
     * @fn int rowCount(const QModelIndex& parent = QModelIndex()) const override
     * @brief A valid parent has zero children because the model is flat.
     * @author Alex (<https://github.com/lextpf>)
     */
    int rowCount(const QModelIndex& parent = QModelIndex()) const override;

    /**
     * @fn QVariant data(const QModelIndex& index, int role = Qt::DisplayRole) const override
     * @brief Read a role without caching derived brand, host or display labels.
     * @author Alex (<https://github.com/lextpf>)
     *
     * SiteBinding avoids duplicate scans by using an empty record span.
     *
     * @param index Column is ignored.
     * @return Invalid for missing records, stale generation, invalid row/record index
     *         or unsupported role, including Qt::DisplayRole.
     */
    QVariant data(const QModelIndex& index, int role = Qt::DisplayRole) const override;

    QHash<int, QByteArray> roleNames() const override;

    /**
     * @fn void setRecords(const std::vector<seal::VaultRecord>* records, const uint64_t*
     *     ownerGeneration = nullptr)
     * @brief Borrow the record store and refresh immediately.
     * @author Alex (<https://github.com/lextpf>)
     *
     * @param records Borrowed vector at a stable address until detachment or model
     *                destruction; null detaches.
     * @param ownerGeneration Borrowed counter that outlives this model or the next
     *                        setRecords() call; null disables stale-generation checks.
     */
    void setRecords(const std::vector<seal::VaultRecord>* records,
                    const uint64_t* ownerGeneration = nullptr);

    /**
     * @fn void setFilter(const QString& filter)
     * @brief Filter live records by a case-insensitive platform substring.
     * @author Alex (<https://github.com/lextpf>)
     *
     * Refresh only when the filter changes.
     *
     * @param filter Empty shows all live records.
     */
    void setFilter(const QString& filter);

    /**
     * @fn void setSortMode(int mode)
     * @brief Invalid modes select Alphabetical; refresh only on change.
     * @author Alex (<https://github.com/lextpf>)
     */
    void setSortMode(int mode);

    /**
     * @fn int sortMode() const
     * @brief Read the normalized row-ordering mode.
     * @author Alex (<https://github.com/lextpf>)
     *
     * @return A valid SortMode enumerator encoded as an integer.
     */
    int sortMode() const;

    /**
     * @fn void refresh()
     * @brief Snapshot generation and reset the model, invalidating all prior row indices.
     * @author Alex (<https://github.com/lextpf>)
     *
     * Emit `countChanged()` only when the visible count changes.
     */
    void refresh();

    int count() const;

    /**
     * @fn int recordIndexForRow(int row) const
     * @brief Map a visible row to its backing record; -1 when out of range.
     * @author Alex (<https://github.com/lextpf>)
     *
     * Map again after refresh. Record indices survive only until the next owner mutation.
     */
    int recordIndexForRow(int row) const;

    /**
     * @fn int rowForRecordIndex(int recordIndex) const
     * @brief Find a record in the current row snapshot.
     * @author Alex (<https://github.com/lextpf>)
     *
     * Scan visible rows in linear time. Refresh after a workspace mutation before
     * using this mapping; the helper does not check the generation.
     *
     * @param recordIndex Full record index in the current workspace.
     * @return Visible row, or -1 if the snapshot contains no matching index.
     */
    int rowForRecordIndex(int recordIndex) const;

signals:
    void countChanged();

private:
    void rebuildFilteredIndices();

    const std::vector<seal::VaultRecord>* m_Records = nullptr;  ///< Borrowed record vector or null.
    const uint64_t* m_OwnerGeneration = nullptr;  ///< Owner's mutation counter (null = unchecked).
    uint64_t m_SnapshotGeneration = 0;  ///< Generation at the last refresh(); stale = blank rows.
    QString m_Filter;
    std::vector<int> m_FilteredIndices;  ///< Visible row -> index into the borrowed vector.
    SortMode m_SortMode = SortMode::Alphabetical;
};

}  // namespace seal

#endif  // USE_QT_UI
