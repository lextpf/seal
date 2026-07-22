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
 * @brief Filtered, sorted view of the vault records for the QML list.
 * @author Alex (https://github.com/lextpf)
 * @ingroup VaultModel
 *
 * Presents the in-memory vault as a flat list a QML `ListView` or `Repeater`
 * binds to directly. Each row carries the cleartext platform name, fixed masked
 * placeholders, and the real index into the backing `std::vector<VaultRecord>`.
 * The model borrows that vector through setRecords(): it owns no record data
 * and never mutates it. Every mutation goes through AppViewModel.
 *
 * QML sees the `count` property and the roles below, and nothing else: the
 * model exposes no invokable methods, and a source-scan test enforces that.
 *
 * ## :material-filter: Row pipeline
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
 * setFilter() matches a case-insensitive substring against the stored platform
 * string, not against the DisplayPlatform label: the filter `com` still matches
 * a record whose chip reads `github`. An empty filter keeps every non-deleted
 * record. Ordering runs over the survivors of the filter. Both steps rerun on
 * every refresh(), so a row number is valid only until the next one.
 *
 * ## :material-sync: Model updates and staleness
 *
 * The model never observes its owner. Call refresh() after any mutation (add,
 * edit, delete, load, save): it runs one `beginResetModel` / `endResetModel`
 * cycle that invalidates every QModelIndex and every row index handed out
 * earlier. A successful CredentialWorkspace::save() needs one too: it erases
 * soft-deleted records and shifts later indices without bumping the generation
 * counter.
 *
 * setRecords() borrows the owner's generation counter, and refresh() snapshots
 * it. While the live counter differs from that snapshot the row-to-record map
 * is stale, so data() returns an invalid QVariant for every row instead of
 * reading a shifted record. A null counter disables the check.
 *
 * @par Roles exposed to QML
 * | Roles enum      | roleNames() key   | data() returns                    | Secret |
 * |-----------------|-------------------|-----------------------------------|--------|
 * | Platform        | `platform`        | cleartext platform name           | no     |
 * | MaskedUsername  | `maskedUsername`  | 8 U+2022 glyphs (fixed)           | masked |
 * | MaskedPassword  | `maskedPassword`  | 12 U+2022 glyphs (fixed)          | masked |
 * | RecordIndex     | `recordIndex`     | real index into the record vector | n/a    |
 * | BrandIconPath   | `brandIconPath`   | qrc brand-icon path, or empty     | no     |
 * | SiteBinding     | `siteBinding`     | strict browser host, or empty     | no     |
 * | DisplayPlatform | `displayPlatform` | registrable label, no suffix      | no     |
 *
 * The masked roles return a fixed-width run of U+2022 bullet characters that is
 * independent of the real secret length; plaintext never reaches QML.
 *
 * @note Not internally synchronised, and Qt models are GUI-thread objects: call
 *       this model only on the thread that owns the view.
 *
 * @see AppViewModel, CredentialWorkspace
 */
class VaultListModel : public QAbstractListModel
{
    Q_OBJECT
    Q_PROPERTY(int count READ count NOTIFY countChanged)

public:
    /// @enum Roles
    /// @brief Custom data roles for vault record display.
    /// Numbering starts at Qt::UserRole + 1; data() serves no standard Qt role.
    enum class Roles
    {
        Platform = Qt::UserRole + 1,  ///< Cleartext service/platform name.
        MaskedUsername,               ///< Fixed bullet-dot placeholder for username.
        MaskedPassword,               ///< Fixed bullet-dot placeholder for password.
        RecordIndex,                  ///< Real index for decrypt-on-demand lookups.
        BrandIconPath,                ///< qrc path for the resolved brand icon, or empty.
        SiteBinding,                  ///< Strict browser-binding host, or empty.
        DisplayPlatform               ///< Registrable chip label; subdomains and suffix removed.
    };

    /// @enum SortMode
    /// @brief Visual ordering for the filtered chip grid.
    /// @note GroupedByBrand resolves brand membership inside the comparator and
    ///       caches nothing, so it adds about 2*n*log2(n) BrandIconResolver
    ///       lookups to every refresh(); the other two modes add none. Each
    ///       lookup probes a qrc index that is built once, so it costs a hash
    ///       probe, not file I/O.
    enum class SortMode
    {
        Alphabetical = 0,    ///< Platform name A to Z (case-insensitive).
        ReverseAlpha = 1,    ///< Platform name Z to A (case-insensitive).
        GroupedByBrand = 2,  ///< Records with a resolved brand icon first, then unbranded, each
                             ///< group sorted alphabetically.
    };

    /// @brief Construct an empty model with no backing data and no filter.
    explicit VaultListModel(QObject* parent = nullptr);

    /**
     * @brief Number of visible (filtered) rows.
     * @param parent Must be an invalid index; the list is flat, so a valid
     *               parent has no children.
     * @return Number of rows that pass the filter, or 0 when @p parent is valid.
     */
    int rowCount(const QModelIndex& parent = QModelIndex()) const override;

    /**
     * @brief Value of @p role for the row at @p index.
     *
     * BrandIconPath, SiteBinding and DisplayPlatform are recomputed on every
     * call and never cached. SiteBinding passes an empty record span, so it
     * never reports a duplicate count and never scans the other records.
     *
     * @param index Model index whose row is read; the column is ignored.
     * @param role  One of the Roles values, cast to int.
     * @return Role value, or an invalid QVariant when @p index is out of range,
     *         when no record vector is attached, when the generation counter
     *         differs from the last refresh() snapshot, when the mapped record
     *         index is out of range, or when @p role is not a Roles value. No
     *         standard Qt role is served, Qt::DisplayRole included.
     */
    QVariant data(const QModelIndex& index, int role = Qt::DisplayRole) const override;

    /**
     * @brief Map Roles values to the QML role name strings.
     * @return The Roles-to-key mapping listed in the class table.
     */
    QHash<int, QByteArray> roleNames() const override;

    /**
     * @brief Attach the backing record store (non-owning pointer).
     *
     * Snapshots @p ownerGeneration and calls refresh(), so the view repopulates
     * immediately. A null @p records detaches the model and leaves zero rows.
     *
     * @param records         Record vector to borrow. It must outlive this model
     *                        and keep a stable address; may be null.
     * @param ownerGeneration Owner's monotonic mutation counter to borrow, or
     *                        null to disable the staleness check. When it is
     *                        non-null and the counter moves without a refresh(),
     *                        data() reports every row as invalid.
     */
    void setRecords(const std::vector<seal::VaultRecord>* records,
                    const uint64_t* ownerGeneration = nullptr);

    /**
     * @brief Set the platform-name filter text.
     *
     * Matching is a case-insensitive substring test against the stored platform
     * string. A @p filter equal to the current one is a no-op; otherwise the
     * model resets through refresh().
     *
     * @param filter Substring to match; an empty string shows all non-deleted
     *               records.
     */
    void setFilter(const QString& filter);

    /**
     * @brief Set the visual ordering applied after filtering.
     *
     * The parameter is an int because the value reaches this model from QML
     * through AppViewModel. A value that is not a SortMode enumerator becomes
     * SortMode::Alphabetical. An unchanged mode is a no-op; otherwise the model
     * resets through refresh().
     *
     * @param mode SortMode enumerator value as an int.
     */
    void setSortMode(int mode);

    /**
     * @brief Active ordering mode.
     * @return The current SortMode as an int; always a valid enumerator, even
     *         after setSortMode() received an out-of-range value.
     */
    int sortMode() const;

    /**
     * @brief Re-filter, re-order, and notify the attached views.
     *
     * Re-snapshots the owner's generation counter, then runs one
     * beginResetModel/endResetModel cycle. Every QModelIndex and every row
     * index taken before the call is invalid afterwards. countChanged() fires
     * only when the visible row count changed, so an in-place edit repaints
     * through the reset but reports no count change.
     */
    void refresh();

    /**
     * @brief Number of visible (filtered) records.
     * @return The same value as rowCount() for the root index.
     */
    int count() const;

    /**
     * @brief Map a filtered-model row to the real record index.
     * @param row Row index in the filtered view.
     * @return Index into the backing `std::vector<VaultRecord>`, or -1 when
     *         @p row is out of range. Row numbering changes on every refresh(),
     *         so map again after each one; the record index itself stays valid
     *         until the owner mutates the vector.
     */
    int recordIndexForRow(int row) const;

    /**
     * @brief Map a real record index back to its visible (filtered) row.
     *
     * Linear scan over the filtered rows; cost is O(visible rows).
     *
     * @param recordIndex Index into the backing `std::vector<VaultRecord>`.
     * @return Row in the filtered view, or -1 when that record is filtered out,
     *         soft-deleted, or out of range.
     * @note Not exposed to QML, which never resolves indices. AppViewModel uses
     *       it to highlight an auto-armed record.
     */
    int rowForRecordIndex(int recordIndex) const;

signals:
    /// @brief Emitted from refresh() only when the visible row count changed.
    void countChanged();

private:
    /// @brief Rebuild m_FilteredIndices: drop deleted and non-matching records,
    /// then order the survivors per m_SortMode.
    void rebuildFilteredIndices();

    const std::vector<seal::VaultRecord>* m_Records = nullptr;  ///< Borrowed record vector or null.
    const uint64_t* m_OwnerGeneration = nullptr;  ///< Owner's mutation counter (null = unchecked).
    uint64_t m_SnapshotGeneration = 0;   ///< Generation at the last refresh(); stale = blank rows.
    QString m_Filter;                    ///< Case-insensitive substring; empty shows every record.
    std::vector<int> m_FilteredIndices;  ///< Visible row -> index into the borrowed vector.
    SortMode m_SortMode = SortMode::Alphabetical;  ///< Ordering applied after filtering.
};

}  // namespace seal

#endif  // USE_QT_UI
