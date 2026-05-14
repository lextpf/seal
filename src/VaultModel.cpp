#ifdef USE_QT_UI

#include "VaultModel.hpp"
#include "Diagnostics.hpp"
#include "Logging.hpp"

namespace seal
{

VaultListModel::VaultListModel(QObject* parent)
    : QAbstractListModel(parent)
{
}

// m_FilteredIndices maps visible model rows to indices in the real m_Records
// vector.  This lets QML see only the non-deleted, filter-matching subset
// while the underlying record storage stays stable (indices don't shift).
int VaultListModel::rowCount(const QModelIndex& parent) const
{
    if (parent.isValid())
        return 0;
    return (int)m_FilteredIndices.size();
}

QVariant VaultListModel::data(const QModelIndex& index, int role) const
{
    if (!index.isValid() || index.row() < 0 || index.row() >= (int)m_FilteredIndices.size())
        return {};
    if (!m_Records)
        return {};
    // Generation check: if the owner mutated the records since our last
    // setRecords() call, the filtered indices may reference stale storage.
    if (m_OwnerGeneration && *m_OwnerGeneration != m_SnapshotGeneration)
        return {};

    // Translate the QML-visible row number into the real record index.
    int realIdx = m_FilteredIndices[index.row()];
    if (realIdx < 0 || realIdx >= (int)m_Records->size())
        return {};

    const auto& rec = (*m_Records)[realIdx];

    switch (role)
    {
        case static_cast<int>(Roles::Platform):
            return QString::fromUtf8(rec.platform.c_str());
        case static_cast<int>(Roles::MaskedUsername):
            return QStringLiteral("\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022");
        case static_cast<int>(Roles::MaskedPassword):
            return QStringLiteral(
                "\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022");
        case static_cast<int>(Roles::RecordIndex):
            return realIdx;
        default:
            return {};
    }
}

QHash<int, QByteArray> VaultListModel::roleNames() const
{
    return {{static_cast<int>(Roles::Platform), "platform"},
            {static_cast<int>(Roles::MaskedUsername), "maskedUsername"},
            {static_cast<int>(Roles::MaskedPassword), "maskedPassword"},
            {static_cast<int>(Roles::RecordIndex), "recordIndex"}};
}

void VaultListModel::setRecords(const std::vector<seal::VaultRecord>* records,
                                const uint64_t* ownerGeneration)
{
    m_Records = records;
    m_OwnerGeneration = ownerGeneration;
    m_SnapshotGeneration = ownerGeneration ? *ownerGeneration : 0;
    refresh();
}

void VaultListModel::setFilter(const QString& filter)
{
    if (m_Filter == filter)
        return;
    m_Filter = filter;
    qCDebug(logBackend).noquote() << QString::fromStdString(
        seal::diag::joinFields({"event=model.filter.set",
                                seal::diag::kv("active", !filter.isEmpty()),
                                seal::diag::kv("filter_len", filter.toUtf8().size())}));
    refresh();
}

void VaultListModel::refresh()
{
    int oldCount = (int)m_FilteredIndices.size();
    // Sync the generation snapshot so data() doesn't reject requests as
    // stale. The owner bumps the counter before calling refresh(), so the
    // snapshot must be updated here to match.
    if (m_OwnerGeneration)
        m_SnapshotGeneration = *m_OwnerGeneration;
    // beginResetModel / endResetModel tells every connected QML view to
    // discard its cached state and re-query all rows.  This is simpler
    // (and fast enough for our data size) than emitting fine-grained
    // row-insert/remove signals when the filter or record set changes.
    beginResetModel();
    rebuildFilteredIndices();
    endResetModel();
    qCDebug(logBackend).noquote() << QString::fromStdString(
        seal::diag::joinFields({"event=model.refresh",
                                seal::diag::kv("previous_visible", oldCount),
                                seal::diag::kv("visible_count", m_FilteredIndices.size()),
                                seal::diag::kv("filter_active", !m_Filter.isEmpty())}));
    if ((int)m_FilteredIndices.size() != oldCount)
        emit countChanged();
}

int VaultListModel::count() const
{
    return (int)m_FilteredIndices.size();
}

int VaultListModel::recordIndexForRow(int row) const
{
    if (row < 0 || row >= (int)m_FilteredIndices.size())
        return -1;
    return m_FilteredIndices[row];
}

// Walk every record and collect the indices of those that are not deleted
// and match the current search filter.  The resulting m_FilteredIndices
// vector becomes the authoritative row-to-record mapping for QML.
void VaultListModel::rebuildFilteredIndices()
{
    m_FilteredIndices.clear();
    if (!m_Records)
        return;

    for (size_t i = 0; i < m_Records->size(); ++i)
    {
        const auto& rec = (*m_Records)[i];
        if (rec.deleted)
            continue;
        if (!m_Filter.isEmpty())
        {
            QString platform = QString::fromUtf8(rec.platform.c_str());
            if (!platform.contains(m_Filter, Qt::CaseInsensitive))
                continue;
        }
        // Store the real index so data() and recordIndexForRow() can map back.
        m_FilteredIndices.push_back((int)i);
    }
}

}  // namespace seal

#endif  // USE_QT_UI
