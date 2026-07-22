#ifdef USE_QT_UI

#include "VaultModel.hpp"

#include <algorithm>
#include <span>

#include "AutoStagePolicy.hpp"
#include "BrandIconResolver.hpp"
#include "Diagnostics.hpp"
#include "Logging.hpp"

namespace seal
{

VaultListModel::VaultListModel(QObject* parent)
    : QAbstractListModel(parent)
{
}

// m_FilteredIndices maps visible row -> real m_Records index, so its size is the
// row count: QML sees only the non-deleted, filter-matching subset while record
// storage stays stable. The list is flat, so a valid parent asks for children
// and has none.
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
    // The row->record map is stale once the owner mutates without a refresh().
    // Report every row as empty rather than read a shifted record; refresh()
    // re-syncs the snapshot and restores the rows.
    if (m_OwnerGeneration && *m_OwnerGeneration != m_SnapshotGeneration)
        return {};

    // Translate visible row -> real record index.
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
        case static_cast<int>(Roles::BrandIconPath):
            return seal::brand::resolveBrandIconPath(QString::fromUtf8(rec.platform.c_str()));
        case static_cast<int>(Roles::SiteBinding):
        {
            // The chip needs only bindable/unbindable state. Duplicate
            // detection belongs to the account dialog; doing it here would scan
            // the record vector once per chip on every full model render.
            const auto preview =
                seal::previewSiteBinding(std::span<const seal::VaultRecord>{}, rec.platform);
            return QString::fromStdString(preview.m_Host);
        }
        case static_cast<int>(Roles::DisplayPlatform):
            return QString::fromStdString(seal::url::platformDisplayName(rec.platform));
        default:
            return {};
    }
}

QHash<int, QByteArray> VaultListModel::roleNames() const
{
    return {{static_cast<int>(Roles::Platform), "platform"},
            {static_cast<int>(Roles::MaskedUsername), "maskedUsername"},
            {static_cast<int>(Roles::MaskedPassword), "maskedPassword"},
            {static_cast<int>(Roles::RecordIndex), "recordIndex"},
            {static_cast<int>(Roles::BrandIconPath), "brandIconPath"},
            {static_cast<int>(Roles::SiteBinding), "siteBinding"},
            {static_cast<int>(Roles::DisplayPlatform), "displayPlatform"}};
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

void VaultListModel::setSortMode(int mode)
{
    // The mode arrives from QML as a plain int; anything outside the enum
    // falls back to Alphabetical instead of producing an invalid SortMode.
    SortMode coerced = SortMode::Alphabetical;
    if (mode == static_cast<int>(SortMode::ReverseAlpha))
    {
        coerced = SortMode::ReverseAlpha;
    }
    else if (mode == static_cast<int>(SortMode::GroupedByBrand))
    {
        coerced = SortMode::GroupedByBrand;
    }
    if (coerced == m_SortMode)
    {
        return;
    }
    m_SortMode = coerced;
    qCDebug(logBackend).noquote() << QString::fromStdString(seal::diag::joinFields(
        {"event=model.sort.set", seal::diag::kv("mode", static_cast<int>(m_SortMode))}));
    refresh();
}

int VaultListModel::sortMode() const
{
    return static_cast<int>(m_SortMode);
}

void VaultListModel::refresh()
{
    int oldCount = (int)m_FilteredIndices.size();
    // Sync the generation snapshot; the owner bumps before calling refresh().
    if (m_OwnerGeneration)
        m_SnapshotGeneration = *m_OwnerGeneration;
    // The reset tells QML to discard cached state and re-query every row.
    // Simpler than fine-grained insert/remove signals and fast enough at this
    // data size.
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

int VaultListModel::rowForRecordIndex(int recordIndex) const
{
    for (int row = 0; row < (int)m_FilteredIndices.size(); ++row)
    {
        if (m_FilteredIndices[row] == recordIndex)
            return row;
    }
    return -1;
}

// Collect non-deleted, filter-matching record indices into m_FilteredIndices
// (the row->record map QML sees), then order them per m_SortMode. Alphabetical
// sorts are case-insensitive; grouped-by-brand partitions on BrandIconResolver
// and sorts alphabetically within each partition.
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
        m_FilteredIndices.push_back((int)i);
    }

    const auto platformAt = [this](int idx)
    { return QString::fromUtf8((*m_Records)[idx].platform.c_str()); };
    const auto compareAlpha = [&platformAt](int lhs, int rhs)
    { return QString::compare(platformAt(lhs), platformAt(rhs), Qt::CaseInsensitive) < 0; };

    switch (m_SortMode)
    {
        case SortMode::Alphabetical:
        {
            std::sort(m_FilteredIndices.begin(), m_FilteredIndices.end(), compareAlpha);
            break;
        }
        case SortMode::ReverseAlpha:
        {
            std::sort(m_FilteredIndices.begin(),
                      m_FilteredIndices.end(),
                      [&compareAlpha](int lhs, int rhs) { return compareAlpha(rhs, lhs); });
            break;
        }
        case SortMode::GroupedByBrand:
        {
            const auto hasBrand = [&platformAt](int idx)
            { return !seal::brand::resolveBrandIconPath(platformAt(idx)).isEmpty(); };
            std::sort(m_FilteredIndices.begin(),
                      m_FilteredIndices.end(),
                      [&hasBrand, &compareAlpha](int lhs, int rhs)
                      {
                          const bool leftBrand = hasBrand(lhs);
                          const bool rightBrand = hasBrand(rhs);
                          if (leftBrand != rightBrand)
                          {
                              return leftBrand;
                          }
                          return compareAlpha(lhs, rhs);
                      });
            break;
        }
    }
}

}  // namespace seal

#endif  // USE_QT_UI
