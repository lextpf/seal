#ifdef USE_QT_UI

#include "AsyncRunner.hpp"

namespace seal
{
AsyncRunner::AsyncRunner(QObject* parent)
    : QObject(parent)
{
}

AsyncRunner::~AsyncRunner()
{
    // Cooperative cancel of everything still in flight, then a clean join - no terminate().
    for (const auto& flag : m_LiveFlags)
    {
        flag->store(true, std::memory_order_release);
    }
    m_Pool.waitForDone();
}
}  // namespace seal

#endif  // USE_QT_UI
