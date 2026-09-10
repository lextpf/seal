#pragma once

#ifdef USE_QT_UI

#include <QFutureWatcher>
#include <QObject>
#include <QtConcurrent/QtConcurrentRun>
#include <QThreadPool>

#include <atomic>
#include <memory>
#include <type_traits>
#include <utility>
#include <vector>

#include "CancellationToken.hpp"

namespace seal
{
/**
 * @class AsyncHandle
 * @brief Share a task cancellation flag across handles and threads.
 * @author Alex (<https://github.com/lextpf>)
 * @ingroup ViewModel
 *
 * Default handles are invalid; completed tasks retain valid handles. Cancellation
 * only requests a stop and requires a `runCancellable()` body that polls its token.
 */
class AsyncHandle
{
public:
    AsyncHandle() = default;

    /**
     * @fn void cancel()
     * @brief Request cancellation with release ordering; the flag never resets.
     * @author Alex (<https://github.com/lextpf>)
     */
    void cancel()
    {
        if (m_Flag)
        {
            m_Flag->store(true, std::memory_order_release);
        }
    }

    /**
     * @fn bool valid() const noexcept
     * @brief Report whether this handle holds a task cancellation flag.
     * @author Alex (<https://github.com/lextpf>)
     *
     * @return True for submitted tasks, including those that have already completed.
     */
    bool valid() const noexcept { return static_cast<bool>(m_Flag); }

private:
    friend class AsyncRunner;
    explicit AsyncHandle(std::shared_ptr<std::atomic<bool>> flag)
        : m_Flag(std::move(flag))
    {
    }
    std::shared_ptr<std::atomic<bool>> m_Flag;
};

/**
 * @class AsyncRunner
 * @brief Run work on a private pool and deliver results on the receiver thread.
 * @author Alex (<https://github.com/lextpf>)
 * @ingroup ViewModel
 *
 * Destroying the receiver skips completion; its flag and watcher remain until
 * runner destruction. Receiver destruction does not cancel the worker. Calls and
 * receivers must share the runner thread because task bookkeeping has no lock.
 *
 * Work and completion callables must be copyable, and results must not be void.
 * Capture secrets in shared locked buffers, cleanse them in the worker, and
 * return non-secret results. Workers must own everything they access after submission;
 * a receiver pointer in a capture does not keep that receiver alive.
 *
 * @verbatim
 *   Runner and receiver thread                 Worker pool
 *   run(receiver, work, onDone)
 *     create flag and watcher
 *     submit work ----------------------------> work()
 *     return handle                               |
 *                                                 | result
 *     watcher finished <--------------------------'
 *       onDone(result), if receiver is alive
 *       remove flag; schedule watcher deletion
 * @endverbatim
 */
class AsyncRunner : public QObject
{
    Q_OBJECT

public:
    explicit AsyncRunner(QObject* parent = nullptr);

    /**
     * @fn ~AsyncRunner()
     * @brief Request cancellation and block until all workers finish.
     * @author Alex (<https://github.com/lextpf>)
     *
     * Completion callbacks for in-flight tasks do not run during this join. Required
     * teardown must not depend on them; uncooperative workers delay destruction.
     */
    ~AsyncRunner() override;

    /**
     * @fn AsyncHandle run(QObject* receiver, Work&& work, OnDone&& onDone)
     * @brief Run work without a cancellation token.
     * @author Alex (<https://github.com/lextpf>)
     *
     * Cancelling the returned handle neither interrupts work nor suppresses completion.
     *
     * @param receiver Non-null; same thread affinity as this runner; destruction skips delivery.
     * @param work Copyable callable with a non-void result.
     * @param onDone Copyable result callback.
     * @return A valid handle for the task; its cancellation flag is not read by this worker.
     */
    template <typename Work, typename OnDone>
    AsyncHandle run(QObject* receiver, Work&& work, OnDone&& onDone)
    {
        using T = std::invoke_result_t<Work>;
        auto flag = makeFlag();
        QFuture<T> future = QtConcurrent::run(&m_Pool, std::forward<Work>(work));
        watch<T>(receiver, future, std::forward<OnDone>(onDone), flag);
        return AsyncHandle(flag);
    }

    /**
     * @fn AsyncHandle runCancellable(QObject* receiver, Work&& work, OnDone&& onDone)
     * @brief Pass a cancellation token to the worker.
     * @author Alex (<https://github.com/lextpf>)
     *
     * The token survives discarded handles. Completion still runs after cancellation;
     * the result must distinguish cancellation from success.
     *
     * @param receiver Non-null; same thread affinity as this runner; destruction skips delivery.
     * @param work Copyable callable that polls its token and returns a non-void result.
     * @param onDone Copyable result callback.
     * @return A handle that requests cooperative cancellation; discarding it does not cancel.
     */
    template <typename Work, typename OnDone>
    AsyncHandle runCancellable(QObject* receiver, Work&& work, OnDone&& onDone)
    {
        using T = std::invoke_result_t<Work, CancellationToken>;
        auto flag = makeFlag();
        CancellationToken token(flag);
        QFuture<T> future = QtConcurrent::run(
            &m_Pool, [work = std::forward<Work>(work), token]() mutable { return work(token); });
        watch<T>(receiver, future, std::forward<OnDone>(onDone), flag);
        return AsyncHandle(flag);
    }

private:
    std::shared_ptr<std::atomic<bool>> makeFlag()
    {
        auto flag = std::make_shared<std::atomic<bool>>(false);
        m_LiveFlags.push_back(flag);
        return flag;
    }

    template <typename T, typename OnDone>
    void watch(QObject* receiver,
               const QFuture<T>& future,
               OnDone&& onDone,
               const std::shared_ptr<std::atomic<bool>>& flag)
    {
        auto* watcher = new QFutureWatcher<T>(this);
        QObject::connect(watcher,
                         &QFutureWatcher<T>::finished,
                         receiver,
                         [this, watcher, flag, onDone = std::forward<OnDone>(onDone)]() mutable
                         {
                             onDone(watcher->future().takeResult());
                             std::erase(m_LiveFlags, flag);
                             watcher->deleteLater();
                         });
        watcher->setFuture(future);
    }

    QThreadPool m_Pool;  ///< Private worker pool; the destructor joins it via waitForDone().
    /// Runner-thread bookkeeping; completion removes finished flags.
    std::vector<std::shared_ptr<std::atomic<bool>>> m_LiveFlags;
};
}  // namespace seal

#endif  // USE_QT_UI
