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
 * @brief Handle to one async task; lets the caller cooperatively cancel it.
 * @author Alex (https://github.com/lextpf)
 * @ingroup ViewModel
 *
 * Returned by AsyncRunner::run() and AsyncRunner::runCancellable(). Cheap to copy: every copy
 * shares one cancellation flag, so cancel() works from any copy on any thread. A
 * default-constructed handle is not valid() and cancel() on it does nothing.
 *
 * The handle carries no completion state and stays valid() after the task has finished.
 *
 * @warning cancel() only raises a flag. A run() body receives no CancellationToken and never
 * reads that flag, so cancelling such a handle does not stop the work. Only a runCancellable()
 * body can act on it.
 */
class AsyncHandle
{
public:
    AsyncHandle() = default;

    /// @brief Request cancellation; the work body must poll its CancellationToken.
    /// The flag is set with release ordering and is never cleared again.
    void cancel()
    {
        if (m_Flag)
        {
            m_Flag->store(true, std::memory_order_release);
        }
    }

    /// @brief Whether this handle refers to a (possibly already-finished) task.
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
 * @brief Runs background work on a private thread pool and delivers each result on the
 *        receiver's thread.
 * @author Alex (https://github.com/lextpf)
 * @ingroup ViewModel
 *
 * run() and runCancellable() launch the work body on the pool, then invoke `onDone(result)` on
 * `receiver`'s thread (the GUI thread at every call site) through a per-call QFutureWatcher.
 *
 * @par Marshalling flow
 * @verbatim
 *   GUI thread                          |  worker pool (m_Pool)
 *   ------------------------------------+--------------------
 *   run(receiver, work, onDone)         |
 *     makeFlag(), m_LiveFlags.push      |
 *     QtConcurrent::run(&m_Pool, work) -+--->  work()  --.
 *     return AsyncHandle(flag)          |                |
 *                                       |                | result (QFuture<T>)
 *     QFutureWatcher::finished  <-------+----------------'
 *     (runs on receiver's thread)       |
 *       onDone(future.takeResult())     |
 *       erase(m_LiveFlags, flag)        |
 *       watcher->deleteLater()          |
 * @endverbatim
 * The completion connection binds to `receiver`. If `receiver` dies first, `onDone` is skipped,
 * the flag stays in m_LiveFlags, and the watcher (parented to this runner) dies with the runner.
 *
 * @par Threading contract
 * run() and runCancellable() append to m_LiveFlags without a lock, so call both from the thread
 * that owns this AsyncRunner. The completion lambda erases the flag on `receiver`'s thread, so
 * `receiver` must have the same thread affinity: a receiver on another thread races run() and the
 * destructor on the unlocked vector. The pool is free-threaded; only the bookkeeping is not.
 *
 * @note The result type must not be `void`: the completion lambda calls `QFuture<T>::takeResult()`,
 *       which `QFuture<void>` does not provide. A body with nothing to report must return a
 *       placeholder value.
 *
 * @warning `QtConcurrent::run` decay-copies the callable, so the work body and `onDone` must be
 * copyable. Capture a secret as `std::shared_ptr<SecureWide>`, never a moved SecureWide. The work
 * body cleanses the secret itself and returns only a non-secret result.
 */
class AsyncRunner : public QObject
{
    Q_OBJECT

public:
    /// @brief Construct an idle runner that owns a private QThreadPool.
    explicit AsyncRunner(QObject* parent = nullptr);

    /// @brief Cancel every live task, then block until the pool is idle - a clean join, never a
    /// `terminate()`. A body that polls no token still runs to completion, and the destructor
    /// waits for it. `onDone` never runs for a task still in flight: no event loop runs during
    /// the join, and the watchers die with this runner. State that teardown must restore cannot
    /// live in `onDone` alone.
    ~AsyncRunner() override;

    /**
     * @brief Run @p work on the pool, then deliver its result on @p receiver's thread.
     *
     * @p work gets no CancellationToken here; use runCancellable() when the body must stop early.
     *
     * @param receiver Context object whose thread runs `onDone`; destroying it skips delivery.
     *                 It must have the same thread affinity as this AsyncRunner.
     * @param work     Copyable nullary callable. Its deduced result type must not be `void`.
     * @param onDone   Copyable callable invoked as `onDone(result)` when @p work completes.
     * @return A handle whose cancel() flag only the destructor reads, because a run() body
     *         polls nothing.
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
     * @brief As run(), but @p work receives a read-only CancellationToken it must poll.
     *
     * The token is copied into the pool task, so it stays valid for the whole run even when the
     * returned handle is discarded. `onDone` still runs after a cancelled body returns, so the
     * body must report the cancellation in its result value.
     *
     * @param receiver Context object whose thread runs `onDone`; destroying it skips delivery.
     *                 It must have the same thread affinity as this AsyncRunner.
     * @param work     Copyable callable taking the CancellationToken. It polls the token and
     *                 returns early once cancellation is requested. Its result must not be `void`.
     * @param onDone   Copyable callable invoked as `onDone(result)` when @p work completes.
     * @return A handle whose cancel() sets the token @p work polls.
     */
    template <typename Work, typename OnDone>
    AsyncHandle runCancellable(QObject* receiver, Work&& work, OnDone&& onDone)
    {
        using T = std::invoke_result_t<Work, CancellationToken>;
        auto flag = makeFlag();
        CancellationToken token(flag);  // shared_ptr<atomic> -> shared_ptr<const atomic> (implicit)
        QFuture<T> future = QtConcurrent::run(
            &m_Pool, [work = std::forward<Work>(work), token]() mutable { return work(token); });
        watch<T>(receiver, future, std::forward<OnDone>(onDone), flag);
        return AsyncHandle(flag);
    }

private:
    std::shared_ptr<std::atomic<bool>> makeFlag()
    {
        auto flag = std::make_shared<std::atomic<bool>>(false);
        m_LiveFlags.push_back(flag);  // runner thread only; no lock
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
                             std::erase(m_LiveFlags, flag);  // prune; runner thread only
                             watcher->deleteLater();
                         });
        watcher->setFuture(future);
    }

    QThreadPool m_Pool;  ///< Private worker pool; the destructor joins it via waitForDone().
    /// Live per-task cancellation flags, pruned on completion. Touched only on the runner's own
    /// thread (the GUI thread at every call site), so it needs no lock.
    std::vector<std::shared_ptr<std::atomic<bool>>> m_LiveFlags;
};
}  // namespace seal

#endif  // USE_QT_UI
