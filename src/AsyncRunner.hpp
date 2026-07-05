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
 * @ingroup ViewModel
 *
 * Returned by AsyncRunner::run / AsyncRunner::runCancellable. Cheap to copy: every copy
 * shares ownership of the same cancellation flag, so cancel() may be called from any of
 * them. A default-constructed handle is not valid() and cancel() on it is a no-op.
 */
class AsyncHandle
{
public:
    AsyncHandle() = default;

    /// @brief Request cancellation; the work body must poll its CancellationToken.
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
 * @brief Runs background work on a dedicated thread pool and delivers completion on the GUI thread.
 * @ingroup ViewModel
 *
 * Replaces hand-rolled QThread::create workers: `run`/`runCancellable` launch @p work on the pool,
 * then invoke `onDone(result)` on the GUI thread via a per-call QFutureWatcher bound to @p receiver
 * (so the completion is auto-skipped if @p receiver is destroyed first). The destructor cancels all
 * live tasks then `waitForDone()`s - a clean join, no `terminate()`.
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
 * If @p receiver is destroyed before `finished`, the connection is dropped and `onDone` is skipped;
 * the flag lingers in m_LiveFlags until the destructor cancels and joins.
 *
 * @warning `QtConcurrent::run` decay-copies the callable, so @p work and @p onDone must be
 * COPYABLE. Capture secrets via `std::shared_ptr<SecureWide>`, never a moved SecureWide. @p work
 * must cleanse the secret itself and return only a non-secret result.
 */
class AsyncRunner : public QObject
{
    Q_OBJECT

public:
    explicit AsyncRunner(QObject* parent = nullptr);
    ~AsyncRunner() override;

    /**
     * @brief Run @p work on the pool; deliver `onDone(result)` on @p receiver's thread.
     *
     * @param receiver  Context object whose thread runs `onDone`; destroying it skips delivery.
     * @param work      Copyable nullary callable run on the pool; its result type is deduced.
     * @param onDone    Copyable callable invoked as `onDone(result)` when @p work completes.
     * @return A handle the caller may cancel().
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
     * @param receiver  Context object whose thread runs `onDone`; destroying it skips delivery.
     * @param work      Copyable callable taking the CancellationToken; it polls the token and
     *                  returns early once cancellation is requested.
     * @param onDone    Copyable callable invoked as `onDone(result)` when @p work completes.
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
        m_LiveFlags.push_back(flag);  // GUI-thread only; no lock
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
                             std::erase(m_LiveFlags, flag);  // prune; GUI-thread only
                             watcher->deleteLater();
                         });
        watcher->setFuture(future);
    }

    QThreadPool m_Pool;  ///< Private worker pool; the destructor joins it via waitForDone().
    /// Live per-task cancellation flags, pruned on completion. Touched on the GUI thread only,
    /// so it needs no lock.
    std::vector<std::shared_ptr<std::atomic<bool>>> m_LiveFlags;
};
}  // namespace seal

#endif  // USE_QT_UI
