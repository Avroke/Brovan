using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtReleaseWorkerFactoryWorker : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong WorkerFactoryHandle = Instance.WinHelper.GetArg64(0);

            WinWorkerFactory Factory = WorkerFactoryHelper.GetFactory(Instance, WorkerFactoryHandle);
            if (Factory == null)
                return NTSTATUS.STATUS_INVALID_HANDLE;

            if (Factory.PendingReleaseCount == uint.MaxValue)
                return NTSTATUS.STATUS_UNSUCCESSFUL;

            Factory.PendingReleaseCount++;
            if (!Factory.ReleasePending)
            {
                Factory.ReleasePending = true;
                if (!WorkerFactoryHelper.EnqueueReleaseCompletion(Instance, WorkerFactoryHandle))
                {
                    Factory.ReleasePending = false;
                    Factory.PendingReleaseCount--;
                    return NTSTATUS.STATUS_INVALID_HANDLE;
                }
            }

            WorkerFactoryHelper.EnsureWorkerThreads(Instance, Factory);

            // The release enqueued work onto the factory's completion queue but signalled no waitable
            // object. Wake a worker already parked in NtWaitForWorkViaWorkerFactory so it re-runs its
            // wait, dequeues the release, and executes the queued work — otherwise a parked worker
            // stays blocked forever (INFINITE) and the released work never runs, deadlocking the .NET
            // thread pool during runtime startup. (EnsureWorkerThreads only creates *new* workers; it
            // does not wake existing parked ones.)
            Instance.WakeWorkerFactoryWaitersForFactory(WorkerFactoryHandle);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
