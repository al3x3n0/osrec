/* Capture adapter, not original kernel code. Include after los_process_pri.h.
 * The caller holds the scheduler lock and restores the parent's field once
 * after the batch. The original helper performs every captured write.
 */
#ifndef OSREC_PARENT_ARGUMENT_ADAPTER_H
#define OSREC_PARENT_ARGUMENT_ADAPTER_H
STATIC INLINE VOID OsrecParentExitSignalSet(LosProcessCB *processCB, UINT32 signal)
{
    OsProcessExitCodeSignalSet(processCB->parentProcess, signal);
}
#endif
