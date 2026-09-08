(in-package #:image-daemon)

(defparameter *daemon-thread-stop-timeout-seconds*
  1
  "The total seconds allowed for graceful exit and forced termination of one thread.")

(defun daemon-stop-thread (thread)
  "Stop and reap THREAD within one deadline, unless it is NIL or the caller.

Allow half the budget for graceful exit and the remainder after termination.
An unreaped thread signals DAEMON-ERROR with operation :STOP-THREAD. Its cause
is a JOIN-THREAD-ERROR retaining the target through SB-THREAD:THREAD-ERROR-THREAD;
release the blocked cleanup and retry this operation to finish reaping it."
  (when (and thread (not (eq thread (bordeaux-threads:current-thread))))
    (let* ((timeout *daemon-thread-stop-timeout-seconds*)
           (deadline (+ (get-internal-real-time)
                        (* timeout internal-time-units-per-second)))
           (failure (daemon--join-thread thread (/ timeout 2))))
      (when (and failure (eq (sb-thread:join-thread-problem failure) ':timeout))
        (handler-case (sb-thread:terminate-thread thread)
          (sb-thread:interrupt-thread-error () nil))
        (setf failure
              (daemon--join-thread
               thread (max 0 (/ (- deadline (get-internal-real-time))
                                internal-time-units-per-second)))))
      (when failure
        (daemon-fail :message "The transport thread could not be reaped before its deadline."
                     :operation ':stop-thread :cause failure))))
  nil)

(defun daemon--join-thread (thread timeout)
  "Return NIL after joining THREAD, otherwise its structured join failure."
  (handler-case
      (progn (sb-thread:join-thread thread :timeout timeout) nil)
    (sb-thread:join-thread-error (condition)
      (unless (eq (sb-thread:join-thread-problem condition) ':abort)
        condition))))
