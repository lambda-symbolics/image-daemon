(in-package #:image-daemon)

;;;; -- Supervised Process Ownership --

(define-condition handoff-process-error (daemon-error)
  ((code
    :initarg       :code
    :reader        handoff-process-error-code
    :documentation "The native operating-system error code."))
  (:documentation "A native supervised-process operation failed."))

(defgeneric handoff-process-id (process)
  (:documentation "Return PROCESS's native root identifier."))

(defgeneric handoff-process-alive-p (process)
  (:documentation "Return true while PROCESS is active.
On Windows this includes every descendant in the owned job."))

(defgeneric handoff-process-terminate (process &key force)
  (:documentation "Terminate PROCESS and the replacement tree it owns."))

(defgeneric handoff-process-wait (process)
  (:documentation "Wait for PROCESS to finish and release owned resources.
Return the supervisor's exit status on POSIX, or T on Windows."))

(defgeneric handoff-process-release (process)
  (:documentation "Release this caller's native ownership without stopping PROCESS.
Repeated calls are harmless. A released Windows process cannot be managed further."))

#-win32
(defmethod handoff-process-id ((process t))
  "Return the UIOP supervisor's identifier."
  (uiop:process-info-pid process))

#-win32
(defmethod handoff-process-alive-p ((process t))
  "Return whether the UIOP supervisor is active."
  (not (null (uiop:process-alive-p process))))

#-win32
(defmethod handoff-process-terminate ((process t) &key force)
  "Terminate the existing POSIX supervisor, preserving its cleanup protocol."
  (uiop:terminate-process process :urgent force))

#-win32
(defmethod handoff-process-wait ((process t))
  "Reap the UIOP supervisor and return its exit status."
  (uiop:wait-process process))

#-win32
(defmethod handoff-process-release ((process t))
  "Leave the UIOP supervisor running without additional native ownership."
  (declare (ignore process))
  nil)
