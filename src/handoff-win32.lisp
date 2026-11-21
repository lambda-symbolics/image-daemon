(in-package #:image-daemon)

(sb-alien:define-alien-type handoff-win32-wide-string
                            (sb-alien:c-string :external-format :ucs-2le))

(sb-alien:define-alien-type handoff-win32-handle (sb-alien:signed 64))

(sb-alien:define-alien-type handoff-win32-dword (sb-alien:unsigned 32))

(sb-alien:define-alien-type handoff-win32-bool sb-alien:int)

(sb-alien:define-alien-routine ("CloseHandle" handoff-win32--close-handle) handoff-win32-bool
                               (handle handoff-win32-handle))

(sb-alien:define-alien-routine ("CreateJobObjectW" handoff-win32--create-job-object)
                               handoff-win32-handle (security (* t))
                               (name handoff-win32-wide-string))

(sb-alien:define-alien-routine
 ("AssignProcessToJobObject" handoff-win32--assign-process-to-job-object) handoff-win32-bool
 (job handoff-win32-handle) (process handoff-win32-handle))

(sb-alien:define-alien-routine ("TerminateJobObject" handoff-win32--terminate-job-object)
                               handoff-win32-bool (job handoff-win32-handle)
                               (code handoff-win32-dword))

(sb-alien:define-alien-routine ("ResumeThread" handoff-win32--resume-thread)
                               handoff-win32-dword (thread handoff-win32-handle))

(sb-alien:define-alien-routine
 ("InitializeProcThreadAttributeList" handoff-win32--initialize-attributes) handoff-win32-bool
 (attributes (* t)) (count handoff-win32-dword) (flags handoff-win32-dword)
 (size (* (sb-alien:unsigned 64))))

(sb-alien:define-alien-routine ("UpdateProcThreadAttribute" handoff-win32--update-attribute)
                               handoff-win32-bool (attributes (* t))
                               (flags handoff-win32-dword) (attribute (sb-alien:unsigned 64))
                               (value (* t)) (size (sb-alien:unsigned 64)) (previous (* t))
                               (returned (* t)))

(sb-alien:define-alien-routine
 ("DeleteProcThreadAttributeList" handoff-win32--delete-attributes) sb-alien:void
 (attributes (* t)))

(sb-alien:define-alien-routine ("QueryInformationJobObject" handoff-win32--query-job)
                               handoff-win32-bool (job handoff-win32-handle)
                               (class sb-alien:int) (information (* t))
                               (size handoff-win32-dword) (returned (* t)))

(sb-alien:define-alien-routine ("SetInformationJobObject" handoff-win32--set-job)
                               handoff-win32-bool (job handoff-win32-handle)
                               (class sb-alien:int) (information (* t))
                               (size handoff-win32-dword))

(sb-alien:define-alien-routine ("CreateProcessW" handoff-win32--create-process)
                               handoff-win32-bool (application-name handoff-win32-wide-string)
                               (command-line handoff-win32-wide-string)
                               (process-security (* t)) (thread-security (* t))
                               (inherit-handles handoff-win32-bool)
                               (creation-flags handoff-win32-dword) (environment (* t))
                               (directory handoff-win32-wide-string) (startup-info (* t))
                               (process-information (* t)))

(sb-alien:define-alien-routine ("WaitForSingleObject" handoff-win32--wait-for-single-object)
                               handoff-win32-dword (handle handoff-win32-handle)
                               (milliseconds handoff-win32-dword))

(sb-alien:define-alien-routine ("CreateFileW" handoff-win32--create-file) handoff-win32-handle
                               (name handoff-win32-wide-string) (access handoff-win32-dword)
                               (share handoff-win32-dword) (security (* t))
                               (disposition handoff-win32-dword) (flags handoff-win32-dword)
                               (template handoff-win32-handle))

(sb-alien:define-alien-routine ("TerminateProcess" handoff-win32--terminate-process)
                               handoff-win32-bool (handle handoff-win32-handle)
                               (code handoff-win32-dword))

(sb-alien:define-alien-routine ("GetCurrentProcess" handoff-win32--get-current-process)
                               handoff-win32-handle)

(sb-alien:define-alien-routine ("DuplicateHandle" handoff-win32--duplicate-handle)
                               handoff-win32-bool (source-process handoff-win32-handle)
                               (source-handle handoff-win32-handle)
                               (target-process handoff-win32-handle)
                               (target-handle (* handoff-win32-handle))
                               (desired-access handoff-win32-dword)
                               (inherit-handle handoff-win32-bool)
                               (options handoff-win32-dword))

(defparameter *handoff-win32-invalid-handle*
  -1
  "The handle value CreateFileW and FindFirstFileW return on failure.")

(defparameter *handoff-win32-generic-read*
  2147483648
  "GENERIC_READ, which includes READ_CONTROL for security queries.")

(defparameter *handoff-win32-generic-write*
  1073741824
  "GENERIC_WRITE, which includes READ_CONTROL for security queries.")

(defparameter *handoff-win32-share-all*
  7
  "FILE_SHARE_READ, FILE_SHARE_WRITE, and FILE_SHARE_DELETE together.")

(defparameter *handoff-win32-open-existing*
  3
  "The CreateFileW disposition that fails when the file is absent.")

(defparameter *handoff-win32-file-attribute-normal* 128 "FILE_ATTRIBUTE_NORMAL.")

(defparameter *handoff-win32-create-new-process-group*
  512
  "CREATE_NEW_PROCESS_GROUP for a detached child.")

(defparameter *handoff-win32-detached-process*
  8
  "DETACHED_PROCESS for a child without the parent's console.")

(defparameter *handoff-win32-startf-use-std-handles*
  256
  "STARTF_USESTDHANDLES in STARTUPINFO.dwFlags.")

(defparameter *handoff-win32-duplicate-same-access*
  2
  "DUPLICATE_SAME_ACCESS for inherited handle copies.")

(defclass handoff-win32-process nil
          ((handle :initarg :handle :reader handoff-win32-process-handle :documentation
            "The owned process handle.")
           (job-handle :initarg :job-handle :reader handoff-win32-process-job-handle
            :documentation "The job containing the replacement and its descendants.")
           (process-id :initarg :process-id :reader handoff-win32-process-id :documentation
            "The native process identifier.")
           (closed-p :initform nil :accessor handoff-win32-process-closed-p :documentation
            "Whether the process handle has been closed."))
          (:documentation "A native Windows process launched without a console attachment."))

(sb-alien:define-alien-routine ("GetLastError" handoff-win32--get-last-error)
                               handoff-win32-dword)

(-> handoff-win32--fail (keyword t) nil)
(defun handoff-win32--fail (operation pathname)
  "Signal the native error from OPERATION on PATHNAME."
  (let ((code (handoff-win32--get-last-error)))
    (error 'handoff-process-error
           :operation operation
           :code      code
           :message   (format nil "Windows error ~D during ~A on ~S." code operation pathname))))

(-> handoff-win32--namestring (t) (or null string))
(defun handoff-win32--namestring (pathname)
  "Return PATHNAME's native namestring, or NIL for the current directory."
  (and pathname (uiop/filesystem:native-namestring pathname)))

(-> handoff-win32--command-line-argument (string) string)
(defun handoff-win32--command-line-argument (argument)
  "Quote ARGUMENT for the Windows command-line parser."
  (if (and (> (length argument) 0)
           (not (find-if (lambda (character) (find character '(#\  #\Tab #\"))) argument)))
      argument
      (with-output-to-string (stream)
        (write-char #\" stream)
        (let ((slashes 0))
          (loop for character across argument
                do (if (char= character #\\)
                       (incf slashes)
                       (progn
                        (dotimes
                            (ignored
                             (if (char= character #\")
                                 (1+ (* 2 slashes))
                                 slashes))
                          (declare (ignorable ignored))
                          (write-char #\\ stream))
                        (setf slashes 0)
                        (write-char character stream))))
          (dotimes (ignored (* 2 slashes))
            (declare (ignorable ignored))
            (write-char #\\ stream)))
        (write-char #\" stream))))

(-> handoff-win32--command-line (list) string)
(defun handoff-win32--command-line (arguments)
  "Build a mutable CreateProcessW command line from ARGUMENTS."
  (format nil "~{~A~^ ~}" (mapcar #'handoff-win32--command-line-argument arguments)))

(-> handoff-win32--stream-handle (t) integer)
(defun handoff-win32--stream-handle (stream)
  "Return STREAM's native handle, or zero when it has none."
  (if (and stream (find-symbol "FD-STREAM-FD" "SB-SYS") (typep stream 'sb-sys:fd-stream))
      (funcall (symbol-function (find-symbol "FD-STREAM-FD" "SB-SYS")) stream)
      0))

(-> handoff-win32--sap-uint64 (sb-sys:system-area-pointer (integer 0)) (unsigned-byte 64))
(defun handoff-win32--sap-uint64 (sap offset)
  "Read an unsigned 64-bit value from SAP at byte OFFSET."
  (logior (sb-sys:sap-ref-32 sap offset) (ash (sb-sys:sap-ref-32 sap (+ offset 4)) 32)))

(-> handoff-win32--duplicate-inheritable-handle (integer) integer)
(defun handoff-win32--duplicate-inheritable-handle (handle)
  "Return an inheritable duplicate of HANDLE."
  (sb-alien:with-alien ((copy handoff-win32-handle))
    (unless
        (plusp
         (handoff-win32--duplicate-handle (handoff-win32--get-current-process) handle
          (handoff-win32--get-current-process) (sb-alien:addr copy) 0 1
          *handoff-win32-duplicate-same-access*))
      (handoff-win32--fail ':launch nil))
    copy))

(-> handoff-win32--null-handle nil integer)
(defun handoff-win32--null-handle ()
  "Open NUL for use as valid child standard handles."
  (let ((handle
         (handoff-win32--create-file "NUL"
          (logior *handoff-win32-generic-read* *handoff-win32-generic-write*)
          *handoff-win32-share-all* nil *handoff-win32-open-existing*
          *handoff-win32-file-attribute-normal* 0)))
    (when (= handle *handoff-win32-invalid-handle*) (handoff-win32--fail ':launch nil))
    handle))

(-> handoff-win32--call-with-inherited-handles (list function) t)
(defun handoff-win32--call-with-inherited-handles (handles function)
  "Call FUNCTION with a native attribute list inheriting only HANDLES."
  (sb-alien:with-alien ((size (sb-alien:unsigned 64) 0) (list (array handoff-win32-handle 3)))
    (handoff-win32--initialize-attributes nil 1 0 (sb-alien:addr size))
    (let ((attributes (sb-alien:make-alien (sb-alien:unsigned 8) size)) (initialized-p nil))
      (unwind-protect
          (progn
           (unless
               (plusp
                (handoff-win32--initialize-attributes attributes 1 0 (sb-alien:addr size)))
             (handoff-win32--fail ':launch nil))
           (setf initialized-p t)
           (loop for handle in handles
                 for index from 0
                 do (setf (sb-alien:deref list index) handle))
           (unless
               (plusp
                (handoff-win32--update-attribute attributes 0 131074 (sb-alien:alien-sap list)
                 24 nil nil))
             (handoff-win32--fail ':launch nil))
           (funcall function (sb-alien:alien-sap attributes)))
        (when initialized-p (handoff-win32--delete-attributes attributes))
        (sb-alien:free-alien attributes)))))

(-> handoff-win32--job-kill-on-close (integer t) null)
(defun handoff-win32--job-kill-on-close (job enabled-p)
  "Enable or disable termination of JOB when its last handle is closed."
  (sb-alien:with-alien ((limits (array (sb-alien:unsigned 8) 144)))
    (let ((sap (sb-alien:alien-sap limits)))
      (dotimes (index 144) (setf (sb-sys:sap-ref-8 sap index) 0))
      (setf (sb-sys:sap-ref-32 sap 16)
            (if enabled-p
                8192
                0))
      (unless (plusp (handoff-win32--set-job job 9 sap 144))
        (handoff-win32--fail ':launch nil)))))

(-> handoff-win32--launch (list (or pathname string) &key (:directory t) (:output t))
    handoff-win32-process)
(defun handoff-win32--launch (arguments ticket &key directory output)
  "Create a suspended process and assign it to a job before running user code.
Terminate the job on abandonment. After a successful handoff, release
ownership without terminating the detached session."
  (let ((launcher-pid-pathname (and ticket (handoff-ticket-sibling ticket ':launcher-pid)))
        (handles               nil)
        (process-handle        0)
        (thread-handle         0)
        (job-handle            0)
        (completed-p           nil))
    (unwind-protect
        (let* ((null-source   (handoff-win32--null-handle))
               (source-output (handoff-win32--stream-handle output)))
          (push null-source handles)
          (let* ((input (handoff-win32--duplicate-inheritable-handle null-source))
                 (out
                  (progn
                   (push input handles)
                   (handoff-win32--duplicate-inheritable-handle
                    (if (plusp source-output)
                        source-output
                        null-source))))
                 (err
                  (progn
                   (push out handles)
                   (handoff-win32--duplicate-inheritable-handle
                    (if (plusp source-output)
                        source-output
                        null-source)))))
            (push err handles)
            (setf job-handle (handoff-win32--create-job-object nil nil))
            (when (zerop job-handle) (handoff-win32--fail ':launch nil))
            (handoff-win32--job-kill-on-close job-handle t)
            (handoff-win32--call-with-inherited-handles (list input out err)
             (lambda (attributes)
               (sb-alien:with-alien ((startup (array (sb-alien:unsigned 8) 112))
                                     (information (array (sb-alien:unsigned 8) 24)))
                 (let ((start (sb-alien:alien-sap startup))
                       (info  (sb-alien:alien-sap information)))
                   (dotimes (index 112) (setf (sb-sys:sap-ref-8 start index) 0))
                   (dotimes (index 24) (setf (sb-sys:sap-ref-8 info index) 0))
                   (setf (sb-sys:sap-ref-32 start 0) 112
                         (sb-sys:sap-ref-32 start 60) *handoff-win32-startf-use-std-handles*
                         (sb-sys:sap-ref-64 start 80) input
                         (sb-sys:sap-ref-64 start 88) out
                         (sb-sys:sap-ref-64 start 96) err
                         (sb-sys:sap-ref-sap start 104) attributes)
                   (unless
                       (plusp
                        (handoff-win32--create-process (first arguments)
                         (handoff-win32--command-line arguments) nil nil 1
                         (logior 4 524288 *handoff-win32-detached-process*
                                 *handoff-win32-create-new-process-group*)
                         nil (handoff-win32--namestring directory) start info))
                     (handoff-win32--fail ':launch nil))
                   (setf process-handle (handoff-win32--sap-uint64 info 0)
                         thread-handle (handoff-win32--sap-uint64 info 8))
                   (unless
                       (plusp
                        (handoff-win32--assign-process-to-job-object job-handle
                         process-handle))
                     (handoff-win32--fail ':launch nil))
                   (let* ((pid (sb-sys:sap-ref-32 info 16))
                          (process
                           (make-instance 'handoff-win32-process :handle process-handle
                                          :job-handle job-handle :process-id pid)))
                     (when launcher-pid-pathname
                       (with-open-file
                           (stream launcher-pid-pathname :direction ':output :if-exists
                            ':supersede)
                         (format stream "~D~%" pid))
                       (setf (ls-compat.posix:file-mode launcher-pid-pathname) 384))
                     (when (= (handoff-win32--resume-thread thread-handle) 4294967295)
                       (handoff-win32--fail ':launch nil))
                     (setf completed-p t)
                     process)))))))
      (unless completed-p
        (when (plusp job-handle) (handoff-win32--terminate-job-object job-handle 1))
        (when (plusp process-handle)
          (handoff-win32--terminate-process process-handle 1)
          (handoff-win32--wait-for-single-object process-handle 4294967295)
          (handoff-win32--close-handle process-handle))
        (when (plusp job-handle) (handoff-win32--close-handle job-handle)))
      (when (plusp thread-handle) (handoff-win32--close-handle thread-handle))
      (dolist (handle handles) (handoff-win32--close-handle handle)))))

(defmethod handoff-process-id ((process handoff-win32-process))
  "Return the detached root's native process identifier."
  (handoff-win32-process-id process))

(defmethod handoff-process-alive-p ((process handoff-win32-process))
  "Return true while any process in the owned job is still active."
  (and (not (handoff-win32-process-closed-p process))
       (sb-alien:with-alien ((accounting (array (sb-alien:unsigned 8) 48)))
         (unless
             (plusp
              (handoff-win32--query-job (handoff-win32-process-job-handle process) 1
               (sb-alien:alien-sap accounting) 48 nil))
           (handoff-win32--fail ':process-state nil))
         (plusp (sb-sys:sap-ref-32 (sb-alien:alien-sap accounting) 40)))))

(defmethod handoff-process-terminate ((process handoff-win32-process) &key force)
  "Terminate the entire owned tree, including children of an exited root."
  (declare (ignore force))
  (unless (handoff-win32-process-closed-p process)
    (unless
        (plusp
         (handoff-win32--terminate-job-object (handoff-win32-process-job-handle process) 1))
      (handoff-win32--fail ':terminate nil)))
  nil)

(defmethod handoff-process-release ((process handoff-win32-process))
  "Release this caller's handles without terminating a successful handoff."
  (unless (handoff-win32-process-closed-p process)
    (handoff-win32--job-kill-on-close (handoff-win32-process-job-handle process) nil)
    (handoff-win32--close-handle (handoff-win32-process-handle process))
    (handoff-win32--close-handle (handoff-win32-process-job-handle process))
    (setf (handoff-win32-process-closed-p process) t))
  nil)

(defmethod handoff-process-wait ((process handoff-win32-process))
  "Wait for the entire owned tree, then release both native handles."
  (loop while (handoff-process-alive-p process)
        do (sleep 0.01))
  (handoff-process-release process)
  t)
