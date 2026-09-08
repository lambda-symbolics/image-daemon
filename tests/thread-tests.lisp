(in-package #:image-daemon/tests)

(defun call-with-blocked-thread-cleanup (function)
  "Call FUNCTION with a thread whose unwind cleanup awaits explicit release."
  (let* ((started (sb-thread:make-semaphore :count 0))
         (cleanup-started (sb-thread:make-semaphore :count 0))
         (release-body (sb-thread:make-semaphore :count 0))
         (release-cleanup (sb-thread:make-semaphore :count 0))
         (thread
           (sb-thread:make-thread
            (lambda ()
              (sb-sys:without-interrupts
                (unwind-protect
                     (sb-sys:with-local-interrupts
                       (sb-thread:signal-semaphore started)
                       (sb-thread:wait-on-semaphore release-body))
                  (sb-thread:signal-semaphore cleanup-started)
                  (sb-thread:wait-on-semaphore release-cleanup))))
            :name "Blocked daemon thread cleanup test")))
    (unwind-protect
         (progn
           (check (sb-thread:wait-on-semaphore started :timeout 2)
                  "target thread entered its protected body")
           (funcall function thread cleanup-started release-cleanup))
      (sb-thread:signal-semaphore release-body)
      (sb-thread:signal-semaphore release-cleanup)
      (sb-thread:join-thread thread :timeout 2 :default nil))))

(defun check-blocked-thread-stop (thread &key cleanup-started release-cleanup stop-function)
  "Require STOP-FUNCTION to report a bounded, recoverable thread-stop failure."
  (let ((completed (sb-thread:make-semaphore :count 0))
        (stopper nil)
        (failure nil)
        (returned-p nil))
    (unwind-protect
         (progn
           (setf stopper
                 (sb-thread:make-thread
                  (lambda ()
                    (let ((*daemon-thread-stop-timeout-seconds* 0.1))
                      (handler-case (funcall stop-function)
                        (error (condition) (setf failure condition))))
                    (sb-thread:signal-semaphore completed))
                  :name "Bounded daemon thread stop test"))
           (check (sb-thread:wait-on-semaphore cleanup-started :timeout 2)
                  "termination entered the blocked unwind cleanup")
           (setf returned-p (sb-thread:wait-on-semaphore completed :timeout 2))
           (check (sb-thread:thread-alive-p thread)
                  "a blocked cleanup is still live when the stop operation ends"))
      ;; Release before joining even when testing the former unbounded stopper.
      (sb-thread:signal-semaphore release-cleanup)
      (when stopper (sb-thread:join-thread stopper :timeout 2)))
    (check (and returned-p (typep failure 'daemon-error)
                (eq (daemon-error-operation failure) ':stop-thread))
           "blocked cleanup reports a bounded daemon thread-stop failure")
    (check (and (typep (daemon-error-cause failure) 'sb-thread:join-thread-error)
                (eq (sb-thread:join-thread-problem (daemon-error-cause failure)) ':timeout)
                (eq (sb-thread:thread-error-thread (daemon-error-cause failure)) thread))
           "failure retains the target thread for later reaping")))

(defun test-relay-stop-recovery ()
  "Close every relay attachment and retain failed writer cleanup for retry."
  (call-with-blocked-thread-cleanup
   (lambda (thread cleanup-started release-cleanup)
     (let* ((socket (make-instance 'sb-bsd-sockets:inet-socket
                                  :type ':stream :protocol ':tcp))
            (blocked (make-instance 'attachment :socket socket
                                    :stream (make-broadcast-stream) :mode ':control))
            (observer (make-instance 'attachment :socket socket
                                     :stream (make-broadcast-stream) :mode ':read-only))
            (relay (make-instance 'relay)))
       (unwind-protect
            (progn
              (transport-start relay)
              (setf (attachment-writer-thread blocked) thread
                    (image-daemon::relay-controller relay) blocked
                    (image-daemon::relay-observers relay) (list observer))
              (check-blocked-thread-stop
               thread :cleanup-started cleanup-started :release-cleanup release-cleanup
                      :stop-function (lambda () (transport-stop relay)))
              (check (and (image-daemon::attachment-closed-p observer)
                          (null (image-daemon::relay-controller relay))
                          (null (image-daemon::relay-observers relay)))
                     "one failed writer cannot prevent closing later attachments")
              (check (equal (image-daemon::relay-closing-attachments relay) (list blocked))
                     "the relay retains only the writer awaiting reaping")
              (transport-stop relay)
              (check (and (null (image-daemon::relay-closing-attachments relay))
                          (not (sb-thread:thread-alive-p thread)))
                     "retrying relay stop finishes the retained cleanup"))
         (sb-thread:signal-semaphore release-cleanup)
         (transport-stop relay)
         (ignore-errors (sb-bsd-sockets:socket-close socket)))))))

(defun test-thread-stop-deadline ()
  "Exercise bounded termination and attachment/runtime ownership on failure."
  (dolist (owner '(:thread :attachment :runtime))
    (call-with-blocked-thread-cleanup
     (lambda (thread cleanup-started release-cleanup)
       (let* ((socket (make-instance 'sb-bsd-sockets:inet-socket
                                     :type ':stream :protocol ':tcp))
              (attachment (make-instance 'attachment :socket socket
                                          :stream (make-broadcast-stream) :mode ':read-only))
              (root (merge-pathnames (format nil "daemon-stop-~A/" (daemon-random-nonce))
                                    (uiop:temporary-directory)))
              (runtime nil))
         (unwind-protect
              (progn
                (setf runtime
                      (daemon-runtime-create
                       :directory root :identifier "stop-test"
                       :request-function (lambda (&rest arguments) (declare (ignore arguments))))
                      (attachment-writer-thread attachment) thread
                      (daemon-runtime-client-threads runtime) (list thread))
                (flet ((stop ()
                         (ecase owner
                           (:thread (daemon-stop-thread thread))
                           (:attachment (attachment-close attachment))
                           (:runtime (daemon-runtime-stop runtime)))))
                  (check-blocked-thread-stop thread :cleanup-started cleanup-started
                                            :release-cleanup release-cleanup :stop-function #'stop)
                  (check (and (eq (attachment-writer-thread attachment) thread)
                              (member thread (daemon-runtime-client-threads runtime)))
                         "attachment and runtime retain owned threads after failed stop")
                  (stop)
                  (check (not (sb-thread:thread-alive-p thread))
                         "retry reaps the target after cleanup is released")))
           (sb-thread:signal-semaphore release-cleanup)
           (when runtime (daemon-runtime-stop runtime))
           (attachment-close attachment)
           (ignore-errors (sb-bsd-sockets:socket-close socket))
           (uiop:delete-directory-tree root :validate t :if-does-not-exist ':ignore))))))
  (call-with-blocked-thread-cleanup
   (lambda (thread cleanup-started release-cleanup)
     (declare (ignore cleanup-started))
     (sb-thread:signal-semaphore release-cleanup)
     (let ((*daemon-thread-stop-timeout-seconds* 0.1))
       (check (null (daemon-stop-thread thread)) "forced termination reaps completed cleanup"))
     (check (not (sb-thread:thread-alive-p thread)) "terminated target is no longer live")))
  (check (null (daemon-stop-thread nil)) "empty thread owner needs no reap")
  (check (null (daemon-stop-thread (bordeaux-threads:current-thread)))
         "a thread does not join itself")
  (let ((thread (sb-thread:make-thread (lambda () (values nil :timeout)))))
    (check (null (daemon-stop-thread thread)) "normal thread values are not join failures")))
