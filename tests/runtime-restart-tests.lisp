(in-package #:image-daemon/tests)

(-> call-with-restart-runtime (function &key (:request-function t) (:error-function t)) *)
(defun call-with-restart-runtime (function &key request-function error-function)
  "Call FUNCTION with a private published runtime, then retire its resources."
  (let* ((root (merge-pathnames (format nil "daemon-restart-~A/" (daemon-random-nonce))
                                (uiop:temporary-directory)))
         (runtime (daemon-runtime-create
                   :directory root :identifier "restart" :token "restart-capability"
                   :request-function (or request-function
                                         (lambda (runtime request &key socket stream)
                                           (declare (ignore runtime request socket))
                                           (daemon-write-packet stream '(:ok))))
                   :error-function error-function)))
    (unwind-protect
         (funcall function runtime)
      (daemon-runtime-stop runtime)
      (uiop:delete-directory-tree root :validate t :if-does-not-exist ':ignore))))

(-> restart-test--join (daemon-runtime) sb-thread:thread)
(defun restart-test--join (runtime)
  "Reap RUNTIME's failed generation without terminating a live handler."
  (let ((thread (daemon-runtime-server-thread runtime)))
    (check (null (image-daemon::daemon--join-thread thread 2)) "the endpoint generation exits")
    (check (not (bordeaux-threads:thread-alive-p thread)) "the failed thread is completely dead")
    thread))

(-> test-runtime-timer-restart () t)
(defun test-runtime-timer-restart ()
  "Classify host callback failures and explicitly restart after correcting them."
  (dolist (failure '(:next :wake :invalid))
    (let ((seen nil)
          (original (make-condition 'simple-error :format-control "Host timer failed")))
      (call-with-restart-runtime
       (lambda (runtime)
         (image-daemon:daemon-runtime-set-timer
          runtime
          :next-deadline-function
          (lambda (runtime)
            (declare (ignore runtime))
            (ecase failure
              (:next (error original))
              (:wake (get-universal-time))
              (:invalid ':invalid)))
          :wake-function (lambda (runtime) (declare (ignore runtime)) (error original)))
         (daemon-runtime-start runtime)
         (let* ((old-thread (restart-test--join runtime))
                (old-record (daemon-runtime-record runtime)))
           (check (= (length seen) 1) "one callback report per failed explicit start")
           (check (typep (first seen) 'daemon-error) "timer failures use the daemon condition")
           (check (eq (daemon-error-operation (first seen)) ':timer) "timer failure is classified")
           (unless (eq failure ':invalid)
             (check (eq (daemon-error-cause (first seen)) original) "the host condition is retained"))
           (image-daemon:daemon-runtime-set-timer runtime)
           (daemon-runtime-start runtime)
           (check (not (eq old-thread (daemon-runtime-server-thread runtime))) "restart installs a new generation")
           (check (eq (first (daemon-call (daemon-runtime-port runtime) (daemon-runtime-token runtime) ':status)) ':ok)
                  "the corrected endpoint answers")
           (let ((record (daemon-registry-read (daemon-runtime-registry-pathname runtime))))
             (check (equal record (daemon-runtime-record runtime)) "restart publishes its new transport")
             (dolist (key '(:token :created-at :session-id))
               (check (equal (getf (rest old-record) key) (getf (rest record) key))
                      "restart preserves endpoint identity")))))
       :error-function (lambda (condition) (push condition seen)))))
  t)

(-> test-runtime-persistent-timer-failure () t)
(defun test-runtime-persistent-timer-failure ()
  "Leave a bad callback installed and require another explicit start for each report."
  (let ((reports (sb-thread:make-semaphore :count 0)))
    (call-with-restart-runtime
     (lambda (runtime)
       (image-daemon:daemon-runtime-set-timer
        runtime
        :next-deadline-function (lambda (runtime) (declare (ignore runtime)) ':invalid)
        :wake-function (lambda (runtime) (declare (ignore runtime))))
       (loop repeat 2
             do (daemon-runtime-start runtime)
                (check (sb-thread:wait-on-semaphore reports :timeout 2) "the explicit start reports failure")
                (restart-test--join runtime)
                (check (not (sb-thread:wait-on-semaphore reports :timeout 0.05)) "a broken timer never retries itself")))
     :error-function (lambda (condition) (declare (ignore condition)) (sb-thread:signal-semaphore reports))))
  t)

(-> test-runtime-closed-listener-restart () t)
(defun test-runtime-closed-listener-restart ()
  "Replace a failed listener once while concurrent callers share the new generation."
  (let ((seen nil))
    (call-with-restart-runtime
     (lambda (runtime)
       (let ((close-p t))
         (image-daemon:daemon-runtime-set-timer
          runtime
          :next-deadline-function
          (lambda (owner)
            (when close-p
              (setf close-p nil)
              (sb-bsd-sockets:socket-close (daemon-runtime-listener owner)))
            nil)
          :wake-function (lambda (owner) (declare (ignore owner)))))
       (daemon-runtime-start runtime)
       (let ((previous (restart-test--join runtime))
             (gate (sb-thread:make-semaphore :count 0))
             (starters nil))
         (check (and (= (length seen) 1) (typep (first seen) 'daemon-error)
                     (eq (daemon-error-operation (first seen)) ':listen))
                "an invalid listener reports one transport failure, not a timer defect")
         (unwind-protect
              (progn
                (setf starters
                      (loop repeat 12 collect
                            (bordeaux-threads:make-thread
                             (lambda ()
                               (sb-thread:wait-on-semaphore gate)
                               (daemon-runtime-start runtime)
                               (daemon-runtime-server-thread runtime)))))
                (sb-thread:signal-semaphore gate 12)
                (let ((threads (mapcar #'bordeaux-threads:join-thread starters)))
                  (check (not (eq previous (first threads))) "a closed listener gets a new generation")
                  (check (every (lambda (thread) (eq thread (first threads))) threads) "concurrent starts coalesce")
                  (check (eq (first (daemon-call (daemon-runtime-port runtime) (daemon-runtime-token runtime) ':status)) ':ok)
                         "the replacement listener serves requests")))
           (sb-thread:signal-semaphore gate 12)
           (mapc #'daemon-stop-thread starters))))
     :error-function (lambda (condition) (push condition seen))))
  t)

(-> test-runtime-restart-retains-client () t)
(defun test-runtime-restart-retains-client ()
  "Keep an accepted client's thread and transport across listener replacement."
  (let ((entered (sb-thread:make-semaphore :count 0))
        (release (sb-thread:make-semaphore :count 0))
        (client nil))
    (unwind-protect
         (call-with-restart-runtime
          (lambda (runtime)
            (daemon-runtime-start runtime)
            (setf client (bordeaux-threads:make-thread
                          (lambda () (daemon-call (daemon-runtime-port runtime) (daemon-runtime-token runtime) ':hold))))
            (check (sb-thread:wait-on-semaphore entered :timeout 2) "the old listener accepts the client")
            (let ((accepted (bordeaux-threads:with-lock-held ((daemon-runtime-lock runtime))
                              (copy-list (daemon-runtime-client-threads runtime)))))
              (sb-thread:terminate-thread (daemon-runtime-server-thread runtime))
              (restart-test--join runtime)
              (daemon-runtime-start runtime)
              (check (bordeaux-threads:with-lock-held ((daemon-runtime-lock runtime))
                       (every (lambda (thread) (member thread (daemon-runtime-client-threads runtime))) accepted))
                     "the accepted handler stays registered")
              (sb-thread:signal-semaphore release)
              (check (eq (first (bordeaux-threads:join-thread client)) ':ok) "the original client receives its response")
              (setf client nil)))
          :request-function
          (lambda (runtime request &key socket stream)
            (declare (ignore runtime request socket))
            (sb-thread:signal-semaphore entered)
            (sb-thread:wait-on-semaphore release)
            (daemon-write-packet stream '(:ok))))
      (sb-thread:signal-semaphore release)
      (daemon-stop-thread client)))
  t)

(-> test-runtime-restart-stop-race () t)
(defun test-runtime-restart-stop-race ()
  "Do not replace a running error handler or admit a start after shutdown begins."
  (let ((entered (sb-thread:make-semaphore :count 0))
        (release (sb-thread:make-semaphore :count 0))
        (stopper nil))
    (unwind-protect
         (call-with-restart-runtime
          (lambda (runtime)
            (image-daemon:daemon-runtime-set-timer
             runtime
             :next-deadline-function (lambda (runtime) (declare (ignore runtime)) ':invalid)
             :wake-function (lambda (runtime) (declare (ignore runtime))))
            (daemon-runtime-start runtime)
            (check (sb-thread:wait-on-semaphore entered :timeout 2) "the error handler is running")
            (let ((previous (daemon-runtime-server-thread runtime)))
              (daemon-runtime-start runtime)
              (check (eq previous (daemon-runtime-server-thread runtime)) "a live error handler owns its generation"))
            (setf stopper (bordeaux-threads:make-thread (lambda () (daemon-runtime-stop runtime))))
            (check (wait-until (lambda () (daemon-runtime-stopping-p runtime)) 2) "shutdown commits before reentry")
            (expect-failure (lambda () (daemon-runtime-start runtime)) ':start)
            (sb-thread:signal-semaphore release)
            (bordeaux-threads:join-thread stopper)
            (setf stopper nil)
            (expect-failure (lambda () (daemon-runtime-start runtime)) ':start)
            (check (null (daemon-registry-read (daemon-runtime-registry-pathname runtime))) "shutdown unpublishes the endpoint"))
          :error-function
          (lambda (condition)
            (declare (ignore condition))
            (sb-thread:signal-semaphore entered)
            (sb-thread:wait-on-semaphore release)))
      (sb-thread:signal-semaphore release)
      (daemon-stop-thread stopper)))
  t)

(-> test-runtime-restart-rollback () t)
(defun test-runtime-restart-rollback ()
  "Retire a failed replacement and retain the dead generation for a later explicit start."
  (dolist (boundary '(daemon-registry-publish bordeaux-threads:make-thread))
    (call-with-restart-runtime
     (lambda (runtime)
       (image-daemon:daemon-runtime-set-timer
        runtime
        :next-deadline-function (lambda (runtime) (declare (ignore runtime)) ':invalid)
        :wake-function (lambda (runtime) (declare (ignore runtime))))
       (daemon-runtime-start runtime)
       (let ((previous (restart-test--join runtime))
             (old-listener (daemon-runtime-listener runtime))
             (old-port (daemon-runtime-port runtime))
             (replacement nil)
             (replacement-record nil))
         (image-daemon:daemon-runtime-set-timer runtime)
         (call-with-replacement
          boundary
          (lambda (&rest arguments)
            (declare (ignore arguments))
            (setf replacement (daemon-runtime-listener runtime)
                  replacement-record (daemon-runtime-record runtime))
            (daemon-fail :message "Injected replacement failure." :operation ':start))
          (lambda () (expect-failure (lambda () (daemon-runtime-start runtime)) ':start)))
         (check (and (eq previous (daemon-runtime-server-thread runtime))
                     (eq old-listener (daemon-runtime-listener runtime))
                     (= old-port (daemon-runtime-port runtime)))
                "a failed replacement restores the dead generation's handles")
         (check (minusp (sb-bsd-sockets:socket-file-descriptor replacement))
                "the provisional listener is closed")
         (check (not (equal replacement-record
                            (daemon-registry-read (daemon-runtime-registry-pathname runtime))))
                "the failed replacement has no discovery record")
         (daemon-runtime-start runtime)
         (check (eq (first (daemon-call (daemon-runtime-port runtime) (daemon-runtime-token runtime) ':status)) ':ok)
                "a later explicit start succeeds")))))
  t)
