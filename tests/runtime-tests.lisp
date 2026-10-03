(in-package #:image-daemon/tests)

(defun call-with-replacement (name replacement function)
  "Call FUNCTION with NAME temporarily replaced, restoring it on every exit."
  (let ((original (symbol-function name)))
    (unwind-protect
         (progn (setf (symbol-function name) replacement) (funcall function))
      (setf (symbol-function name) original))))

(defclass hooked-runtime (daemon-runtime)
  ())

(defmethod daemon-runtime-request-valid-p ((runtime hooked-runtime) request)
  (daemon-request-valid-p request (daemon-runtime-token runtime)
                          :request-tag ':custom-request
                          :protocol-version nil))

(defmethod daemon-runtime-error-response ((runtime hooked-runtime) condition)
  (declare (ignore runtime condition))
  '(:hook-error :seen t))

(defun test-registry ()
  "Exercise ownership, malformed records, reconciliation and compare-and-delete."
  (let* ((root (merge-pathnames (format nil "daemon-registry-~A/" (daemon-random-nonce))
                                (uiop:temporary-directory)))
         (path (daemon-registry-pathname root "session"))
         (record (daemon-registry-record :identifier "session" :token "capability"
                                         :port 12345 :created-at 1)))
    (unwind-protect
         (progn
           (check (null (daemon-registry-read path)) "missing discovery record")
           (dolist (bad (list nil '(:localgroup-endpoint :version "wrong")
                              '(:localgroup-endpoint :version)
                              (cons :localgroup-endpoint 7)))
             (check (not (daemon-registry-record-p bad)) "reject malformed record"))
           (expect-failure (lambda () (daemon-registry-pathname root "../escape"))
                           ':registry)
           (daemon-registry-publish path record)
           (check (equal record (daemon-registry-read path)) "publish and discover")
           (check (= (logand #o777 (sb-posix:stat-mode (sb-posix:stat path))) #o600)
                  "private discovery record")
           (check (= (logand #o777 (sb-posix:stat-mode (sb-posix:stat root))) #o700)
                  "private discovery directory")
           (let ((other (copy-list record)))
             (setf (getf (rest other) :token) "other")
             (expect-failure (lambda () (daemon-registry-publish path other)) ':publish)
             (check (not (daemon-registry-delete-matching path other))
                    "compare-and-delete preserves a replacement"))
           (let ((next (copy-list record)))
             (setf (getf (rest next) :port) 23456)
             (daemon-registry-publish path next)
             (check (not (daemon-registry-delete-matching path record))
                    "old endpoint cannot delete successor with same token"))
           (check (= (length (daemon-registry-discover root)) 1) "discover endpoint")
           (dolist (state '(:alive :unknown))
             (call-with-replacement
              'daemon-process-state (lambda (pid) (declare (ignore pid)) state)
              (lambda ()
                (check (zerop (daemon-registry-reconcile root))
                       "preserve live and uncertain endpoints"))))
           (let ((before (daemon-registry-read path)) (raced-p nil))
             (call-with-replacement
              'daemon-process-state
              (lambda (pid)
                (declare (ignore pid))
                (unless raced-p
                  (setf raced-p t)
                  (sexp-store:snapshot-write path record))
                ':dead)
              (lambda ()
                (check (zerop (daemon-registry-reconcile root))
                       "reconciliation preserves replacement written after inspection")))
             (check (not (equal before (daemon-registry-read path)))
                    "replacement retained"))
           (call-with-replacement
            'daemon-process-state (lambda (pid) (declare (ignore pid)) ':dead)
            (lambda ()
              (check (= (daemon-registry-reconcile root) 1) "remove dead endpoint")))
           (check (null (daemon-registry-read path)) "dead endpoint removed"))
      (uiop:delete-directory-tree root :validate t :if-does-not-exist ':ignore))))

(defun test-runtime-lifecycle ()
  "Exercise authentication, successor ownership and blocked request shutdown."
  (let* ((root
          (merge-pathnames (format nil "daemon-runtime-~A/" (daemon-random-nonce))
                           (uiop/stream:temporary-directory)))
         (first nil)
         (next nil)
         (blocked nil)
         (blocked-stream nil)
         (threads nil))
    (flet ((respond (runtime request &key socket stream)
             (declare (ignore runtime socket))
             (daemon-write-packet stream
                                  (list :ok :operation
                                        (getf (rest request) :operation)))))
      (unwind-protect
          (progn
           (setf first
                   (daemon-runtime-create :directory root :identifier "service" :token
                    "capability" :request-function #'respond))
           (check (null (daemon-registry-discover root)) "create is unpublished")
           (daemon-runtime-start first)
           (check
            (eq
             (first
              (daemon-call (daemon-runtime-port first) (daemon-runtime-token first)
                           ':status))
             ':ok)
            "authenticated callback round trip")
           (check
            (eq (first (daemon-call (daemon-runtime-port first) "wrong" ':status))
                ':error)
            "wrong capability is rejected before dispatch")
           (multiple-value-setq (blocked blocked-stream)
             (daemon-connect (daemon-runtime-port first)))
           (check
            (wait-until
             (lambda ()
               (bordeaux-threads:with-lock-held ((daemon-runtime-lock first))
                 (setf threads (copy-list (daemon-runtime-client-threads first)))))
             2)
            "accepted client blocks awaiting a frame")
           (setf next
                   (daemon-runtime-create :directory root :identifier "service" :token
                    "capability" :request-function #'respond))
           (daemon-runtime-start next)
           (daemon-runtime-stop first)
           (check
            (every (lambda (thread) (not (bordeaux-threads:thread-alive-p thread)))
                   threads)
            "shutdown joins blocked request threads")
           (check
            (equal (daemon-registry-read (daemon-runtime-registry-pathname next))
                   (daemon-runtime-record next))
            "old endpoint stop preserves its successor")
           (daemon-runtime-stop first)
           (daemon-runtime-stop next)
           (check (null (daemon-registry-discover root))
            "stop unpublishes owned record"))
        (when first (daemon-runtime-stop first))
        (when next (daemon-runtime-stop next))
        (when blocked-stream (ignore-errors (close blocked-stream :abort t)))
        (when blocked (ignore-errors (sb-bsd-sockets:socket-close blocked)))
        (uiop/filesystem:delete-directory-tree root :validate t :if-does-not-exist
                                               ':ignore)))))

(defun test-runtime-ephemeral-and-hooks ()
  "Exercise unpublished lifecycle and customizable protocol hooks."
  (let ((runtime nil)
        (root (merge-pathnames (format nil "daemon-ephemeral-~A/" (daemon-random-nonce))
                               (uiop/stream:temporary-directory))))
    (labels ((respond (runtime request &key socket stream)
               (declare (ignore runtime socket))
               (if (eq (getf (rest request) :operation) ':explode)
                   (daemon-fail :message "dispatch failed" :operation ':dispatch)
                   (daemon-write-packet stream '(:ok :hook t))))
             (call (request)
               (multiple-value-bind (socket stream)
                   (daemon-connect (daemon-runtime-port runtime))
                 (declare (ignore socket))
                 (unwind-protect
                      (progn
                        (daemon-write-packet stream request)
                        (daemon-read-packet stream))
                   (ignore-errors (close stream))))))
      (unwind-protect
           (progn
             (setf runtime
                   (daemon-runtime-create
                    :directory root :publish-p nil :token "capability"
                    :request-function #'respond :class 'hooked-runtime))
             (check (and (null (daemon-runtime-identifier runtime))
                         (null (daemon-runtime-registry-pathname runtime))
                         (null (daemon-runtime-publish-p runtime))
                         (not (probe-file root)))
                    "ephemeral runtimes do not require registry metadata")
             (daemon-runtime-start runtime)
             (check (equal (call '(:custom-request :version 999
                                   :token "capability" :operation :status))
                           '(:ok :hook t))
                    "custom request validation accepts a versionless protocol")
             (check (equal (call '(:custom-request :version 999
                                   :token "wrong" :operation :status))
                           '(:hook-error :seen t))
                    "custom error responses handle authentication rejection")
             (check (equal (call '(:wrong-request :version 999
                                   :token "capability" :operation :status))
                           '(:hook-error :seen t))
                    "custom error responses handle malformed request tags")
             (check (equal (call '(:custom-request :version 999
                                   :token "capability" :operation 7))
                           '(:hook-error :seen t))
                    "custom validation still requires keyword operations")
             (check (equal (call '(:custom-request :version 999
                                   :token "capability" :operation :explode))
                           '(:hook-error :seen t))
                    "custom error responses handle callback failures")
             (check (daemon-request-valid-p
                     '(:custom-request :version 999 :token "capability"
                       :operation :status)
                     "capability" :request-tag ':custom-request
                     :protocol-version nil)
                    "NIL protocol version skips only version validation")
             (check (not (daemon-request-valid-p
                          '(:custom-request :version 999 :token "wrong"
                            :operation :status)
                          "capability" :request-tag ':custom-request
                          :protocol-version nil))
                    "versionless validation still checks the capability")
             (check (not (daemon-request-valid-p
                          '(:custom-request :version 999 :token "capability")
                          "capability" :request-tag ':custom-request
                          :protocol-version nil))
                    "versionless validation still checks the operation")
             (daemon-runtime-stop runtime)
             (setf runtime nil)
             (check (not (probe-file root))
                    "stopping an ephemeral runtime does not create a registry directory"))
        (when runtime (daemon-runtime-stop runtime))
        (uiop/filesystem:delete-directory-tree root :validate t
                                               :if-does-not-exist ':ignore)))))

(defun test-runtime-start-rollback ()
  "Exercise publication rollback when server startup fails."
  (let* ((root (merge-pathnames (format nil "daemon-rollback-~A/" (daemon-random-nonce))
                                (uiop/stream:temporary-directory)))
         (runtime nil)
         (failed-p nil))
    (unwind-protect
         (progn
           (setf runtime
                 (daemon-runtime-create
                  :directory root :identifier "rollback" :token "capability"
                  :request-function (lambda (runtime request &key socket stream)
                                      (declare (ignore runtime request socket stream)))))
           (call-with-replacement
            'bordeaux-threads:make-thread
            (lambda (&rest arguments)
              (declare (ignore arguments))
              (error "thread startup failed"))
            (lambda ()
              (handler-case
                  (daemon-runtime-start runtime)
                (error () (setf failed-p t)))))
           (check failed-p "server startup failure is reported")
           (check (and (null (daemon-runtime-server-thread runtime))
                       (null (daemon-registry-read
                              (daemon-runtime-registry-pathname runtime))))
                  "failed startup rolls back its registry publication"))
      (when runtime (daemon-runtime-stop runtime))
      (uiop/filesystem:delete-directory-tree root :validate t
                                             :if-does-not-exist ':ignore))))

(defun test-relay-authority ()
  "Exercise exclusive control, observer rejection and takeover authority."
  (let ((relay (relay-create))
        (controller (make-instance 'attachment :socket nil :stream (make-broadcast-stream)
                                              :mode ':control))
        (observer (make-instance 'attachment :socket nil :stream (make-broadcast-stream)
                                            :mode ':read-only))
        (next (make-instance 'attachment :socket nil :stream (make-broadcast-stream)
                                        :mode ':take-over)))
    (unwind-protect
         (progn
           (transport-start relay)
           (relay-attach relay controller :rows 24 :columns 80 :session-id "authority")
           (expect-failure
            (lambda () (relay-attach relay controller :rows 24 :columns 80)) ':attach)
           (relay-attach relay observer :rows 10 :columns 20 :session-id "authority")
           (check (not (relay-enqueue-event relay observer #\x)) "observer cannot submit input")
           (check (and (= (transport-rows relay) 24) (= (transport-columns relay) 80))
                  "observer cannot change controlling geometry")
           (relay-attach relay next :rows 30 :columns 90 :session-id "authority")
           (check (and (attachment-closed-p controller)
                       (not (relay-enqueue-event relay controller #\x))
                       (relay-enqueue-event relay next #\y)
                       (eql (transport-read-event relay) #\y))
                  "takeover revokes old authority and accepts replacement input")
           (check (not (relay-detach relay controller)) "old detach does not release new controller")
           (check (relay-detach relay next) "new controller can detach"))
      (transport-stop relay)
      (mapc #'attachment-close (list controller observer next)))))


(defun test-runtime-attachment-cleanup ()
  "Exercise detach cleanup followed immediately by another authenticated request."
  (let* ((root (merge-pathnames (format nil "daemon-cleanup-~A/" (daemon-random-nonce))
                                (uiop:temporary-directory)))
         (runtime nil)
         (retired-socket nil)
         (retired-stream nil)
         (late-shutdowns 0)
         (shutdown (symbol-function 'sb-bsd-sockets:socket-shutdown)))
    (labels ((respond (runtime request &key socket stream)
               (declare (ignore runtime))
               (if (eq (getf (rest request) :operation) ':detach)
                   (progn
                     (setf retired-socket socket retired-stream stream)
                     (attachment-close
                      (make-instance 'attachment :socket socket :stream stream
                                                 :mode ':read-only)))
                   (daemon-write-packet stream '(:ok))))
             (shutdown-socket (socket &key direction)
               (if (and (eq socket retired-socket)
                        retired-stream (not (open-stream-p retired-stream)))
                   (incf late-shutdowns)
                   (funcall shutdown socket :direction direction))))
      (unwind-protect
           (progn
             (setf runtime (daemon-runtime-create :directory root :identifier "cleanup"
                                                  :token "capability"
                                                  :request-function #'respond))
             (daemon-runtime-start runtime)
             (call-with-replacement
              'sb-bsd-sockets:socket-shutdown #'shutdown-socket
              (lambda ()
                (handler-case
                    (daemon-call (daemon-runtime-port runtime) "capability" ':detach)
                  (daemon-error () nil))
                (check (and retired-stream (not (open-stream-p retired-stream)))
                       "detach callback closes the transferred stream")
                (check (wait-until
                        (lambda ()
                          (bordeaux-threads:with-lock-held ((daemon-runtime-lock runtime))
                            (null (daemon-runtime-client-threads runtime))))
                        2)
                       "request cleanup unregisters the detached transport")
                (check (zerop late-shutdowns)
                       "runtime cleanup never shuts down a retired descriptor")
                (check (eq (first (daemon-call (daemon-runtime-port runtime)
                                               "capability" ':status)) ':ok)
                       "the next authenticated connection completes"))))
        (when runtime (daemon-runtime-stop runtime))
        (uiop/filesystem:delete-directory-tree root :validate t
                                               :if-does-not-exist ':ignore)))))
