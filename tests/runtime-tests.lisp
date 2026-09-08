(in-package #:image-daemon/tests)

(defun call-with-replacement (name replacement function)
  "Call FUNCTION with NAME temporarily replaced, restoring it on every exit."
  (let ((original (symbol-function name)))
    (unwind-protect
         (progn (setf (symbol-function name) replacement) (funcall function))
      (setf (symbol-function name) original))))

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
