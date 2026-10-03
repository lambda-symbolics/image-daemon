(in-package #:image-daemon)

;;;; -- Persistent Loopback Services --

(defclass daemon-runtime ()
  ((identifier :initarg :identifier :accessor daemon-runtime-identifier
               :documentation "The public discovery identifier, or NIL for ephemeral runtimes.")
   (publish-p :initarg :publish-p :reader daemon-runtime-publish-p
              :documentation "Whether this runtime owns a registry record.")
   (token :initarg :token :reader daemon-runtime-token
          :documentation "The private request capability, never a display value.")
   (listener :initarg :listener :accessor daemon-runtime-listener
             :documentation "The listening socket, or NIL after shutdown.")
   (port :initarg :port :reader daemon-runtime-port
         :documentation "The bound loopback TCP port.")
   (registry-pathname :initarg :registry-pathname :accessor daemon-runtime-registry-pathname
                      :documentation "The owned private discovery record, or NIL when unpublished.")
   (created-at :initarg :created-at :reader daemon-runtime-created-at
               :documentation "Universal time at initial creation.")
   (lock :initform (bordeaux-threads:make-lock "Image daemon runtime")
         :reader daemon-runtime-lock :documentation "Protects lifecycle and clients.")
   (stopping-p :initform nil :accessor daemon-runtime-stopping-p
               :documentation "Whether shutdown has begun.")
   (server-thread :initform nil :accessor daemon-runtime-server-thread
                  :documentation "The accept-loop thread.")
   (client-threads :initform nil :accessor daemon-runtime-client-threads
                   :documentation "Active request threads.")
   (client-sockets :initform nil :accessor daemon-runtime-client-sockets
                   :documentation "Accepted sockets awaiting cleanup.")
   (request-function :initarg :request-function :reader daemon-runtime-request-function
                     :documentation "Callback (runtime request &key socket stream) for authenticated requests.")
   (error-function :initarg :error-function :initform nil :reader daemon-runtime-error-function
                   :documentation "Optional callback for accept-loop failures."))
  (:documentation "One local service with explicitly owned transport resources."))

(defgeneric daemon-runtime-request-valid-p (runtime request)
  (:documentation "Return true when RUNTIME accepts REQUEST's protocol and capability."))

(defmethod daemon-runtime-request-valid-p ((runtime daemon-runtime) request)
  (daemon-request-valid-p request (daemon-runtime-token runtime)))

(defgeneric daemon-runtime-error-response (runtime condition)
  (:documentation "Return the packet sent when RUNTIME rejects or cannot handle a request."))

(defmethod daemon-runtime-error-response ((runtime daemon-runtime) condition)
  (declare (ignore runtime))
  (list :error :message (princ-to-string condition)))

(defun daemon-runtime-record (runtime)
  "Return RUNTIME's current private discovery record."
  (daemon-registry-record :identifier (daemon-runtime-identifier runtime)
                          :token (daemon-runtime-token runtime)
                          :port (daemon-runtime-port runtime)
                          :created-at (daemon-runtime-created-at runtime)))

(defun daemon-request-valid-p (request token &key
                                             (request-tag ':localgroup-request)
                                             (protocol-version *daemon-protocol-version*))
  "Return true when REQUEST has REQUEST-TAG, TOKEN and a valid operation.

When PROTOCOL-VERSION is NIL, omit only the version comparison."
  (handler-case
      (and (proper-list-p request)
           (eq (first request) request-tag)
           (or (null protocol-version)
               (= (getf (rest request) :version) protocol-version))
           (stringp (getf (rest request) :token))
           (string= (getf (rest request) :token) token)
           (keywordp (getf (rest request) :operation)))
    (error () nil)))

(defun daemon-runtime-create (&key directory identifier request-function error-function
                                  token created-at (publish-p t)
                                  (class 'daemon-runtime) initargs)
  "Open a runtime, published unless PUBLISH-P is NIL.

Published runtimes require DIRECTORY and IDENTIFIER. Ephemeral runtimes do not
inspect or modify the registry and retain no registry pathname. No threads
start until DAEMON-RUNTIME-START."
  (unless (and (functionp request-function)
               (or (not publish-p)
                   (and directory (uiop:directory-pathname-p directory)
                        identifier)))
    (daemon-fail :message "A published endpoint requires an explicit directory and identifier, and a request callback."
                 :operation ':create))
  (when publish-p
    (daemon-registry-reconcile directory))
  (let ((listener (make-instance 'sb-bsd-sockets:inet-socket :type ':stream :protocol ':tcp))
        (completed-p nil))
    (unwind-protect
         (progn
           (setf (sb-bsd-sockets:sockopt-reuse-address listener) t)
           (sb-bsd-sockets:socket-bind listener
                                       (sb-bsd-sockets:make-inet-address "127.0.0.1") 0)
           (sb-bsd-sockets:socket-listen listener 16)
           (multiple-value-bind (address port) (sb-bsd-sockets:socket-name listener)
             (declare (ignore address))
             (prog1
                 (apply #'make-instance class
                        :identifier identifier :publish-p publish-p
                        :token (or token (daemon-random-token))
                        :listener listener :port port
                        :registry-pathname (and publish-p
                                                (daemon-registry-pathname directory identifier))
                        :created-at (or created-at (get-universal-time))
                        :request-function request-function :error-function error-function
                        initargs)
               (setf completed-p t))))
      (unless completed-p
        (ignore-errors (sb-bsd-sockets:socket-close listener))))))

(defun daemon-runtime--handle-client (runtime socket)
  "Read one authenticated request, then close and unregister SOCKET on every exit."
  (let ((stream nil)
        (*daemon-client-transport-lock* (daemon-runtime-lock runtime)))
    (unwind-protect
         (handler-case
             (progn
               (bordeaux-threads:with-lock-held ((daemon-runtime-lock runtime))
                 (setf stream (daemon-socket-stream socket)))
               (let ((request (daemon-read-packet stream)))
                 (unless (daemon-runtime-request-valid-p runtime request)
                   (daemon-fail :message "The localgroup request was rejected."
                                :operation ':request))
                 (funcall (daemon-runtime-request-function runtime)
                          runtime request :socket socket :stream stream)))
           (error (condition)
             (when stream
               (ignore-errors
                (daemon-write-packet
                 stream (daemon-runtime-error-response runtime condition))))))
      (bordeaux-threads:with-lock-held ((daemon-runtime-lock runtime))
        ;; SOCKET-CLOSE consults the cached stream before closing its descriptor.
        ;; A raw shutdown here could target a descriptor already reused after detach.
        (ignore-errors (sb-bsd-sockets:socket-close socket :abort t))
        (setf (daemon-runtime-client-threads runtime)
              (delete (bordeaux-threads:current-thread) (daemon-runtime-client-threads runtime))
              (daemon-runtime-client-sockets runtime)
              (delete socket (daemon-runtime-client-sockets runtime))))))
)

(defun daemon-runtime--serve (runtime)
  "Accept requests until RUNTIME stops; never register a client after shutdown."
  (loop
    (when (bordeaux-threads:with-lock-held ((daemon-runtime-lock runtime))
            (daemon-runtime-stopping-p runtime))
      (return))
    (handler-case
        (let ((socket (sb-bsd-sockets:socket-accept (daemon-runtime-listener runtime))))
          (bordeaux-threads:with-lock-held ((daemon-runtime-lock runtime))
            (if (daemon-runtime-stopping-p runtime)
                (ignore-errors (sb-bsd-sockets:socket-close socket))
                (handler-case
                    (let ((thread
                            (bordeaux-threads:make-thread
                             (lambda () (daemon-runtime--handle-client runtime socket))
                             :name "Image daemon request")))
                      (push socket (daemon-runtime-client-sockets runtime))
                      (push thread (daemon-runtime-client-threads runtime)))
                  (error (condition)
                    (ignore-errors (sb-bsd-sockets:socket-close socket))
                    (error condition))))))
      (error (condition)
        (when (and (not (daemon-runtime-stopping-p runtime))
                   (daemon-runtime-error-function runtime))
          (funcall (daemon-runtime-error-function runtime) condition))
        (return))))
  nil)

(defun daemon-runtime-start (runtime)
  "Publish when configured and start RUNTIME, rolling back ownership on failure."
  (bordeaux-threads:with-lock-held ((daemon-runtime-lock runtime))
    (when (daemon-runtime-server-thread runtime)
      (return-from daemon-runtime-start runtime))
    (when (daemon-runtime-stopping-p runtime)
      (daemon-fail :message "Cannot start a stopped endpoint." :operation ':start))
    (let ((completed-p nil))
      (unwind-protect
           (progn
             (when (daemon-runtime-publish-p runtime)
               (daemon-registry-publish (daemon-runtime-registry-pathname runtime)
                                        (daemon-runtime-record runtime)))
             (setf (daemon-runtime-server-thread runtime)
                   (bordeaux-threads:make-thread
                    (lambda () (daemon-runtime--serve runtime)) :name "Image daemon endpoint")
                   completed-p t))
        (unless completed-p
          (when (daemon-runtime-publish-p runtime)
            (daemon-registry-delete-matching (daemon-runtime-registry-pathname runtime)
                                             (daemon-runtime-record runtime)))))))
  runtime)

(defun daemon-runtime-stop (runtime)
  "Stop RUNTIME, unblock socket readers and writers, and unpublish its record."
  (let (listener server clients sockets)
    (bordeaux-threads:with-lock-held ((daemon-runtime-lock runtime))
      (setf (daemon-runtime-stopping-p runtime) t
            listener (daemon-runtime-listener runtime)
            server (daemon-runtime-server-thread runtime)
            clients (copy-list (daemon-runtime-client-threads runtime))
            sockets (copy-list (daemon-runtime-client-sockets runtime))))
    (when listener
      (ignore-errors
       (multiple-value-bind (socket stream) (daemon-connect (daemon-runtime-port runtime))
         (declare (ignore stream))
         (sb-bsd-sockets:socket-close socket :abort t))))
    (bordeaux-threads:with-lock-held ((daemon-runtime-lock runtime))
      (dolist (socket sockets)
        (ignore-errors (sb-bsd-sockets:socket-close socket :abort t))))
    (daemon-stop-thread server)
    (when listener (ignore-errors (sb-bsd-sockets:socket-close listener)))
    (dolist (thread clients) (daemon-stop-thread thread))
    (bordeaux-threads:with-lock-held ((daemon-runtime-lock runtime))
      (setf (daemon-runtime-listener runtime) nil
            (daemon-runtime-server-thread runtime) nil))
    (when (daemon-runtime-publish-p runtime)
      (daemon-registry-delete-matching (daemon-runtime-registry-pathname runtime)
                                       (daemon-runtime-record runtime))))
  nil)
