(in-package #:image-daemon)

;;;; -- Persistent Loopback Services --

(defclass daemon-runtime ()
  ((identifier :initarg :identifier :accessor daemon-runtime-identifier
               :documentation "The public discovery identifier.")
   (token :initarg :token :reader daemon-runtime-token
          :documentation "The private request capability, never a display value.")
   (listener :initarg :listener :accessor daemon-runtime-listener
             :documentation "The listening socket, or NIL after shutdown.")
   (port :initarg :port :reader daemon-runtime-port
         :documentation "The bound loopback TCP port.")
   (registry-pathname :initarg :registry-pathname :accessor daemon-runtime-registry-pathname
                      :documentation "The owned private discovery record.")
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
  (:documentation "One discoverable local service with explicitly owned transport resources."))

(defun daemon-runtime-record (runtime)
  "Return RUNTIME's current private discovery record."
  (daemon-registry-record :identifier (daemon-runtime-identifier runtime)
                          :token (daemon-runtime-token runtime)
                          :port (daemon-runtime-port runtime)
                          :created-at (daemon-runtime-created-at runtime)))

(defun daemon-request-valid-p (request token)
  "Return true when REQUEST has the deployed protocol version and TOKEN."
  (handler-case
      (and (proper-list-p request) (eq (first request) ':localgroup-request)
           (= (getf (rest request) :version) *daemon-protocol-version*)
           (stringp (getf (rest request) :token))
           (string= (getf (rest request) :token) token)
           (keywordp (getf (rest request) :operation)))
    (error () nil)))

(defun daemon-runtime-create (&key directory identifier request-function error-function
                                  token created-at (class 'daemon-runtime) initargs)
  "Open an unpublished endpoint beneath DIRECTORY.

CLASS may extend DAEMON-RUNTIME with host state supplied in INITARGS. No threads
start until DAEMON-RUNTIME-START, so the host can finish its own startup transaction."
  (unless (and directory (uiop:directory-pathname-p directory) (functionp request-function))
    (daemon-fail :message "An explicit directory and request callback are required."
                 :operation ':create))
  (daemon-registry-reconcile directory)
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
                        :identifier identifier :token (or token (daemon-random-token))
                        :listener listener :port port
                        :registry-pathname (daemon-registry-pathname directory identifier)
                        :created-at (or created-at (get-universal-time))
                        :request-function request-function :error-function error-function
                        initargs)
               (setf completed-p t))))
      (unless completed-p
        (ignore-errors (sb-bsd-sockets:socket-close listener))))))

(defun daemon-runtime--handle-client (runtime socket)
  "Read one authenticated request, then close and unregister SOCKET on every exit."
  (let ((stream nil))
    (unwind-protect
         (handler-case
             (progn
               (setf stream (daemon-socket-stream socket))
               (let ((request (daemon-read-packet stream)))
                 (if (daemon-request-valid-p request (daemon-runtime-token runtime))
                     (funcall (daemon-runtime-request-function runtime)
                              runtime request :socket socket :stream stream)
                     (daemon-write-packet
                      stream (list :error :message "The localgroup request was rejected.")))))
           (error (condition)
             (when stream
               (ignore-errors
                (daemon-write-packet stream (list :error :message (princ-to-string condition)))))))
      (ignore-errors (sb-bsd-sockets:socket-shutdown socket :direction ':io))
      (when stream (ignore-errors (close stream :abort t)))
      (ignore-errors (sb-bsd-sockets:socket-close socket))
      (bordeaux-threads:with-lock-held ((daemon-runtime-lock runtime))
        (setf (daemon-runtime-client-threads runtime)
              (delete (bordeaux-threads:current-thread) (daemon-runtime-client-threads runtime))
              (daemon-runtime-client-sockets runtime)
              (delete socket (daemon-runtime-client-sockets runtime)))))))

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
  "Publish and start RUNTIME, rolling back ownership if thread creation fails."
  (bordeaux-threads:with-lock-held ((daemon-runtime-lock runtime))
    (when (daemon-runtime-server-thread runtime)
      (return-from daemon-runtime-start runtime))
    (when (daemon-runtime-stopping-p runtime)
      (daemon-fail :message "Cannot start a stopped endpoint." :operation ':start))
    (let ((completed-p nil))
      (unwind-protect
           (progn
             (daemon-registry-publish (daemon-runtime-registry-pathname runtime)
                                      (daemon-runtime-record runtime))
             (setf (daemon-runtime-server-thread runtime)
                   (bordeaux-threads:make-thread
                    (lambda () (daemon-runtime--serve runtime)) :name "Image daemon endpoint")
                   completed-p t))
        (unless completed-p
          (daemon-registry-delete-matching (daemon-runtime-registry-pathname runtime)
                                           (daemon-runtime-record runtime))))))
  runtime)

(defun daemon-runtime-stop (runtime)
  "Stop RUNTIME, unblock socket readers and writers, and delete only its own record."
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
         (declare (ignore socket))
         (close stream :abort t))))
    (dolist (socket sockets)
      (ignore-errors (sb-bsd-sockets:socket-shutdown socket :direction ':io))
      (ignore-errors (sb-bsd-sockets:socket-close socket)))
    (daemon-stop-thread server)
    (when listener (ignore-errors (sb-bsd-sockets:socket-close listener)))
    (dolist (thread clients) (daemon-stop-thread thread))
    (bordeaux-threads:with-lock-held ((daemon-runtime-lock runtime))
      (setf (daemon-runtime-listener runtime) nil
            (daemon-runtime-server-thread runtime) nil))
    (daemon-registry-delete-matching (daemon-runtime-registry-pathname runtime)
                                     (daemon-runtime-record runtime)))
  nil)
