(in-package #:image-daemon)

(defclass daemon-runtime nil
          ((identifier :initarg :identifier :accessor daemon-runtime-identifier :documentation
            "The public discovery identifier, or NIL for ephemeral runtimes.")
           (publish-p :initarg :publish-p :reader daemon-runtime-publish-p :documentation
            "Whether this runtime owns a registry record.")
           (token :initarg :token :reader daemon-runtime-token :documentation
            "The private request capability, never a display value.")
           (listener :initarg :listener :accessor daemon-runtime-listener :documentation
            "The listening socket, or NIL after shutdown.")
           (port :initarg :port :reader daemon-runtime-port :documentation
            "The bound loopback TCP port.")
           (registry-pathname :initarg :registry-pathname :accessor
            daemon-runtime-registry-pathname :documentation
            "The owned private discovery record, or NIL when unpublished.")
           (created-at :initarg :created-at :reader daemon-runtime-created-at :documentation
            "Universal time at initial creation.")
           (lock :initform (bordeaux-threads:make-lock "Image daemon runtime") :reader
            daemon-runtime-lock :documentation "Protects lifecycle and clients.")
           (stopping-p :initform nil :accessor daemon-runtime-stopping-p :documentation
            "Whether shutdown has begun.")
           (server-thread :initform nil :accessor daemon-runtime-server-thread :documentation
            "The accept-loop thread.")
           (client-threads :initform nil :accessor daemon-runtime-client-threads :documentation
            "Active request threads.")
           (client-sockets :initform nil :accessor daemon-runtime-client-sockets :documentation
            "Accepted sockets awaiting cleanup.")
           (next-deadline-function :initform nil :accessor daemon-runtime--next-deadline-function
            :documentation "Optional callback returning the next universal-time deadline.")
           (wake-function :initform nil :accessor daemon-runtime--wake-function :documentation
            "Optional deadline callback, called on the accept-loop thread.")
           (request-function :initarg :request-function :reader daemon-runtime-request-function
            :documentation
            "Callback (runtime request &key socket stream) for authenticated requests.")
           (error-function :initarg :error-function :initform nil :reader
            daemon-runtime-error-function :documentation
            "Optional callback for accept-loop failures.")
           (failure :initform nil :accessor daemon-runtime-failure :documentation
            "The original accept-loop failure, retained before host diagnostics.")
           (cleanup-cause :initform nil :accessor daemon-runtime-cleanup-cause :documentation
            "The first cleanup failure until the owned stop completes.")
           (cleanup-failures :initform nil :accessor daemon-runtime-cleanup-failures :documentation
            "The last ordered set of failed cleanup resources."))
          (:documentation "One local service with explicitly owned transport resources."))

(export '(daemon-runtime-read-request daemon-runtime-client-limit
          daemon-runtime-set-timer daemon-runtime-notify))

(defgeneric daemon-runtime-request-valid-p (runtime request)
  (:documentation "Return true when RUNTIME accepts REQUEST's protocol and capability."))

(defmethod daemon-runtime-request-valid-p ((runtime daemon-runtime) request)
  "Accept a :LOCALGROUP-REQUEST at the current protocol version with RUNTIME's token."
  (daemon-request-valid-p request (daemon-runtime-token runtime)))

(defgeneric daemon-runtime-error-response (runtime condition)
  (:documentation "Return the packet sent when RUNTIME rejects or cannot handle a request."))

(defmethod daemon-runtime-error-response ((runtime daemon-runtime) condition)
  "Return an :ERROR packet holding CONDITION's report."
  (declare (ignore runtime))
  (list :error :message (princ-to-string condition)))

(-> daemon-runtime-live-p (daemon-runtime) boolean)
(defun daemon-runtime-live-p (runtime)
  "Return whether RUNTIME owns a live listener generation without a recorded failure."
  (bordeaux-threads:with-lock-held ((daemon-runtime-lock runtime))
    (let ((thread (daemon-runtime-server-thread runtime)))
      (not (null (and (not (daemon-runtime-stopping-p runtime))
                      (null (daemon-runtime-failure runtime))
                      (daemon-runtime-listener runtime)
                      thread (bordeaux-threads:thread-alive-p thread)))))))

(-> daemon-runtime-record (daemon-runtime) list)
(defun daemon-runtime-record (runtime)
  "Return RUNTIME's current private discovery record."
  (daemon-registry-record :identifier (daemon-runtime-identifier runtime)
                          :token      (daemon-runtime-token runtime)
                          :port       (daemon-runtime-port runtime)
                          :created-at (daemon-runtime-created-at runtime)))

(-> daemon-request-valid-p
    (t t &key (:request-tag keyword) (:protocol-version (or null integer)))
    boolean)
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

(-> daemon-runtime-create
    (&key (:directory t) (:identifier t) (:request-function t) (:error-function t) (:token t)
          (:created-at t) (:publish-p t) (:class (or symbol class)) (:initargs list))
    daemon-runtime)
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
    (daemon-fail :message   "A published endpoint requires an explicit directory and identifier, and a request callback."
                 :operation ':create))
  (when publish-p
    (daemon-registry-reconcile directory))
  (multiple-value-bind (listener port) (daemon-runtime--open-listener)
    (let ((completed-p nil))
      (unwind-protect
           (prog1
               (apply #'make-instance class
                      :identifier identifier :publish-p publish-p
                      :token             (or token (daemon-random-token))
                      :listener listener :port port
                      :registry-pathname (and publish-p
                                              (daemon-registry-pathname directory identifier))
                      :created-at        (or created-at (get-universal-time))
                      :request-function request-function :error-function error-function
                      initargs)
             (setf completed-p t))
        (unless completed-p
          ; mallet:suppress no-ignore-errors -- closing the unused listener must not mask the creation failure
          (ignore-errors (sb-bsd-sockets:socket-close listener)))))))

(-> daemon-runtime--open-listener () (values sb-bsd-sockets:inet-socket (integer 1 65535)))
(defun daemon-runtime--open-listener ()
  "Open a loopback listener and return its socket and allocated port."
  (let ((listener    (make-instance 'sb-bsd-sockets:inet-socket :type ':stream :protocol ':tcp))
        (completed-p nil))
    (unwind-protect
         (progn
           (setf (sb-bsd-sockets:sockopt-reuse-address listener) t)
           (sb-bsd-sockets:socket-bind listener
                                       (sb-bsd-sockets:make-inet-address "127.0.0.1") 0)
           (sb-bsd-sockets:socket-listen listener 16)
           (multiple-value-bind (address port) (sb-bsd-sockets:socket-name listener)
             (declare (ignore address))
             (setf completed-p t)
             (values listener port)))
      (unless completed-p
        ; mallet:suppress no-ignore-errors -- closing the unused listener must not mask the bind failure
        (ignore-errors (sb-bsd-sockets:socket-close listener))))))

(defgeneric daemon-runtime-read-request (runtime stream)
  (:documentation "Read one request from STREAM using RUNTIME's framing/deadline policy."))

(defmethod daemon-runtime-read-request ((runtime daemon-runtime) stream)
  "Read one packet from STREAM under the default packet limit."
  (declare (ignore runtime))
  (daemon-read-packet stream))

(defgeneric daemon-runtime-client-limit (runtime)
  (:documentation "Return RUNTIME's concurrent client bound, or NIL for unbounded admission."))

(defmethod daemon-runtime-client-limit ((runtime daemon-runtime))
  "Admit any number of clients."
  (declare (ignore runtime))
  nil)

(-> daemon-runtime--handle-client (daemon-runtime sb-bsd-sockets:socket) t)
(defun daemon-runtime--handle-client (runtime socket)
  "Read one authenticated request, then close and unregister SOCKET on every exit."
  (let ((stream                         nil)
        (*daemon-client-transport-lock* (daemon-runtime-lock runtime)))
    (unwind-protect
         (handler-case
             (progn
               (bordeaux-threads:with-lock-held ((daemon-runtime-lock runtime))
                 (setf stream (daemon-socket-stream socket)))
               (let ((request (daemon-runtime-read-request runtime stream)))
                 (unless (daemon-runtime-request-valid-p runtime request)
                   (daemon-fail :message   "The localgroup request was rejected."
                                :operation ':request))
                 (if (eq (getf (rest request) :operation) ':runtime-notify)
                     (daemon-write-packet stream '(:runtime-notified))
                     (funcall (daemon-runtime-request-function runtime)
                              runtime request :socket socket :stream stream))))
           (error (condition)
             (when stream
               ; mallet:suppress no-ignore-errors -- the client may be gone, and its request failed either way
               (ignore-errors
                (daemon-write-packet
                 stream (daemon-runtime-error-response runtime condition))))))
      (bordeaux-threads:with-lock-held ((daemon-runtime-lock runtime))
        ;; SOCKET-CLOSE consults the cached stream before closing its descriptor.
        ;; A raw shutdown here could target a descriptor already reused after detach.
        ; mallet:suppress no-ignore-errors -- cleanup unregisters the client even when its socket close fails
        (ignore-errors (sb-bsd-sockets:socket-close socket :abort t))
        (setf (daemon-runtime-client-threads runtime)
              (delete (bordeaux-threads:current-thread) (daemon-runtime-client-threads runtime))
              (daemon-runtime-client-sockets runtime)
              (delete socket (daemon-runtime-client-sockets runtime)))))))

(-> daemon-runtime-notify (daemon-runtime) boolean)
(defun daemon-runtime-notify (runtime)
  "Wake RUNTIME after changing a host deadline, using its authenticated listener.
Return T after acknowledgement, or NIL when not started/stopping. No host request
callback is invoked. The accept loop then recomputes its next deadline."
  (let ((server (bordeaux-threads:with-lock-held ((daemon-runtime-lock runtime))
                  (let ((thread (daemon-runtime-server-thread runtime)))
                    (and (not (daemon-runtime-stopping-p runtime))
                         thread (bordeaux-threads:thread-alive-p thread) thread)))))
    (unless server (return-from daemon-runtime-notify nil))
    ;; The accept-loop callback will recompute deadlines on its own return.
    (when (eq server (bordeaux-threads:current-thread))
      (return-from daemon-runtime-notify t))
    (equal (daemon-call (daemon-runtime-port runtime) (daemon-runtime-token runtime) ':runtime-notify)
           '(:runtime-notified))))

(-> daemon-runtime-set-timer
    (daemon-runtime &key (:next-deadline-function t) (:wake-function t))
    daemon-runtime)
(defun daemon-runtime-set-timer (runtime &key next-deadline-function wake-function)
  "Install or clear paired timer callbacks without creating another runner thread.
NEXT-DEADLINE-FUNCTION receives RUNTIME and returns a universal-time integer or
NIL. WAKE-FUNCTION receives RUNTIME on the existing accept-loop thread and must
advance/clear a due deadline before returning. Both run outside the runtime lock.
Call DAEMON-RUNTIME-NOTIFY after later host deadline changes. Configure before
start or update live; notification wakes a blocked listener after publication."
  (unless (or (and (null next-deadline-function) (null wake-function))
              (and (functionp next-deadline-function) (functionp wake-function)))
    (daemon-fail :message   "Timer callbacks must be a pair of functions or NIL."
                 :operation ':timer))
  (bordeaux-threads:with-lock-held ((daemon-runtime-lock runtime))
    (setf (daemon-runtime--next-deadline-function runtime) next-deadline-function
          (daemon-runtime--wake-function runtime) wake-function))
  (daemon-runtime-notify runtime)
  runtime)

(-> daemon-runtime--call-timer (function daemon-runtime) t)
(defun daemon-runtime--call-timer (function runtime)
  "Call a host timer FUNCTION, retaining its failure as a timer condition's cause."
  (handler-case
      (funcall function runtime)
    (error (condition)
      (daemon-fail :message "A host timer callback failed."
                   :operation ':timer :cause condition))))

(-> daemon-runtime--wait-for-client (daemon-runtime) boolean)
(defun daemon-runtime--wait-for-client (runtime)
  "Wait for listener readiness or service one due deadline, without polling."
  (multiple-value-bind (next-function wake-function)
      (bordeaux-threads:with-lock-held ((daemon-runtime-lock runtime))
        (values (daemon-runtime--next-deadline-function runtime)
                (daemon-runtime--wake-function runtime)))
    (let ((deadline (and next-function (daemon-runtime--call-timer next-function runtime))))
      (unless (typep deadline '(or null (integer 0 *)))
        (daemon-fail :message   "A timer deadline must be a universal-time integer or NIL."
                     :operation ':timer))
      (if (and deadline (<= deadline (get-universal-time)))
          (progn
            (daemon-runtime--call-timer wake-function runtime)
            (let ((next (daemon-runtime--call-timer next-function runtime)))
              (unless (or (null next) (and (integerp next) (> next (get-universal-time))))
                (daemon-fail :message   "A timer callback did not advance its due deadline."
                             :operation ':timer)))
            nil)
          (let ((descriptor
                  (sb-bsd-sockets:socket-file-descriptor (daemon-runtime-listener runtime))))
            (unless (typep descriptor '(integer 0 *))
              (daemon-fail :message "The endpoint listener is closed." :operation ':listen))
            (sb-sys:wait-until-fd-usable
             descriptor ':input (and deadline (max 0 (- deadline (get-universal-time)))) nil))))))

(-> daemon-runtime--serve (daemon-runtime) null)
(defun daemon-runtime--serve (runtime)
  "Accept requests until RUNTIME stops; never register a client after shutdown."
  (loop
   (when
       (bordeaux-threads:with-lock-held ((daemon-runtime-lock runtime))
         (daemon-runtime-stopping-p runtime))
     (return))
   (handler-case
    (when (daemon-runtime--wait-for-client runtime)
      (let ((socket (sb-bsd-sockets:socket-accept (daemon-runtime-listener runtime))))
        (bordeaux-threads:with-lock-held ((daemon-runtime-lock runtime))
          (if (or (daemon-runtime-stopping-p runtime)
                  (let ((limit (daemon-runtime-client-limit runtime)))
                    (and limit (>= (length (daemon-runtime-client-sockets runtime)) limit))))
              ; mallet:suppress no-ignore-errors -- closing a refused client is best effort
              (ignore-errors (sb-bsd-sockets:socket-close socket))
              (handler-case
               (let ((thread
                      (bordeaux-threads:make-thread
                       (lambda () (daemon-runtime--handle-client runtime socket)) :name
                       "Image daemon request")))
                 (push socket (daemon-runtime-client-sockets runtime))
                 (push thread (daemon-runtime-client-threads runtime)))
               (error (condition)
                 ; mallet:suppress no-ignore-errors -- preserve the handler startup failure
                 (ignore-errors (sb-bsd-sockets:socket-close socket))
                 (error condition)))))))
    (error (condition)
           (bordeaux-threads:with-lock-held ((daemon-runtime-lock runtime))
             (unless (daemon-runtime-stopping-p runtime)
               (setf (daemon-runtime-failure runtime) condition)))
           (handler-case
            (when
                (and (not (daemon-runtime-stopping-p runtime))
                     (daemon-runtime-error-function runtime))
              (funcall (daemon-runtime-error-function runtime) condition))
            (error nil nil))
           (return))))
  nil)

(-> daemon-runtime-start (daemon-runtime) daemon-runtime)
(defun daemon-runtime-start (runtime)
  "Start RUNTIME, or replace its confirmed-dead accept thread and listener.
A live thread, including one still running its error callback, is reused.
Explicit shutdown forbids further starts. Restart preserves accepted clients,
the capability and creation time; owners decide when a failed runtime may retry."
  (bordeaux-threads:with-lock-held ((daemon-runtime-lock runtime))
    (when (daemon-runtime-stopping-p runtime)
      (daemon-fail :message "Cannot start a stopped endpoint." :operation ':start))
    (let* ((previous     (daemon-runtime-server-thread runtime))
           (old-listener (daemon-runtime-listener runtime))
           (old-port     (daemon-runtime-port runtime)))
      (when (and previous (bordeaux-threads:thread-alive-p previous))
        (return-from daemon-runtime-start runtime))
      (when previous
        (let ((failure (daemon--join-thread previous 0)))
          (when failure
            (daemon-fail :message "The failed endpoint thread could not be reaped." :operation
                         ':start :cause failure))))
      (multiple-value-bind (listener port)
          (if previous
              (daemon-runtime--open-listener)
              (values old-listener old-port))
        (let ((completed-p nil))
          (unwind-protect
              (progn
               (setf (daemon-runtime-listener runtime) listener
                     (slot-value runtime 'port) port)
               (when (daemon-runtime-publish-p runtime)
                 (daemon-registry-publish (daemon-runtime-registry-pathname runtime)
                                          (daemon-runtime-record runtime)))
               (setf (daemon-runtime-server-thread runtime)
                     (bordeaux-threads:make-thread (lambda () (daemon-runtime--serve runtime))
                                                   :name "Image daemon endpoint")
                     completed-p t
                     (daemon-runtime-failure runtime) nil))
            (unless completed-p
              (when (daemon-runtime-publish-p runtime)
                (daemon-registry-delete-matching (daemon-runtime-registry-pathname runtime)
                                                 (daemon-runtime-record runtime)))
              (setf (daemon-runtime-listener runtime) old-listener
                    (slot-value runtime 'port) old-port
                    (daemon-runtime-server-thread runtime) previous)
              ; mallet:suppress no-ignore-errors -- preserve failed replacement startup
              (when previous (ignore-errors (sb-bsd-sockets:socket-close listener)))))
          ; mallet:suppress no-ignore-errors -- the dead generation has already been replaced
          (when previous (ignore-errors (sb-bsd-sockets:socket-close old-listener)))))))
  runtime)

(-> daemon-runtime-stop (daemon-runtime) null)
(defun daemon-runtime-stop (runtime)
  "Attempt all stop stages, releasing only resources whose cleanup succeeds.

Failed resources and the first cause remain owned for a later stop retry."
  (let (listener server clients sockets failures registry)
    (bordeaux-threads:with-lock-held ((daemon-runtime-lock runtime))
      (setf (daemon-runtime-stopping-p runtime) t
            listener (daemon-runtime-listener runtime)
            server (daemon-runtime-server-thread runtime)
            clients (copy-list (daemon-runtime-client-threads runtime))
            sockets (copy-list (daemon-runtime-client-sockets runtime))
            registry (daemon-runtime-registry-pathname runtime)))
    (labels ((attempt (stage resource function &key release)
               (handler-case (progn (funcall function) (when release (funcall release)))
                             (error (condition) (push (list stage resource condition) failures))))

             (reap (thread)
               (daemon-stop-thread thread)
               (when (bordeaux-threads:thread-alive-p thread)
                 (daemon-fail :operation ':stop-thread :message
                              "The endpoint still owns a live thread after stop."))))
      (when listener
        (handler-case
         (multiple-value-bind (socket stream)
             (daemon-connect (daemon-runtime-port runtime))
           (declare (ignore stream))
           (sb-bsd-sockets:socket-close socket :abort t))
         (error nil nil)))
      (dolist (socket sockets)
        (attempt ':client-socket socket
         (lambda ()
           (bordeaux-threads:with-lock-held ((daemon-runtime-lock runtime))
             (sb-bsd-sockets:socket-close socket :abort t)))
         :release
         (lambda ()
           (bordeaux-threads:with-lock-held ((daemon-runtime-lock runtime))
             (setf (daemon-runtime-client-sockets runtime)
                   (delete socket (daemon-runtime-client-sockets runtime) :test #'eq))))))
      (when server
        (attempt ':server-thread server (lambda () (reap server)) :release
         (lambda ()
           (bordeaux-threads:with-lock-held ((daemon-runtime-lock runtime))
             (when (eq server (daemon-runtime-server-thread runtime))
               (setf (daemon-runtime-server-thread runtime) nil))))))
      (when listener
        (attempt ':listener listener (lambda () (sb-bsd-sockets:socket-close listener :abort t))
         :release
         (lambda ()
           (bordeaux-threads:with-lock-held ((daemon-runtime-lock runtime))
             (when (eq listener (daemon-runtime-listener runtime))
               (setf (daemon-runtime-listener runtime) nil))))))
      (dolist (thread clients)
        (attempt ':client-thread thread (lambda () (reap thread)) :release
         (lambda ()
           (bordeaux-threads:with-lock-held ((daemon-runtime-lock runtime))
             (setf (daemon-runtime-client-threads runtime)
                   (delete thread (daemon-runtime-client-threads runtime) :test #'eq))))))
      (when (and (daemon-runtime-publish-p runtime) registry)
        (attempt ':registry registry
         (lambda ()
           (daemon-registry-delete-matching registry (daemon-runtime-record runtime) :errorp t)))))
    (setf failures (nreverse failures))
    (bordeaux-threads:with-lock-held ((daemon-runtime-lock runtime))
      (setf (daemon-runtime-cleanup-failures runtime) failures)
      (when (and failures (null (daemon-runtime-cleanup-cause runtime)))
        (setf (daemon-runtime-cleanup-cause runtime) (third (first failures))))
      (unless failures (setf (daemon-runtime-cleanup-cause runtime) nil)))
    (when failures
      (error 'daemon-cleanup-error :operation ':stop :failures failures :cause
             (daemon-runtime-cleanup-cause runtime) :message
             "Endpoint cleanup failed; retained resources can be stopped again.")))
  nil)
