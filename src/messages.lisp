(in-package #:image-daemon)

;;;; -- Bounded Message Endpoint Transport --

(export '(message-runtime daemon-message-endpoint-create daemon-message-handle-request
          daemon-message-call daemon-message-error daemon-message-error-reason))

(define-condition daemon-message-error (daemon-error)
  ((reason :initarg :reason :reader daemon-message-error-reason
           :documentation "A non-secret transport or remote rejection reason."))
  (:documentation "A rejected message or an uncertain delivery outcome."))

(defun daemon-message--fail (reason)
  "Signal a message failure without printing a capability or message payload."
  (error 'daemon-message-error :reason reason :operation ':message
         :message (format nil "Daemon message request ended with ~S." reason)))

(defun daemon-message--portable-p (value)
  "Return true for bounded proper lists of strings, rational numbers and keywords."
  (let ((active (make-hash-table :test 'eq)) (nodes 0))
    (labels ((valid (value depth)
               (and (<= (incf nodes) 100000) (<= depth 64)
                    (typecase value
                      (null t)
                      (string t)
                      (rational t)
                      (keyword t)
                      (cons
                       (let ((marked nil))
                         (unwind-protect
                              (loop for tail = value then (rest tail)
                                    while (consp tail)
                                    do (when (or (gethash tail active) (> (incf nodes) 100000))
                                         (return nil))
                                       (setf (gethash tail active) t)
                                       (push tail marked)
                                    unless (valid (first tail) (1+ depth)) do (return nil)
                                    finally (return (null tail)))
                           (dolist (cell marked) (remhash cell active)))))
                      (t (eq value t))))))
      (not (null (valid value 0))))))

(defun daemon-message--bounded (value limit)
  "Validate portable VALUE and its readable character bound before writing."
  (unless (and (daemon-message--portable-p value)
               (<= (length (packet-payload value)) limit))
    (daemon-message--fail ':payload-limit))
  value)

(defun daemon-message--identity-p (value)
  "Return true for a bounded stable identity string."
  (and (stringp value) (<= 1 (length value) 256)))

(defun daemon-message--envelope-p (value)
  "Return true for a well-formed operation envelope without duplicate/unknown keys."
  (and (proper-list-p value) (= (length value) 10)
       (equal (loop for (key datum) on value by #'cddr collect key)
              '(:action :id :sender :receiver :payload))
       (keywordp (getf value :action))
       (every #'daemon-message--identity-p
              (list (getf value :id) (getf value :sender) (getf value :receiver)))))

(defclass message-runtime (daemon-runtime)
  ((dispatcher :initarg :dispatcher :reader message-runtime-dispatcher
               :documentation "Function (envelope &key cancelled-p) returning portable data.")
   (character-limit :initarg :character-limit :reader message-runtime-character-limit
                    :documentation "Maximum request and response frame characters.")
   (client-limit :initarg :client-limit :reader message-runtime-client-limit
                 :documentation "Maximum concurrently admitted connections.")
   (request-timeout :initarg :request-timeout :reader message-runtime-request-timeout
                    :documentation "Deadline for request reading and dispatch in seconds."))
  (:documentation "An ordinary authenticated runtime hosting bounded message operations."))

(defmethod daemon-runtime-client-limit ((runtime message-runtime))
  (message-runtime-client-limit runtime))

(defmethod daemon-runtime-error-response ((runtime message-runtime) condition)
  (declare (ignore runtime condition))
  ;; A reader/type error can retain capability-bearing request data.
  '(:message-error :reason :request))

(defmethod daemon-runtime-read-request ((runtime message-runtime) stream)
  (let ((*daemon-packet-character-limit* (message-runtime-character-limit runtime)))
    (sb-sys:with-deadline (:seconds (message-runtime-request-timeout runtime))
      (daemon-read-packet stream))))

(defun daemon-message-handle-request (runtime request &key stream dispatcher
                                                          (character-limit 65536)
                                                          (request-timeout 2))
  "Handle an authenticated MESSAGE request within an existing RUNTIME callback.
DISPATCHER receives (envelope &key cancelled-p); it owns authority, durable
mailboxes/wakeups, deduplication and semantic acknowledgements. The cancellation
predicate observes runtime shutdown. This function also validates authentication
when invoked directly. Reply loss, timeout or cancellation may follow a committed
effect: clients must inspect/retry the SAME stable message ID, never assume failure.
When composing an existing endpoint, its pre-dispatch frame bound still applies."
  (unless (and (functionp dispatcher) (typep character-limit '(integer 256 8388608))
               (typep request-timeout '(real (0) *)))
    (daemon-message--fail ':configuration))
  (unless (daemon-runtime-request-valid-p runtime request) (daemon-message--fail ':request))
  (let ((envelope (getf (rest request) :arguments)))
    (unless (and (eq (getf (rest request) :operation) ':message)
                 (daemon-message--envelope-p envelope))
      (daemon-message--fail ':request))
    (daemon-message--bounded request character-limit)
    (let* ((id (getf envelope :id))
           (response
             (handler-case
                 (sb-sys:with-deadline (:seconds request-timeout)
                   (let ((result
                           (funcall dispatcher envelope
                                    :cancelled-p
                                    (lambda ()
                                      (bordeaux-threads:with-lock-held ((daemon-runtime-lock runtime))
                                        (daemon-runtime-stopping-p runtime))))))
                    (handler-case
                        (daemon-message--bounded (list :message-result :id id :status :ok :value result)
                                                 character-limit)
                      (daemon-message-error ()
                        ;; The dispatcher already returned; its effects may have committed.
                        (list :message-result :id id :status :unknown :reason :result-limit)))))
               (daemon-message-error (condition)
                 (list :message-result :id id :status :rejected
                      :reason (let ((reason (daemon-message-error-reason condition)))
                                (if (keywordp reason) reason ':rejected))))
               (sb-sys:deadline-timeout ()
                 (list :message-result :id id :status :unknown :reason :timeout))
               (error ()
                 (list :message-result :id id :status :unknown :reason :dispatch)))))
      (sb-sys:with-deadline (:seconds request-timeout)
        (daemon-write-packet stream response))
      response)))

(defun daemon-message-endpoint-create (&key directory identifier dispatcher token
                                           (publish-p t) (character-limit 65536)
                                           (client-limit 32) (request-timeout 2))
  "Create an unstarted message runtime using existing private registry discovery.
Start/stop with DAEMON-RUNTIME-START/STOP. No application or mailbox package is
required. Stable IDs and sender/receiver are transport correlation, not authority;
the dispatcher must authorize them. Request/response frames and clients are bounded."
  (unless (and (functionp dispatcher) (typep character-limit '(integer 256 8388608))
               (typep client-limit '(integer 1 4096)) (typep request-timeout '(real (0) *)))
    (daemon-message--fail ':configuration))
  (daemon-runtime-create
   :directory directory :identifier identifier :token token :publish-p publish-p
   :class 'message-runtime
   :initargs (list :dispatcher dispatcher :character-limit character-limit
                  :client-limit client-limit :request-timeout request-timeout)
   :request-function
   (lambda (runtime request &key socket stream)
     (declare (ignore socket))
     (daemon-message-handle-request runtime request :stream stream :dispatcher dispatcher
                                   :character-limit character-limit :request-timeout request-timeout))))

(defun daemon-message-call (record &key action id sender receiver payload (timeout 2)
                                       cancelled-p (character-limit 65536))
  "Send one bounded correlated operation through a discovered private RECORD.
Return the dispatcher result, or signal DAEMON-MESSAGE-ERROR. A remote UNKNOWN,
timeout, cancellation or disconnect is an uncertain outcome, not proof of failed
admission. Retry/inspect by the same stable ID. CANCELLED-P cancels local waiting
and does not roll back remote effects; semantic cancellation is a dispatcher action."
  (unless (and (typep timeout '(real (0) *)) (typep character-limit '(integer 256 8388608))
               (or (null cancelled-p) (functionp cancelled-p)))
    (daemon-message--fail ':configuration))
  (unless (daemon-registry-record-p record) (daemon-message--fail ':request))
  (let* ((envelope (list :action action :id id :sender sender :receiver receiver :payload payload))
         (request (list :localgroup-request :version *daemon-protocol-version*
                        :token (getf (rest record) :token) :operation :message :arguments envelope))
         (*daemon-connect-timeout-seconds* timeout)
         (*daemon-packet-character-limit* character-limit)
         (monitor nil) (finished nil) (cancelled nil) (lock (bordeaux-threads:make-lock)))
    (unless (daemon-message--envelope-p envelope)
      (daemon-message--fail ':request))
    (daemon-message--bounded request character-limit)
    (when (and cancelled-p (funcall cancelled-p)) (daemon-message--fail ':cancelled))
    (handler-case
        (multiple-value-bind (socket stream) (daemon-connect (getf (rest record) :port))
          (unwind-protect
               (progn
                 (when cancelled-p
                   (setf monitor
                         (bordeaux-threads:make-thread
                          (lambda ()
                            (loop
                              (when (bordeaux-threads:with-lock-held (lock) finished) (return))
                              (when (handler-case (funcall cancelled-p) (error () t))
                                (bordeaux-threads:with-lock-held (lock)
                                  (unless finished
                                    (setf cancelled t)
                                    (ignore-errors (sb-bsd-sockets:socket-shutdown socket :direction ':io))))
                                (return))
                              (sleep 0.01)))
                          :name "Image daemon message cancellation")))
                 (sb-sys:with-deadline (:seconds timeout)
                   (daemon-write-packet stream request)
                   (let ((response (daemon-read-response stream ':message)))
                     (when (bordeaux-threads:with-lock-held (lock) cancelled)
                       (daemon-message--fail ':cancelled))
                     (unless (and (proper-list-p response) (eq (first response) ':message-result)
                                  (equal id (getf (rest response) :id)))
                       (daemon-message--fail ':uncertain))
                     (case (getf (rest response) :status)
                       (:ok
                        (daemon-message--bounded (getf (rest response) :value) character-limit))
                       (:rejected
                        (daemon-message--fail (or (getf (rest response) :reason) ':rejected)))
                       (t (daemon-message--fail ':uncertain))))))
            (bordeaux-threads:with-lock-held (lock) (setf finished t))
            (daemon-stop-thread monitor)
            (ignore-errors (close stream :abort t))))
      (daemon-message-error (condition) (error condition))
      (error ()
        (daemon-message--fail (if (bordeaux-threads:with-lock-held (lock) cancelled)
                                 ':cancelled ':uncertain))))))
