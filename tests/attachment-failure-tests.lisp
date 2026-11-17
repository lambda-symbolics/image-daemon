(in-package #:image-daemon/tests)

(defclass failure-recording-attachment (attachment)
  ((encoding-failure :initform nil :accessor failure-recording-attachment-encoding-failure
                     :documentation "An injected encoder condition before queue admission."))
  (:documentation "An attachment borrowing its output stream for failure tests."))

(defmethod attachment-release-transport ((attachment failure-recording-attachment))
  "Leave borrowed output available after shutdown."
  (declare (ignore attachment))
  nil)

(defmethod attachment-packet-string ((attachment failure-recording-attachment) packet)
  "Inject an encoding failure before any queued handshake commit."
  (let ((condition (failure-recording-attachment-encoding-failure attachment)))
    (if condition (error condition) (call-next-method))))

(defclass retirement-failing-attachment (failure-recording-attachment)
          ((retirement-failure :initform nil :accessor retirement-failure :documentation
            "The transport-release condition to inject.")
           (retirement-count :initform 0 :accessor retirement-count :documentation
            "Number of transport release attempts.")
           (retirement-owner :initform (bordeaux-threads:current-thread) :reader retirement-owner :documentation
            "The cleanup caller receiving the injected failure."))
          (:documentation "An attachment whose transport release can fail and later succeed."))

(defmethod attachment-release-transport ((attachment retirement-failing-attachment))
  "Inject release failure in the owning cleanup caller, after any writer exits."
  (incf (retirement-count attachment))
  (when (and (eq (bordeaux-threads:current-thread) (retirement-owner attachment))
             (retirement-failure attachment))
    (error (retirement-failure attachment)))
  (call-next-method))

(-> test-daemon-runtime-stop-retry () t)
(defun test-daemon-runtime-stop-retry ()
  "Attempt independent stop stages, retain failed owners and preserve the first cause."
  (let* ((server         (bordeaux-threads:make-thread (lambda () nil)))
         (bad-client     (bordeaux-threads:make-thread (lambda () nil)))
         (good-client    (bordeaux-threads:make-thread (lambda () nil)))
         (listener       (gensym "listener"))
         (socket         (gensym "accepted-socket"))
         (registry       #P"injected-registry")
         (runtime
          (make-instance 'daemon-runtime :identifier "stop-retry" :publish-p t :token "test-only"
                         :listener listener :port 1 :registry-pathname registry :created-at 1
                         :request-function
                         (lambda (&rest arguments) (declare (ignore arguments)) nil)))
         (reap-cause     (make-condition 'simple-error :format-control "server reap failed"))
         (close-cause    (make-condition 'simple-error :format-control "listener close failed"))
         (client-cause   (make-condition 'simple-error :format-control "client reap failed"))
         (registry-cause (make-condition 'simple-error :format-control "unpublication failed"))
         (pass           0)
         (attempts       nil))
    (dolist (thread (list server bad-client good-client)) (bordeaux-threads:join-thread thread))
    (setf (daemon-runtime-server-thread runtime) server
          (daemon-runtime-client-threads runtime) (list bad-client good-client)
          (image-daemon:daemon-runtime-client-sockets runtime) (list socket))
    (call-with-replacement 'daemon-connect
     (lambda (&rest arguments) (declare (ignore arguments)) (error "Advisory wake unavailable."))
     (lambda ()
       (call-with-replacement 'sb-bsd-sockets:socket-close
        (lambda (resource &key abort)
          (declare (ignore abort))
          (push resource attempts)
          (when (and (eq resource listener) (< pass 2)) (error close-cause)))
        (lambda ()
          (call-with-replacement 'image-daemon:daemon-stop-thread
           (lambda (thread)
             (push thread attempts)
             (when (zerop pass)
               (cond ((eq thread server)
                      (error reap-cause))
                     ((eq thread bad-client)
                      (error client-cause)))))
           (lambda ()
             (call-with-replacement 'image-daemon:daemon-registry-delete-matching
              (lambda (path record &key errorp)
                (declare (ignore record))
                (push path attempts)
                (check errorp "unpublication requests actionable failures")
                (when (zerop pass) (error registry-cause))
                t)
              (lambda ()
                (let ((failure
                       (handler-case (daemon-runtime-stop runtime)
                                     (image-daemon::daemon-cleanup-error (condition) condition))))
                  (check
                   (and failure (eq (daemon-error-cause failure) reap-cause)
                        (equal
                         (mapcar #'first (image-daemon::daemon-cleanup-error-failures failure))
                         '(:server-thread :listener :client-thread :registry)))
                   "all independent failures are collected behind the original cause")
                  (check
                   (and
                    (equal (reverse attempts)
                           (list socket server listener bad-client good-client registry))
                    (eq (daemon-runtime-listener runtime) listener)
                    (eq (daemon-runtime-server-thread runtime) server)
                    (equal (daemon-runtime-client-threads runtime) (list bad-client))
                    (null (image-daemon:daemon-runtime-client-sockets runtime))
                    (eq (daemon-runtime-registry-pathname runtime) registry))
                   "successful owners are released and failed owners remain reachable"))
                (setf pass 1
                      attempts nil)
                (let ((failure
                       (handler-case (daemon-runtime-stop runtime)
                                     (image-daemon::daemon-cleanup-error (condition) condition))))
                  (check
                   (and failure (eq (daemon-error-cause failure) reap-cause)
                        (equal
                         (mapcar #'first (image-daemon::daemon-cleanup-error-failures failure))
                         '(:listener))
                        (null (daemon-runtime-server-thread runtime))
                        (null (daemon-runtime-client-threads runtime))
                        (eq (daemon-runtime-registry-pathname runtime) registry))
                   "retry attempts outstanding resources without replacing the first cause"))
                (setf pass 2
                      attempts nil)
                (daemon-runtime-stop runtime)
                (check
                 (and (equal (reverse attempts) (list listener registry))
                      (null (daemon-runtime-listener runtime))
                      (null (image-daemon::daemon-runtime-cleanup-cause runtime)))
                 "the final retry releases the listener and clears completed cleanup state"))))))))))
  t)

(-> test-relay-retirement-retry () t)
(defun test-relay-retirement-retry ()
  "Retain failed finish, detach and takeover ownership for a later transport stop."
  (dolist (operation '(:finish :release :take-over))
    (let* ((transport    (make-instance 'relay))
           (stream       (make-string-output-stream))
           (other-stream (make-string-output-stream))
           (controller   (make-instance 'retirement-failing-attachment
                                        :stream stream :mode ':control))
           (other        (make-instance 'retirement-failing-attachment
                                        :stream other-stream :mode
                                        (if (eq operation ':take-over) ':take-over ':read-only)))
           (cause        (make-condition 'simple-error :format-control "retirement failed")))
      (unwind-protect
           (progn
             (setf (relay-controller transport) controller
                   (retirement-failure controller) cause)
             (when (eq operation ':finish)
               (setf (relay-observers transport) (list other)))
             (let ((failure
                     (handler-case
                         (ecase operation
                           (:finish
                            (relay-finish transport :status 1 :message "Failed."))
                           (:release
                            (relay-release-control transport))
                           (:take-over
                            (relay-attach transport other :rows 24 :columns 80)))
                       (image-daemon::daemon-cleanup-error (condition) condition))))
               (check (and (typep failure 'image-daemon::daemon-cleanup-error)
                           (eq (daemon-error-cause failure) cause)
                           (member controller (image-daemon::relay-closing-attachments transport)
                                   :test #'eq)
                           (not (eq controller (relay-controller transport))))
                      "removed controllers retain their original cause and cleanup ownership")
               (when (eq operation ':finish)
                 (check (and (plusp (retirement-count other))
                             (not (member other
                                          (image-daemon::relay-closing-attachments transport)
                                          :test #'eq))
                             (null (relay-observers transport)))
                        "a failing first finish does not skip or forget the second attachment")))
             (setf (retirement-failure controller) nil)
             (transport-stop transport)
             (check (and (>= (retirement-count controller) 2)
                         (null (image-daemon::relay-closing-attachments transport))
                         (null (relay-controller transport))
                         (null (image-daemon::relay-cleanup-cause transport)))
                    "transport stop retries removed attachments and completes ownership release"))
        (setf (retirement-failure controller) nil)
        (ignore-errors (transport-stop transport))
        (attachment-close controller)
        (attachment-close other)
        (close stream)
        (close other-stream))))
  (dolist (operation '(:stop :release :release-direct :take-over))
    (let* ((direct     (make-instance 'relay))
           (transport  (make-instance 'relay :direct-terminal direct))
           (stream     (make-string-output-stream))
           (attachment (make-instance 'failure-recording-attachment
                                      :stream stream :mode (if (eq operation ':take-over)
                                                               ':take-over ':control)))
           (cause      (make-condition 'simple-error :format-control "foreground stop failed"))
           (failure-p  t)
           (attempts   0)
           (original   (fdefinition 'transport-stop)))
      (setf (image-daemon:transport-started-p transport) t)
      (unwind-protect
           (call-with-replacement
            'transport-stop
            (lambda (candidate)
              (if (eq candidate direct)
                  (progn (incf attempts) (when failure-p (error cause)) candidate)
                  (funcall original candidate)))
            (lambda ()
              (let ((failure
                     (handler-case
                         (ecase operation
                           (:stop
                            (transport-stop transport))
                           (:release
                            (image-daemon:relay-release-control transport))
                           (:release-direct
                            (image-daemon:relay-release-direct transport))
                           (:take-over
                            (relay-attach transport attachment :rows 24 :columns 80)))
                       (image-daemon:daemon-cleanup-error (condition) condition))))
                (check (and failure (eq (daemon-error-cause failure) cause)
                            (member direct (image-daemon::relay-closing-direct-transports transport)))
                       "failed foreground release retains ownership and the original cause"))
              (setf failure-p nil)
              (transport-stop transport)
              (check (and (= attempts 2)
                          (null (image-daemon::relay-closing-direct-transports transport))
                          (null (image-daemon::relay-cleanup-cause transport)))
                     "relay stop retries foreground cleanup after stop, release or takeover")))
        (attachment-close attachment)
        (close stream))))
  t)

(-> test-attachment-failure-state () t)
(defun test-attachment-failure-state ()
  "Retain handshake admission and overflow diagnostics independently of cleanup."
  (let* ((stream     (make-string-output-stream))
         (attachment (make-instance 'failure-recording-attachment
                                    :stream stream :mode ':read-only))
         (cause      (make-condition 'simple-error :format-control "encoder failure")))
    (unwind-protect
         (progn
           (setf (failure-recording-attachment-encoding-failure attachment) cause)
           (check (and (eq (handler-case
                               (attachment-try-send attachment '(:attached))
                             (error (condition) condition))
                           cause)
                       (not (image-daemon:attachment-handshake-committed-p attachment))
                       (structlisp:deque-empty-p (attachment-queue attachment)))
                  "encoding failure preserves its cause and does not commit a handshake")
           (setf (failure-recording-attachment-encoding-failure attachment) nil)
           (check (and (eq (attachment-try-send attachment '(:attached)) ':accepted)
                       (image-daemon:attachment-handshake-committed-p attachment))
                  "queue admission commits the handshake before writer startup")
           (let ((*attachment-queue-character-limit* 1))
             (check (eq (attachment-try-send attachment '(:output "overflow")) ':overflow)
                    "overflow is distinguished from a closed queue"))
           (attachment-close attachment)
           (check (and (equal (getf (image-daemon:attachment-failure attachment) :reason)
                              "queue-overflow")
                       (image-daemon:attachment-handshake-committed-p attachment)
                       (structlisp:deque-empty-p (attachment-queue attachment)))
                  "overflow reason and commit state survive abortive cleanup"))
      (attachment-close attachment)
      (close stream)))
  t)

(-> test-attachment-failure-drain () t)
(defun test-attachment-failure-drain ()
  "Drain committed success and terminal failure in FIFO order through one writer."
  (let* ((stream     (make-string-output-stream))
         (attachment (make-instance 'failure-recording-attachment
                                    :stream stream :mode ':read-only)))
    (unwind-protect
         (progn
           (attachment-try-send attachment '(:attached :mode :read-only))
           (attachment-finish attachment
                              '(:exit :status 1 :message "Attachment failed."
                                :details (:reason "attachment-failure" :stage "replay")))
           (let ((packets (with-input-from-string (input (get-output-stream-string stream))
                            (loop for packet = (daemon-read-packet input)
                                  while packet collect packet))))
             (check (and (= (length packets) 2)
                         (eq (first (first packets)) ':attached)
                         (eq (first (second packets)) ':exit)
                         (= (getf (rest (second packets)) :status) 1)
                         (not (bordeaux-threads:thread-alive-p
                               (attachment-writer-thread attachment))))
                    "success precedes the distinct failure and the writer is reaped")))
      (attachment-close attachment)
      (close stream)))
  t)
