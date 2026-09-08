(in-package #:image-daemon/tests)

(defun wait-until (predicate timeout)
  "Wait boundedly for PREDICATE."
  (loop with deadline = (+ (get-internal-real-time)
                           (* timeout internal-time-units-per-second))
        when (funcall predicate) return t
        when (> (get-internal-real-time) deadline) return nil
        do (sleep 0.005)))

(defun call-with-replacements (replacements function)
  "Run FUNCTION with bounded, serial function replacements."
  (if (null replacements)
      (funcall function)
      (call-with-replacement (first (first replacements)) (second (first replacements))
                             (lambda () (call-with-replacements (rest replacements) function)))))

(defun test-replay ()
  "Exercise handshake order, bounded replay and queue overflow."
  (let* ((transport (relay-create))
         (socket
          (make-instance 'sb-bsd-sockets:inet-socket :type ':stream :protocol ':tcp))
         (stream (make-string-output-stream))
         (attachment
          (make-instance 'attachment :socket socket :stream stream :mode ':read-only)))
    (unwind-protect
        (let ((*relay-output-chunk-character-limit* 4)
              (*relay-history-character-limit* 5)
              (text (format nil "abcdefghij~%")))
          (check
           (relay-attach transport attachment :rows 24 :columns 80 :styled-p nil
            :session-id "ORDER")
           "localgroup terminal accepts a read-only attachment")
          (transport-write transport text)
          (let* ((frames
                  (bordeaux-threads:with-lock-held ((attachment-lock attachment))
                    (coerce (structlisp:deque->vector (attachment-queue attachment))
                            'list)))
                 (packets
                  (mapcar
                   (lambda (frame) (daemon-read-packet (make-string-input-stream frame)))
                   frames))
                 (handshake (first packets))
                 (output (apply #'concatenate 'string (mapcar #'second (rest packets)))))
            (check
             (and (= (length frames) 4) (eq (first handshake) ':attached)
                  (string= (getf (rest handshake) :session-id) "ORDER")
                  (every (lambda (packet) (eq (first packet) ':output)) (rest packets))
                  (string= output text)
                  (string= (relay-history-text transport)
                           (subseq text (- (length text) 5))))
             "the handshake precedes bounded lossless output and exact replay"))
          (let ((*attachment-queue-character-limit* 1))
            (check
             (and (not (attachment-send attachment '(:oversized)))
                  (attachment-closed-p attachment)
                  (structlisp:deque-empty-p (attachment-queue attachment))
                  (zerop (structlisp:deque-total-weight (attachment-queue attachment))))
             "attachment overflow closes the client and releases its queue")))
      (relay-detach transport attachment)
      (attachment-close attachment)
      (ignore-errors (sb-bsd-sockets:socket-close socket)))))

(defclass test-localgroup-close-stream (sb-gray:fundamental-character-output-stream)
          ((lock :initform (bordeaux-threads:make-lock "Image daemonp close stream")
            :reader test-localgroup-close-stream-lock :documentation
            "The lock protecting recorded transport operations.")
           (operations :initform nil :accessor test-localgroup-close-stream-operations
            :type list :documentation
            "The shutdown and close operations observed in call order.")
           (stall-writes-p :initarg :stall-writes-p :initform nil :reader
            test-localgroup-close-stream-stall-writes-p :type boolean :documentation
            "Whether writes wait for socket shutdown before returning.")
           (write-started-p :initform nil :accessor
            test-localgroup-close-stream-write-started-p :type boolean :documentation
            "Whether a stalled write has begun."))
          (:documentation
           "A stream double whose ordinary close and selected writes block."))

(defclass test-localgroup-socket nil
          ((stream :initarg :stream :reader test-localgroup-socket-stream :type
            test-localgroup-close-stream :documentation
            "The close stream sharing this socket double's operation log."))
          (:documentation
           "A socket double recording shutdown against its paired stream."))

(defun test-localgroup-close-stream--record (stream operation)
  "Append OPERATION to STREAM's synchronized transport log."
  (bordeaux-threads:with-lock-held ((test-localgroup-close-stream-lock stream))
    (setf (test-localgroup-close-stream-operations stream)
            (append (test-localgroup-close-stream-operations stream) (list operation))))
  nil)

(defun test-localgroup-close-stream-operation-snapshot (stream)
  "Return a synchronized copy of STREAM's transport operations."
  (bordeaux-threads:with-lock-held ((test-localgroup-close-stream-lock stream))
    (copy-tree (test-localgroup-close-stream-operations stream))))

(defmethod sb-gray:stream-write-char ((stream test-localgroup-close-stream) character)
  "Accept CHARACTER without retaining output."
  (declare (ignore stream))
  character)

(defmethod sb-gray:stream-write-string
           ((stream test-localgroup-close-stream) string &optional (start 0) end)
  "Accept STRING's selected range, optionally waiting for socket shutdown."
  (declare (ignore start end))
  (when (test-localgroup-close-stream-stall-writes-p stream)
    (bordeaux-threads:with-lock-held ((test-localgroup-close-stream-lock stream))
      (setf (test-localgroup-close-stream-write-started-p stream) t))
    (loop until (find ':shutdown (test-localgroup-close-stream-operation-snapshot stream)
                      :key #'first)
          do (sleep 0.001)))
  string)

(defmethod sb-gray:stream-finish-output ((stream test-localgroup-close-stream))
  "Accept a finish request without blocking."
  (declare (ignore stream))
  nil)

(defmethod close ((stream test-localgroup-close-stream) &key abort)
  "Record closure and block forever when it is flushing rather than abortive."
  (test-localgroup-close-stream--record stream (list :close (not (null abort))))
  (unless abort (loop (sleep 60)))
  t)

(defun test-localgroup--bounded-call (function)
  "Call FUNCTION in a thread and report prompt return plus any failure."
  (let ((completed-p nil) (failure nil) (thread nil))
    (unwind-protect
        (progn
         (setf thread
                 (bordeaux-threads:make-thread
                  (lambda ()
                    (handler-case (funcall function)
                                  (error (condition) (setf failure condition)))
                    (setf completed-p t))
                  :name "Image daemonp bounded close test"))
         (let ((returned-p (wait-until (lambda () completed-p) 2)))
           (values returned-p failure)))
      (daemon-stop-thread thread))))

(defun test-localgroup-attachment-close-safety ()
  "Test overflow and explicit close use shutdown followed by abortive stream close."
  (flet ((shutdown-socket (socket &key direction)
           "Record DIRECTION against SOCKET without performing system I/O."
           (test-localgroup-close-stream--record (test-localgroup-socket-stream socket)
            (list :shutdown direction))
           nil))
    (let* ((stream (make-instance 'test-localgroup-close-stream))
           (socket (make-instance 'test-localgroup-socket :stream stream))
           (attachment
            (make-instance 'attachment :socket socket :stream stream :mode ':read-only)))
      (call-with-replacements
       (list (list 'sb-bsd-sockets:socket-shutdown #'shutdown-socket))
       (lambda ()
         (multiple-value-bind (returned-p failure)
             (test-localgroup--bounded-call (lambda () (attachment-close attachment)))
           (check (and returned-p (null failure))
            "explicit attachment close returns despite a flushing-close trap"))
         (check
          (equal (test-localgroup-close-stream-operation-snapshot stream)
                 '((:shutdown :io) (:close t)))
          "explicit attachment close shuts down socket I/O before abortive close"))))
    (let* ((stream (make-instance 'test-localgroup-close-stream :stall-writes-p t))
           (socket (make-instance 'test-localgroup-socket :stream stream))
           (attachment
            (make-instance 'attachment :socket socket :stream stream :mode ':read-only))
           (transport (relay-create))
           (writer nil))
      (setf (relay-observers transport) (list attachment))
      (unwind-protect
          (call-with-replacements
           (list (list 'sb-bsd-sockets:socket-shutdown #'shutdown-socket))
           (lambda ()
             (setf writer
                     (bordeaux-threads:make-thread
                      (lambda () (image-daemon::attachment--writer-loop attachment))
                      :name "Image daemonp overflow close test")
                   (attachment-writer-thread attachment) writer)
             (check (attachment-send attachment '(:queued))
              "the attachment writer accepts output before it stalls")
             (check
              (wait-until
               (lambda ()
                 (bordeaux-threads:with-lock-held ((test-localgroup-close-stream-lock
                                                    stream))
                   (test-localgroup-close-stream-write-started-p stream)))
               2)
              "the attachment writer stalls inside transport output")
             (multiple-value-bind (returned-p failure)
                 (test-localgroup--bounded-call
                  (lambda ()
                    (let ((*attachment-queue-character-limit* 1))
                      (transport-write transport "overflow"))))
               (check (and returned-p (null failure))
                "terminal output returns while a stalled attachment is disconnected"))
             (check
              (wait-until
               (lambda ()
                 (find ':close (test-localgroup-close-stream-operation-snapshot stream)
                       :key #'first))
               2)
              "the disconnected attachment writer closes its stream promptly")
             (daemon-stop-thread writer)
             (let* ((operations (test-localgroup-close-stream-operation-snapshot stream))
                    (close-position (position ':close operations :key #'first)))
               (check
                (and close-position (plusp close-position)
                     (every
                      (lambda (operation)
                        (or (not (eq (first operation) ':close))
                            (eq (second operation) t)))
                      operations)
                     (eq (first (first operations)) ':shutdown)
                     (eq (second (first operations)) ':io)
                     (attachment-closed-p attachment)
                     (structlisp:deque-empty-p (attachment-queue attachment))
                     (not (bordeaux-threads:thread-alive-p writer)))
                "terminal overflow shuts down before abortive writer close"))))
        (setf (relay-observers transport) nil)
        (daemon-stop-thread writer)))
    nil))

(defclass test-attachment-duplex-stream
    (test-localgroup-close-stream sb-gray:fundamental-character-input-stream)
  ((read-started :initform (sb-thread:make-semaphore :count 0)
                 :reader test-attachment-duplex-read-started
                 :documentation "Signals entry into the receiver's blocking read.")
   (reader-thread :initform nil :accessor test-attachment-duplex-reader-thread
                  :documentation "The receiver retained for fixture cleanup."))
  (:documentation "A duplex stream whose reads and writes require transport shutdown."))

(defmethod sb-gray:stream-read-char ((stream test-attachment-duplex-stream))
  "Block until the transport close callback supplies end of input."
  (setf (test-attachment-duplex-reader-thread stream) (bordeaux-threads:current-thread))
  (sb-thread:signal-semaphore (test-attachment-duplex-read-started stream))
  (loop until (find ':shutdown (test-localgroup-close-stream-operation-snapshot stream)
                    :key #'first)
        do (sleep 0.001))
  :eof)

(defun test-attachment-client-blocked-detach ()
  "Require local exit to close a transport even when a detach write would block."
  (let* ((stream (make-instance 'test-attachment-duplex-stream :stall-writes-p t))
         (completed (sb-thread:make-semaphore :count 0))
         (client nil)
         (failure nil)
         (returned-p nil)
         (receiver-reaped-p nil))
    (flet ((shutdown ()
             (test-localgroup-close-stream--record stream '(:shutdown :io))
             (close stream :abort t)))
      (unwind-protect
           (progn
             (setf client
                   (sb-thread:make-thread
                    (lambda ()
                      (handler-case
                          (daemon-attach-client-run
                           stream :mode ':control
                           :input-ready-function
                           (lambda ()
                             (unless (sb-thread:wait-on-semaphore
                                      (test-attachment-duplex-read-started stream) :timeout 2)
                               (error "Attachment receiver did not start."))
                             t)
                           :read-event-function (lambda () :stream-end)
                           :close-function #'shutdown)
                        (error (condition) (setf failure condition)))
                      (sb-thread:signal-semaphore completed))
                    :name "Blocked attachment detach test"))
             (setf returned-p (sb-thread:wait-on-semaphore completed :timeout 2)
                   receiver-reaped-p
                   (and returned-p
                        (not (sb-thread:thread-alive-p
                              (test-attachment-duplex-reader-thread stream))))))
        (shutdown)
        (when client (sb-thread:join-thread client :timeout 2))
        (when (test-attachment-duplex-reader-thread stream)
          (sb-thread:join-thread (test-attachment-duplex-reader-thread stream) :timeout 2)))
      (check (and returned-p (null failure))
             "local stream end closes the attachment without a blocking detach write")
      (check receiver-reaped-p "attachment exit reaps the receiver before returning"))))

(defun test-localgroup-blocking-read-lifecycle ()
  "Test relay ownership transitions wake or preserve a blocking semantic read."
  (labels ((attachment (mode)
             (make-instance 'attachment :socket nil :stream (make-broadcast-stream) :mode
                            mode))
           (attach (transport client)
             (multiple-value-bind (attached-p released-p)
                 (relay-attach transport client :rows 24 :columns 80 :styled-p nil
                  :session-id "read-test")
               (declare (ignore released-p))
               (check attached-p "the relay accepts its test controller")))
           (run-ending-transition (transition)
             (let* ((transport (relay-create))
                    (client (attachment ':control))
                    (result ':pending)
                    (reader nil))
               (transport-start transport)
               (attach transport client)
               (unwind-protect
                   (progn
                    (setf reader
                            (bordeaux-threads:make-thread
                             (lambda () (setf result (transport-read-event transport)))
                             :name "Autolith relay lifecycle read test"))
                    (sleep 0.05)
                    (check
                     (and (eq result ':pending) (bordeaux-threads:thread-alive-p reader))
                     "the relay read blocks before ownership changes")
                    (ecase transition
                      (:stop (transport-stop transport))
                      (:detach
                       (check (relay-detach transport client)
                        "detaching reports released control"))
                      (:release (relay-release-control transport)))
                    (check (wait-until (lambda () (not (eq result ':pending))) 2)
                     "an ending ownership transition wakes the relay read")
                    (check (eq result ':stream-end)
                     "an ownership transition without a controller ends input"))
                 (transport-stop transport)
                 (attachment-close client)
                 (when reader (bordeaux-threads:join-thread reader))))))
    (dolist (transition '(:stop :detach :release)) (run-ending-transition transition))
    (let* ((transport (relay-create))
           (first-client (attachment ':control))
           (next-client (attachment ':take-over))
           (result ':pending)
           (reader nil))
      (transport-start transport)
      (attach transport first-client)
      (unwind-protect
          (progn
           (setf reader
                   (bordeaux-threads:make-thread
                    (lambda () (setf result (transport-read-event transport))) :name
                    "Autolith relay takeover read test"))
           (sleep 0.05)
           (attach transport next-client)
           (sleep 0.05)
           (check (and (eq result ':pending) (bordeaux-threads:thread-alive-p reader))
            "controller takeover keeps the empty relay read blocked")
           (check (relay-enqueue-event transport next-client ':replacement-event)
            "the replacement controller can queue input")
           (check (wait-until (lambda () (not (eq result ':pending))) 2)
            "replacement controller input wakes the relay read")
           (check (eq result ':replacement-event)
            "the relay read returns replacement controller input"))
        (transport-stop transport)
        (attachment-close first-client)
        (attachment-close next-client)
        (when reader (bordeaux-threads:join-thread reader)))))
  nil)
