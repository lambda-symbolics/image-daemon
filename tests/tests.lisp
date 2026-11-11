(in-package #:image-daemon/tests)

(defvar *assertions* 0
  "The number of assertions checked in the current run.")

(-> check (t string &rest t) null)
(defun check (value control &rest arguments)
  "Count one assertion and fail with CONTROL unless VALUE is true."
  (incf *assertions*)
  (unless value
    (error (apply #'format nil control arguments))))

(-> expect-failure (function keyword) t)
(defun expect-failure (thunk operation)
  "Require THUNK to fail with a daemon error naming OPERATION."
  (handler-case
      (progn
        (funcall thunk)
        (check nil "expected a daemon failure at ~S" operation))
    (daemon-error (condition)
      (check (eq (daemon-error-operation condition) operation)
             "failure operation ~S is not ~S"
             (daemon-error-operation condition) operation))))

(-> test-framing () t)
(defun test-framing ()
  "Test bounded frames preserve packets and reject unsafe payloads."
  (let* ((text
           (concatenate 'string
                        "first"
                        (string #\Newline)
                        "second"
                        (string #\Return)
                        " quoted \"text\" \\ λ"))
         (packets
           (list (list :output text)
                 (list :event (list :paste text))))
         (wire
           (with-output-to-string (stream)
             (dolist (packet packets)
               (daemon-write-packet stream packet))))
         (input (make-string-input-stream wire)))
    (check (and (equal (daemon-read-packet input) (first packets))
                (equal (daemon-read-packet input) (second packets))
                (null (daemon-read-packet input)))
           "length-prefixed frames preserve multiline Unicode packets"))
  (let* ((evaluated-p nil)
         (payload     "#.(setf evaluated-p t)")
         (wire        (format nil "~D~%~A" (length payload) payload)))
    (declare (special evaluated-p))
    (expect-failure
     (lambda ()
       (daemon-read-packet (make-string-input-stream wire)))
     ':read-packet)
    (check (not evaluated-p)
           "rejected reader syntax never executes"))
  (expect-failure
   (lambda ()
     (daemon-read-packet
      (make-string-input-stream (format nil "5~%(:x"))))
   ':read-packet)
  (expect-failure
   (lambda ()
     (daemon-read-packet
      (make-string-input-stream (format nil "999999999999~%x"))))
   ':read-packet)
  (expect-failure
   (lambda ()
     (daemon-read-packet (make-string-input-stream "not-a-number")))
   ':read-packet)
  (expect-failure
   (lambda ()
     (daemon-write-packet
      (make-broadcast-stream)
      (list :output (make-string
                     (1+ *daemon-packet-character-limit*)
                     :initial-element #\a))))
   ':write-packet))

(-> test-identifiers () t)
(defun test-identifiers ()
  "Test canonical identifiers, legacy identifiers, and rejection."
  (let* ((canonical (session-identifier-normalize "z5tRZJx"))
         (display   (session-identifier-display canonical)))
    (check (string= (session-identifier-normalize display) canonical)
           "display forms normalize back to canonical identifiers"))
  (check (string= (session-identifier-normalize "ABCDEF012345")
                  "abcdef012345")
         "legacy hexadecimal identifiers normalize to lowercase")
  (check (null (session-identifier-timestamp "abcdef012345"))
         "legacy identifiers carry no timestamp")
  (expect-failure
   (lambda () (session-identifier-normalize "definitely not an id"))
   ':arguments))

(-> test-identity-material () t)
(defun test-identity-material ()
  "Test token and nonce shapes."
  (let ((token (daemon-random-token))
        (nonce (daemon-random-nonce)))
    (check (and (= (length token) 64)
                (every (lambda (c) (digit-char-p c 16)) token)
                (string= token (string-upcase token)))
           "capability tokens are 64 uppercase hexadecimal characters")
    (check (and (= (length nonce) 12)
                (every (lambda (c) (digit-char-p c 16)) nonce))
           "nonces are 12 hexadecimal characters")
    (check (not (string= (daemon-random-token) token))
           "tokens are fresh")))

(-> test-response-deadline () t)
(defun test-response-deadline ()
  "Test unanswered sockets respect both the transport and an earlier caller deadline."
  (dolist (limits '((0.05 nil) (10 0.05)))
    (let ((listener (make-instance 'sb-bsd-sockets:inet-socket
                                   :type ':stream :protocol ':tcp))
          (socket   nil)
          (stream   nil)
          (reader   nil)
          (failure  nil)
          (done     (sb-thread:make-semaphore)))
      (unwind-protect
           (progn
             (sb-bsd-sockets:socket-bind
              listener (sb-bsd-sockets:make-inet-address "127.0.0.1") 0)
             (sb-bsd-sockets:socket-listen listener 4)
             (setf (values socket stream)
                   (daemon-connect (nth-value 1 (sb-bsd-sockets:socket-name listener))))
             (setf reader
                   (bordeaux-threads:make-thread
                    (lambda ()
                      (let ((*daemon-connect-timeout-seconds* (first limits)))
                        (unwind-protect
                             (handler-case
                                 (if (second limits)
                                     (sb-sys:with-deadline (:seconds (second limits))
                                       (daemon-read-response stream ':status))
                                     (daemon-read-response stream ':status))
                               (serious-condition (condition)
                                 (setf failure condition)))
                          (sb-thread:signal-semaphore done))))
                    :name "Image daemon response deadline test"))
             (check (sb-thread:wait-on-semaphore done :timeout 2)
                    "response read stops before the watchdog with limits ~S" limits)
             (bordeaux-threads:join-thread reader)
             (check (typep failure 'daemon-error)
                    "response timeout signals a daemon condition, got ~S" failure)
             (check (and (eq (daemon-error-operation failure) ':status)
                         (typep (daemon-error-cause failure) 'sb-ext:timeout))
                    "response timeout preserves its operation and typed cause"))
        (daemon-stop-thread reader)
        (when stream
          (ignore-errors (close stream :abort t)))
        (when socket
          (ignore-errors (sb-bsd-sockets:socket-close socket :abort t)))
        (sb-bsd-sockets:socket-close listener)))))

(-> run-tests () t)
(defun run-tests ()
  "Run the image-daemon tests and return true on success."
  (setf *assertions* 0)
  (test-framing)
  (test-identifiers)
  (test-identity-material)
  (test-response-deadline)
  (test-thread-stop-deadline)
  (test-relay-stop-recovery)
  (test-registry)
  (test-registry-locking)
  (test-replay)
  (test-localgroup-attachment-close-safety)
  (test-attachment-client-blocked-detach)
  (test-relay-finish-exit)
  (test-attachment-host-packets)
  (test-localgroup-blocking-read-lifecycle)
  (test-runtime-attachment-cleanup)
  (test-runtime-lifecycle)
  (test-runtime-ephemeral-and-hooks)
  (test-runtime-ephemeral-failures)
  (test-runtime-start-rollback)
  (test-relay-authority)
  (test-handoff-tickets)
  #-win32 (test-handoff-supervised-launch)
  (test-handoff-endpoint-readiness)
  (test-eval-frames)
  (test-eval-configuration)
  (test-eval-debugger-hook)
  (test-eval-lifecycle)
  #-win32 (test-eval-unix-paths)
  (test-eval-token-file)
  (test-eval-client-bounds)
  (test-eval-start-failure)
  (format t "~&~D image-daemon assertions passed.~%" *assertions*)
  t)
