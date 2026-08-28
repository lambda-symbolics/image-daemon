(defpackage #:image-daemon/tests
  (:use #:cl #:image-daemon)
  (:export #:run-tests))

(in-package #:image-daemon/tests)

(defvar *assertions* 0)

(defun check (value control &rest arguments)
  "Count one assertion and fail with CONTROL unless VALUE is true."
  (incf *assertions*)
  (unless value
    (error (apply #'format nil control arguments))))

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
         (payload "#.(setf evaluated-p t)")
         (wire (format nil "~D~%~A" (length payload) payload)))
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

(defun test-identifiers ()
  "Test canonical identifiers, legacy identifiers, and rejection."
  (let* ((canonical (session-identifier-normalize "z5tRZJx"))
         (display (session-identifier-display canonical)))
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

(defun run-tests ()
  "Run the image-daemon tests and return true on success."
  (setf *assertions* 0)
  (test-framing)
  (test-identifiers)
  (test-identity-material)
  (format t "~&~D image-daemon assertions passed.~%" *assertions*)
  t)
