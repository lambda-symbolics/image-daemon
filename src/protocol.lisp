(in-package #:image-daemon)

;;;; -- Protocol Constants and Hooks --

(defparameter *daemon-protocol-version* 1
  "The loopback control protocol version.")

(defparameter *daemon-packet-character-limit* (* 8 1024 1024)
  "The maximum accepted character count for one packet payload.")

(defparameter *daemon-frame-header-character-limit* 16
  "The maximum accepted character count for one decimal frame header.")

(defparameter *daemon-connect-timeout-seconds* 2
  "Seconds allowed for endpoint connection and required responses.")

(defparameter *daemon-error-class* 'daemon-error
  "The condition class signaled for daemon protocol failures.

Host applications may substitute a subclass of DAEMON-ERROR to join
their own condition hierarchy.")


;;;; -- Conditions --

(define-condition daemon-error (error)
  ((message
    :initarg :message
    :reader daemon-error-message
    :type string
    :documentation "The complete failure description.")
   (operation
    :initarg :operation
    :reader daemon-error-operation
    :type keyword
    :documentation "The daemon operation that failed.")
   (session-id
    :initarg :session-id
    :initform nil
    :reader daemon-error-session-id
    :type (or null string)
    :documentation "The requested session identifier, when known.")
   (cause
    :initarg :cause
    :initform nil
    :reader daemon-error-cause
    :documentation "The underlying condition, when one exists."))
  (:report (lambda (condition stream)
             (write-string (daemon-error-message condition) stream)))
  (:documentation "A structured failure in the daemon control protocol."))

(defun daemon-fail (&key message operation session-id cause)
  "Signal a structured daemon protocol failure."
  (error *daemon-error-class*
         :message message
         :operation operation
         :session-id session-id
         :cause cause))


;;;; -- Identity --

(defun proper-list-p (value)
  "Return true when VALUE is a proper list."
  (and (listp value)
       (handler-case
           (not (null (list-length value)))
         (type-error ()
           nil))))

(defun daemon-random-token ()
  "Return a fresh unguessable capability token."
  (string-upcase
   (ironclad:byte-array-to-hex-string (ironclad:random-data 32))))

(defun daemon-random-nonce ()
  "Return a fresh hexadecimal nonce for private pathnames."
  (string-upcase
   (subseq (ironclad:byte-array-to-hex-string (ironclad:random-data 8)) 0 12)))

(defun legacy-session-identifier-p (value)
  "Return true when VALUE is one former twelve-character hexadecimal session ID."
  (not
   (null
    (and (stringp value)
         (= (length value) 12)
         (every (lambda (character) (digit-char-p character 16)) value)))))

(defun session-identifier-normalize (value)
  "Return VALUE's canonical daemon session identifier.

Canonical idsmall identifiers accept their visual hyphen. Former
hexadecimal session identifiers remain accepted for discovery and
detached handoff."
  (handler-case
      (idsmall:identifier-normalize value)
    (idsmall:identifier-error ()
      (if (legacy-session-identifier-p value)
          (string-downcase value)
          (daemon-fail
           :message
           "A session identifier must be a seven-character Bitcoin Base58 identifier, with an optional hyphen after the first, or a legacy twelve-character hexadecimal identifier."
           :operation ':arguments
           :session-id (and (stringp value) value))))))

(defun session-identifier-display (identifier)
  "Return IDENTIFIER in readable canonical form, retaining legacy IDs plainly."
  (handler-case
      (idsmall:identifier-display identifier)
    (idsmall:identifier-error ()
      (if (legacy-session-identifier-p identifier)
          (string-downcase identifier)
          identifier))))

(defun session-identifier-timestamp (identifier)
  "Return the timestamp encoded by canonical IDENTIFIER, or NIL for legacy IDs."
  (handler-case
      (idsmall:identifier-timestamp identifier)
    (idsmall:identifier-error () nil)))


;;;; -- Packet Framing --

(defun packet-payload (packet)
  "Return PACKET as readable text without reader evaluation syntax."
  (with-standard-io-syntax
    (let ((*print-circle* nil)
          (*print-readably* t)
          (*print-pretty* nil))
      (with-output-to-string (stream)
        (write packet :stream stream)))))

(defun packet-string (packet)
  "Return PACKET as one bounded decimal-length-prefixed wire frame."
  (let ((payload (packet-payload packet)))
    (when (> (length payload) *daemon-packet-character-limit*)
      (daemon-fail
       :message "A daemon packet exceeded the configured limit."
       :operation ':write-packet))
    (format nil "~D~%~A" (length payload) payload)))

(defun daemon-write-packet (stream packet)
  "Write and flush one bounded daemon PACKET frame to STREAM."
  (write-string (packet-string packet) stream)
  (finish-output stream)
  nil)

(defun read-frame-header (stream)
  "Read one bounded decimal frame header, returning NIL only at clean end of file."
  (let ((characters (make-array 16
                                :element-type 'character
                                :adjustable t
                                :fill-pointer 0)))
    (loop for character = (read-char stream nil nil)
          do (cond
               ((null character)
                (if (zerop (length characters))
                    (return nil)
                    (daemon-fail
                     :message "A daemon frame header ended early."
                     :operation ':read-packet)))
               ((char= character #\Newline)
                (return (coerce characters 'string)))
               ((>= (length characters)
                    *daemon-frame-header-character-limit*)
                (daemon-fail
                 :message "A daemon frame header exceeded the configured limit."
                 :operation ':read-packet))
               (t
                (vector-push-extend character characters))))))

(defun read-frame-length (stream)
  "Read and validate one packet character count from STREAM."
  (let ((header (read-frame-header stream)))
    (unless header
      (return-from read-frame-length nil))
    (unless (and (plusp (length header))
                 (every #'digit-char-p header))
      (daemon-fail
       :message "A daemon frame header is malformed."
       :operation ':read-packet))
    (let ((length (parse-integer header)))
      (unless (<= 1 length *daemon-packet-character-limit*)
        (daemon-fail
         :message "A daemon packet exceeded the configured limit."
         :operation ':read-packet))
      length)))

(defun read-frame-payload (stream length)
  "Read exactly LENGTH decoded packet characters from STREAM."
  (let ((payload (make-string length)))
    (loop for index below length
          for character = (read-char stream nil nil)
          do (unless character
               (daemon-fail
                :message "A daemon packet ended before its declared length."
                :operation ':read-packet))
             (setf (char payload index) character))
    payload))

(defun daemon-read-packet (stream)
  "Read one safe, proper-list daemon packet frame from STREAM."
  (let ((length (read-frame-length stream)))
    (unless length
      (return-from daemon-read-packet nil))
    (let ((payload (read-frame-payload stream length)))
      (handler-case
          (with-standard-io-syntax
            (let ((*read-eval* nil)
                  (*readtable* (copy-readtable nil)))
              (multiple-value-bind (packet position)
                  (read-from-string payload nil nil)
                (unless (and packet
                             (proper-list-p packet)
                             (every (lambda (character)
                                      (find character '(#\Space #\Tab #\Return
                                                        #\Newline)))
                                    (subseq payload position)))
                  (daemon-fail
                   :message "A daemon packet is malformed."
                   :operation ':read-packet))
                packet)))
        (daemon-error (condition)
          (error condition))
        (error (condition)
          (daemon-fail
           :message "A daemon packet could not be read safely."
           :operation ':read-packet
           :cause condition))))))

(defun daemon-read-response (stream operation)
  "Read one required response within the daemon transport deadline."
  (handler-case
      (sb-sys:with-deadline (:seconds *daemon-connect-timeout-seconds*)
        (or (daemon-read-packet stream)
            (daemon-fail
             :message "The daemon endpoint closed without a response."
             :operation operation)))
    (sb-sys:deadline-timeout (condition)
      (daemon-fail
       :message "The daemon endpoint did not respond in time."
       :operation operation
       :cause condition))))


;;;; -- Loopback Transport --

(defun socket-stream (socket)
  "Return a buffered UTF-8 character stream for SOCKET."
  (sb-bsd-sockets:socket-make-stream
   socket
   :input t
   :output t
   :element-type 'character
   :external-format ':utf-8
   :buffering ':full))

(defun daemon-connect (port)
  "Connect to the loopback daemon endpoint at PORT."
  (let ((socket (make-instance 'sb-bsd-sockets:inet-socket
                               :type ':stream
                               :protocol ':tcp))
        (stream nil))
    (handler-case
        (progn
          (setf (sb-bsd-sockets:sockopt-tcp-nodelay socket) t)
          (sb-sys:with-deadline (:seconds *daemon-connect-timeout-seconds*)
            (sb-bsd-sockets:socket-connect
             socket
             (sb-bsd-sockets:make-inet-address "127.0.0.1")
             port))
          (setf stream (socket-stream socket))
          (values socket stream))
      (error (condition)
        (if stream
            (ignore-errors (close stream))
            (ignore-errors (sb-bsd-sockets:socket-close socket)))
        (daemon-fail
         :message (format nil "Could not connect to daemon port ~D." port)
         :operation ':connect
         :cause condition)))))

(defun daemon-call (port token operation &optional arguments)
  "Perform one authenticated daemon OPERATION and return its response.

The request frame keeps the historical :LOCALGROUP-REQUEST tag for
compatibility with deployed endpoints."
  (multiple-value-bind (socket stream)
      (daemon-connect port)
    (declare (ignore socket))
    (unwind-protect
         (progn
           (daemon-write-packet
            stream
            (list :localgroup-request
                  :version *daemon-protocol-version*
                  :token token
                  :operation operation
                  :arguments arguments))
           (daemon-read-response stream operation))
      (ignore-errors (close stream)))))
