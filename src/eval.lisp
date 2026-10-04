(in-package #:image-daemon)

;;;; -- Evaluation Endpoints --

;;; An evaluation endpoint lets trusted local programs evaluate Common Lisp in
;;; the running image. Each connection proves knowledge of a private token with
;;; HMAC-SHA-256 over a fresh nonce, so the reusable token never crosses the
;;; wire, and then sends one request at a time to the single serial evaluator.
;;; A frame is a four-octet big-endian length followed by that many UTF-8
;;; octets holding one S-expression, read through a closed sexp-config grammar
;;; both before and after authentication.

(defparameter *eval-protocol-version* 1
  "The evaluation endpoint wire protocol version.")

(defparameter *eval-nonce-octets* 32
  "The number of random octets in one authentication nonce.")

(defparameter *eval-proof-octets* 32
  "The HMAC-SHA-256 proof size in octets.")

(defparameter *eval-token-maximum-octets* 4096
  "The largest accepted token file.")

(defparameter *eval-maximum-protocol-list-length* 16
  "The most cons cells one protocol request may hold.")

(defparameter *eval-minimum-frame-size* 128
  "The smallest frame bound that still carries a structured protocol failure.")

(defparameter *eval-stop-timeout-seconds* 2
  "The seconds EVAL-ENDPOINT-STOP waits for endpoint threads by default.")

(defparameter *eval-make-thread-function* #'sb-thread:make-thread
  "The thread constructor EVAL-ENDPOINT-START calls, as (function &key name).")

(defparameter *eval-frame-keywords*
  '(:authenticate :proof :evaluate :source :challenge :version :algorithm
    :hmac-sha-256 :nonce :authenticated :protocol-error :reason :oversized
    :truncated :encoding :empty :trailing :malformed :request :evaluation-result
    :status :ok :timeout :condition :condition-type :report :report-truncated-p
    :output :output-truncated-p :values :values-truncated-p)
  "Every keyword a protocol frame may name, so no frame interns a new symbol.")


;;;; -- Classes --

(defclass eval-output-stream (trivial-gray-streams:fundamental-character-output-stream)
  ((builder
    :initarg :builder
    :reader eval-output-stream--builder
    :documentation "The structlisp builder retaining the captured prefix.")
   (column
    :initform 0
    :accessor eval-output-stream--column
    :documentation "The logical output column for FORMAT and FRESH-LINE."))
  (:documentation
   "A character output stream retaining at most a fixed prefix of its output.

Output beyond the capacity is discarded and marks the stream truncated, while
the logical column keeps following everything written."))

(defclass eval-request ()
  ((source
    :initarg :source
    :reader eval-request-source
    :documentation "The bounded source text holding exactly one form.")
   (deadline
    :initarg :deadline
    :reader eval-request-deadline
    :documentation "The internal real time by which the response is due.")
   (lock
    :initform (sb-thread:make-mutex :name "Image daemon evaluation request")
    :reader eval-request-lock
    :documentation "Guards completion and the response.")
   (condition-variable
    :initform (sb-thread:make-waitqueue :name "Image daemon evaluation request")
    :reader eval-request-condition-variable
    :documentation "Wakes the client waiting for completion.")
   (completed-p
    :initform nil
    :accessor eval-request-completed-p
    :documentation "Whether a response has been installed.")
   (response
    :initform nil
    :accessor eval-request-response
    :documentation "The bounded protocol response."))
  (:documentation "One authenticated evaluation and its completion state."))

(defclass eval-endpoint ()
  ((transport
    :initarg :transport
    :reader eval-endpoint-transport
    :documentation "Either :UNIX or :TCP.")
   (unix-pathname
    :initarg :unix-pathname
    :reader eval-endpoint-unix-pathname
    :documentation "The absolute Unix socket pathname for the :UNIX transport.")
   (tcp-address
    :initarg :tcp-address
    :reader eval-endpoint-tcp-address
    :documentation "The IPv4 loopback address for the :TCP transport.")
   (tcp-port
    :initarg :tcp-port
    :accessor eval-endpoint-tcp-port
    :documentation "The TCP port; zero before start asks for an ephemeral one.")
   (token-pathname
    :initarg :token-pathname
    :reader eval-endpoint-token-pathname
    :documentation "The private token file, read only while checking one proof.")
   (package
    :initarg :package
    :reader eval-endpoint-package
    :documentation "The package sources are read and evaluated in.")
   (evaluation-timeout
    :initarg :evaluation-timeout
    :reader eval-endpoint-evaluation-timeout
    :documentation "Seconds one request may take, from submission to response.")
   (authentication-timeout
    :initarg :authentication-timeout
    :reader eval-endpoint-authentication-timeout
    :documentation "The absolute seconds a connection has to authenticate.")
   (maximum-frame-size
    :initarg :maximum-frame-size
    :reader eval-endpoint-maximum-frame-size
    :documentation "The largest frame in octets, in either direction.")
   (maximum-source-size
    :initarg :maximum-source-size
    :reader eval-endpoint-maximum-source-size
    :documentation "The largest evaluation source in UTF-8 octets.")
   (maximum-output-size
    :initarg :maximum-output-size
    :reader eval-endpoint-maximum-output-size
    :documentation "The most characters of output and value text one response keeps.")
   (queue-capacity
    :initarg :queue-capacity
    :reader eval-endpoint-queue-capacity
    :documentation "The most pending evaluations.")
   (maximum-clients
    :initarg :maximum-clients
    :reader eval-endpoint-maximum-clients
    :documentation "The most accepted connections, authenticated or not.")
   (error-function
    :initarg :error-function
    :reader eval-endpoint-error-function
    :documentation "NIL or a function receiving configuration failures met while serving.")
   (listener
    :initform nil
    :accessor eval-endpoint-listener
    :documentation "The listening socket, or NIL when not listening.")
   (owned-unix-identity
    :initform nil
    :accessor eval-endpoint-owned-unix-identity
    :documentation "The file identity of the Unix socket this endpoint created.")
   (lock
    :initform (sb-thread:make-mutex :name "Image daemon evaluation endpoint")
    :reader eval-endpoint-lock
    :documentation "Guards lifecycle, clients and the request queue.")
   (condition-variable
    :initform (sb-thread:make-waitqueue :name "Image daemon evaluation queue")
    :reader eval-endpoint-condition-variable
    :documentation "Wakes the evaluator for work and shutdown.")
   (stopping-p
    :initform nil
    :accessor eval-endpoint-stopping-p
    :documentation "Whether shutdown has begun; a stopped endpoint never restarts.")
   (requests
    :initform nil
    :accessor eval-endpoint-requests
    :documentation "The FIFO of pending evaluation requests.")
   (listener-thread
    :initform nil
    :accessor eval-endpoint-listener-thread
    :documentation "The accept-loop thread.")
   (evaluator-thread
    :initform nil
    :accessor eval-endpoint-evaluator-thread
    :documentation "The sole evaluator thread.")
   (client-threads
    :initform nil
    :accessor eval-endpoint-client-threads
    :documentation "The connection handler threads.")
   (client-sockets
    :initform nil
    :accessor eval-endpoint-client-sockets
    :documentation "The accepted sockets, closed during shutdown."))
  (:documentation
   "An authenticated endpoint evaluating trusted Lisp forms in this image.

It retains the token file pathname, never the token octets."))


;;;; -- Conditions --

(define-condition eval-endpoint-error (daemon-error)
  ((reason
    :initarg :reason
    :initform nil
    :reader eval-endpoint-error-reason
    :documentation "The non-secret failure category, a keyword.")
   (threads
    :initarg :threads
    :initform nil
    :reader eval-endpoint-error-threads
    :documentation "The names of endpoint threads that did not stop, for :QUIESCE."))
  (:documentation
   "A structured evaluation endpoint failure.

The operation is :CONFIGURE, :CREDENTIALS, :LISTEN, :PROTOCOL, :AUTHENTICATE,
:QUEUE, :EVALUATE or :QUIESCE, and the reason narrows it without revealing
secrets."))

(defun eval--fail (operation reason message &key threads cause)
  "Signal EVAL-ENDPOINT-ERROR for OPERATION and REASON with MESSAGE."
  (error 'eval-endpoint-error :operation operation :reason reason :message message
                              :threads threads :cause cause))


;;;; -- Bounded Capture --

(defun eval-output-stream-create (capacity)
  "Return a stream retaining at most CAPACITY characters."
  (make-instance 'eval-output-stream
                 :builder (structlisp:make-bounded-sequence-builder
                           capacity :element-type 'character)))

(defun eval-output-stream-text (stream)
  "Return a fresh string holding STREAM's retained prefix."
  (coerce (structlisp:bounded-sequence-builder-snapshot (eval-output-stream--builder stream))
          'string))

(defun eval-output-stream-truncated-p (stream)
  "Return true when STREAM discarded output beyond its capacity."
  (structlisp:bounded-sequence-builder-overflowed-p (eval-output-stream--builder stream)))

(defun eval-output-stream--capture (stream character)
  "Retain CHARACTER while STREAM has room and advance its logical column."
  (structlisp:bounded-sequence-builder-try-append (eval-output-stream--builder stream)
                                                  character)
  (setf (eval-output-stream--column stream)
        (case character
          ((#\Newline #\Return) 0)
          (#\Tab
           (let ((column (eval-output-stream--column stream)))
             (+ column (- 8 (mod column 8)))))
          (otherwise
           (1+ (eval-output-stream--column stream)))))
  nil)

(defmethod trivial-gray-streams:stream-write-char ((stream eval-output-stream) character)
  "Capture CHARACTER within STREAM's capacity."
  (eval-output-stream--capture stream character)
  character)

(defmethod trivial-gray-streams:stream-write-string
    ((stream eval-output-stream) string &optional (start 0) end)
  "Capture the range of STRING that fits STREAM's capacity."
  (loop for index from start below (or end (length string))
        do (eval-output-stream--capture stream (char string index)))
  string)

(defmethod trivial-gray-streams:stream-line-column ((stream eval-output-stream))
  "Return STREAM's logical output column."
  (eval-output-stream--column stream))

(defun eval-print-bounded (value limit)
  "Return a bounded, escaped rendering of VALUE and whether it was truncated.

Circular structure prints with labels, nesting beyond eight levels and lists
beyond 64 elements are elided, and at most LIMIT characters are kept."
  (let ((stream (eval-output-stream-create limit)))
    (let ((*print-readably* nil)
          (*print-escape* t)
          (*print-circle* t)
          (*print-level* 8)
          (*print-length* 64))
      (write value :stream stream))
    (values (eval-output-stream-text stream)
            (eval-output-stream-truncated-p stream))))


;;;; -- Wire Frames --

(defun eval--protocol-error (reason message)
  "Signal a protocol failure for REASON."
  (eval--fail ':protocol reason message))

(defun eval--frame-grammar (maximum-size)
  "Return the closed data grammar of frames no larger than MAXIMUM-SIZE octets."
  (sexp-config:make-source-grammar
   :label "Evaluation protocol frame"
   :keywords *eval-frame-keywords*
   :maximum-depth 8
   :maximum-nodes 1024
   :maximum-string-characters maximum-size
   :readable-strings-permitted-p t
   :qualified-common-lisp-symbols-permitted-p t
   :allowed-atom-predicate (lambda (value)
                             (or (null value) (eq value t) (keywordp value)
                                 (stringp value) (integerp value)))))

(defun eval--integer->header (value)
  "Encode unsigned VALUE as a four-octet network-order frame header."
  (let ((header (make-array 4 :element-type '(unsigned-byte 8))))
    (setf (aref header 0) (ldb (byte 8 24) value)
          (aref header 1) (ldb (byte 8 16) value)
          (aref header 2) (ldb (byte 8 8) value)
          (aref header 3) (ldb (byte 8 0) value))
    header))

(defun eval--header->integer (header)
  "Decode a four-octet network-order frame HEADER."
  (logior (ash (aref header 0) 24)
          (ash (aref header 1) 16)
          (ash (aref header 2) 8)
          (aref header 3)))

(defun eval--read-exactly (stream count &key eof-ok-p)
  "Read exactly COUNT octets from STREAM.

Return NIL at a clean end of input before the first octet when EOF-OK-P."
  (let ((octets (make-array count :element-type '(unsigned-byte 8))))
    (loop with position = 0
          while (< position count)
          for next = (read-sequence octets stream :start position)
          do (when (= next position)
               (if (and eof-ok-p (zerop position))
                   (return-from eval--read-exactly nil)
                   (eval--protocol-error ':truncated "Truncated evaluation protocol frame.")))
             (setf position next))
    octets))

(defun eval-read-frame (stream maximum-size)
  "Read one frame of at most MAXIMUM-SIZE octets from octet STREAM.

Return its single form, or :END-OF-INPUT at a clean end of input. The length is
checked before the payload is read, and the payload is parsed by a closed
grammar that interns nothing. Failures signal EVAL-ENDPOINT-ERROR with
operation :PROTOCOL and reason :EMPTY, :TRAILING, :OVERSIZED, :TRUNCATED,
:ENCODING or :MALFORMED."
  (let ((header (eval--read-exactly stream 4 :eof-ok-p t)))
    (unless header
      (return-from eval-read-frame ':end-of-input))
    (let ((length (eval--header->integer header)))
      (when (or (zerop length) (> length maximum-size))
        (eval--protocol-error ':oversized
                              "Evaluation protocol frame size is outside its bound."))
      (let ((source (handler-case
                        (ls-compat:utf8-octets-to-string (eval--read-exactly stream length))
                      (ls-compat:utf8-conversion-failed ()
                        (eval--protocol-error ':encoding
                                              "Evaluation protocol frame is not UTF-8.")))))
        (handler-case
            (sexp-config:read-source source (eval--frame-grammar maximum-size))
          (sexp-config:sexp-config-error (condition)
            (eval--protocol-error
             (case (sexp-config:sexp-config-error-kind condition)
               (:no-form ':empty)
               (:multiple-forms ':trailing)
               ((:data-too-deep :data-too-large) ':oversized)
               (otherwise ':malformed))
             "Evaluation protocol frame violates its data grammar.")))))))

(defun eval-write-frame (stream value maximum-size)
  "Print VALUE readably as one frame of at most MAXIMUM-SIZE octets to STREAM.

Signal EVAL-ENDPOINT-ERROR with reason :OVERSIZED, writing nothing, when the
encoding does not fit."
  (let ((capture (eval-output-stream-create maximum-size)))
    (with-standard-io-syntax
      (let ((*print-readably* t)
            (*print-circle* t)
            (*print-level* 12)
            (*print-length* 256))
        (write value :stream capture)))
    (let ((octets (and (not (eval-output-stream-truncated-p capture))
                       (ls-compat:utf8-string-to-octets (eval-output-stream-text capture)))))
      (unless (and octets (<= (length octets) maximum-size))
        (eval--protocol-error ':oversized
                              "Evaluation protocol response exceeds its frame bound."))
      (write-sequence (eval--integer->header (length octets)) stream)
      (write-sequence octets stream)
      (force-output stream)))
  nil)

(defun eval--write-response (stream value maximum-size)
  "Write VALUE, degrading an oversized encoding to a bounded protocol error."
  (handler-case
      (eval-write-frame stream value maximum-size)
    (eval-endpoint-error (condition)
      (unless (eq (eval-endpoint-error-reason condition) ':oversized)
        (error condition))
      (eval-write-frame stream '(:protocol-error :reason :oversized) maximum-size)))
  nil)

(defun eval--decode-schema (form tag keys)
  "Return the properties of FORM, which must be TAG with each of KEYS exactly once."
  (unless (and (consp form) (eq (first form) tag))
    (eval--protocol-error ':request "Evaluation protocol request has the wrong tag."))
  (let ((problem (sexp-store:plist-schema-problem
                  (rest form) :allowed-keys keys :required-keys keys
                              :maximum-length (1- *eval-maximum-protocol-list-length*))))
    (when problem
      (eval--protocol-error (if (member problem '(:improper :too-long)) ':malformed ':request)
                            "Evaluation protocol request does not match its schema.")))
  (rest form))


;;;; -- Authentication --

(defun eval--octets->hex (octets)
  "Return the lowercase hexadecimal encoding of OCTETS."
  (string-downcase (ironclad:byte-array-to-hex-string octets)))

(defun eval--hex->octets (text expected-length)
  "Decode hexadecimal TEXT only when it holds exactly EXPECTED-LENGTH octets, else NIL."
  (when (and (stringp text)
             (= (length text) (* expected-length 2))
             (every (lambda (character) (digit-char-p character 16)) text))
    (let ((octets (make-array expected-length :element-type '(unsigned-byte 8))))
      (dotimes (index expected-length octets)
        (setf (aref octets index)
              (parse-integer text :start (* index 2) :end (+ (* index 2) 2) :radix 16))))))

(defun eval--constant-time-equal-p (left right)
  "Return true when octet vectors LEFT and RIGHT are equal, without an early return."
  (let ((difference (logxor (length left) (length right))))
    (loop for index below (max (length left) (length right))
          for left-octet = (if (< index (length left)) (aref left index) 0)
          for right-octet = (if (< index (length right)) (aref right index) 0)
          do (setf difference (logior difference (logxor left-octet right-octet))))
    (zerop difference)))

(defun eval--token-file-octets (pathname)
  "Read the token in private regular file PATHNAME without following a link."
  (let ((stream nil))
    (unwind-protect
         (multiple-value-bind (opened information)
             (handler-case (ls-compat.posix:open-regular-file pathname)
               (error (condition)
                 (eval--fail ':credentials ':token-open
                             "The evaluation token file is unavailable or unsafe."
                             :cause condition)))
           (setf stream opened)
           (let ((length (ls-compat.posix:file-information-size information)))
             (unless (and (ls-compat.posix:file-information-private-p information)
                          (<= 1 length *eval-token-maximum-octets*))
               (eval--fail ':credentials ':unsafe-token-file
                           (format nil "The evaluation token file must be a nonempty regular file private to the current user and no larger than ~D octets."
                                   *eval-token-maximum-octets*)))
             (let ((token (make-array length :element-type '(unsigned-byte 8))))
               (unless (= (read-sequence token stream) length)
                 (fill token 0)
                 (eval--fail ':credentials ':token-read
                             "The evaluation token file could not be read completely."))
               token)))
      (when stream
        (ignore-errors (close stream))))))

(defun eval--hmac (token nonce)
  "Return HMAC-SHA-256 of octet vector NONCE keyed by octet vector TOKEN."
  (let ((hmac (ironclad:make-hmac token ':sha256)))
    (ironclad:update-hmac hmac nonce)
    (ironclad:hmac-digest hmac)))

(defun eval-proof (token nonce)
  "Return the hexadecimal proof answering hexadecimal challenge NONCE with TOKEN.

TOKEN is the token file's content, as an octet vector or a string encoded as
UTF-8. Intermediate octets are wiped before returning."
  (let ((key (if (stringp token) (ls-compat:utf8-string-to-octets token) (copy-seq token)))
        (nonce-octets (eval--hex->octets nonce *eval-nonce-octets*))
        (proof nil))
    (unwind-protect
         (progn
           (unless nonce-octets
             (eval--protocol-error ':malformed "The evaluation challenge nonce is malformed."))
           (setf proof (eval--hmac key nonce-octets))
           (eval--octets->hex proof))
      (fill key 0)
      (when nonce-octets
        (fill nonce-octets 0))
      (when proof
        (fill proof 0)))))

(defun eval--authenticate (stream token-pathname maximum-frame-size)
  "Challenge STREAM with a fresh nonce and require the matching proof.

The token is read from TOKEN-PATHNAME only for this comparison, and every
secret octet is wiped on every exit."
  (let ((nonce (ironclad:random-data *eval-nonce-octets*))
        (token nil)
        (expected nil)
        (supplied nil))
    (unwind-protect
         (progn
           (eval-write-frame stream
                             (list ':challenge :version *eval-protocol-version*
                                               :algorithm ':hmac-sha-256
                                               :nonce (eval--octets->hex nonce))
                             maximum-frame-size)
           (let ((proof (handler-case
                            (getf (eval--decode-schema
                                   (eval-read-frame stream maximum-frame-size)
                                   ':authenticate '(:proof))
                                  :proof)
                          (eval-endpoint-error ()
                            (eval--fail ':authenticate ':malformed
                                        "Evaluation authentication request is malformed.")))))
             (setf supplied (eval--hex->octets proof *eval-proof-octets*)
                   token (eval--token-file-octets token-pathname)
                   expected (eval--hmac token nonce))
             (unless (and supplied (eval--constant-time-equal-p supplied expected))
               (eval--fail ':authenticate ':proof "Evaluation authentication failed."))))
      (fill nonce 0)
      (dolist (octets (list token expected supplied))
        (when octets
          (fill octets 0)))))
  (eval--write-response stream (list ':authenticated :version *eval-protocol-version*)
                        maximum-frame-size)
  nil)


;;;; -- Endpoint Creation --

(defun eval--loopback-address-p (address)
  "Return true when ADDRESS is an IPv4 loopback literal."
  (and (stringp address)
       (handler-case (= (aref (sb-bsd-sockets:make-inet-address address) 0) 127)
         (error ()
           nil))
       t))

(defun eval-endpoint-create (&key (transport ':tcp) unix-pathname (tcp-address "127.0.0.1")
                                  (tcp-port 0) token-pathname (package "CL-USER")
                                  (evaluation-timeout 10) (authentication-timeout 10)
                                  (maximum-frame-size 1048576) (maximum-source-size 262144)
                                  (maximum-output-size 262144) (queue-capacity 8)
                                  (maximum-clients 8) error-function)
  "Return a validated, unstarted evaluation endpoint.

TRANSPORT :UNIX listens on absolute socket UNIX-PATHNAME, which hosts without
filesystem sockets refuse; :TCP listens on IPv4 loopback TCP-ADDRESS and
TCP-PORT, where port zero picks a free port at start. TOKEN-PATHNAME names the
private token file. Sources are read and evaluated in PACKAGE.
ERROR-FUNCTION, when given, receives each configuration failure met while
serving a client, such as an unsafe token file. Invalid settings signal
EVAL-ENDPOINT-ERROR with operation :CONFIGURE."
  (flet ((require-setting (valid-p reason message)
           (unless valid-p
             (eval--fail ':configure reason message))))
    (require-setting (member transport '(:unix :tcp)) ':transport
                     "The evaluation transport must be :UNIX or :TCP.")
    #+win32
    (require-setting (eq transport ':tcp) ':transport
                     "This host has no filesystem sockets; use the :TCP transport.")
    (require-setting (or (eq transport ':tcp)
                         (and (pathnamep unix-pathname)
                              (uiop:absolute-pathname-p unix-pathname)
                              (uiop:file-pathname-p unix-pathname)))
                     ':unix-pathname "The Unix transport needs an absolute socket pathname.")
    (require-setting (or (eq transport ':unix) (eval--loopback-address-p tcp-address))
                     ':non-loopback "The TCP transport requires an IPv4 loopback address.")
    (require-setting (typep tcp-port '(integer 0 65535)) ':tcp-port
                     "The TCP port must be an integer from 0 to 65535.")
    (require-setting (and (pathnamep token-pathname) (uiop:absolute-pathname-p token-pathname))
                     ':token-pathname "The token file must be an absolute pathname.")
    (require-setting (find-package package) ':package
                     "The evaluation package does not exist.")
    (require-setting (typep maximum-frame-size `(integer ,*eval-minimum-frame-size*))
                     ':frame-size
                     (format nil "The maximum frame size must be at least ~D octets."
                             *eval-minimum-frame-size*))
    (require-setting (every (lambda (value) (typep value '(integer 1)))
                            (list evaluation-timeout authentication-timeout
                                  maximum-source-size maximum-output-size
                                  queue-capacity maximum-clients))
                     ':bounds "Evaluation timeouts, sizes and capacities must be positive integers.")
    (require-setting (or (null error-function) (functionp error-function)) ':error-function
                     "The error function must be NIL or a function."))
  (make-instance 'eval-endpoint
                 :transport transport
                 :unix-pathname unix-pathname
                 :tcp-address tcp-address
                 :tcp-port tcp-port
                 :token-pathname token-pathname
                 :package (find-package package)
                 :evaluation-timeout evaluation-timeout
                 :authentication-timeout authentication-timeout
                 :maximum-frame-size maximum-frame-size
                 :maximum-source-size maximum-source-size
                 :maximum-output-size maximum-output-size
                 :queue-capacity queue-capacity
                 :maximum-clients maximum-clients
                 :error-function error-function))


;;;; -- Evaluation --

(defun eval--remaining-seconds (request)
  "Return REQUEST's nonnegative remaining time in seconds."
  (max 0 (/ (- (eval-request-deadline request) (get-internal-real-time))
            internal-time-units-per-second)))

(defun eval--complete-request (request response)
  "Install RESPONSE once and wake REQUEST's waiting client."
  (sb-thread:with-mutex ((eval-request-lock request))
    (unless (eval-request-completed-p request)
      (setf (eval-request-response request) response
            (eval-request-completed-p request) t)
      (sb-thread:condition-broadcast (eval-request-condition-variable request))))
  nil)

(defun eval--read-source-form (source package)
  "Read exactly one form from SOURCE in PACKAGE with read-time evaluation off."
  (with-standard-io-syntax
    (let ((*read-eval* nil)
          (*readtable* (copy-readtable nil))
          (*package* package))
      (multiple-value-bind (form position) (read-from-string source nil ':end-of-input)
        (when (eq form ':end-of-input)
          (eval--protocol-error ':empty "The evaluation source contains no form."))
        (unless (eq (read-from-string source nil ':end-of-input :start position) ':end-of-input)
          (eval--protocol-error ':trailing "The evaluation source contains trailing data."))
        form))))

(defun eval--evaluate-request (endpoint request)
  "Evaluate REQUEST with bounded output before its deadline and return the response.

Debugger entry, including BREAK, becomes a :CONDITION result before any process
debugger hook runs."
  (let* ((output-limit (min (eval-endpoint-maximum-output-size endpoint)
                            (max 16 (floor (eval-endpoint-maximum-frame-size endpoint) 4))))
         (output (eval-output-stream-create output-limit)))
    (labels ((condition-response (condition timed-out-p)
               "Return the bounded failure response for CONDITION."
               (multiple-value-bind (report report-truncated-p)
                   (eval-print-bounded condition output-limit)
                 (list ':evaluation-result
                       :status (if timed-out-p ':timeout ':condition)
                       :condition-type (string (type-of condition))
                       :report report
                       :report-truncated-p report-truncated-p
                       :output (eval-output-stream-text output)
                       :output-truncated-p (eval-output-stream-truncated-p output))))

             (render-values (values)
               "Return the success response rendering every one of VALUES."
               (let ((remaining output-limit)
                     (rendered nil)
                     (truncated-p nil))
                 (dolist (value values)
                   (multiple-value-bind (text value-truncated-p)
                       (eval-print-bounded value remaining)
                     (push text rendered)
                     (decf remaining (length text))
                     (when value-truncated-p
                       (setf truncated-p t))))
                 (list ':evaluation-result
                       :status ':ok
                       :values (nreverse rendered)
                       :values-truncated-p truncated-p
                       :output (eval-output-stream-text output)
                       :output-truncated-p (eval-output-stream-truncated-p output)))))
      (handler-case
          (let ((remaining (eval--remaining-seconds request))
                (hook (lambda (condition hook)
                        (declare (ignore hook))
                        (return-from eval--evaluate-request
                          (condition-response condition nil)))))
            (when (<= remaining 0)
              (eval--fail ':evaluate ':expired "The evaluation expired before it started."))
            (sb-ext:with-timeout remaining
              (let* ((silent-input (make-string-input-stream ""))
                     (*package* (eval-endpoint-package endpoint))
                     (*standard-output* output)
                     (*error-output* output)
                     (*trace-output* output)
                     (*debug-io* (make-two-way-stream silent-input output))
                     (*query-io* (make-two-way-stream silent-input output))
                     (*terminal-io* (make-two-way-stream silent-input output))
                     (*debugger-hook* hook)
                     (sb-ext:*invoke-debugger-hook* hook))
                (render-values
                 (multiple-value-list
                  (eval (eval--read-source-form (eval-request-source request)
                                                (eval-endpoint-package endpoint))))))))
        (sb-ext:timeout (condition)
          (condition-response condition t))
        (serious-condition (condition)
          (condition-response condition nil))))))

(defun eval--run-evaluator (endpoint)
  "Evaluate ENDPOINT's queued requests one at a time until shutdown drains it."
  (loop for request = (sb-thread:with-mutex ((eval-endpoint-lock endpoint))
                        (loop while (and (null (eval-endpoint-requests endpoint))
                                         (not (eval-endpoint-stopping-p endpoint)))
                              do (sb-thread:condition-wait
                                  (eval-endpoint-condition-variable endpoint)
                                  (eval-endpoint-lock endpoint)))
                        (pop (eval-endpoint-requests endpoint)))
        while request
        do (eval--complete-request request (eval--evaluate-request endpoint request)))
  nil)

(defun eval--submit (endpoint source)
  "Queue SOURCE on ENDPOINT and return its response, waiting no longer than its deadline."
  (let ((request (make-instance 'eval-request
                                :source source
                                :deadline (+ (get-internal-real-time)
                                             (* (eval-endpoint-evaluation-timeout endpoint)
                                                internal-time-units-per-second)))))
    (sb-thread:with-mutex ((eval-endpoint-lock endpoint))
      (when (or (eval-endpoint-stopping-p endpoint)
                (>= (length (eval-endpoint-requests endpoint))
                    (eval-endpoint-queue-capacity endpoint)))
        (eval--fail ':queue ':capacity "The evaluation queue is full or stopping."))
      (setf (eval-endpoint-requests endpoint)
            (nconc (eval-endpoint-requests endpoint) (list request)))
      (sb-thread:condition-notify (eval-endpoint-condition-variable endpoint)))
    (sb-thread:with-mutex ((eval-request-lock request))
      (loop until (eval-request-completed-p request)
            for remaining = (eval--remaining-seconds request)
            while (plusp remaining)
            do (sb-thread:condition-wait (eval-request-condition-variable request)
                                         (eval-request-lock request)
                                         :timeout remaining))
      (if (eval-request-completed-p request)
          (eval-request-response request)
          (list ':evaluation-result
                :status ':timeout
                :condition-type "TIMEOUT"
                :report "The evaluation deadline expired."
                :report-truncated-p nil
                :output ""
                :output-truncated-p nil)))))

(defun eval--request-source (request maximum-source-size)
  "Return the source of evaluation REQUEST, no longer than MAXIMUM-SOURCE-SIZE octets."
  (let ((source (getf (eval--decode-schema request ':evaluate '(:source)) :source)))
    (unless (stringp source)
      (eval--protocol-error ':request "The evaluation source must be a string."))
    (when (> (length (ls-compat:utf8-string-to-octets source)) maximum-source-size)
      (eval--protocol-error ':oversized "The evaluation source is oversized."))
    source))


;;;; -- Listening --

(defun eval--native-namestring (pathname)
  "Return PATHNAME's native namestring."
  (sb-ext:native-namestring pathname))

#-win32
(defun eval--connect-unix (pathname)
  "Return a stream socket connected to the Unix endpoint at PATHNAME."
  (let ((socket (make-instance 'sb-bsd-sockets:local-socket :type ':stream)))
    (handler-case
        (progn
          (sb-bsd-sockets:socket-connect socket (eval--native-namestring pathname))
          socket)
      (error (condition)
        (ignore-errors (sb-bsd-sockets:socket-close socket))
        (error condition)))))

(defun eval--connect-tcp (address port)
  "Return a stream socket connected to TCP ADDRESS and PORT."
  (let ((socket (make-instance 'sb-bsd-sockets:inet-socket :type ':stream :protocol ':tcp)))
    (handler-case
        (progn
          (sb-bsd-sockets:socket-connect socket (sb-bsd-sockets:make-inet-address address) port)
          socket)
      (error (condition)
        (ignore-errors (sb-bsd-sockets:socket-close socket))
        (error condition)))))

#-win32
(defun eval--prepare-unix-directory (directory)
  "Create DIRECTORY when needed and require it private to the current user."
  (ensure-directories-exist directory)
  (let ((information (handler-case (ls-compat.posix:file-information directory)
                       (ls-compat.posix:file-operation-failed ()
                         nil))))
    (unless (and information
                 (eq (ls-compat.posix:file-information-kind information) ':directory)
                 (ls-compat.posix:file-information-owned-p information))
      (eval--fail ':listen ':unsafe-socket-directory
                  "The evaluation socket directory is not owned by the current user."))
    (setf (ls-compat.posix:file-mode directory) #o700))
  nil)

#-win32
(defun eval--require-stale-unix-endpoint (pathname)
  "Signal unless the socket at PATHNAME provably refuses connections."
  (let ((probe nil))
    (unwind-protect
         (handler-case
             (progn
               (setf probe (eval--connect-unix pathname))
               (eval--fail ':listen ':active-endpoint
                           "The evaluation Unix endpoint is already active."))
           (sb-bsd-sockets:connection-refused-error ()
             nil)
           (sb-bsd-sockets:socket-error ()
             (eval--fail ':listen ':unproven-stale
                         "The evaluation Unix socket could not be proven stale.")))
      (when probe
        (ignore-errors (sb-bsd-sockets:socket-close probe)))))
  nil)

#-win32
(defun eval--prepare-unix-path (pathname)
  "Make PATHNAME free, removing only a provably stale socket the current user owns.

The stale socket is first renamed to a private quarantine name and removed only
when the renamed object is still the socket that was inspected."
  (eval--prepare-unix-directory (uiop:pathname-directory-pathname pathname))
  (let ((status (handler-case (ls-compat.posix:file-information pathname)
                  (ls-compat.posix:file-operation-failed (condition)
                    (unless (eq (ls-compat.posix:file-operation-failed-reason condition)
                                ':missing)
                      (eval--fail ':listen ':socket-inspection
                                  "The evaluation socket path could not be inspected."
                                  :cause condition))
                    nil))))
    (when status
      (unless (and (eq (ls-compat.posix:file-information-kind status) ':socket)
                   (ls-compat.posix:file-information-owned-p status))
        (eval--fail ':listen ':unsafe-socket-path
                    "The evaluation socket path holds an alien or non-socket object."))
      (eval--require-stale-unix-endpoint pathname)
      (let ((quarantine (make-pathname :name (format nil ".eval-stale-~A" (daemon-random-nonce))
                                       :type nil
                                       :defaults pathname)))
        (handler-case
            (sb-posix:rename (eval--native-namestring pathname)
                             (eval--native-namestring quarantine))
          (sb-posix:syscall-error (condition)
            (eval--fail ':listen ':socket-inspection
                        "The stale evaluation socket could not be quarantined."
                        :cause condition)))
        (let ((moved (handler-case (ls-compat.posix:file-information quarantine)
                       (ls-compat.posix:file-operation-failed ()
                         nil))))
          (unless (and moved
                       (eq (ls-compat.posix:file-information-kind moved) ':socket)
                       (ls-compat.posix:file-information-same-object-p status moved))
            (eval--fail ':listen ':socket-replaced
                        "The evaluation socket changed during stale-path quarantine."))
          (delete-file quarantine)))))
  nil)

#-win32
(defun eval--unix-listener (endpoint)
  "Bind and return ENDPOINT's private Unix listener, recording the socket's identity."
  (let ((pathname (eval-endpoint-unix-pathname endpoint)))
    (eval--prepare-unix-path pathname)
    (let ((listener (make-instance 'sb-bsd-sockets:local-socket :type ':stream)))
      (handler-case
          (progn
            (sb-bsd-sockets:socket-bind listener (eval--native-namestring pathname))
            (setf (ls-compat.posix:file-mode pathname) #o600
                  (eval-endpoint-owned-unix-identity endpoint)
                  (ls-compat.posix:file-information-identity
                   (ls-compat.posix:file-information pathname)))
            (sb-bsd-sockets:socket-listen listener (eval-endpoint-maximum-clients endpoint))
            listener)
        (error (condition)
          (ignore-errors (sb-bsd-sockets:socket-close listener))
          (when (eval--owned-unix-path-p endpoint)
            (ignore-errors (delete-file pathname)))
          (eval--fail ':listen ':bind "The evaluation Unix socket could not listen."
                      :cause condition))))))

(defun eval--tcp-listener (endpoint)
  "Bind and return ENDPOINT's loopback TCP listener, recording its bound port."
  (let ((listener (make-instance 'sb-bsd-sockets:inet-socket :type ':stream :protocol ':tcp)))
    (handler-case
        (progn
          (setf (sb-bsd-sockets:sockopt-reuse-address listener) t)
          (sb-bsd-sockets:socket-bind listener
                                      (sb-bsd-sockets:make-inet-address
                                       (eval-endpoint-tcp-address endpoint))
                                      (eval-endpoint-tcp-port endpoint))
          (sb-bsd-sockets:socket-listen listener (eval-endpoint-maximum-clients endpoint))
          (setf (eval-endpoint-tcp-port endpoint)
                (nth-value 1 (sb-bsd-sockets:socket-name listener)))
          listener)
      (error (condition)
        (ignore-errors (sb-bsd-sockets:socket-close listener))
        (eval--fail ':listen ':bind "The evaluation TCP endpoint could not listen."
                    :cause condition)))))

(defun eval--owned-unix-path-p (endpoint)
  "Return true when ENDPOINT's Unix pathname still names the socket it created."
  (let ((identity (eval-endpoint-owned-unix-identity endpoint)))
    (and identity
         (handler-case
             (let ((information (ls-compat.posix:file-information
                                 (eval-endpoint-unix-pathname endpoint))))
               (and (eq (ls-compat.posix:file-information-kind information) ':socket)
                    (equal (ls-compat.posix:file-information-identity information) identity)))
           (error ()
             nil))
         t)))

(defun eval--wake-listener (endpoint)
  "Unblock a pending accept on ENDPOINT's listener by connecting to it once."
  (let ((socket (ignore-errors
                 (ecase (eval-endpoint-transport endpoint)
                   (:unix
                    #-win32 (eval--connect-unix (eval-endpoint-unix-pathname endpoint))
                    #+win32 nil)
                   (:tcp
                    (eval--connect-tcp (eval-endpoint-tcp-address endpoint)
                                       (eval-endpoint-tcp-port endpoint)))))))
    (when socket
      (ignore-errors (sb-bsd-sockets:socket-close socket))))
  nil)


;;;; -- Serving --

(defun eval--report (endpoint condition)
  "Pass serving failure CONDITION to ENDPOINT's error function, if any."
  (let ((function (eval-endpoint-error-function endpoint)))
    (when function
      (ignore-errors (funcall function condition))))
  nil)

(defun eval--handle-client (endpoint socket)
  "Authenticate SOCKET, then serve its requests one at a time until it closes."
  (let ((maximum (eval-endpoint-maximum-frame-size endpoint))
        (stream nil))
    (unwind-protect
         (handler-case
             (progn
               (setf stream (sb-bsd-sockets:socket-make-stream
                             socket :input t :output t
                                    :element-type '(unsigned-byte 8)
                                    :buffering ':none
                                    :timeout (eval-endpoint-evaluation-timeout endpoint)))
               (sb-ext:with-timeout (eval-endpoint-authentication-timeout endpoint)
                 (eval--authenticate stream (eval-endpoint-token-pathname endpoint) maximum))
               (loop for request = (eval-read-frame stream maximum)
                     until (eq request ':end-of-input)
                     do (eval--write-response
                         stream
                         (eval--submit endpoint
                                       (eval--request-source
                                        request (eval-endpoint-maximum-source-size endpoint)))
                         maximum)))
           (eval-endpoint-error (condition)
             (when (eq (daemon-error-operation condition) ':credentials)
               (eval--report endpoint condition)))
           (sb-ext:timeout ()
             nil)
           (error ()
             nil))
      (if stream
          (ignore-errors (close stream))
          (ignore-errors (sb-bsd-sockets:socket-close socket)))))
  nil)

(defun eval--run-client (endpoint socket)
  "Serve SOCKET, then remove it and this thread from ENDPOINT."
  (unwind-protect
       (eval--handle-client endpoint socket)
    (sb-thread:with-mutex ((eval-endpoint-lock endpoint))
      (setf (eval-endpoint-client-threads endpoint)
            (delete sb-thread:*current-thread* (eval-endpoint-client-threads endpoint))
            (eval-endpoint-client-sockets endpoint)
            (delete socket (eval-endpoint-client-sockets endpoint)))))
  nil)

(defun eval--serve (endpoint)
  "Accept connections up to ENDPOINT's client bound until shutdown."
  (loop
    (handler-case
        (let ((socket (sb-bsd-sockets:socket-accept (eval-endpoint-listener endpoint))))
          (sb-thread:with-mutex ((eval-endpoint-lock endpoint))
            (when (eval-endpoint-stopping-p endpoint)
              (ignore-errors (sb-bsd-sockets:socket-close socket))
              (return))
            (if (>= (length (eval-endpoint-client-sockets endpoint))
                    (eval-endpoint-maximum-clients endpoint))
                (ignore-errors (sb-bsd-sockets:socket-close socket))
                (handler-case
                    (let ((thread (sb-thread:make-thread
                                   (lambda () (eval--run-client endpoint socket))
                                   :name "Image daemon evaluation client")))
                      (push socket (eval-endpoint-client-sockets endpoint))
                      (push thread (eval-endpoint-client-threads endpoint)))
                  (error ()
                    (ignore-errors (sb-bsd-sockets:socket-close socket)))))))
      (error ()
        (return))))
  nil)


;;;; -- Lifecycle --

(defun eval-endpoint-start (endpoint)
  "Listen and start ENDPOINT's evaluator and accept threads, then return ENDPOINT.

Starting a running endpoint returns it unchanged; a stopped endpoint never
restarts. When any step fails, everything already started is stopped and the
failure is resignaled."
  (sb-thread:with-mutex ((eval-endpoint-lock endpoint))
    (when (eval-endpoint-stopping-p endpoint)
      (eval--fail ':listen ':stopped "A stopped evaluation endpoint cannot restart."))
    (when (eval-endpoint-listener endpoint)
      (return-from eval-endpoint-start endpoint))
    (setf (eval-endpoint-listener endpoint)
          (ecase (eval-endpoint-transport endpoint)
            (:unix
             #-win32 (eval--unix-listener endpoint)
             #+win32 (eval--fail ':listen ':transport "This host has no filesystem sockets."))
            (:tcp
             (eval--tcp-listener endpoint)))))
  (handler-case
      (progn
        (setf (eval-endpoint-evaluator-thread endpoint)
              (funcall *eval-make-thread-function*
                       (lambda () (eval--run-evaluator endpoint))
                       :name "Image daemon evaluator")
              (eval-endpoint-listener-thread endpoint)
              (funcall *eval-make-thread-function*
                       (lambda () (eval--serve endpoint))
                       :name "Image daemon evaluation endpoint"))
        endpoint)
    (error (condition)
      (ignore-errors (eval-endpoint-stop endpoint))
      (error condition))))

(defun eval--wait-for-threads (threads timeout)
  "Return those of THREADS still alive after waiting at most TIMEOUT seconds."
  (let ((deadline (+ (get-internal-real-time) (* timeout internal-time-units-per-second))))
    (loop for alive = (remove-if-not (lambda (thread)
                                       (and thread
                                            (not (eq thread sb-thread:*current-thread*))
                                            (sb-thread:thread-alive-p thread)))
                                     threads)
          while (and alive (< (get-internal-real-time) deadline))
          do (sleep 0.01)
          finally (return alive))))

(defun eval-endpoint-stop (endpoint &key (timeout *eval-stop-timeout-seconds*))
  "Stop ENDPOINT and wait at most TIMEOUT seconds for its threads.

Pending requests complete as conditions, the listener and every client socket
close, and the Unix socket is removed while it is still the one ENDPOINT
created. Stopping again is harmless, and the evaluator thread may stop its own
endpoint. Threads still alive at the deadline signal EVAL-ENDPOINT-ERROR with
operation :QUIESCE naming them."
  (let (listener sockets threads pending)
    (sb-thread:with-mutex ((eval-endpoint-lock endpoint))
      (setf (eval-endpoint-stopping-p endpoint) t
            listener (eval-endpoint-listener endpoint)
            sockets (copy-list (eval-endpoint-client-sockets endpoint))
            threads (list* (eval-endpoint-listener-thread endpoint)
                           (eval-endpoint-evaluator-thread endpoint)
                           (eval-endpoint-client-threads endpoint))
            pending (eval-endpoint-requests endpoint)
            (eval-endpoint-requests endpoint) nil)
      (sb-thread:condition-broadcast (eval-endpoint-condition-variable endpoint)))
    (dolist (request pending)
      (eval--complete-request request '(:evaluation-result :status :condition)))
    (when listener
      (eval--wake-listener endpoint)
      (ignore-errors (sb-bsd-sockets:socket-close listener)))
    (dolist (socket sockets)
      (ignore-errors (sb-bsd-sockets:socket-close socket)))
    (let ((alive (eval--wait-for-threads threads timeout)))
      (when alive
        (eval--fail ':quiesce ':threads
                    "Evaluation endpoint threads did not stop before the deadline."
                    :threads (mapcar (lambda (thread)
                                       (or (sb-thread:thread-name thread) "unnamed"))
                                     alive))))
    (when (eval--owned-unix-path-p endpoint)
      (ignore-errors (delete-file (eval-endpoint-unix-pathname endpoint))))
    (sb-thread:with-mutex ((eval-endpoint-lock endpoint))
      (setf (eval-endpoint-listener endpoint) nil)))
  nil)


;;;; -- Clients --

(defun eval-connect (&key (transport ':tcp) unix-pathname (tcp-address "127.0.0.1") tcp-port
                          token (maximum-frame-size 1048576) (timeout 10))
  "Connect to an evaluation endpoint and authenticate with TOKEN.

TOKEN is the token file's content, as a string or octet vector. Return two
values: the socket and its authenticated octet stream, whose reads and writes
wait at most TIMEOUT seconds. A refused proof signals EVAL-ENDPOINT-ERROR with
operation :AUTHENTICATE."
  (let ((socket (ecase transport
                  (:unix
                   #-win32 (eval--connect-unix unix-pathname)
                   #+win32 (eval--fail ':listen ':transport "This host has no filesystem sockets."))
                  (:tcp
                   (eval--connect-tcp tcp-address tcp-port))))
        (completed-p nil))
    (unwind-protect
         (let* ((stream (sb-bsd-sockets:socket-make-stream
                         socket :input t :output t
                                :element-type '(unsigned-byte 8)
                                :buffering ':none
                                :timeout timeout))
                (challenge (eval-read-frame stream maximum-frame-size)))
           (unless (and (consp challenge) (eq (first challenge) ':challenge))
             (eval--fail ':authenticate ':malformed "The endpoint sent no challenge."))
           (eval-write-frame stream
                             (list ':authenticate
                                   :proof (eval-proof token (getf (rest challenge) :nonce)))
                             maximum-frame-size)
           (let ((answer (eval-read-frame stream maximum-frame-size)))
             (unless (and (consp answer) (eq (first answer) ':authenticated))
               (eval--fail ':authenticate ':proof "The endpoint refused the proof.")))
           (setf completed-p t)
           (values socket stream))
      (unless completed-p
        (ignore-errors (sb-bsd-sockets:socket-close socket))))))

(defun eval-call (stream source &key (maximum-frame-size 1048576))
  "Send SOURCE for evaluation on authenticated STREAM and return the response form.

A success is (:EVALUATION-RESULT :STATUS :OK :VALUES TEXTS ...); failures carry
:STATUS :CONDITION or :TIMEOUT with a bounded report."
  (eval-write-frame stream (list ':evaluate :source source) maximum-frame-size)
  (eval-read-frame stream maximum-frame-size))
