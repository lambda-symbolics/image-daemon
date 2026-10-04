(in-package #:image-daemon/tests)

(defun eval-tests--root (name)
  "Return a fresh private temporary directory pathname for test NAME."
  (merge-pathnames (format nil "daemon-eval-~A-~A/" name (daemon-random-nonce))
                   (uiop:temporary-directory)))

(defun eval-tests--write-token (root token)
  "Write TOKEN to a private token file beneath ROOT and return its pathname."
  (let ((pathname (merge-pathnames "token" root)))
    (ensure-directories-exist pathname)
    (with-open-file (stream pathname :direction :output :if-exists :supersede
                                     :external-format :utf-8)
      (write-string token stream))
    (setf (ls-compat.posix:file-mode pathname) #o600)
    pathname))

(defun eval-tests--endpoint (root &rest arguments)
  "Return an unstarted endpoint beneath ROOT, adjusted by ARGUMENTS."
  (apply #'eval-endpoint-create
         (append arguments
                 (list :transport #-win32 ':unix #+win32 ':tcp
                       :unix-pathname (merge-pathnames "private/eval.sock" root)
                       :token-pathname (merge-pathnames "token" root)
                       :evaluation-timeout 1 :authentication-timeout 1
                       :maximum-frame-size 65536 :maximum-source-size 4096
                       :maximum-output-size 4096 :queue-capacity 2 :maximum-clients 2))))

(defun eval-tests--connect (endpoint token)
  "Connect and authenticate to ENDPOINT with TOKEN, returning the socket and stream."
  (eval-connect :transport (eval-endpoint-transport endpoint)
                :unix-pathname (eval-endpoint-unix-pathname endpoint)
                :tcp-address (eval-endpoint-tcp-address endpoint)
                :tcp-port (eval-endpoint-tcp-port endpoint)
                :token token :maximum-frame-size 65536 :timeout 2))

(defun eval-tests--frame (source)
  "Return an octet input stream holding SOURCE as one frame."
  (let ((octets (ls-compat:utf8-string-to-octets source))
        (length nil))
    (setf length (length octets))
    (flexi-streams:make-in-memory-input-stream
     (concatenate '(vector (unsigned-byte 8))
                  (vector (ldb (byte 8 24) length) (ldb (byte 8 16) length)
                          (ldb (byte 8 8) length) (ldb (byte 8 0) length))
                  octets))))

(defun eval-tests--reason (thunk)
  "Return the reason of the EVAL-ENDPOINT-ERROR THUNK signals, or :NONE."
  (handler-case (progn (funcall thunk) ':none)
    (eval-endpoint-error (condition)
      (eval-endpoint-error-reason condition))))

(defun eval-tests--with-root (name function)
  "Call FUNCTION with a fresh root for NAME and remove the root afterwards."
  (let ((root (eval-tests--root name)))
    (unwind-protect (funcall function root)
      (uiop:delete-directory-tree root :validate t :if-does-not-exist :ignore))))

(defun test-eval-frames ()
  "Test bounded frames, the closed grammar and request schemas."
  (let ((output (flexi-streams:make-in-memory-output-stream)))
    (eval-write-frame output '(:evaluate :source "(+ 1 2)") 4096)
    (check (equal (eval-read-frame (flexi-streams:make-in-memory-input-stream
                                    (flexi-streams:get-output-stream-sequence output))
                                   4096)
                  '(:evaluate :source "(+ 1 2)"))
           "frames round-trip one readable form"))
  (check (eq (eval-read-frame (flexi-streams:make-in-memory-input-stream #()) 4096)
             ':end-of-input)
         "a clean end of input is reported")
  (loop for (source reason) in
        (list (list "   " ':empty)
              (list "(:authenticate :proof \"x\") nil" ':trailing)
              (list "#1=(:authenticate :proof #1#)" ':malformed)
              (list "(:authenticate :proof #A((999999999) BASE-CHAR . \"x\"))" ':malformed)
              (list "(:authenticate :proof eval-untrusted-symbol)" ':malformed)
              (list "(:authenticate :proof :eval-untrusted-keyword)" ':malformed)
              (list (format nil "~A nil ~A" (make-string 100 :initial-element #\()
                            (make-string 100 :initial-element #\)))
                    ':oversized)
              (list (format nil "(~{~A ~})" (make-list 600 :initial-element "nil"))
                    ':oversized))
        do (check (eq (eval-tests--reason
                       (lambda () (eval-read-frame (eval-tests--frame source) 65536)))
                      reason)
                  "~S is refused as ~S" source reason))
  (check (null (find-symbol "EVAL-UNTRUSTED-KEYWORD" '#:keyword))
         "unauthenticated frames intern nothing")
  (check (eq (eval-tests--reason
              (lambda ()
                (eval-read-frame (flexi-streams:make-in-memory-input-stream
                                  #(0 0 1 0 40)) 65536)))
             ':truncated)
         "a short payload is truncated")
  (check (eq (eval-tests--reason
              (lambda ()
                (eval-read-frame (flexi-streams:make-in-memory-input-stream
                                  #(0 1 0 1)) 128)))
             ':oversized)
         "a declared length beyond the bound is refused before reading")
  (dolist (request (list (list :evaluate :source "1" :source "2")
                         (list :evaluate :source "1" :unknown t)
                         (list :evaluate)
                         (let ((cyclic (list :evaluate :source "1")))
                           (setf (rest (last cyclic)) cyclic)
                           cyclic)))
    (check (not (eq (eval-tests--reason
                     (lambda () (image-daemon::eval--request-source request 4096)))
                    ':none))
           "duplicate, unknown, missing and cyclic request keys are refused"))
  (let ((output (flexi-streams:make-in-memory-output-stream)))
    (image-daemon::eval--write-response
     output (list :evaluation-result :output (make-string 4096 :initial-element #\x)) 128)
    (check (equal (eval-read-frame (flexi-streams:make-in-memory-input-stream
                                    (flexi-streams:get-output-stream-sequence output))
                                   128)
                  '(:protocol-error :reason :oversized))
           "an oversized response degrades to a bounded protocol error"))
  (multiple-value-bind (text truncated-p) (eval-print-bounded (make-list 100) 20)
    (check (and (= (length text) 20) truncated-p)
           "bounded printing keeps a marked prefix")))

(defun test-eval-configuration ()
  "Test endpoint settings validation and token proofs."
  (eval-tests--with-root
   "configuration"
   (lambda (root)
     (let ((token (merge-pathnames "token" root)))
       (loop for (arguments reason) in
             `(((:transport :pipe) :transport)
               ((:transport :tcp :tcp-address "192.0.2.1") :non-loopback)
               ((:transport :tcp :tcp-port 70000) :tcp-port)
               ((:transport :unix :unix-pathname #p"relative.sock") :unix-pathname)
               ((:token-pathname nil) :token-pathname)
               ((:maximum-frame-size 64) :frame-size)
               ((:queue-capacity 0) :bounds)
               ((:package "NO-SUCH-EVAL-PACKAGE") :package))
             do (check (eq (eval-tests--reason
                            (lambda ()
                              (apply #'eval-endpoint-create
                                     (append arguments (list :token-pathname token)))))
                           reason)
                       "~S is refused as ~S" arguments reason))
       (check (typep (eval-endpoint-create :token-pathname token) 'eval-endpoint)
              "loopback TCP is the default transport")))))

(defun test-eval-debugger-hook ()
  "Test evaluation intercepts debugger entry before the process hook."
  (let* ((endpoint (eval-endpoint-create :token-pathname #p"/nonexistent/token"))
         (request (make-instance 'image-daemon::eval-request
                                 :source "(break \"eval test\")"
                                 :deadline (+ (get-internal-real-time)
                                              (* 2 internal-time-units-per-second))))
         (outer-hook-called-p nil))
    (let ((sb-ext:*invoke-debugger-hook* (lambda (condition hook)
                                           (declare (ignore condition hook))
                                           (setf outer-hook-called-p t)
                                           (error "The process debugger hook ran."))))
      (let ((response (image-daemon::eval--evaluate-request endpoint request)))
        (check (and (not outer-hook-called-p)
                    (eq (getf (rest response) :status) ':condition)
                    (search "eval test" (getf (rest response) :report)))
               "BREAK becomes a condition result")))))

(defun test-eval-lifecycle ()
  "Test authentication, evaluation, wrong tokens and idempotent shutdown."
  (eval-tests--with-root
   "lifecycle"
   (lambda (root)
     (eval-tests--write-token root "eval-token")
     (let ((endpoint (eval-tests--endpoint root))
           (stream nil))
       (unwind-protect
            (progn
              (eval-endpoint-start endpoint)
              (check (eq endpoint (eval-endpoint-start endpoint))
                     "starting a running endpoint is harmless")
              (multiple-value-bind (socket connected) (eval-tests--connect endpoint "eval-token")
                (declare (ignore socket))
                (setf stream connected)
                (let ((response (eval-call stream "(progn (format t \"hello\") (values 42 :done))"
                                           :maximum-frame-size 65536)))
                  (check (and (eq (getf (rest response) :status) ':ok)
                              (equal (getf (rest response) :values) '("42" ":DONE"))
                              (string= (getf (rest response) :output) "hello"))
                         "every value and the captured output return"))
                (let ((response (eval-call stream "(error \"boom\")" :maximum-frame-size 65536)))
                  (check (and (eq (getf (rest response) :status) ':condition)
                              (search "boom" (getf (rest response) :report)))
                         "an error becomes a bounded condition result"))
                (let ((response (eval-call stream "(sleep 5)" :maximum-frame-size 65536)))
                  (check (eq (getf (rest response) :status) ':timeout)
                         "an evaluation stops at its deadline"))
                (close stream)
                (setf stream nil))
              (check (eq (eval-tests--reason (lambda () (eval-tests--connect endpoint "wrong")))
                         ':proof)
                     "a wrong token is refused")
              (eval-endpoint-stop endpoint)
              (eval-endpoint-stop endpoint)
              (check (eq (eval-tests--reason (lambda () (eval-endpoint-start endpoint)))
                         ':stopped)
                     "a stopped endpoint never restarts")
              #-win32
              (check (not (probe-file (eval-endpoint-unix-pathname endpoint)))
                     "shutdown removes the owned Unix socket"))
         (when stream
           (ignore-errors (close stream)))
         (ignore-errors (eval-endpoint-stop endpoint)))))))

#-win32
(defun test-eval-unix-paths ()
  "Test stale-socket quarantine and refusal of active or alien socket paths."
  (eval-tests--with-root
   "paths"
   (lambda (root)
     (eval-tests--write-token root "path-token")
     (let ((first (eval-tests--endpoint root))
           (second (eval-tests--endpoint root))
           (pathname (merge-pathnames "private/eval.sock" root)))
       (unwind-protect
            (progn
              (eval-endpoint-start first)
              (check (eq (eval-tests--reason (lambda () (eval-endpoint-start second)))
                         ':active-endpoint)
                     "an active endpoint is never replaced")
              (eval-endpoint-stop first)
              (let ((stale (make-instance 'sb-bsd-sockets:local-socket :type :stream)))
                (sb-bsd-sockets:socket-bind stale (sb-ext:native-namestring pathname))
                (sb-bsd-sockets:socket-close stale))
              (check (probe-file pathname) "a stale socket remains on disk")
              (let ((third (eval-tests--endpoint root)))
                (unwind-protect
                     (progn
                       (eval-endpoint-start third)
                       (multiple-value-bind (socket stream)
                           (eval-tests--connect third "path-token")
                         (declare (ignore socket))
                         (close stream))
                       (check t "a provably stale socket is replaced"))
                  (eval-endpoint-stop third)))
              (with-open-file (stream pathname :direction :output :if-exists :supersede)
                (write-string "alien" stream))
              (check (eq (eval-tests--reason
                          (lambda () (eval-endpoint-start (eval-tests--endpoint root))))
                         ':unsafe-socket-path)
                     "a non-socket object at the path is refused")
              (check (probe-file pathname) "a refused path is left alone"))
         (ignore-errors (eval-endpoint-stop first))
         (ignore-errors (eval-endpoint-stop second)))))))

(defun test-eval-token-file ()
  "Test that only a private regular token file authenticates."
  (eval-tests--with-root
   "token"
   (lambda (root)
     (let* ((pathname (eval-tests--write-token root "token-text"))
            (failures nil)
            (endpoint (eval-tests--endpoint root :transport ':tcp
                                                 :error-function (lambda (condition)
                                                                   (push condition failures)))))
       (unwind-protect
            (progn
              (eval-endpoint-start endpoint)
              (setf (ls-compat.posix:file-mode pathname) #o644)
              (check (eq (eval-tests--reason (lambda () (eval-tests--connect endpoint "token-text")))
                         ':proof)
                     "a token file readable by others refuses authentication")
              (check (loop repeat 100
                           until failures
                           do (sleep 0.01)
                           finally (return
                                     (and failures
                                          (eq (eval-endpoint-error-reason (first failures))
                                              ':unsafe-token-file))))
                     "the unsafe token file is reported to the error function")
              (setf (ls-compat.posix:file-mode pathname) #o600)
              (multiple-value-bind (socket stream) (eval-tests--connect endpoint "token-text")
                (declare (ignore socket))
                (close stream)
                (check t "a private token file authenticates again")))
         (eval-endpoint-stop endpoint))))))

(defun test-eval-client-bounds ()
  "Test the client bound and the absolute authentication deadline."
  (eval-tests--with-root
   "bounds"
   (lambda (root)
     (eval-tests--write-token root "bound-token")
     (let ((endpoint (eval-tests--endpoint root :transport ':tcp :maximum-clients 1))
           (sockets nil))
       (flet ((raw-stream ()
                (let ((socket (image-daemon::eval--connect-tcp
                               "127.0.0.1" (eval-endpoint-tcp-port endpoint))))
                  (push socket sockets)
                  (sb-bsd-sockets:socket-make-stream socket :input t :output t
                                                            :element-type '(unsigned-byte 8)
                                                            :buffering :none :timeout 2))))
         (unwind-protect
              (let ((partial (progn (eval-endpoint-start endpoint) (raw-stream))))
                (eval-read-frame partial 65536)
                (write-sequence #(0 0) partial)
                (force-output partial)
                (let ((overload (raw-stream)))
                  (check (handler-case (eq (read-byte overload nil :end) :end)
                           (error () t))
                         "connections beyond the client bound close at once"))
                (check (sb-ext:with-timeout 3
                         (loop while (sb-thread:with-mutex
                                         ((image-daemon::eval-endpoint-lock endpoint))
                                       (image-daemon::eval-endpoint-client-sockets endpoint))
                               do (sleep 0.01))
                         t)
                       "partial authentication ends at its absolute deadline")
                (multiple-value-bind (socket stream) (eval-tests--connect endpoint "bound-token")
                  (declare (ignore socket))
                  (close stream))
                (check (sb-ext:with-timeout 3 (eval-endpoint-stop endpoint) t)
                       "shutdown stays bounded after incomplete authentication"))
           (dolist (socket sockets)
             (ignore-errors (sb-bsd-sockets:socket-close socket)))
           (ignore-errors (eval-endpoint-stop endpoint))))))))

(defun test-eval-start-failure ()
  "Test a failed thread start removes the listener and the owned socket."
  (eval-tests--with-root
   "start"
   (lambda (root)
     (eval-tests--write-token root "start-token")
     (let ((endpoint (eval-tests--endpoint root))
           (calls 0))
       (let ((*eval-make-thread-function*
               (lambda (function &key name)
                 (when (= (incf calls) 2)
                   (error "Injected thread failure."))
                 (sb-thread:make-thread function :name name))))
         (check (handler-case (progn (eval-endpoint-start endpoint) nil)
                  (error () t))
                "a thread failure is reported"))
       (check (and (null (image-daemon::eval-endpoint-listener endpoint))
                   (not (sb-thread:thread-alive-p (eval-endpoint-evaluator-thread endpoint)))
                   #-win32 (not (probe-file (eval-endpoint-unix-pathname endpoint))))
              "a failed start leaves nothing running")))))
