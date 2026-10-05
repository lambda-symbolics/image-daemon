(defpackage #:image-daemon/message-tests
  (:use #:cl)
  (:export #:run-tests #:child-serve))

(in-package #:image-daemon/message-tests)

(defvar *checks* 0)

(defun check (value)
  "Count one behavioral assertion."
  (incf *checks*)
  (unless value (error "Message assertion ~D failed." *checks*)))

(defun failure (reason function)
  "Require a typed message failure from FUNCTION."
  (check (handler-case (progn (funcall function) nil)
           (image-daemon:daemon-message-error (condition)
             (eq reason (image-daemon:daemon-message-error-reason condition))))))

(defun child-serve (directory)
  "Host a real detached test endpoint until its authenticated stop operation."
  (let ((done nil) (lock (bordeaux-threads:make-lock)) (runtime nil))
    (setf runtime
          (image-daemon:daemon-message-endpoint-create
           :directory directory :identifier "message-test" :character-limit 2048 :request-timeout 0.3
           :dispatcher
           (lambda (envelope &key cancelled-p)
             (case (getf envelope :action)
               (:echo (list :pid (sb-posix:getpid) :data (getf envelope :payload)))
               (:oversize (make-string 4096 :initial-element #\x))
               (:block (loop until (funcall cancelled-p) do (sleep 0.02)) nil)
               (:reject (error 'image-daemon:daemon-message-error :reason ':denied
                               :message "Denied" :operation ':message))
               (:stop (bordeaux-threads:with-lock-held (lock) (setf done t)) ':stopping)
               (t (error "Unknown test action"))))))
    (unwind-protect
         (progn
           (image-daemon:daemon-runtime-start runtime)
           (loop until (bordeaux-threads:with-lock-held (lock) done) do (sleep 0.01))
           ;; The request thread must finish writing its acknowledgement before teardown.
           (sleep 0.05))
      (image-daemon:daemon-runtime-stop runtime))))

(defun test-process-transport ()
  "Run actual subprocess discovery, framing, correlation, failures and cancellation."
  (let* ((root (asdf:system-source-directory "image-daemon"))
         (setup-symbol (find-symbol "*QUICKLISP-HOME*" "QL-SETUP"))
         (setup (and setup-symbol (merge-pathnames "setup.lisp" (symbol-value setup-symbol))))
         (directory (merge-pathnames (format nil "daemon-messages-~A/" (image-daemon:daemon-random-nonce))
                                    (uiop:temporary-directory)))
         (process nil) (record nil))
    (unless (and setup (probe-file setup)) (error "Message subprocess tests require Quicklisp setup."))
    (ensure-directories-exist directory)
    (setf (ls-compat.posix:file-mode directory) #o700)
    (unwind-protect
         (progn
           (setf process
                 (uiop:launch-program
                  (list (or (uiop:getenv "AUTOLITH_SBCL") (first sb-ext:*posix-argv*))
                        "--noinform" "--non-interactive" "--load" (namestring setup)
                        "--eval" (format nil "(asdf:initialize-source-registry '(:source-registry (:directory ~S) :inherit-configuration))" root)
                        "--eval" "(asdf:load-system \"image-daemon/message-tests\")"
                        "--eval" (format nil "(image-daemon/message-tests:child-serve ~S)" directory))
                  :input nil :output (merge-pathnames "child.log" directory) :error-output :output))
           (check (image-daemon:daemon-wait-until
                   (lambda () (setf record (rest (first (image-daemon:daemon-registry-discover directory)))))
                   20 :interval 0.02))
           (let* ((reply (image-daemon:daemon-message-call record :action ':echo :id "m1"
                                                          :sender "sender" :receiver "receiver"
                                                          :payload '(:text "hello λ"))))
             (check (/= (getf reply :pid) (sb-posix:getpid)))
             (check (= (getf reply :pid) (getf (rest record) :pid)))
             (check (equal (getf reply :data) '(:text "hello λ"))))
           (failure ':denied (lambda () (image-daemon:daemon-message-call record :action ':reject :id "m2" :sender "a" :receiver "b")))
           (failure ':uncertain (lambda () (image-daemon:daemon-message-call record :action ':oversize :id "m3" :sender "a" :receiver "b")))
           (failure ':uncertain (lambda () (image-daemon:daemon-message-call record :action ':block :id "m4" :sender "a" :receiver "b" :timeout 0.1)))
           (let ((start (get-internal-real-time)))
             (failure ':cancelled
                      (lambda () (image-daemon:daemon-message-call
                                  record :action ':block :id "m5" :sender "a" :receiver "b"
                                  :cancelled-p (lambda () (> (- (get-internal-real-time) start)
                                                           (* 0.03 internal-time-units-per-second))))))
             (check (< (- (get-internal-real-time) start) internal-time-units-per-second)))
           (failure ':payload-limit
                    (lambda () (image-daemon:daemon-message-call record :action ':echo :id "large" :sender "a" :receiver "b"
                                                                :payload (make-string 10000 :initial-element #\x)
                                                                :character-limit 1024)))
           (let ((bad (copy-list record)))
             (setf (getf (rest bad) :token) "wrong")
             (failure ':uncertain (lambda () (image-daemon:daemon-message-call bad :action ':echo :id "bad" :sender "a" :receiver "b"))))
           (check (eq ':stopping (image-daemon:daemon-message-call record :action ':stop :id "stop" :sender "a" :receiver "b")))
           (check (image-daemon:daemon-wait-until (lambda () (not (uiop:process-alive-p process))) 5 :interval 0.01))
           (check (zerop (uiop:wait-process process)))
           (check (null (image-daemon:daemon-registry-discover directory)))
           (failure ':uncertain (lambda () (image-daemon:daemon-message-call record :action ':echo :id "closed" :sender "a" :receiver "b"))))
      (when (and process (uiop:process-alive-p process)) (uiop:terminate-process process :urgent t))
      (when process (ignore-errors (uiop:wait-process process)))
      (uiop:delete-directory-tree directory :validate t :if-does-not-exist ':ignore))))

(defun test-client-capacity ()
  "Bound admitted connections before frame parsing and stop blocked clients."
  (let ((runtime (image-daemon:daemon-message-endpoint-create :publish-p nil :client-limit 1
                                                             :request-timeout 2
                                                             :dispatcher (lambda (envelope &key cancelled-p)
                                                                           (declare (ignore cancelled-p)) envelope)))
        (socket nil) (stream nil))
    (unwind-protect
         (progn
           (image-daemon:daemon-runtime-start runtime)
           (multiple-value-setq (socket stream) (image-daemon:daemon-connect (image-daemon:daemon-runtime-port runtime)))
           (check (image-daemon:daemon-wait-until
                   (lambda () (bordeaux-threads:with-lock-held ((image-daemon:daemon-runtime-lock runtime))
                                (= 1 (length (image-daemon:daemon-runtime-client-sockets runtime)))))
                   2 :interval 0.01))
           (let ((record (image-daemon:daemon-registry-record
                          :identifier "ephemeral" :token (image-daemon:daemon-runtime-token runtime)
                          :port (image-daemon:daemon-runtime-port runtime) :created-at (get-universal-time))))
             (failure ':uncertain (lambda () (image-daemon:daemon-message-call record :action ':echo :id "full" :sender "a" :receiver "b" :timeout 0.2))))
           (image-daemon:daemon-runtime-stop runtime)
           (check (null (image-daemon:daemon-runtime-client-sockets runtime))))
      (when stream (ignore-errors (close stream :abort t)))
      (when socket (ignore-errors (sb-bsd-sockets:socket-close socket)))
      (image-daemon:daemon-runtime-stop runtime))))

(defun test-timers ()
  "Exercise deadlines and changed-deadline notification on the existing accept loop."
  (let ((runtime (image-daemon:daemon-runtime-create
                  :publish-p nil :request-function (lambda (runtime request &key socket stream)
                                                    (declare (ignore runtime request socket))
                                                    (image-daemon:daemon-write-packet stream '(:unexpected)))))
        (next nil) (wakes 0) (thread nil) (callback-notified nil) (lock (bordeaux-threads:make-lock)))
    (unwind-protect
         (progn
           (image-daemon:daemon-runtime-set-timer
            runtime :next-deadline-function (lambda (runtime) (declare (ignore runtime))
                                              (bordeaux-threads:with-lock-held (lock) next))
            :wake-function (lambda (runtime)
                             (let ((notified (image-daemon:daemon-runtime-notify runtime)))
                               (bordeaux-threads:with-lock-held (lock)
                                 (setf next nil thread (bordeaux-threads:current-thread)
                                       callback-notified notified)
                                 (incf wakes)))))
           (check (null (image-daemon:daemon-runtime-notify runtime)))
           (image-daemon:daemon-runtime-start runtime)
           (bordeaux-threads:with-lock-held (lock) (setf next (+ 10 (get-universal-time))))
           (check (image-daemon:daemon-runtime-notify runtime))
           (bordeaux-threads:with-lock-held (lock) (setf next (get-universal-time)))
           (check (image-daemon:daemon-runtime-notify runtime))
           (check (image-daemon:daemon-wait-until (lambda () (bordeaux-threads:with-lock-held (lock) (= wakes 1)))
                                                2 :interval 0.01))
           (check (eq thread (image-daemon:daemon-runtime-server-thread runtime)))
           (check callback-notified)
           (bordeaux-threads:with-lock-held (lock) (setf next (1+ (get-universal-time))))
           (check (image-daemon:daemon-runtime-notify runtime))
           (check (image-daemon:daemon-wait-until (lambda () (bordeaux-threads:with-lock-held (lock) (= wakes 2)))
                                                3 :interval 0.01))
           (image-daemon:daemon-runtime-set-timer runtime)
           (image-daemon:daemon-runtime-stop runtime)
           (check (null (image-daemon:daemon-runtime-notify runtime))))
      (image-daemon:daemon-runtime-stop runtime))))

(defun run-tests ()
  "Run actual subprocess transport and existing-loop timer checks."
  (let ((*checks* 0))
    (test-timers)
    (test-client-capacity)
    (test-process-transport)
    (format t "~&image-daemon messages: ~D assertions passed.~%" *checks*)
    t))
