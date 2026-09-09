(in-package #:image-daemon)

;;;; -- Endpoint Discovery and Ownership --

(defparameter *daemon-registry-version* 1
  "The readable endpoint registry version.")

(defun daemon-registry-pathname (directory identifier)
  "Return IDENTIFIER's discovery pathname beneath DIRECTORY."
  (unless (and (stringp identifier) (plusp (length identifier))
               (every (lambda (character)
                        (or (alphanumericp character) (find character "-_")))
                      identifier))
    (daemon-fail :message "Invalid endpoint identifier." :operation ':registry))
  (merge-pathnames (make-pathname :name identifier :type "sexp") directory))

(defun daemon-registry-record (&key identifier token port created-at
                                   (pid (sb-posix:getpid)))
  "Construct an endpoint discovery record using the deployed wire format."
  (list :localgroup-endpoint :version *daemon-registry-version*
        :session-id identifier :pid pid :address "127.0.0.1"
        :port port :token token :created-at created-at))

(defun daemon-registry-record-p (record)
  "Return true when RECORD is a supported, well-typed endpoint record."
  (handler-case
      (and (proper-list-p record)
           (eq (first record) ':localgroup-endpoint)
           (= (getf (rest record) :version) *daemon-registry-version*)
           (let ((identifier (getf (rest record) :session-id))
                 (token (getf (rest record) :token)))
             (and (stringp identifier) (plusp (length identifier))
                  (stringp token) (plusp (length token))))
           (typep (getf (rest record) :pid) '(integer 1))
           (equal (getf (rest record) :address) "127.0.0.1")
           (typep (getf (rest record) :port) '(integer 1 65535))
           (typep (getf (rest record) :created-at) '(integer 0)))
    (error () nil)))

(defun daemon-registry-read (pathname)
  "Return PATHNAME's valid complete endpoint record, or NIL."
  (handler-case
      (multiple-value-bind (record complete-p)
          (sexp-store:snapshot-read pathname)
        (and complete-p (daemon-registry-record-p record) record))
    (error () nil)))

(defun daemon-registry-call-with-lock (pathname function)
  "Call FUNCTION while serializing registry updates beside PATHNAME."
  (let ((lock-pathname (make-pathname :name "registry" :type "lock"
                                    :defaults pathname)))
    (ensure-directories-exist lock-pathname)
    (ls-flock:call-with-file-lock lock-pathname function)))

(defun daemon-process-state (pid)
  "Return :ALIVE, :DEAD or :UNKNOWN without mistaking denied access for death."
  (handler-case
      (ls-compat.posix:process-state pid)
    (error () ':unknown)))

(defun daemon-registry-publish (pathname record)
  "Atomically publish RECORD unless a different live capability owns PATHNAME.

Writers serialize through a directory lock. A surviving capability may replace
its own endpoint during process handoff. Unknown process state retains ownership."
  (unless (daemon-registry-record-p record)
    (daemon-fail :message "Invalid endpoint registry record." :operation ':publish))
  (daemon-registry-call-with-lock
   pathname
   (lambda ()
     (let ((current (daemon-registry-read pathname)))
       (when (and current (not (equal current record))
                  (not (eq (daemon-process-state (getf (rest current) :pid)) ':dead))
                  (not (string= (getf (rest current) :token)
                                (getf (rest record) :token))))
         (daemon-fail :message "A live localgroup endpoint already owns this conversation."
                      :operation ':publish :session-id (getf (rest record) :session-id))))
     (setf (ls-compat.posix:file-mode (uiop:pathname-directory-pathname pathname))
           #o700)
     (sexp-store:snapshot-write pathname record)
     (setf (ls-compat.posix:file-mode pathname) #o600)))
  nil)

(defun daemon-registry-delete-matching (pathname record)
  "Delete PATHNAME only while its complete record equals RECORD."
  (handler-case
      (daemon-registry-call-with-lock
       pathname
       (lambda ()
         (when (equal record (daemon-registry-read pathname))
           (delete-file pathname)
           t)))
    (error () nil)))

(defun daemon-registry-discover (directory)
  "Return (PATHNAME . RECORD) entries ordered by newest publication first."
  (sort (loop for pathname in (uiop:directory-files directory "*.sexp")
              for record = (daemon-registry-read pathname)
              when record collect (cons pathname record))
        #'> :key (lambda (entry)
                   (or (ignore-errors (file-write-date (first entry))) 0))))

(defun daemon-registry-reconcile (directory)
  "Delete definitely dead discovery entries and return their count."
  (loop for (pathname . record) in (daemon-registry-discover directory)
        count (and (eq (daemon-process-state (getf (rest record) :pid)) ':dead)
                   (daemon-registry-delete-matching pathname record))))
