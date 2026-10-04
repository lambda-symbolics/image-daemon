(in-package #:image-daemon)

;;;; -- Process Handoff Tickets --

;;; A ticket is the private file through which one process hands its work to a
;;; detached replacement it launches. The replacement claims the ticket by
;;; renaming it, the launcher can cancel it by renaming it, and every state the
;;; handoff passes through lives in a sibling named after the ticket, so one
;;; family of pathnames describes and cleans up one handoff.

(defparameter *handoff-ticket-states* '(:claimed :cancelled :pid :launcher-pid :gate)
  "The sibling states of a handoff ticket, each a file named after the ticket.")

(defparameter *handoff-supervisor-script*
  "set -u
launcher=$1
pidfile=$2
gate=$3
shift 3
child=
cleanup()
{
  status=$?
  trap - EXIT HUP INT TERM
  if [[ -n \"$child\" ]]; then
    kill -TERM -- \"-$child\" 2>/dev/null || true
    wait \"$child\" 2>/dev/null || true
  fi
  rm -f -- \"$gate\"
  exit \"$status\"
}
trap cleanup EXIT HUP INT TERM
rm -f -- \"$gate\" \"$pidfile\"
mkfifo -m 600 -- \"$gate\"
set -m
(
  IFS= read -r ready < \"$gate\" || exit 70
  exec \"$launcher\" \"$@\"
) &
child=$!
printf '%s\\n' \"$child\" > \"$pidfile\"
chmod 600 \"$pidfile\"
printf 'start\\n' > \"$gate\"
rm -f -- \"$gate\"
wait \"$child\"
status=$?
child=
exit \"$status\""
  "The Bash supervisor that gates the replacement and owns its process group.

The replacement runs in its own process group, created before the launcher
starts, and only once its group identifier is recorded beside the ticket, so a
failed handoff can always find and stop everything the replacement started.")

(defun handoff-ticket-pathname (directory name)
  "Return a fresh, unguessable ticket pathname for NAME beneath DIRECTORY."
  (unless (and (stringp name) (plusp (length name))
               (every (lambda (character)
                        (or (alphanumericp character) (find character "-_")))
                      name))
    (daemon-fail :message "Invalid handoff ticket name." :operation ':handoff))
  (merge-pathnames (make-pathname :name (format nil "~A-~A" name (daemon-random-nonce))
                                  :type "sexp")
                   directory))

(defun handoff-ticket-sibling (pathname state)
  "Return the sibling of ticket PATHNAME that holds STATE."
  (unless (member state *handoff-ticket-states*)
    (daemon-fail :message (format nil "Unknown handoff ticket state ~S." state)
                 :operation ':handoff))
  (make-pathname :name (format nil "~A-~(~A~)" (pathname-name pathname) state)
                 :defaults pathname))

(defun handoff-ticket-family (pathname)
  "Return ticket PATHNAME and every sibling it may have."
  (cons pathname
        (mapcar (lambda (state) (handoff-ticket-sibling pathname state))
                *handoff-ticket-states*)))

(defun handoff-ticket-write (pathname record)
  "Atomically write RECORD to PATHNAME, private to the current user."
  (ensure-directories-exist pathname)
  (setf (ls-compat.posix:file-mode (uiop:pathname-directory-pathname pathname)) #o700)
  (sexp-store:snapshot-write pathname record)
  (setf (ls-compat.posix:file-mode pathname) #o600)
  pathname)

(defun handoff-ticket-read (pathname &key (validate (constantly t)))
  "Return PATHNAME's complete record when VALIDATE accepts it, otherwise NIL."
  (handler-case
      (multiple-value-bind (record complete-p) (sexp-store:snapshot-read pathname)
        (and complete-p (funcall validate record) record))
    (error ()
      nil)))

(defun handoff-ticket-claim (pathname)
  "Claim ticket PATHNAME for this process and return the claimed pathname.

The rename is the claim: it fails when the launcher cancelled or another process
claimed the ticket first. The claimant then records its process identifier, which
HANDOFF-TICKET-OWNED-RECORD and HANDOFF-TICKET-REPLACEMENT-PID read."
  (let ((claimed (handoff-ticket-sibling pathname ':claimed)))
    (handler-case
        (rename-file pathname claimed)
      (error (condition)
        (daemon-fail :message "The handoff ticket was cancelled before startup."
                     :operation ':handoff :cause condition)))
    (handoff-ticket-write (handoff-ticket-sibling pathname ':pid)
                          (list :handoff-pid :pid (sb-posix:getpid)))
    claimed))

(defun handoff-ticket--acknowledged-pid (pathname)
  "Return the process identifier that claimed ticket PATHNAME, or NIL."
  (let ((record (handoff-ticket-read
                 (handoff-ticket-sibling pathname ':pid)
                 :validate (lambda (record)
                             (and (consp record)
                                  (eq (first record) :handoff-pid)
                                  (typep (getf (rest record) :pid) '(integer 1)))))))
    (and record (getf (rest record) :pid))))

(defun handoff-ticket-owned-record (pathname &key token (validate (constantly t)))
  "Return ticket PATHNAME's record while this process still owns its claim, else NIL.

The claimed sibling must still hold a pending or claimed record carrying TOKEN,
and the acknowledged claimant must be this process; a launcher that cancelled the
handoff has renamed the ticket away."
  (let ((record (handoff-ticket-read (handoff-ticket-sibling pathname ':claimed)
                                     :validate validate)))
    (and record
         (member (getf (rest record) :state) '(:pending :claimed))
         (equal (getf (rest record) :token) token)
         (eql (handoff-ticket--acknowledged-pid pathname) (sb-posix:getpid))
         record)))

(defun handoff-ticket-cancel (pathname &key (validate (constantly t)))
  "Atomically cancel ticket PATHNAME, pending or claimed, and return the cancelled sibling.

The pending or claimed record is renamed to the cancelled sibling and rewritten
with :STATE :CANCELLED, so a replacement that later checks its claim sees the
cancellation. One brief retry covers a claim racing the cancellation."
  (let ((claimed (handoff-ticket-sibling pathname ':claimed))
        (cancelled (handoff-ticket-sibling pathname ':cancelled)))
    (flet ((cancel-from (source)
             (let ((record (and (probe-file source)
                                (handoff-ticket-read source :validate validate))))
               (when record
                 (handler-case
                     (progn
                       (rename-file source cancelled)
                       (setf (getf (rest record) :state) ':cancelled)
                       (handoff-ticket-write cancelled record)
                       t)
                   (error ()
                     nil))))))
      (or (probe-file cancelled)
          (cancel-from pathname)
          (cancel-from claimed)
          (progn
            (sleep 0.05)
            (or (probe-file cancelled)
                (cancel-from pathname)
                (cancel-from claimed))))
      cancelled)))

(defun handoff-ticket-replacement-pid (pathname &key (validate (constantly t)))
  "Return the replacement's process identifier for ticket PATHNAME, when known.

The claimant's acknowledgement wins; otherwise any family record that names a
:REPLACEMENT-PID answers."
  (or (handoff-ticket--acknowledged-pid pathname)
      (loop for candidate in (list pathname
                                   (handoff-ticket-sibling pathname ':claimed)
                                   (handoff-ticket-sibling pathname ':cancelled))
            for record = (and (probe-file candidate)
                              (handoff-ticket-read candidate :validate validate))
            for pid = (and record (getf (rest record) :replacement-pid))
            when (typep pid '(integer 1))
              return pid)))

(defun handoff-ticket-launcher-pid (pathname)
  "Return the supervised launcher's process group identifier for ticket PATHNAME, or NIL."
  (handler-case
      (with-open-file (stream (handoff-ticket-sibling pathname ':launcher-pid)
                              :external-format :utf-8)
        (let ((line (read-line stream nil nil)))
          (and line (plusp (length line)) (every #'digit-char-p line)
               (let ((pid (parse-integer line)))
                 (and (plusp pid) pid)))))
    (error ()
      nil)))

(defun handoff-ticket-delete (pathname)
  "Delete every file of ticket PATHNAME's family that exists."
  (dolist (candidate (handoff-ticket-family pathname))
    (when (probe-file candidate)
      (ignore-errors (delete-file candidate))))
  nil)


;;;; -- Supervised Launch --

(defun handoff-launch-supervised (arguments ticket &key directory output)
  "Start ARGUMENTS behind the gated supervisor that records its group beside TICKET.

Return the UIOP process of the supervisor. The launcher's process group
identifier appears in TICKET's launcher-pid sibling before the launcher runs.
Hosts without POSIX job control signal DAEMON-ERROR."
  #+win32
  (declare (ignore arguments ticket directory output))
  #+win32
  (daemon-fail :message "This host cannot supervise a detached process group."
               :operation ':handoff)
  #-win32
  (let ((launcher-pid (handoff-ticket-sibling ticket ':launcher-pid))
        (gate (handoff-ticket-sibling ticket ':gate)))
    (dolist (pathname (list launcher-pid gate))
      (when (probe-file pathname)
        (ignore-errors (delete-file pathname))))
    (uiop:launch-program (append (list "bash" "-c" *handoff-supervisor-script*
                                       "image-daemon-handoff"
                                       (first arguments)
                                       (namestring launcher-pid)
                                       (namestring gate))
                                 (rest arguments))
                         :input nil
                         :output output
                         :error-output :output
                         :directory directory
                         :wait nil)))


;;;; -- Replacement Readiness --

(defun daemon-endpoint-status (record token old-pid)
  "Return the status plist of RECORD's endpoint when a new process serves it with TOKEN.

The endpoint must belong to a process other than OLD-PID, carry TOKEN, and answer
an authenticated :STATUS request; otherwise NIL."
  (when (and (daemon-registry-record-p record)
             (/= (getf (rest record) :pid) old-pid)
             (equal (getf (rest record) :token) token))
    (handler-case
        (let ((response (daemon-call (getf (rest record) :port) token ':status)))
          (and (eq (first response) ':ok)
               (or (getf (rest response) :status) t)))
      (error ()
        nil))))

(defun daemon-wait-until (function timeout-seconds &key (interval 0.05))
  "Call FUNCTION every INTERVAL seconds until it returns true or TIMEOUT-SECONDS pass.

Return FUNCTION's first true value, or NIL after the deadline."
  (let ((deadline (+ (get-internal-real-time)
                     (* timeout-seconds internal-time-units-per-second))))
    (loop
      (let ((value (funcall function)))
        (when value
          (return value)))
      (when (>= (get-internal-real-time) deadline)
        (return nil))
      (sleep interval))))
