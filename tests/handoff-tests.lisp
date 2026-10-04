(in-package #:image-daemon/tests)

(defun handoff-tests--record (state token)
  "Return a host handoff record in STATE carrying TOKEN."
  (list :test-handoff :state state :token token :replacement-pid nil))

(defun handoff-tests--valid-p (record)
  "Accept only test handoff records."
  (and (consp record) (eq (first record) :test-handoff)))

(defun test-handoff-tickets ()
  "Exercise ticket claim, ownership, cancellation and cleanup."
  (let* ((root (merge-pathnames (format nil "daemon-handoff-~A/" (daemon-random-nonce))
                                (uiop:temporary-directory)))
         (ticket (handoff-ticket-pathname root "session")))
    (unwind-protect
         (progn
           (expect-failure (lambda () (handoff-ticket-pathname root "../escape")) ':handoff)
           (check (search "session-" (pathname-name ticket))
                  "ticket names keep their caller's name")
           (check (not (equal ticket (handoff-ticket-pathname root "session")))
                  "ticket names are unguessable")
           (handoff-ticket-write ticket (handoff-tests--record :pending "token"))
           (check (= (logand #o777 (sb-posix:stat-mode (sb-posix:stat ticket))) #o600)
                  "tickets are private")
           (check (null (handoff-ticket-owned-record ticket :token "token"))
                  "an unclaimed ticket is owned by nobody")
           (let ((claimed (handoff-ticket-claim ticket)))
             (check (and (probe-file claimed) (not (probe-file ticket)))
                    "a claim renames the ticket")
             (check (handoff-ticket-owned-record ticket :token "token"
                                                 :validate #'handoff-tests--valid-p)
                    "the claimant owns its ticket")
             (check (null (handoff-ticket-owned-record ticket :token "other"))
                    "ownership needs the ticket's token")
             (check (eql (handoff-ticket-replacement-pid ticket) (sb-posix:getpid))
                    "the claimant's process identifier is acknowledged"))
           (expect-failure (lambda () (handoff-ticket-claim ticket)) ':handoff)
           (let ((cancelled (handoff-ticket-cancel ticket :validate #'handoff-tests--valid-p)))
             (check (eq (getf (rest (handoff-ticket-read cancelled)) :state) ':cancelled)
                    "cancelling rewrites the claimed record as cancelled")
             (check (null (handoff-ticket-owned-record ticket :token "token"))
                    "a cancelled claim is no longer owned")
             (check (equal cancelled (handoff-ticket-cancel ticket))
                    "cancelling twice is harmless"))
           (with-open-file (stream (handoff-ticket-sibling ticket ':launcher-pid)
                                   :direction :output :if-exists :supersede)
             (format stream "4242~%"))
           (check (eql (handoff-ticket-launcher-pid ticket) 4242)
                  "the supervised launcher's group is read back")
           (handoff-ticket-delete ticket)
           (check (notany #'probe-file (handoff-ticket-family ticket))
                  "deleting a ticket removes its whole family"))
      (uiop:delete-directory-tree root :validate t :if-does-not-exist :ignore))))

(defun test-handoff-supervised-launch ()
  "Exercise the gated supervisor recording its launcher's process group."
  (let* ((root (merge-pathnames (format nil "daemon-supervisor-~A/" (daemon-random-nonce))
                                (uiop:temporary-directory)))
         (ticket (handoff-ticket-pathname root "launch"))
         (marker (merge-pathnames "ran" root)))
    (unwind-protect
         (progn
           (ensure-directories-exist root)
           (let ((process (handoff-launch-supervised
                           (list "/bin/sh" "-c"
                                 (format nil "echo ran > '~A'; exit 7" (namestring marker)))
                           ticket :directory root)))
             (check (= 7 (uiop:wait-process process))
                    "the supervisor exits with its launcher's status")
             (check (probe-file marker) "the gated launcher ran")
             (check (handoff-ticket-launcher-pid ticket)
                    "the launcher's process group was recorded before it ran")
             (check (not (probe-file (handoff-ticket-sibling ticket ':gate)))
                    "the start gate is removed")))
      (uiop:delete-directory-tree root :validate t :if-does-not-exist :ignore))))

(defun test-handoff-endpoint-readiness ()
  "Exercise authenticated readiness of a replacement endpoint."
  (let* ((root (merge-pathnames (format nil "daemon-ready-~A/" (daemon-random-nonce))
                                (uiop:temporary-directory)))
         (runtime nil))
    (flet ((respond (runtime request &key socket stream)
             (declare (ignore runtime socket))
             (daemon-write-packet stream
                                  (list :ok :status
                                        (list :operation (getf (rest request) :operation))))))
      (unwind-protect
           (progn
             (setf runtime (daemon-runtime-create :directory root :identifier "ready"
                                                  :token "capability"
                                                  :request-function #'respond))
             (daemon-runtime-start runtime)
             (let ((record (daemon-runtime-record runtime)))
               (check (equal (daemon-endpoint-status record "capability" 1)
                             '(:operation :status))
                      "a new process answering with the token is ready")
               (check (null (daemon-endpoint-status record "capability" (sb-posix:getpid)))
                      "the old process itself is never the replacement")
               (check (null (daemon-endpoint-status record "wrong" 1))
                      "a foreign token is not ready")
               (check (null (daemon-endpoint-status '(:localgroup-endpoint) "capability" 1))
                      "a malformed record is not ready"))
             (let ((calls 0))
               (check (eq :done (daemon-wait-until (lambda () (and (= (incf calls) 3) :done))
                                                   5 :interval 0.01))
                      "waiting returns the first true value")
               (check (null (daemon-wait-until (constantly nil) 0.05 :interval 0.01))
                      "waiting gives up after its deadline")))
        (when runtime
          (daemon-runtime-stop runtime))
        (uiop:delete-directory-tree root :validate t :if-does-not-exist :ignore)))))
