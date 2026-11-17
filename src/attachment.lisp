(in-package #:image-daemon)

(defparameter *attachment-queue-character-limit*
  (* 4 1024 1024)
  "The maximum pending output retained for one attached client.")

(defparameter *relay-history-character-limit*
  (* 1024 1024)
  "The maximum rendered terminal output replayed to a new attachment.")

(defparameter *relay-output-chunk-character-limit*
  (* 64 1024)
  "The maximum terminal output characters carried in one attachment packet.")

(defvar *daemon-client-transport-lock* nil
  "Runtime cleanup lock captured by attachments created in a request callback.")

(define-condition daemon-cleanup-error (daemon-error)
  ((failures :initarg :failures :reader daemon-cleanup-error-failures
             :documentation "Ordered stage, retained resource and original condition triples."))
  (:documentation "Independent cleanup stages failed while resource ownership was retained."))

(defclass attachment nil
          ((socket :initarg :socket :reader attachment-socket :type sb-bsd-sockets:socket
            :documentation "The accepted loopback socket owned by this attachment.")
           (stream :initarg :stream :reader attachment-stream :type stream :documentation
            "The duplex UTF-8 packet stream.")
           (mode :initarg :mode :reader attachment-mode :type
            (member :read-only :control :take-over) :documentation
            "The observation or terminal-control authority of this attachment.")
           (transport-lock :initarg :transport-lock :initform
            (or *daemon-client-transport-lock*
                (bordeaux-threads:make-lock "Image daemon transport"))
            :reader attachment-transport-lock :documentation
            "Serializes native shutdown and close with runtime cleanup.")
           (lock :initform (bordeaux-threads:make-lock "Image daemonp attachment") :reader
            attachment-lock :type t :documentation "The lock protecting output and closure state.")
           (condition-variable :initform
            (bordeaux-threads:make-condition-variable :name "Image daemonp attachment") :reader
            attachment-condition-variable :type t :documentation
            "The condition waking the output writer.")
           (queue :initform (structlisp:make-deque :weight-function #'length) :reader
            attachment-queue :type structlisp:deque :documentation
            "FIFO serialized packets awaiting the writer with maintained size.")
           (closed-p :initform nil :accessor attachment-closed-p :type boolean :documentation
            "Whether the stream no longer accepts packets.")
           (socket-shutdown-p :initform nil :accessor attachment-socket-shutdown-p :type boolean
            :documentation "Whether transport shutdown has been claimed.")
           (stream-closed-p :initform nil :accessor attachment-stream-closed-p :type boolean
            :documentation "Whether stream closure has been claimed.")
           (writer-thread :initform nil :accessor attachment-writer-thread :type t :documentation
            "The bounded asynchronous output writer.")
           (handshake-committed-p :initform nil :accessor attachment-handshake-committed-p :type
            boolean :documentation
            "Whether the success handshake was admitted to the serialized writer queue.")
           (failure :initform nil :accessor attachment-failure :documentation
            "The first output failure or overflow reason, retained after cleanup."))
          (:documentation "One persistent read-only or controlling terminal attachment."))

(defgeneric attachment-packet-string (attachment packet)
  (:documentation "Encode PACKET for ATTACHMENT before acquiring its queue lock."))

(defmethod attachment-packet-string ((attachment attachment) packet)
  "Encode PACKET using the ordinary daemon framing policy."
  (declare (ignore attachment))
  (daemon-packet-string packet))

(-> attachment-shutdown (attachment) null)
(defun attachment-shutdown (attachment)
  "Shut down ATTACHMENT's socket once under its shared transport lock."
  (bordeaux-threads:with-lock-held ((attachment-transport-lock attachment))
    (unless (attachment-socket-shutdown-p attachment)
      (setf (attachment-socket-shutdown-p attachment) t)
      ; mallet:suppress no-ignore-errors -- the peer may have closed the socket already
      (ignore-errors
       (sb-bsd-sockets:socket-shutdown (attachment-socket attachment) :direction ':io))))
  nil)

(defgeneric attachment-release-transport (attachment)
  (:documentation "Release ATTACHMENT's transport outside its queue lock.

Called on writer exit and by lifecycle operations, possibly repeatedly and
concurrently. Methods must be idempotent and synchronize with the transport
owner. The default shuts down and abortively closes the owned stream; a method
for borrowed transport must leave closure to its owner. Do not join the writer
from a method, which can run in that writer's unwind cleanup."))

(defmethod attachment-release-transport ((attachment attachment))
  "Shut down and abortively close owned transport once under its shared lock."
  (attachment-shutdown attachment)
  (bordeaux-threads:with-lock-held ((attachment-transport-lock attachment))
    (unless (attachment-stream-closed-p attachment)
      (setf (attachment-stream-closed-p attachment) t)
      ; mallet:suppress no-ignore-errors -- broken transport must not stop teardown
      (ignore-errors (close (attachment-stream attachment) :abort t))))
  nil)

(-> attachment--writer-loop (attachment) null)
(defun attachment--writer-loop (attachment)
  "Write queued packets and release transport on every exit, including termination."
  (unwind-protect
      (block write-packets
        (handler-case
         (loop for packet = (bordeaux-threads:with-lock-held ((attachment-lock attachment))
                              (loop while (and
                                           (structlisp:deque-empty-p (attachment-queue attachment))
                                           (not (attachment-closed-p attachment)))
                                    do (bordeaux-threads:condition-wait
                                        (attachment-condition-variable attachment)
                                        (attachment-lock attachment)))
                              (when (structlisp:deque-empty-p (attachment-queue attachment))
                                (return-from write-packets nil))
                              (structlisp:deque-pop-front (attachment-queue attachment)))
               do (write-string packet (attachment-stream attachment)) (finish-output
                                                                        (attachment-stream
                                                                         attachment)))
         (error (condition)
                (bordeaux-threads:with-lock-held ((attachment-lock attachment))
                  (unless (attachment-failure attachment)
                    (setf (attachment-failure attachment)
                          (list :reason "transport-failure" :stage "writer" :condition
                                condition)))))))
    (bordeaux-threads:with-lock-held ((attachment-lock attachment))
      (setf (attachment-closed-p attachment) t)
      (structlisp:deque-clear (attachment-queue attachment))
      (bordeaux-threads:condition-notify (attachment-condition-variable attachment)))
    (attachment-release-transport attachment))
  nil)

(-> attachment-start (attachment) attachment)
(defun attachment-start (attachment)
  "Start ATTACHMENT once, including a sealed queue awaiting its final drain.

An abortively closed or overflowed attachment has no queued output and cannot
start. Admission, start and close share the queue lock. Failed startup closes
admission and releases transport outside that lock. Return ATTACHMENT."
  (let ((completed-p nil))
    (unwind-protect
         (progn
           (bordeaux-threads:with-lock-held ((attachment-lock attachment))
             (when (and (null (attachment-writer-thread attachment))
                        (or (not (attachment-closed-p attachment))
                            (not (structlisp:deque-empty-p (attachment-queue attachment)))))
               (setf (attachment-writer-thread attachment)
                     (bordeaux-threads:make-thread
                      (lambda () (attachment--writer-loop attachment))
                      :name "Image daemon attachment output"))))
           (setf completed-p t))
      (unless completed-p (attachment-close attachment))))
  attachment)

(-> attachment-create (sb-bsd-sockets:socket stream keyword) attachment)
(defun attachment-create (socket stream mode)
  "Construct and start an attachment over SOCKET and STREAM with MODE."
  (attachment-start (make-instance 'attachment :socket socket :stream stream :mode mode)))

(-> attachment-try-send (attachment t) (member :accepted :closed :overflow))
(defun attachment-try-send (attachment packet)
  "Encode and admit PACKET, retaining its success commit or overflow reason.

Return :ACCEPTED, :CLOSED or :OVERFLOW without releasing transport or joining
threads. The first overflow reason survives abortive queue cleanup."
  (let ((text (attachment-packet-string attachment packet)))
    (bordeaux-threads:with-lock-held ((attachment-lock attachment))
      (cond
        ((attachment-closed-p attachment)
         ':closed)
        ((> (+ (structlisp:deque-total-weight (attachment-queue attachment)) (length text))
            *attachment-queue-character-limit*)
         (unless (attachment-failure attachment)
           (setf (attachment-failure attachment)
                 '(:reason "queue-overflow" :stage "output")))
         (setf (attachment-closed-p attachment) t)
         (structlisp:deque-clear (attachment-queue attachment))
         (bordeaux-threads:condition-notify (attachment-condition-variable attachment))
         ':overflow)
        (t
         (structlisp:deque-push-back (attachment-queue attachment) text)
         (when (and (consp packet) (eq (first packet) ':attached))
           (setf (attachment-handshake-committed-p attachment) t))
         (bordeaux-threads:condition-notify (attachment-condition-variable attachment))
         ':accepted)))))

(-> attachment-send (attachment t) boolean)
(defun attachment-send (attachment packet)
  "Queue PACKET, releasing transport outside the queue lock on overflow."
  (let ((status (attachment-try-send attachment packet)))
    (when (eq status ':overflow)
      (attachment-release-transport attachment))
    (eq status ':accepted)))

(-> attachment-close (attachment) null)
(defun attachment-close (attachment)
  "Discard pending output, release transport and reap ATTACHMENT's writer."
  (let ((writer nil))
    (bordeaux-threads:with-lock-held ((attachment-lock attachment))
      (setf (attachment-closed-p attachment) t
            writer (attachment-writer-thread attachment))
      (structlisp:deque-clear (attachment-queue attachment))
      (bordeaux-threads:condition-notify (attachment-condition-variable attachment)))
    (attachment-release-transport attachment)
    (when writer (daemon-stop-thread writer)))
  nil)

(-> attachment-seal (attachment t) null)
(defun attachment-seal (attachment packet)
  "Close admission and append final PACKET, bypassing capacity, without cleanup.

Previously queued packets retain FIFO order. A closed attachment is unchanged."
  (let ((text (attachment-packet-string attachment packet)))
    (bordeaux-threads:with-lock-held ((attachment-lock attachment))
      (unless (attachment-closed-p attachment)
        (structlisp:deque-push-back (attachment-queue attachment) text)
        (setf (attachment-closed-p attachment) t))
      (bordeaux-threads:condition-notify (attachment-condition-variable attachment))))
  nil)

(-> attachment-finish (attachment t) null)
(defun attachment-finish (attachment packet)
  "Seal ATTACHMENT, start any deferred drain, reap its writer and release transport.

An unread peer can lose queued output at the bounded stop deadline. Reaping
failures propagate; the retained writer can be reaped by retrying."
  (attachment-seal attachment packet)
  (attachment-start attachment)
  (let ((writer (bordeaux-threads:with-lock-held ((attachment-lock attachment))
                  (attachment-writer-thread attachment))))
    (unwind-protect (when writer (daemon-stop-thread writer))
      (attachment-release-transport attachment)))
  nil)

(defclass relay (transport)
          ((lock :initform (bordeaux-threads:make-lock "Image daemonp terminal") :reader relay-lock
            :type t :documentation "The lock protecting terminal ownership, input, and history.")
           (direct-terminal :initform nil :initarg :direct-terminal :accessor relay-direct-terminal
            :type t :documentation "The terminal inherited from the launching foreground process.")
           (controller :initform nil :accessor relay-controller :type (option attachment)
            :documentation "The attachment currently allowed to submit terminal input.")
           (observers :initform nil :accessor relay-observers :type list :documentation
            "Read-only attachments receiving rendered terminal output.")
           (closing-attachments :initform nil :accessor relay-closing-attachments :type list
            :documentation "Detached attachments retained until their writers have been reaped.")
           (closing-direct-transports :initform nil :accessor relay-closing-direct-transports
            :type list :documentation "Released foreground transports awaiting successful stop.")
           (input-condition-variable :initform
            (bordeaux-threads:make-condition-variable :name "Image daemonp terminal input") :reader
            relay-input-condition-variable :type t :documentation
            "The condition waking a blocking semantic input read.")
           (input-events :initform (structlisp:make-deque) :reader relay-input-events :type
            structlisp:deque :documentation
            "FIFO semantic events received from the controlling attachment.")
           (history :initform (structlisp:make-deque :weight-function #'length) :reader
            relay-history :type structlisp:deque :documentation
            "Bounded terminal output chunks with maintained character size.")
           (history-position :initform 0 :accessor relay-history-position :type (integer 0)
            :documentation "Total output characters retained, including evicted history.")
           (wake-function :initform nil :accessor relay-wake-function :type (option function)
            :documentation "The callback waking the responsive input controller.")
           (cleanup-cause :initform nil :accessor relay-cleanup-cause :documentation
            "First retirement failure retained until closing attachments are released."))
          (:documentation "A terminal relay supporting foreground, detached, and observed use."))

(-> relay-set-wake-function (relay (or null function)) null)
(defun relay-set-wake-function (transport function)
  "Set TERMINAL's responsive-reader wake FUNCTION."
  (bordeaux-threads:with-lock-held ((relay-lock transport))
    (setf (relay-wake-function transport) function))
  nil)

(-> relay--output-chunks (string) list)
(defun relay--output-chunks (text)
  "Return TEXT as ordered bounded attachment-output chunks."
  (loop with length = (length text)
        for start = 0 then
        end
        while (< start length)
        for
        end = (min length (+ start *relay-output-chunk-character-limit*))
        collect (subseq text start end)))

(-> relay--retain-output (relay string) null)
(defun relay--retain-output (transport text)
  "Append TEXT to TERMINAL's exactly bounded attachment replay history while locked."
  (let ((history (relay-history transport)))
    (structlisp:deque-push-back history text)
    (incf (relay-history-position transport) (length text))
    (loop while (> (structlisp:deque-total-weight history)
                   *relay-history-character-limit*)
          for excess = (- (structlisp:deque-total-weight history)
                          *relay-history-character-limit*)
          for first = (structlisp:deque-front history)
          do (if (<= (length first) excess)
                 (structlisp:deque-pop-front history)
                 (setf (structlisp:deque-ref history 0) (subseq first excess)))))
  nil)

(-> relay-history-text (relay) string)
(defun relay-history-text (transport)
  "Return a consistent copy of TERMINAL's retained rendered output."
  (bordeaux-threads:with-lock-held ((relay-lock transport))
    (apply #'concatenate 'string
           (cons ""
                 (coerce (structlisp:deque->vector (relay-history transport)) 'list)))))

(defmethod transport-start ((transport relay))
  "Start TERMINAL's inherited direct transport when one exists."
  (bordeaux-threads:with-lock-held ((relay-lock transport))
    (when (transport-started-p transport) (return-from transport-start transport))
    (let ((direct (relay-direct-terminal transport)))
      (when direct
        (transport-start direct)
        (transport-set-dimensions transport (transport-columns direct) :rows
         (transport-rows direct))
        (setf (transport-interactive-p transport) (transport-interactive-p direct)
              (transport-styled-p transport) (transport-styled-p direct)))
      (setf (transport-started-p transport) t)))
  transport)

(-> relay--retire-attachments (relay list &key (:packet list) (:direct t)) null)
(defun relay--retire-attachments (transport attachments &key packet direct)
  "Retire attachments and foreground transports independently, retaining failed cleanup."
  (let (directs failures cause)
    (bordeaux-threads:with-lock-held ((relay-lock transport))
      (when direct
        (pushnew direct (relay-closing-direct-transports transport) :test #'eq))
      (setf directs (copy-list (relay-closing-direct-transports transport)))
      (dolist (attachment attachments)
        (pushnew attachment (relay-closing-attachments transport) :test #'eq)))
    (dolist (foreground directs)
      (handler-case
          (progn
            (transport-stop foreground)
            (bordeaux-threads:with-lock-held ((relay-lock transport))
              (setf (relay-closing-direct-transports transport)
                    (remove foreground (relay-closing-direct-transports transport) :test #'eq))))
        (error (condition)
          (push (list ':direct-transport foreground condition) failures))))
    (dolist (attachment attachments)
      (handler-case
          (progn
            (if packet
                (attachment-finish attachment packet)
                (attachment-close attachment))
            (bordeaux-threads:with-lock-held ((relay-lock transport))
              (setf (relay-closing-attachments transport)
                    (remove attachment (relay-closing-attachments transport) :test #'eq))))
        (error (condition)
          (push (list ':attachment attachment condition) failures))))
    (setf failures (nreverse failures))
    (bordeaux-threads:with-lock-held ((relay-lock transport))
      (when (and failures (null (relay-cleanup-cause transport)))
        (setf (relay-cleanup-cause transport) (third (first failures))))
      (unless (or (relay-closing-attachments transport)
                  (relay-closing-direct-transports transport))
        (setf (relay-cleanup-cause transport) nil))
      (setf cause (relay-cleanup-cause transport)))
    (when failures
      (error 'daemon-cleanup-error :operation ':retire-attachments
             :cause cause :failures failures
             :message                         "Transport cleanup failed; the relay retains it for stop retry.")))
  nil)

(-> relay-retire-attachment (relay attachment &key (:packet list)) null)
(defun relay-retire-attachment (transport attachment &key packet)
  "Finish a removed attachment with PACKET, or abortively close it, retaining failures."
  (relay--retire-attachments transport (list attachment) :packet packet))

(defmethod transport-stop ((transport relay))
  "Stop relay transports, retaining failed attachment cleanup for a later retry."
  (let (direct attachments)
    (bordeaux-threads:with-lock-held ((relay-lock transport))
      (setf direct (and (transport-started-p transport) (relay-direct-terminal transport))
            attachments (remove-duplicates
                         (append (relay-closing-attachments transport)
                                 (when (relay-controller transport)
                                   (list (relay-controller transport)))
                                 (relay-observers transport))
                         :test #'eq)
            (relay-closing-attachments transport) attachments
            (relay-controller transport) nil
            (relay-observers transport) nil
            (transport-interactive-p transport) nil
            (transport-styled-p transport) nil
            (transport-started-p transport) nil)
      (structlisp:deque-clear (relay-input-events transport))
      (sb-thread:condition-broadcast (relay-input-condition-variable transport)))
    (relay--retire-attachments transport attachments :direct direct))
  transport)

(defmethod transport-write ((transport relay) (text string))
  "Write trusted TEXT to the current terminal and every observer in exact order."
  (bordeaux-threads:with-lock-held ((relay-lock transport))
    (let ((direct (relay-direct-terminal transport))
          (attachments
           (remove-duplicates
            (append
             (when (relay-controller transport) (list (relay-controller transport)))
             (relay-observers transport))
            :test #'eq)))
      (when direct (transport-write direct text))
      (dolist (chunk (relay--output-chunks text))
        (relay--retain-output transport chunk)
        (dolist (attachment attachments)
          (attachment-send attachment (list :output chunk))))))
  nil)

(defmethod transport-flush ((transport relay))
  "Flush TERMINAL's direct transport when attached."
  (bordeaux-threads:with-lock-held ((relay-lock transport))
    (let ((direct (relay-direct-terminal transport)))
      (when direct (transport-flush direct))))
  nil)

(defmethod transport-input-ready-p ((transport relay))
  "Return true when TERMINAL has a queued or direct input event."
  (let ((direct nil) (queued-p nil))
    (bordeaux-threads:with-lock-held ((relay-lock transport))
      (setf queued-p (not (structlisp:deque-empty-p (relay-input-events transport)))
            direct (relay-direct-terminal transport)))
    (or queued-p (and direct (transport-input-ready-p direct)))))

(defmethod transport-read-event ((transport relay))
  "Block for one attachment event, or delegate to the direct terminal."
  (let ((event nil) (direct nil))
    (bordeaux-threads:with-lock-held ((relay-lock transport))
      (loop while (and (structlisp:deque-empty-p (relay-input-events transport))
                       (null (relay-direct-terminal transport))
                       (relay-controller transport) (transport-started-p transport))
            do (bordeaux-threads:condition-wait
                (relay-input-condition-variable transport) (relay-lock transport)))
      (if (structlisp:deque-empty-p (relay-input-events transport))
          (setf direct (relay-direct-terminal transport))
          (setf event (structlisp:deque-pop-front (relay-input-events transport)))))
    (cond (event
           event)
          (direct
           (transport-read-event direct))
          (t
           ':stream-end))))

(-> relay-enqueue-event (relay attachment t) boolean)
(defun relay-enqueue-event (transport attachment event)
  "Queue ATTACHMENT's controlling EVENT for TERMINAL."
  (let ((wake-function nil))
    (bordeaux-threads:with-lock-held ((relay-lock transport))
      (unless (eq attachment (relay-controller transport))
        (return-from relay-enqueue-event nil))
      (structlisp:deque-push-back (relay-input-events transport) event)
      (bordeaux-threads:condition-notify (relay-input-condition-variable transport))
      (setf wake-function (relay-wake-function transport)))
    (when wake-function (funcall wake-function))
    t))

(-> relay-release-direct (relay) boolean)
(defun relay-release-direct (transport)
  "Restore and release TERMINAL's launching foreground transport."
  (let ((direct nil))
    (bordeaux-threads:with-lock-held ((relay-lock transport))
      (setf direct (relay-direct-terminal transport)
            (relay-direct-terminal transport) nil)
      (unless (relay-controller transport)
        (setf (transport-interactive-p transport) nil)))
    (when direct (relay--retire-attachments transport nil :direct direct))
    (not (null direct))))

(-> relay-attach
    (relay attachment &key (:rows (or null integer)) (:columns (or null integer)) (:styled-p t)
                     (:session-id t) (:defer-revocation-p boolean))
    (values boolean boolean (or null attachment)))
(defun relay-attach (transport attachment &key rows columns styled-p session-id defer-revocation-p)
  "Attach ATTACHMENT after queueing its handshake and report direct release.

Return success, whether a direct terminal was released, and a replaced controller
when DEFER-REVOCATION-P is true. The caller must send its revocation and close it
outside any shared transport lock. Otherwise revoke and close it before returning."
  (let ((mode              (attachment-mode attachment))
        (old-controller    nil)
        (direct            nil)
        (released-direct-p nil))
    (bordeaux-threads:with-lock-held ((relay-lock transport))
      (when
          (and (eq mode ':control)
               (or (relay-direct-terminal transport) (relay-controller transport)))
        (daemon-fail :message   "The localgroup session already has a controlling terminal."
                     :operation ':attach))
      (let* ((history
              (apply #'concatenate 'string
                     (cons ""
                           (coerce (structlisp:deque->vector (relay-history transport)) 'list))))
             (next-rows
              (if (and (not (eq mode ':read-only)) (plusp rows))
                  rows
                  (transport-rows transport)))
             (next-columns
              (if (and (not (eq mode ':read-only)) (plusp columns))
                  columns
                  (transport-columns transport))))
        (unless
            (attachment-send attachment
                             (list :attached :mode mode :session-id session-id :history history
                                   :history-start
                                   (- (relay-history-position transport) (length history))
                                   :history-position (relay-history-position transport) :rows
                                   next-rows :columns next-columns))
          (return-from relay-attach (values nil nil nil)))
        (ecase mode
          (:read-only
           (pushnew attachment (relay-observers transport) :test #'eq))
          (:control
           (setf (relay-controller transport) attachment))
          (:take-over
           (when (relay-controller transport)
             (pushnew (relay-controller transport) (relay-closing-attachments transport) :test
                      #'eq))
           (setf direct (relay-direct-terminal transport)
                 old-controller (relay-controller transport)
                 (relay-direct-terminal transport) nil
                 (relay-controller transport) attachment
                 released-direct-p (not (null direct)))))
        (sb-thread:condition-broadcast (relay-input-condition-variable transport))
        (when (not (eq mode ':read-only))
          (setf (transport-interactive-p transport) t
                (transport-styled-p transport) (not (null styled-p)))
          (transport-resize transport :rows next-rows :columns next-columns :styled-p styled-p))))
    (relay--retire-attachments
     transport
     (when (and old-controller (not (eq old-controller attachment)) (not defer-revocation-p))
       (list old-controller))
     :packet '(:revoked) :direct direct)
    (values t released-direct-p
            (when (and defer-revocation-p (not (eq old-controller attachment))) old-controller))))

(-> relay-detach (relay attachment) boolean)
(defun relay-detach (transport attachment)
  "Remove ATTACHMENT and report whether it controlled TERMINAL."
  (let ((controlled-p nil))
    (bordeaux-threads:with-lock-held ((relay-lock transport))
      (setf (relay-observers transport) (delete attachment (relay-observers transport)))
      (when (eq attachment (relay-controller transport))
        (setf (relay-controller transport) nil
              controlled-p t)
        (structlisp:deque-clear (relay-input-events transport))
        (unless (relay-direct-terminal transport)
          (setf (transport-interactive-p transport) nil)))
      (sb-thread:condition-broadcast (relay-input-condition-variable transport)))
    controlled-p))

(-> relay-release-control (relay) boolean)
(defun relay-release-control (transport)
  "Release the direct or remote controller, retaining failed remote cleanup."
  (let (direct controller)
    (bordeaux-threads:with-lock-held ((relay-lock transport))
      (setf direct (relay-direct-terminal transport)
            controller (relay-controller transport))
      (when controller
        (pushnew controller (relay-closing-attachments transport) :test #'eq))
      (setf (relay-direct-terminal transport) nil
            (relay-controller transport) nil
            (transport-interactive-p transport) nil)
      (structlisp:deque-clear (relay-input-events transport))
      (sb-thread:condition-broadcast (relay-input-condition-variable transport)))
    (relay--retire-attachments transport (when controller (list controller))
                               :packet '(:detached) :direct direct)
    (not (null direct))))

(-> relay-finish (relay &key (:status t) (:message t) (:details t)) relay)
(defun relay-finish (transport &key status message details)
  "Tell every attachment its application exits with STATUS, then release them.

Each controlling or observing client receives (:EXIT :STATUS STATUS :MESSAGE
MESSAGE) after any queued output, which DAEMON-ATTACH-CLIENT-RUN returns, so a
relaying launcher can exit as the detached application would have. DETAILS,
when present, is an application-defined plist of keywords to strings or
integers that the exit also carries, such as where the application left its
crash context for the relaying launcher. A direct terminal is left to the
application."
  (check-type status (integer 0 255))
  (check-type message (or null string))
  (assert (daemon-exit-details-p details) (details)
          "Exit details ~S are not a plist of keywords to strings or integers." details)
  (let ((attachments nil))
    (bordeaux-threads:with-lock-held ((relay-lock transport))
      (setf attachments
              (remove-duplicates
               (append (relay-closing-attachments transport)
                       (when (relay-controller transport) (list (relay-controller transport)))
                       (relay-observers transport))
               :test #'eq)
            (relay-closing-attachments transport) attachments
            (relay-controller transport) nil
            (relay-observers transport) nil)
      (unless (relay-direct-terminal transport) (setf (transport-interactive-p transport) nil))
      (structlisp:deque-clear (relay-input-events transport))
      (sb-thread:condition-broadcast (relay-input-condition-variable transport)))
    (relay--retire-attachments transport attachments :packet
     (list* :exit :status status :message message (when details (list :details details)))))
  transport)

(-> relay-observer-count (relay) (integer 0))
(defun relay-observer-count (transport)
  "Return TERMINAL's current read-only attachment count."
  (bordeaux-threads:with-lock-held ((relay-lock transport))
    (length (relay-observers transport))))

(-> relay-attached-p (relay) boolean)
(defun relay-attached-p (transport)
  "Return true when TERMINAL has direct or controlling ownership."
  (bordeaux-threads:with-lock-held ((relay-lock transport))
    (not (null (or (relay-direct-terminal transport) (relay-controller transport))))))

(-> relay-attachment-kind (relay) keyword)
(defun relay-attachment-kind (transport)
  "Return TERMINAL's current ownership kind."
  (bordeaux-threads:with-lock-held ((relay-lock transport))
    (cond ((relay-direct-terminal transport)
           ':foreground)
          ((relay-controller transport)
           ':remote)
          (t
           ':detached))))

(-> relay-create
    (&key (:direct-terminal t) (:rows integer) (:columns integer) (:interactive-p t)
          (:styled-p t))
    relay)
(defun relay-create (&key direct-terminal (rows 24) (columns 80) interactive-p styled-p)
  "Create a relay independent of the host terminal implementation."
  (make-instance 'relay :direct-terminal direct-terminal :rows rows :columns columns
                       :interactive-p interactive-p :styled-p styled-p))
