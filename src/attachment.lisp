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

(defclass attachment nil
          ((socket :initarg :socket :reader attachment-socket :type sb-bsd-sockets:socket
            :documentation "The accepted loopback socket owned by this attachment.")
           (stream :initarg :stream :reader attachment-stream :type stream :documentation
            "The duplex UTF-8 packet stream.")
           (mode :initarg :mode :reader attachment-mode :type
            (member :read-only :control :take-over) :documentation
            "The observation or terminal-control authority of this attachment.")
           (lock :initform (bordeaux-threads:make-lock "Image daemonp attachment")
            :reader attachment-lock :type t :documentation
            "The lock protecting output and closure state.")
           (condition-variable :initform
            (bordeaux-threads:make-condition-variable :name "Image daemonp attachment")
            :reader attachment-condition-variable :type t :documentation
            "The condition waking the output writer.")
           (queue :initform (structlisp:make-deque :weight-function #'length) :reader
            attachment-queue :type structlisp:deque :documentation
            "FIFO serialized packets awaiting the writer with maintained size.")
           (closed-p :initform nil :accessor attachment-closed-p :type boolean
            :documentation "Whether the stream no longer accepts packets.")
           (writer-thread :initform nil :accessor attachment-writer-thread :type t
            :documentation "The bounded asynchronous output writer."))
          (:documentation "One persistent read-only or controlling terminal attachment."))

(defun attachment--shutdown-socket (attachment)
  "Shut down ATTACHMENT's socket I/O without signaling."
  (ignore-errors
   (sb-bsd-sockets:socket-shutdown (attachment-socket attachment) :direction ':io))
  nil)

(defun attachment--close-stream (attachment)
  "Shut down and abortively close ATTACHMENT's duplex transport without signaling."
  (attachment--shutdown-socket attachment)
  (ignore-errors (close (attachment-stream attachment) :abort t))
  nil)

(defun attachment--writer-loop (attachment)
  "Write ATTACHMENT's queued packets until closure or transport failure."
  (block write-packets
    (handler-case
     (loop for packet = (bordeaux-threads:with-lock-held ((attachment-lock attachment))
                          (loop while (and
                                       (structlisp:deque-empty-p
                                        (attachment-queue attachment))
                                       (not (attachment-closed-p attachment)))
                                do (bordeaux-threads:condition-wait
                                    (attachment-condition-variable attachment)
                                    (attachment-lock attachment)))
                          (when
                              (and (attachment-closed-p attachment)
                                   (structlisp:deque-empty-p
                                    (attachment-queue attachment)))
                            (return-from write-packets nil))
                          (structlisp:deque-pop-front (attachment-queue attachment)))
           do (write-string packet (attachment-stream attachment)) (finish-output
                                                                    (attachment-stream
                                                                     attachment)))
     (error nil nil)))
  (bordeaux-threads:with-lock-held ((attachment-lock attachment))
    (setf (attachment-closed-p attachment) t)
    (structlisp:deque-clear (attachment-queue attachment))
    (bordeaux-threads:condition-notify (attachment-condition-variable attachment)))
  (attachment--close-stream attachment)
  nil)

(defun attachment-create (socket stream mode)
  "Create a persistent attachment over SOCKET and STREAM with MODE."
  (let ((attachment (make-instance 'attachment :socket socket :stream stream :mode mode)))
    (setf (attachment-writer-thread attachment)
            (bordeaux-threads:make-thread
             (lambda () (attachment--writer-loop attachment)) :name
             "Image daemonp attachment output"))
    attachment))

(defun attachment-send (attachment packet)
  "Queue PACKET for ATTACHMENT, closing a client that falls too far behind."
  (let ((text (daemon-packet-string packet)) (accepted-p nil) (close-p nil))
    (bordeaux-threads:with-lock-held ((attachment-lock attachment))
      (unless (attachment-closed-p attachment)
        (let ((queue (attachment-queue attachment)))
          (if (> (+ (structlisp:deque-total-weight queue) (length text))
                 *attachment-queue-character-limit*)
              (progn
               (setf (attachment-closed-p attachment) t
                     close-p t)
               (structlisp:deque-clear queue))
              (progn (structlisp:deque-push-back queue text) (setf accepted-p t))))
        (bordeaux-threads:condition-notify (attachment-condition-variable attachment))))
    (when close-p (attachment--shutdown-socket attachment))
    accepted-p))

(defun attachment-close (attachment)
  "Close ATTACHMENT and join its writer when called from another thread."
  (let ((writer nil))
    (bordeaux-threads:with-lock-held ((attachment-lock attachment))
      (setf (attachment-closed-p attachment) t
            writer (attachment-writer-thread attachment))
      (structlisp:deque-clear (attachment-queue attachment))
      (bordeaux-threads:condition-notify (attachment-condition-variable attachment)))
    (attachment--close-stream attachment)
    (when writer (daemon-stop-thread writer)))
  nil)

(defclass relay (transport)
          ((lock :initform (bordeaux-threads:make-lock "Image daemonp terminal") :reader
            relay-lock :type t :documentation
            "The lock protecting terminal ownership, input, and history.")
           (direct-terminal :initform nil :initarg :direct-terminal :accessor
            relay-direct-terminal :type t :documentation
            "The terminal inherited from the launching foreground process.")
           (controller :initform nil :accessor relay-controller :type (option attachment)
            :documentation "The attachment currently allowed to submit terminal input.")
           (observers :initform nil :accessor relay-observers :type list :documentation
            "Read-only attachments receiving rendered terminal output.")
           (closing-attachments :initform nil :accessor relay-closing-attachments
            :type list :documentation
            "Detached attachments retained until their writers have been reaped.")
           (input-condition-variable :initform
            (bordeaux-threads:make-condition-variable :name
                                                      "Image daemonp terminal input")
            :reader relay-input-condition-variable :type t :documentation
            "The condition waking a blocking semantic input read.")
           (input-events :initform (structlisp:make-deque) :reader relay-input-events
            :type structlisp:deque :documentation
            "FIFO semantic events received from the controlling attachment.")
           (history :initform (structlisp:make-deque :weight-function #'length) :reader
            relay-history :type structlisp:deque :documentation
            "Bounded terminal output chunks with maintained character size.")
           (wake-function :initform nil :accessor relay-wake-function :type
            (option function) :documentation
            "The callback waking the responsive input controller."))
          (:documentation
           "A terminal relay supporting foreground, detached, and observed use."))

(defun relay-set-wake-function (transport function)
  "Set TERMINAL's responsive-reader wake FUNCTION."
  (bordeaux-threads:with-lock-held ((relay-lock transport))
    (setf (relay-wake-function transport) function))
  nil)

(defun relay--output-chunks (text)
  "Return TEXT as ordered bounded attachment-output chunks."
  (loop with length = (length text)
        for start = 0 then
        end
        while (< start length)
        for
        end = (min length (+ start *relay-output-chunk-character-limit*))
        collect (subseq text start end)))

(defun relay--retain-output (transport text)
  "Append TEXT to TERMINAL's exactly bounded attachment replay history while locked."
  (let ((history (relay-history transport)))
    (structlisp:deque-push-back history text)
    (loop while (> (structlisp:deque-total-weight history)
                   *relay-history-character-limit*)
          for excess = (- (structlisp:deque-total-weight history)
                          *relay-history-character-limit*)
          for first = (structlisp:deque-front history)
          do (if (<= (length first) excess)
                 (structlisp:deque-pop-front history)
                 (setf (structlisp:deque-ref history 0) (subseq first excess)))))
  nil)

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

(defmethod transport-stop ((transport relay))
  "Stop relay transports, retaining failed attachment cleanup for a later retry."
  (let ((direct nil) (attachments nil) (failure nil))
    (bordeaux-threads:with-lock-held ((relay-lock transport))
      (setf direct (and (transport-started-p transport)
                        (relay-direct-terminal transport))
            attachments
            (remove-duplicates
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
    (when direct (ignore-errors (transport-stop direct)))
    (dolist (attachment attachments)
      (handler-case
          (progn
            (attachment-close attachment)
            (bordeaux-threads:with-lock-held ((relay-lock transport))
              (setf (relay-closing-attachments transport)
                    (remove attachment (relay-closing-attachments transport) :test #'eq))))
        (error (condition)
          (unless failure (setf failure condition)))))
    (when failure (error failure)))
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
    (cond (event event) (direct (transport-read-event direct)) (t ':stream-end))))

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

(defun relay-release-direct (transport)
  "Restore and release TERMINAL's launching foreground transport."
  (let ((direct nil))
    (bordeaux-threads:with-lock-held ((relay-lock transport))
      (setf direct (relay-direct-terminal transport)
            (relay-direct-terminal transport) nil)
      (unless (relay-controller transport)
        (setf (transport-interactive-p transport) nil)))
    (when direct (ignore-errors (transport-stop direct)))
    (not (null direct))))

(defun relay-attach (transport attachment &key rows columns styled-p session-id)
  "Attach ATTACHMENT after queueing its handshake and report direct release."
  (let ((mode (attachment-mode attachment))
        (old-controller nil)
        (direct nil)
        (released-direct-p nil))
    (bordeaux-threads:with-lock-held ((relay-lock transport))
      (when
          (and (eq mode ':control)
               (or (relay-direct-terminal transport) (relay-controller transport)))
        (daemon-fail :message
                     "The localgroup session already has a controlling terminal."
                     :operation ':attach))
      (let* ((history
              (apply #'concatenate 'string
                     (cons ""
                           (coerce (structlisp:deque->vector (relay-history transport))
                                   'list))))
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
             (list :attached :mode mode :session-id session-id :history history :rows
                   next-rows :columns next-columns))
          (return-from relay-attach (values nil nil)))
        (ecase mode
          (:read-only (pushnew attachment (relay-observers transport) :test #'eq))
          (:control (setf (relay-controller transport) attachment))
          (:take-over
           (setf direct (relay-direct-terminal transport)
                 old-controller (relay-controller transport)
                 (relay-direct-terminal transport) nil
                 (relay-controller transport) attachment
                 released-direct-p (not (null direct)))))
        (sb-thread:condition-broadcast (relay-input-condition-variable transport))
        (when (not (eq mode ':read-only))
          (setf (transport-interactive-p transport) t
                (transport-styled-p transport) (not (null styled-p)))
          (transport-resize transport :rows next-rows :columns next-columns :styled-p
           styled-p))))
    (when direct (ignore-errors (transport-stop direct)))
    (when (and old-controller (not (eq old-controller attachment)))
      (attachment-send old-controller '(:revoked))
      (attachment-close old-controller))
    (values t released-direct-p)))

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

(defun relay-release-control (transport)
  "Release TERMINAL's direct or remote controller and report direct ownership."
  (let ((direct nil) (controller nil))
    (bordeaux-threads:with-lock-held ((relay-lock transport))
      (setf direct (relay-direct-terminal transport)
            controller (relay-controller transport)
            (relay-direct-terminal transport) nil
            (relay-controller transport) nil
            (transport-interactive-p transport) nil)
      (structlisp:deque-clear (relay-input-events transport))
      (sb-thread:condition-broadcast (relay-input-condition-variable transport)))
    (when direct (ignore-errors (transport-stop direct)))
    (when controller
      (attachment-send controller '(:detached))
      (attachment-close controller))
    (not (null direct))))

(defun relay-observer-count (transport)
  "Return TERMINAL's current read-only attachment count."
  (bordeaux-threads:with-lock-held ((relay-lock transport))
    (length (relay-observers transport))))

(defun relay-attached-p (transport)
  "Return true when TERMINAL has direct or controlling ownership."
  (bordeaux-threads:with-lock-held ((relay-lock transport))
    (not (null (or (relay-direct-terminal transport) (relay-controller transport))))))

(defun relay-attachment-kind (transport)
  "Return TERMINAL's current ownership kind."
  (bordeaux-threads:with-lock-held ((relay-lock transport))
    (cond ((relay-direct-terminal transport) ':foreground)
          ((relay-controller transport) ':remote) (t ':detached))))

(defun relay-create (&key direct-terminal (rows 24) (columns 80) interactive-p styled-p)
  "Create a relay independent of the host terminal implementation."
  (make-instance 'relay :direct-terminal direct-terminal :rows rows :columns columns
                       :interactive-p interactive-p :styled-p styled-p))
