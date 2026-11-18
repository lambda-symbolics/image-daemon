(in-package #:image-daemon)

;;;; -- Attachment Packet Loops --

(-> daemon-terminal-event-p (t) boolean)
(defun daemon-terminal-event-p (event)
  "Return true when EVENT is a supported semantic terminal event."
  (or (keywordp event) (characterp event)
      (and (proper-list-p event) (= (length event) 2)
           (member (first event) '(:insert :paste :line)) (stringp (second event)))))

(-> relay-read-attachment
    (relay attachment &key (:event-validator (or function symbol))
           (:packet-function (or null function)))
    null)
(defun relay-read-attachment
    (relay attachment &key (event-validator #'daemon-terminal-event-p) packet-function)
  "Relay validated controlling input and resize packets until detach or stream end.

PACKET-FUNCTION receives every packet of another kind. A packet that cannot be
decoded, as a client of another version may send, is skipped."
  (loop for packet = (handler-case (daemon-read-decodable-packet (attachment-stream attachment))
                      (error () nil))
        while packet
        do (case (first packet)
             (:detach
              (attachment-finish attachment '(:detached))
              (return))
             (:event
              (when (and (rest packet)
                         (not (eq (attachment-mode attachment) ':read-only))
                         (funcall event-validator (second packet)))
                (relay-enqueue-event relay attachment (second packet))))
             (:resize
              (let ((rows     (getf (rest packet) :rows))
                    (columns  (getf (rest packet) :columns))
                    (styled-p (getf (rest packet) :styled-p)))
                (when (and (typep rows '(integer 1 10000))
                           (typep columns '(integer 1 10000)) (typep styled-p 'boolean))
                  (bordeaux-threads:with-lock-held ((relay-lock relay))
                    (when (eq attachment (relay-controller relay))
                      (transport-resize relay :rows rows :columns columns :styled-p styled-p))))))
             (otherwise
              (when packet-function
                (funcall packet-function packet)))))
  nil)

(-> daemon-exit-details-p (t) boolean)
(defun daemon-exit-details-p (details)
  "Return true when DETAILS is NIL or a plist of keywords to strings or integers."
  (and (proper-list-p details)
       (evenp (length details))
       (loop for (key value) on details by (partial #'nthcdr 2)
             always (and (keywordp key) (typep value '(or string integer))))
       t))

(-> daemon-attach--exit-p (t) boolean)
(defun daemon-attach--exit-p (packet)
  "Return true when PACKET is a well-formed application exit packet."
  (and (proper-list-p packet)
       (eq (first packet) ':exit)
       (typep (getf (rest packet) :status) '(integer 0 255))
       (typep (getf (rest packet) :message) '(or null string))
       (daemon-exit-details-p (getf (rest packet) :details))
       t))

(-> daemon-attach--termination (keyword &key (:condition (or null condition))) list)
(defun daemon-attach--termination (kind &key condition)
  "Describe an attachment end without printing packet contents or condition data."
  (let ((name (when condition (class-name (class-of condition)))))
    (list :kind           kind
          :message        (case kind
                            (:unexpected-eof
                             "The daemon endpoint closed without an exit event.")
                            (:decoding-failure
                             "The daemon sent an invalid attachment packet.")
                            (:callback-failure
                             "A local attachment callback failed.")
                            (:transport-failure
                             "Attachment transport I/O failed.")
                            (:cleanup-failure
                             "Attachment cleanup failed.")
                            (:queue-overflow
                             "The daemon disconnected this attachment because its output queue overflowed.")
                            (:remote-failure
                             "The daemon could not complete this attachment.")
                            (:application-exit
                             "The application exited.")
                            (:revoked
                             "Control of this attachment was revoked.")
                            (:control-packet
                             "The host requested an attachment transition.")
                            (otherwise
                             "The attachment was detached."))
          :condition-type (when (and condition (symbolp name))
                            (subseq (symbol-name name) 0 (min 80 (length (symbol-name name))))))))

(-> daemon-attach--exit-termination (list) list)
(defun daemon-attach--exit-termination (packet)
  "Classify an exit PACKET, including server-side attachment failures."
  (let ((reason (getf (getf (rest packet) :details) :reason)))
    (daemon-attach--termination
     (cond
       ((equal reason "queue-overflow")
        ':queue-overflow)
       ((equal reason "attachment-failure")
        ':remote-failure)
       (t
        ':application-exit)))))

(-> daemon-attach-receive
    (stream stream function &key (:exit-function (or null function))
            (:packet-function (or null function)) (:termination-function (or null function)))
    (values null list))
(defun daemon-attach-receive
    (stream output-stream stop-function &key exit-function packet-function termination-function)
  "Receive attachment packets and always call STOP-FUNCTION.

Preserve the NIL primary return and return a termination plist as the second
value. Distinguish detach, revocation, application exit, unexpected EOF,
broken frames and callback failures. A packet that cannot be decoded, and an
output or exit packet of an unknown shape, is skipped: a host of another
version may send one. EXIT-FUNCTION receives the legacy exit plist.
PACKET-FUNCTION may end reception by returning true. Call the optional
TERMINATION-FUNCTION with the bounded diagnostic before cleanup."
  (let ((termination nil)
        (notified-p  nil))
    (flet ((notify ()
             "Publish the accepted terminal cause once, before legacy observers."
             (unless notified-p
               (setf notified-p t)
               (when termination-function
                 (handler-case (funcall termination-function termination)
                   (error (condition)
                     (setf (getf termination :notification-condition-type)
                           (getf (daemon-attach--termination ':callback-failure :condition condition)
                                 :condition-type))))))))
     (unwind-protect
          (progn
            (loop
              (let ((packet
                      (handler-case
                          (daemon-read-decodable-packet stream)
                        (error (condition)
                          (setf termination
                                (daemon-attach--termination
                                 (if (and (typep condition 'daemon-error)
                                          (eq (daemon-error-operation condition) ':read-packet))
                                     ':decoding-failure
                                     ':transport-failure)
                                 :condition condition))
                          nil))))
                (unless packet
                  (unless termination
                    (setf termination (daemon-attach--termination ':unexpected-eof)))
                  (return))
                (handler-case
                    (case (first packet)
                      (:output
                       (when (stringp (second packet))
                         (write-string (second packet) output-stream)
                         (finish-output output-stream)))
                      (:exit
                       (when (daemon-attach--exit-p packet)
                         (setf termination (daemon-attach--exit-termination packet))
                         (notify)
                         (when exit-function
                           (funcall exit-function
                                    (list* :status  (getf (rest packet) :status)
                                           :message (getf (rest packet) :message)
                                           (let ((details (getf (rest packet) :details)))
                                             (when details (list :details details))))))
                         (return)))
                      ((:detached :revoked)
                       (setf termination (daemon-attach--termination (first packet)))
                       (notify)
                       (return))
                      (otherwise
                       (when (and packet-function (funcall packet-function packet))
                         (setf termination (daemon-attach--termination ':control-packet))
                         (notify)
                         (return))))
                  (error (condition)
                   (if termination
                       (setf (getf termination :observer-condition-type)
                             (getf (daemon-attach--termination ':callback-failure :condition condition)
                                   :condition-type))
                       (setf termination
                             (daemon-attach--termination ':callback-failure :condition condition)))
                   (return)))))
            (notify))
       (handler-case
           (funcall stop-function)
         (error (condition)
           (setf (getf termination :cleanup-condition-type)
                 (getf (daemon-attach--termination ':cleanup-failure :condition condition)
                       :condition-type)))))
     (values nil termination))))

(-> daemon-attach-client-run
    (stream &key (:socket t) (:mode t) (:input-ready-function (or null function))
            (:read-event-function (or null function)) (:resize-function (or null function))
            (:output-stream stream) (:close-function (or null function))
            (:packet-function (or null function)) (:outgoing-function (or null function))
            (:termination-function (or null function)))
    (values list list))
(defun daemon-attach-client-run
    (stream &key socket mode input-ready-function read-event-function resize-function
                 (output-stream *standard-output*) close-function packet-function
                 outgoing-function termination-function)
  "Run an attachment, returning its legacy exit result and a termination plist.

The primary value is an application exit plist or NIL. The second value names
the termination cause, including local input, output and rendering failures.
OUTGOING-FUNCTION, called once per cycle, returns host packets to send whole.
TERMINATION-FUNCTION optionally receives that diagnostic after transport cleanup.
Supply SOCKET or CLOSE-FUNCTION to unblock the receiver during cleanup."
  (unless (or socket close-function)
    (daemon-fail :message   "An attachment socket or shutdown callback is required."
                 :operation ':attach))
  (let ((lock        (bordeaux-threads:make-lock "Image daemon attach client"))
        (stopped-p   nil)
        (receiver    nil)
        (exit        nil)
        (termination nil))
    (labels ((stop ()
               (bordeaux-threads:with-lock-held (lock) (setf stopped-p t)))

             (stopped-p ()
               (bordeaux-threads:with-lock-held (lock) stopped-p))

             (record-exit (plist)
               (bordeaux-threads:with-lock-held (lock) (setf exit plist)))

             (record-termination (plist)
               (bordeaux-threads:with-lock-held (lock)
                 (unless termination
                   (setf termination plist))
                 (setf stopped-p t)))

             (send (packet)
               (handler-case
                   (daemon-write-packet stream packet)
                 (error (condition)
                   (record-termination
                    (daemon-attach--termination ':transport-failure :condition condition)))))

             (cleanup (function)
               (handler-case
                   (funcall function)
                 (error (condition)
                   (bordeaux-threads:with-lock-held (lock)
                     (let ((failure (daemon-attach--termination ':cleanup-failure :condition condition)))
                      (if (null termination)
                          (setf termination failure)
                          (setf (getf termination :cleanup-condition-type)
                                (getf failure :condition-type)))))))))
      (unwind-protect
           (handler-case
               (progn
                 (setf receiver
                       (bordeaux-threads:make-thread
                        (lambda ()
                          (daemon-attach-receive stream output-stream #'stop
                                                 :exit-function        #'record-exit
                                                 :packet-function      packet-function
                                                 :termination-function #'record-termination))
                        :name "Image daemon attach input"))
                 (loop until (stopped-p)
                       do (let ((resize (and resize-function (funcall resize-function))))
                            (when resize (send (cons :resize resize))))
                          (when outgoing-function
                            (mapc #'send (funcall outgoing-function)))
                          (when (and (not (stopped-p)) input-ready-function
                                     (funcall input-ready-function))
                            (let ((event (funcall read-event-function)))
                              (cond
                                ((or (member event '(:end-of-input :stream-end))
                                     (and (eq mode ':read-only) (eq event ':interrupt)))
                                 (record-termination (daemon-attach--termination ':detached)))
                                ((not (eq mode ':read-only))
                                 (send (list :event event))))))
                          (sleep 0.01)))
             (error (condition)
               (record-termination
                (daemon-attach--termination ':callback-failure :condition condition))))
        (stop)
        (when socket
          (cleanup (lambda () (sb-bsd-sockets:socket-shutdown socket :direction ':io))))
        (cleanup (or close-function (lambda () (close stream :abort t))))
        (cleanup (lambda () (daemon-stop-thread receiver))))
      (when termination-function
        (cleanup (lambda () (funcall termination-function termination))))
      (values exit termination))))
