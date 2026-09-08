(in-package #:image-daemon)

;;;; -- Attachment Packet Loops --

(defun daemon-terminal-event-p (event)
  "Return true when EVENT is a supported semantic terminal event."
  (or (keywordp event) (characterp event)
      (and (proper-list-p event) (= (length event) 2)
           (member (first event) '(:insert :paste :line)) (stringp (second event)))))

(defun relay-read-attachment (relay attachment &key (event-validator #'daemon-terminal-event-p))
  "Relay validated controlling input and resize packets until detach or stream end."
  (loop for packet = (handler-case (daemon-read-packet (attachment-stream attachment))
                      (error () nil))
        while packet
        do (case (first packet)
             (:detach (return))
             (:event
              (when (and (= (length packet) 2)
                         (not (eq (attachment-mode attachment) ':read-only))
                         (funcall event-validator (second packet)))
                (relay-enqueue-event relay attachment (second packet))))
             (:resize
              (let ((rows (getf (rest packet) :rows))
                    (columns (getf (rest packet) :columns))
                    (styled-p (getf (rest packet) :styled-p)))
                (when (and (typep rows '(integer 1 10000))
                           (typep columns '(integer 1 10000)) (typep styled-p 'boolean))
                  (bordeaux-threads:with-lock-held ((relay-lock relay))
                    (when (eq attachment (relay-controller relay))
                      (transport-resize relay :rows rows :columns columns :styled-p styled-p))))))))
  nil)

(defun daemon-attach-receive (stream output-stream stop-function)
  "Copy remote output to OUTPUT-STREAM and always call STOP-FUNCTION on exit."
  (unwind-protect
       (handler-case
           (loop for packet = (daemon-read-packet stream) while packet
                 do (case (first packet)
                      (:output
                       (when (stringp (second packet))
                         (write-string (second packet) output-stream)
                         (finish-output output-stream)))
                      ((:detached :revoked) (return))))
         (error () nil))
    (funcall stop-function))
  nil)

(defun daemon-attach-client-run (stream &key socket mode input-ready-function read-event-function
                                           resize-function (output-stream *standard-output*)
                                           close-function)
  "Run a local attachment using explicit input, resize and transport callbacks.

RESIZE-FUNCTION returns NIL or the plist for a resize packet. Observer exit keys
are local only. Supply SOCKET or a CLOSE-FUNCTION that unblocks concurrent I/O.
Teardown uses transport closure as detach, without writing another packet, and
shuts down socket I/O before abortive stream close."
  (unless (or socket close-function)
    (daemon-fail :message "An attachment socket or shutdown callback is required."
                 :operation ':attach))
  (let ((lock (bordeaux-threads:make-lock "Image daemon attach client"))
        (stopped-p nil) (receiver nil))
    (labels ((stop () (bordeaux-threads:with-lock-held (lock) (setf stopped-p t)))

             (stopped-p () (bordeaux-threads:with-lock-held (lock) stopped-p)))
      (unwind-protect
           (progn
             (setf receiver
                   (bordeaux-threads:make-thread
                    (lambda () (daemon-attach-receive stream output-stream #'stop))
                    :name "Image daemon attach input"))
             (loop until (stopped-p)
                   do (let ((resize (and resize-function (funcall resize-function))))
                        (when resize (daemon-write-packet stream (cons :resize resize))))
                      (when (funcall input-ready-function)
                        (let ((event (funcall read-event-function)))
                          (cond ((or (member event '(:end-of-input :stream-end))
                                     (and (eq mode ':read-only) (eq event ':interrupt)))
                                 (return))
                                ((not (eq mode ':read-only))
                                 (daemon-write-packet stream (list :event event))))))
                      (sleep 0.01)))
        (when socket
          (ignore-errors (sb-bsd-sockets:socket-shutdown socket :direction ':io)))
        (if close-function
            (ignore-errors (funcall close-function))
            (ignore-errors (close stream :abort t)))
        (daemon-stop-thread receiver))))
  nil)
