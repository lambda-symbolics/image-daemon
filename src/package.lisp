(defpackage #:image-daemon
  (:use #:cl)
  (:export
   ;; tuning and hooks
   #:*daemon-connect-timeout-seconds*
   #:*daemon-error-class*
   #:*daemon-frame-header-character-limit*
   #:*daemon-packet-character-limit*
   #:*daemon-protocol-version*
   ;; conditions
   #:daemon-error
   #:daemon-error-cause
   #:daemon-error-message
   #:daemon-error-operation
   #:daemon-error-session-id
   #:daemon-fail
   ;; identity
   #:daemon-random-nonce
   #:daemon-random-token
   #:legacy-session-identifier-p
   #:session-identifier-display
   #:session-identifier-normalize
   #:session-identifier-timestamp
   ;; transport
   #:daemon-call
   #:daemon-connect
   #:daemon-read-packet
   #:daemon-socket-stream
   #:daemon-read-response
   #:daemon-write-packet))
