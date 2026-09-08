(in-package #:image-daemon)

(defparameter *daemon-thread-stop-timeout-seconds*
  1
  "The maximum seconds spent waiting for one transport thread to stop.")

(defun daemon-stop-thread (thread)
  "Boundedly stop and reap THREAD when it is live and not the caller."
  (when
      (and thread (not (eq thread (bordeaux-threads:current-thread)))
           (bordeaux-threads:thread-alive-p thread))
    (handler-case
     (sb-ext:with-timeout *daemon-thread-stop-timeout-seconds*
       (bordeaux-threads:join-thread thread))
     (sb-ext:timeout nil
      (when (bordeaux-threads:thread-alive-p thread)
        (ignore-errors (sb-thread:terminate-thread thread)))
      (ignore-errors (bordeaux-threads:join-thread thread)))))
  nil)
