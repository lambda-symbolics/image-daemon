(in-package #:image-daemon/tests)

;;;; -- Native Windows Handoff Fixtures --

(defvar *windows-handoff-assertions* 0
  "Assertions checked in the current native Windows run.")

(-> windows-tests--check (t string) null)
(defun windows-tests--check (value message)
  "Count one assertion and require VALUE."
  (incf *windows-handoff-assertions*)
  (unless value (error message))
  nil)

(-> windows-tests--call-with-directory (function) t)
(defun windows-tests--call-with-directory (function)
  "Call FUNCTION with a private temporary fixture directory, then remove it."
  (let ((root (merge-pathnames (format nil "windows-handoff-~A/" (daemon-random-nonce))
                               (uiop:temporary-directory))))
    (ensure-directories-exist root)
    (unwind-protect (funcall function root)
      (uiop:delete-directory-tree root :validate t))))

(-> windows-tests--script (pathname list) pathname)
(defun windows-tests--script (pathname forms)
  "Write readable FORMS as a native runtime test script."
  (ensure-directories-exist pathname)
  (with-open-file (stream pathname :direction ':output :if-exists ':supersede
                                   :external-format ':utf-8)
    (with-standard-io-syntax
      (let ((*package* (find-package '#:image-daemon/tests)))
        (dolist (form forms)
          (write form :stream stream)
          (terpri stream)))))
  pathname)

(-> windows-tests--command (pathname &rest string) list)
(defun windows-tests--command (script &rest arguments)
  "Return the running runtime's script invocation with literal ARGUMENTS."
  (append (list (namestring sb-ext:*runtime-pathname*) "--noinform"
                "--no-userinit" "--no-sysinit" "--script" (namestring script))
          arguments))

(-> windows-tests--await (function) (eql t))
(defun windows-tests--await (predicate)
  "Require PREDICATE within ten seconds, bounding native process fixtures."
  (let ((deadline (+ (get-internal-real-time) (* 10 internal-time-units-per-second))))
    (loop until (funcall predicate)
          do (when (>= (get-internal-real-time) deadline)
               (error "Native process fixture timed out."))
             (sleep 0.01)))
  t)

(-> test-windows-detached-arguments () null)
(defun test-windows-detached-arguments ()
  "Exercise real Unicode/quoted argv and inherited output through CreateProcessW."
  (windows-tests--call-with-directory
   (lambda (root)
     (let* ((directory (merge-pathnames "Lukáš žluťoučký/" root))
            (script    (windows-tests--script
                        (merge-pathnames "arguments.lisp" directory)
                        '((require :asdf)
                          (write (uiop:command-line-arguments))
                          (terpri) (finish-output))))
            (arguments (list "" "two words" "Lukáš-žluťoučký"
                             (format nil "tab~Cvalue" #\Tab)
                             "slash\\\"quote" "trailing space\\"))
            (log       (merge-pathnames "output.log" directory))
            (ticket    (handoff-ticket-pathname directory "launch"))
            (process   nil))
       (unwind-protect
            (progn
              (with-open-file (output log :direction ':output :if-exists ':supersede)
                (setf process
                      (handoff-launch-supervised
                       (apply #'windows-tests--command script arguments) ticket
                       :directory directory :output output)))
              (windows-tests--await
               (lambda () (not (image-daemon:handoff-process-alive-p process))))
              (image-daemon:handoff-process-wait process)
              (with-open-file (input log :external-format ':utf-8)
                (let ((*read-eval* nil))
                  (windows-tests--check (equal (read input) arguments)
                                        "native launch preserves every literal argument")))
              (image-daemon:handoff-process-release process)
              (windows-tests--check
               (not (image-daemon:handoff-process-alive-p process))
               "waiting and repeated release close resources idempotently"))
         (when process
           (ignore-errors (image-daemon:handoff-process-terminate process :force t))
           (image-daemon:handoff-process-wait process))))))
  nil)

(-> test-windows-detached-descendants () null)
(defun test-windows-detached-descendants ()
  "Cancel descendants after their detached root has already exited."
  (windows-tests--call-with-directory
   (lambda (root)
     (let* ((child    (windows-tests--script (merge-pathnames "child.lisp" root)
                                             '((sleep 60))))
            (pid-file (merge-pathnames "child.pid" root))
            (script
              (windows-tests--script
               (merge-pathnames "parent.lisp" root)
               `((let ((process (sb-ext:run-program
                                 ,(namestring sb-ext:*runtime-pathname*)
                                 '("--noinform" "--script" ,(namestring child))
                                 :wait nil :input nil :output nil :error nil)))
                   (with-open-file (stream ,pid-file :direction ':output
                                                    :if-exists  ':supersede)
                     (write (sb-ext:process-pid process) :stream stream))))))
            (ticket   (handoff-ticket-pathname root "launch"))
            (process  nil))
       (unwind-protect
            (progn
              (setf process (handoff-launch-supervised (windows-tests--command script)
                                                       ticket :directory root))
              (windows-tests--await (lambda () (probe-file pid-file)))
              (windows-tests--await
               (lambda ()
                 (eq (daemon-process-state (image-daemon:handoff-process-id process)) ':dead)))
              (windows-tests--check (image-daemon:handoff-process-alive-p process)
                                    "the owned tree survives an exited root")
              (with-open-file (input pid-file)
                (let* ((*read-eval* nil) (pid (read input)))
                  (windows-tests--check (eq (daemon-process-state pid) ':alive)
                                        "the root's child is running before cancellation")
                  (image-daemon:handoff-process-terminate process)
                  (windows-tests--check (image-daemon:handoff-process-wait process)
                                        "handoff cancellation positively reaps the whole tree")
                  (windows-tests--check (eq (daemon-process-state pid) ':dead)
                                        "no descendant survives a cancelled handoff"))))
         (when process
           (ignore-errors (image-daemon:handoff-process-terminate process :force t))
           (image-daemon:handoff-process-wait process))))))
  nil)

(-> test-windows-detached-startup-failure () null)
(defun test-windows-detached-startup-failure ()
  "Refuse failed job assignment before any replacement code can run."
  (windows-tests--call-with-directory
   (lambda (root)
     (let* ((marker         (merge-pathnames "ran.sexp" root))
            (script         (windows-tests--script
                             (merge-pathnames "marker.lisp" root)
                             `((with-open-file (stream ,marker :direction ':output)
                                 (write :ran :stream stream)))))
            (ticket         (handoff-ticket-pathname root "launch"))
            (process-handle nil)
            (original       (symbol-function 'image-daemon::handoff-win32--assign-process-to-job-object)))
       (unwind-protect
            (progn
              (setf (symbol-function 'image-daemon::handoff-win32--assign-process-to-job-object)
                    (lambda (job process)
                      (declare (ignore job))
                      (setf process-handle process)
                      0))
              (windows-tests--check
               (handler-case
                   (progn
                     (handoff-launch-supervised (windows-tests--command script) ticket
                                                :directory root)
                     nil)
                 (image-daemon:handoff-process-error () t))
               "failed assignment rejects the detached launch"))
         (setf (symbol-function 'image-daemon::handoff-win32--assign-process-to-job-object)
               original))
       (windows-tests--check process-handle "the test reached native job assignment")
       (windows-tests--check (not (probe-file marker))
                             "the suspended replacement never ran before ownership"))))
  nil)

(-> test-windows-detached-release () null)
(defun test-windows-detached-release ()
  "Release a successful handoff without killing its detached process."
  (windows-tests--call-with-directory
   (lambda (root)
     (let* ((marker  (merge-pathnames "completed.sexp" root))
            (script  (windows-tests--script
                      (merge-pathnames "complete.lisp" root)
                      `((sleep 1)
                        (with-open-file (stream ,marker :direction ':output)
                          (write :completed :stream stream)))))
            (process (handoff-launch-supervised (windows-tests--command script)
                                                (handoff-ticket-pathname root "launch")
                                                :directory root))
            (pid     (image-daemon:handoff-process-id process)))
       (unwind-protect
            (progn
              (image-daemon:handoff-process-release process)
              (image-daemon:handoff-process-release process)
              (windows-tests--await (lambda () (probe-file marker)))
              (windows-tests--check (probe-file marker)
                                    "a successful detached session outlives released handles")
              (windows-tests--await (lambda () (eq (daemon-process-state pid) ':dead))))
         (when (eq (daemon-process-state pid) ':alive)
           (ls-compat.posix:signal-process pid ':kill))))))
  nil)

(-> run-windows-handoff-tests () (eql t))
(defun run-windows-handoff-tests ()
  "Run the moved native lifecycle cases on Windows x86-64 only."
  (assert (and (member :win32 *features*) (member :x86-64 *features*)))
  (let ((*windows-handoff-assertions* 0)
        (cases                        '(test-windows-detached-arguments test-windows-detached-descendants
                                        test-windows-detached-startup-failure test-windows-detached-release)))
    (dolist (case cases)
      (funcall case)
      (format t "PASS ~A~%" case))
    (format t "~D cases, ~D assertions passed.~%" (length cases) *windows-handoff-assertions*))
  t)
