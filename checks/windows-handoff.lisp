;;; Native Windows CI uses Quicklisp and the exact Git refs in qlfile.

(require :asdf)
(assert (and (member :win32 *features*) (member :x86-64 *features*)))
(load (merge-pathnames "quicklisp/setup.lisp" (user-homedir-pathname)))

(ql-dist:install-dist "http://beta.quicklisp.org/dist/quicklisp/2026-01-01/distinfo.txt"
                      :replace t :prompt nil)

(let* ((root         (uiop:getcwd))
       (dependencies (merge-pathnames ".ci/dependencies/" root)))
  (ensure-directories-exist dependencies)
  (with-open-file (stream (merge-pathnames "qlfile" root))
    (loop for line = (read-line stream nil)
          while line
          for fields = (remove "" (uiop:split-string (string-right-trim '(#\Return) line)
                                                    :separator '(#\Space))
                               :test #'string=)
          when (equal (first fields) "git")
            do (destructuring-bind (kind name url option ref) fields
                 (declare (ignore kind))
                 (assert (string= option ":ref"))
                 (let ((directory (merge-pathnames (format nil "~A/" name) dependencies)))
                   (uiop:run-program (list "git" "clone" "--quiet" url (namestring directory))
                                     :output t :error-output t)
                   (uiop:run-program (list "git" "checkout" "--quiet" "--detach" ref)
                                     :directory directory :output t :error-output t)))))
  (asdf:initialize-source-registry
   `(:source-registry (:directory ,root) (:tree ,dependencies) :ignore-inherited-configuration))
  (asdf:load-asd (merge-pathnames "image-daemon.asd" root))
  (assert (equal root (asdf:system-source-directory "image-daemon")))
  (ql:quickload "image-daemon/windows-handoff-tests")
  (assert (equal root (asdf:system-source-directory "image-daemon")))
  (asdf:test-system "image-daemon/windows-handoff-tests"))
