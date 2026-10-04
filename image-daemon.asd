(asdf:defsystem #:image-daemon
  :description "Authenticated loopback control endpoints for Lisp image daemons."
  :author "Lambda Symbolics OÜ"
  :license "COLL-Attribution"
  :version "0.1.0"
  :serial t
  :depends-on (#:idsmall #:ironclad #:sb-bsd-sockets)
  :components ((:module "src"
                :serial t
                :components ((:file "package") (:file "protocol"))))
  :in-order-to ((asdf:test-op (asdf:test-op #:image-daemon/tests))))

(asdf:defsystem #:image-daemon/runtime
  :description "Persistent local services, discovery and terminal attachment."
  :depends-on (#:image-daemon #:sb-posix #:sexp-store #:ls-flock #:ls-compat/posix
               #:bordeaux-threads #:structlisp #:serapeum)
  :serial t
  :components ((:module "src"
                :serial t
                :components ((:file "registry")
                             (:file "threads")
                             (:file "transport")
                             (:file "attachment")
                             (:file "runtime")
                             (:file "client")
                             (:file "handoff"))))
  :in-order-to ((asdf:test-op (asdf:test-op #:image-daemon/tests))))

(asdf:defsystem #:image-daemon/eval
  :description "Authenticated evaluation endpoints for trusted local programs."
  :depends-on (#:image-daemon #:sb-posix #:sexp-config #:sexp-store #:ls-compat/posix
               #:structlisp #:trivial-gray-streams)
  :serial t
  :components ((:module "src"
                :serial t
                :components ((:file "eval"))))
  :in-order-to ((asdf:test-op (asdf:test-op #:image-daemon/tests))))

(asdf:defsystem #:image-daemon/tests
  :description "Tests for image-daemon."
  :depends-on (#:image-daemon/runtime #:image-daemon/eval #:flexi-streams)
  :serial t
  :components ((:module "tests"
                :serial t
                :components ((:file "tests")
                             (:file "thread-tests")
                             (:file "runtime-tests")
                             (:file "attachment-tests")
                             (:file "handoff-tests")
                             (:file "eval-tests"))))
  :perform (asdf:test-op (operation component)
             (declare (ignore operation component))
             (uiop:symbol-call '#:image-daemon/tests '#:run-tests)))
