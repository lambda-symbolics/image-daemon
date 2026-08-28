(asdf:defsystem #:image-daemon
  :description "Authenticated loopback control endpoints for Lisp image daemons."
  :author "Lambda Symbolics OÜ"
  :license "COLL-Attribution"
  :version "0.1.0"
  :serial t
  :depends-on (#:idsmall
               #:ironclad
               #:sb-bsd-sockets)
  :components ((:module "src"
                :serial t
                :components ((:file "package")
                             (:file "protocol"))))
  :in-order-to ((asdf:test-op (asdf:test-op #:image-daemon/tests))))

(asdf:defsystem #:image-daemon/tests
  :description "Tests for image-daemon."
  :depends-on (#:image-daemon
               #:sb-posix)
  :serial t
  :components ((:module "tests"
                :serial t
                :components ((:file "tests"))))
  :perform (asdf:test-op (operation component)
             (declare (ignore operation component))
             (uiop:symbol-call '#:image-daemon/tests '#:run-tests)))
