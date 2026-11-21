(in-package #:image-daemon/tests)

(-> registry-test--decode (string &key (:maximum-octets (integer 1)) (:extension-keywords list)) list)
(defun registry-test--decode (text &key (maximum-octets 65536) extension-keywords)
  "Decode UTF-8 TEXT through the public already-open stream API."
  (with-open-stream (stream (flexi-streams:make-in-memory-input-stream
                             (ls-compat:utf8-string-to-octets text)))
    (image-daemon:daemon-registry-read-stream stream
                                           :maximum-octets     maximum-octets
                                           :extension-keywords extension-keywords)))

(-> test-registry-stream-decoder () t)
(defun test-registry-stream-decoder ()
  "Check bounded exact-one decoding, schema validation and stream ownership."
  (let* ((record (daemon-registry-record :identifier "session-λ" :token "capability"
                                         :port 12345 :created-at 1))
         (text   (with-standard-io-syntax (write-to-string record)))
         (octets (ls-compat:utf8-string-to-octets text)))
    (check (equal record (registry-test--decode text)) "registry record round trip")
    (check (equal record (registry-test--decode (format nil " ~A~% ; done~%" text)))
           "one registry record permits trailing whitespace and line comments")
    (check (equal record (registry-test--decode text :maximum-octets (length octets)))
           "registry record accepts its exact UTF-8 byte ceiling")
    (check (null (registry-test--decode text :maximum-octets (1- (length octets))))
           "registry record rejects one byte beyond its ceiling")
    (dolist (bad (list "" " " "(" "nil" "(:localgroup-endpoint :version 9)"
                       (subseq text 0 (1- (length text)))
                       (concatenate 'string text " nil")
                       (concatenate 'string text text)
                       (substitute #\a #\1 text)))
      (check (null (registry-test--decode bad)) "invalid registry data rejected"))
    (let* ((extended (append record (list :fixture-resume-id "next")))
           (text     (with-standard-io-syntax (write-to-string extended))))
      (check (null (registry-test--decode text)) "extension keywords require explicit admission")
      (check (equal extended (registry-test--decode text :extension-keywords '(:fixture-resume-id)))
             "explicit extension keywords preserve the deployed record")
      (check (null (registry-test--decode (concatenate 'string text " nil")
                                         :extension-keywords '(:fixture-resume-id)))
             "extension admission still requires exactly one complete record"))
    (let ((wrong (copy-list record)))
      (setf (getf (rest wrong) :address) "192.0.2.1")
      (check (null (registry-test--decode (with-standard-io-syntax (write-to-string wrong))))
             "registry decoder retains loopback record schema"))
    (with-open-stream (stream (flexi-streams:make-in-memory-input-stream octets))
      (check (equal record (image-daemon:daemon-registry-read-stream stream))
             "decoder consumes the supplied binary stream")
      (check (open-stream-p stream) "decoder leaves caller stream open"))
    (with-open-stream (stream (flexi-streams:make-in-memory-input-stream
                               (make-array 100 :element-type    '(unsigned-byte 8)
                                               :initial-element 32)))
      (check (null (image-daemon:daemon-registry-read-stream stream :maximum-octets 16))
             "oversized registry stream rejected")
      (check (= (file-position stream) 17) "registry capture reads at most limit plus one octet"))
    (with-open-stream (stream (flexi-streams:make-in-memory-input-stream
                               (make-array 2 :element-type     '(unsigned-byte 8)
                                             :initial-contents '(195 40))))
      (check (null (image-daemon:daemon-registry-read-stream stream))
             "invalid UTF-8 registry record rejected"))))

(-> test-registry-stream-identity () t)
(defun test-registry-stream-identity ()
  "Decode the open object's record even after replacing its pathname."
  (let* ((root        (merge-pathnames (format nil "daemon-decoder-~A/" (daemon-random-nonce))
                                       (uiop:temporary-directory)))
         (path        (merge-pathnames "record.sexp" root))
         (replacement (merge-pathnames "replacement.sexp" root))
         (record      (daemon-registry-record :identifier "old" :token "old-token"
                                             :port 12345 :created-at 1))
         (next        (daemon-registry-record :identifier "new" :token "new-token"
                                             :port 23456 :created-at 2)))
    (unwind-protect
         (progn
           (ensure-directories-exist path)
           (sexp-store:snapshot-write path record)
           (sexp-store:snapshot-write replacement next)
           (with-open-file (stream path :element-type '(unsigned-byte 8))
             (uiop:rename-file-overwriting-target replacement path)
             (check (equal record (image-daemon:daemon-registry-read-stream stream))
                    "decoder uses original open object after pathname replacement")
             (check (open-stream-p stream) "identity decoding leaves handle ownership to caller"))
           (check (equal next (daemon-registry-read path)) "replacement record remains independent"))
      (uiop:delete-directory-tree root :validate t :if-does-not-exist :ignore))))
