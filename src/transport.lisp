(in-package #:image-daemon)

(defclass transport nil
          ((rows :initarg :rows :initform 24 :accessor transport-rows :documentation
            "Current terminal height in cells.")
           (columns :initarg :columns :initform 80 :accessor transport-columns
            :documentation "Current terminal width in cells.")
           (started-p :initform nil :accessor transport-started-p :documentation
            "Whether transport input and output are active.")
           (interactive-p :initarg :interactive-p :initform nil :accessor
            transport-interactive-p :documentation
            "Whether a controlling input source is attached.")
           (styled-p :initarg :styled-p :initform nil :accessor transport-styled-p
            :documentation "Whether ANSI presentation is supported."))
          (:documentation
           "State and protocol for an interactive transport, independent of a UI."))

(defgeneric transport-start
    (transport)
  (:documentation "Start TRANSPORT and return it."))

(defgeneric transport-stop
    (transport)
  (:documentation "Stop TRANSPORT and restore its terminal modes, returning it."))

(defgeneric transport-write
    (transport text)
  (:documentation "Write trusted TEXT to TRANSPORT, preserving output order."))

(defgeneric transport-flush
    (transport)
  (:documentation "Flush pending transport output."))

(defgeneric transport-input-ready-p
    (transport)
  (:documentation "Return true when a semantic input event is ready."))

(defgeneric transport-read-event
    (transport)
  (:documentation "Read a semantic event, or return :STREAM-END after closure."))

(defgeneric transport-set-dimensions
    (transport columns &key rows)
  (:documentation "Set TRANSPORT's terminal cell dimensions."))

(defmethod transport-set-dimensions ((transport transport) columns &key rows)
  (setf (transport-columns transport) columns)
  (when rows (setf (transport-rows transport) rows))
  nil)

(defgeneric transport-resize
    (transport &key rows columns styled-p)
  (:documentation "Apply controlling-client geometry and styling to TRANSPORT."))

(defmethod transport-resize ((transport transport) &key rows columns styled-p)
  (setf (transport-interactive-p transport) t
        (transport-styled-p transport) (not (null styled-p)))
  (transport-set-dimensions transport columns :rows rows))
