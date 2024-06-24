(defpackage #:demo (:use #:common-lisp #:prototype))
(in-package #:demo)

(defvar *wallet* (make-unit))
(defvar *evidence* (activate *wallet*))

;; Present wallet trust evidence to the PID provider
(let* ((reader (make-reader))
       (device-data (prove-possession *wallet* *evidence* (pk reader))))
  (assert (verify reader *evidence* device-data)))

;; Request issuance using remote key derivation
(defvar *pk-kem* (request *wallet* *evidence*))

;; Create a key handle and issue a first batch of PID
(defvar *kh*)
(defvar *pid*)
(multiple-value-bind (salt kh) (KEM-Encaps *pk-kem* *ID*)
  (setf *kh* kh)
  (setf *pid* (loop for i in '(0 1 2 3)
                    collect (make-document *evidence* salt i))))

;; Accept the first batch of PID, using synchronised indices
;; (synchronisation is implicit: easy upon first batch)
(loop for i in '(0 1 2 3)
      for doc in *pid*
      do (accept *wallet* *evidence* *kh* i doc))

;; Present PID to various readers
(loop for doc in *pid* do
  (let* ((reader (make-reader))
         (device-data (prove-possession *wallet* doc (pk reader))))
    (assert (verify reader doc device-data))))

(format t "Demo finished~%")
