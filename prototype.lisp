(defpackage #:prototype
  (:export #:KEM-Encaps
           #:HDK #:*ID*
           #:make-unit #:activate #:prove-possession #:request #:accept
           #:make-reader #:pk #:verify
           #:make-document)
  (:use #:common-lisp)
  (:import-from #:crypto
   #:+secp256r1-l+ #:+secp256r1-g+ #:EC-Scalar-Mult #:EC-Point-Equal))

(in-package #:prototype)

(defun || (&rest bs) (apply #'concatenate '(vector (unsigned-byte 8)) bs))
(defun I2OSP (i n) (crypto:integer-to-octets i :n-bits (* n 8)))
(defun OS2IP (os) (crypto:octets-to-integer os))
(defun strxor (s1 s2) (map 'crypto::simple-octet-vector #'logxor s1 s2))
(defun ASCII (s) (crypto:ascii-string-to-byte-array s))
(defun read-bytes (&rest hex-strings)
  (read-from-string (apply #'concatenate 'string "#x" hex-strings)))

(defun H (&rest bs) (loop with hash = (crypto:make-digest :sha256)
                          for b in bs do (crypto:update-digest hash b)
                          finally (return (crypto:produce-digest hash))))
(defun expand_message_xmd (msg dst len)
  (loop with dst = (|| dst (I2OSP (length dst) 1))
        with b = (make-array len :fill-pointer 0)
        with b0 = (H (I2OSP 0 64) msg (I2OSP len 2) (I2OSP 0 1) dst)
        for i from 1 upto (ceiling (/ len 32))
        for bi = (H b0 (I2OSP 1 1) dst) then (H (strxor b0 bi) (I2OSP i 1) dst)
        do (loop for j across bi do (vector-push j b))
        finally (return (coerce b 'crypto::simple-octet-vector))))

(defparameter *q* nil)
(defparameter *DST* nil)
(defun hash_to_field (msg) (mod (OS2IP (expand_message_xmd msg *DST* 48)) *q*))

(defparameter *ID* (ASCII "HDK-ECDH-P256-v1"))

(defparameter *EC* :secp256r1)
(defun EC-Order () +secp256r1-l+)
(defun EC-Random () (1+ (crypto:strong-random (1- (EC-Order)))))
(defun EC-Scalar-Base-Mult (k) (EC-Scalar-Mult +secp256r1-g+ k))

(defun BL-Generate-Blinding-Key-Pair ()
  (let ((sk (EC-Random))) (values (EC-Scalar-Base-Mult sk) sk)))
(defun BL-Derive-Blinding-Factor (msg ctx)
  (let ((*DST* (|| *ID* ctx)) (*q* (EC-Order))) (hash_to_field msg)))
(defun BL-Blind-Public-Key (pk bf) (EC-Scalar-Mult pk bf))
(defun BL-Blind-Private-Key (sk bf) (mod (* sk bf) (EC-Order)))
(defun BL-Combine-Blinding-Factors (bf1 bf2) (mod (* bf1 bf2) (EC-Order)))

(defun ECDH-Create-Shared-Secret (sk pk)
  (I2OSP (getf (crypto:ec-destructure-point (EC-Scalar-Mult pk sk)) :x) 32))

(defun HMAC-SHA256 (key &rest bs)
  (loop with mac = (crypto:make-mac :hmac key :sha256)
        for b in bs do (crypto:update-mac mac b)
        finally (return (crypto:produce-mac mac))))

(defun HKDF-Extract (salt ikm) (HMAC-SHA256 salt ikm))
(defun HKDF-Expand (prk info len)
  (loop with tb = (make-array len :fill-pointer 0)
        for i from 1 upto (ceiling (/ len 32))
        for ti = (HMAC-SHA256 prk (|| info (I2OSP i 1)))
          then (HMAC-SHA256 prk (|| ti info (I2OSP i 1)))
        do (loop for j across ti do (vector-push j tb))
        finally (return (coerce tb '(vector (unsigned-byte 8))))))

(defun ECP2OS (point)
  (|| (I2OSP (getf (crypto:ec-destructure-point point) :x) 32)
      (I2OSP (getf (crypto:ec-destructure-point point) :y) 32)))
(defun OS2ECP (b)
  (crypto:ec-make-point
   *EC* :x (OS2IP (subseq b 0 32)) :y (OS2IP (subseq b 32))))

(defun KEM-Derive-Key-Pair (msg ctx) ; TODO #80
  (let* ((*DST* (|| *ID* '(#x01) ctx))
	 (*q* (EC-Order))
	 (sk (hash_to_field msg)))
    (values (EC-Scalar-Base-Mult sk) sk)))
(defun KEM-Encaps (pk ctx)
  (let* ((sk-prime (EC-Random))
         (pk-prime (EC-Scalar-Base-Mult sk-prime))
         (k-prime (ECDH-Create-Shared-Secret sk-prime pk))
	 (prk (HKDF-Extract (I2OSP 0 32) k-prime)))
    (values (HKDF-Expand prk (|| (ASCII "TMPKEM") ctx) 32) (ECP2OS pk-prime))))
(defun KEM-Decaps (sk c ctx)
  (let* ((pk-prime (OS2ECP c))
	 (k-prime (ECDH-Create-Shared-Secret sk pk-prime))
	 (prk (HKDF-Extract (I2OSP 0 32) k-prime)))
    (HKDF-Expand prk (|| (ASCII "TMPKEM") ctx) 32)))

(defun Authenticate (sk_device reader_data bf)
  (ECDH-Create-Shared-Secret sk_device (EC-Scalar-Mult reader_data bf)))

(defun H1 (msg) (H *ID* msg))
(defparameter *Ns* 32)
(defun HDK (salt index)
  (let ((msg (|| salt (I2OSP index 4))))
    (values (BL-Derive-Blinding-Factor msg *ID*) (H1 msg))))

(defun fold (salt path &optional bf)
  (cond ((null path) (values bf salt))
	((typep (car path) 'number)
	 (multiple-value-bind (bf-prime salt) (HDK salt (car path))
	   (if (null bf) (fold salt (cdr path) bf-prime)
	       (fold salt (cdr path)
		     (BL-Combine-Blinding-Factors bf bf-prime)))))
	(t (multiple-value-bind (pk sk) (KEM-Derive-Key-Pair salt *ID*)
             (declare (ignore pk))
             (fold (KEM-Decaps sk (car path) *ID*) (cdr path) bf)))))

(defclass document () ((pk :reader pk :initarg :pk)))
(defun make-document (doc salt index)
  (make-instance 'document
                 :pk (BL-Blind-Public-Key (pk doc) (HDK salt index))))

(defclass app ()
  ((device :reader device
           :initform (multiple-value-list (BL-Generate-Blinding-Key-Pair)))
   (seed :reader seed :initform (crypto:random-data *Ns*))))
(defun make-app () (make-instance 'app))
(defun pk-device (app) (car (device app)))
(defun get-key-info (app hdk)
  (let ((pk (BL-Blind-Public-Key (pk-device app) (fold (seed app) hdk))))
    (values pk '(:agree-key) (make-instance 'document :pk pk))))
(defun create-shared-secret (app hdk reader-pk)
  (Authenticate (cadr (device app)) reader-pk (fold (seed app) hdk)))
(defun delegate-key-creation (app hdk)
  (KEM-Derive-Key-Pair (nth-value 1 (fold (seed app) hdk)) *ID*))
(defun accept-key (app hdk kh index pk-expected)
  (multiple-value-bind (pk sk) (delegate-key-creation app hdk)
    (declare (ignore pk))
    (let ((salt (KEM-Decaps sk kh *ID*))
          (pk-bl (get-key-info app hdk)))
      (assert (EC-Point-Equal
               pk-expected
               (BL-Blind-Public-Key pk-bl (HDK salt index))))
      (append hdk (list kh index)))))

(defconstant +hdk-root+ '(0))
(defclass unit ()
  ((app :reader app :initform (make-app))
   (index :reader index :initform (make-hash-table :weakness :key))))
(defmacro unit-hdk (unit doc) (list 'gethash doc (list 'index unit)))
(defun make-unit () (make-instance 'unit))
(defun activate (unit)
  (multiple-value-bind (pk purposes doc) (get-key-info (app unit) +hdk-root+)
    (declare (ignore pk purposes))
    (setf (unit-hdk unit doc) +hdk-root+)
    doc))
(defun prove-possession (unit doc reader-data)
  (create-shared-secret (app unit) (unit-hdk unit doc) reader-data))
(defun request (unit doc-parent)
  (delegate-key-creation (app unit) (unit-hdk unit doc-parent)))
(defun accept (unit doc-parent kh index doc)
  (let* ((hdk (unit-hdk unit doc-parent))
         (app (app unit)))
    (setf (unit-hdk unit doc) (accept-key app hdk kh index (pk doc)))))

(defclass reader () ((sk :reader sk :initform (EC-Random))))
(defun make-reader () (make-instance 'reader))
(defun verify (reader doc device-data)
  (= (OS2IP device-data)
     (OS2IP (ECDH-Create-Shared-Secret (sk reader) (pk doc)))))
(defmethod pk ((reader reader)) (EC-Scalar-Base-Mult (sk reader)))

(loop with vectors =
      `((""
	 "QUUX-V01-CS02-with-expander-SHA256-128" #x20
	 ,(read-bytes
	   "68a985b87eb6b46952128911f2a4412bbc302a9d759667f87f7a21d803f07235"))
        ("abc"
	 "QUUX-V01-CS02-with-expander-SHA256-128" #x20
	 ,(read-bytes
	   "d8ccab23b5985ccea865c6c97b6e5b8350e794e603b4b97902f53a8a0d605615"))
        (""
	 "QUUX-V01-CS02-with-expander-SHA256-128" #x80
	 ,(read-bytes
	   "af84c27ccfd45d41914fdff5df25293e221afc53d8ad2ac06d5e3e29485dadbe"
	   "e0d121587713a3e0dd4d5e69e93eb7cd4f5df4cd103e188cf60cb02edc3edf18"
	   "eda8576c412b18ffb658e3dd6ec849469b979d444cf7b26911a08e63cf31f9dc"
	   "c541708d3491184472c2c29bb749d4286b004ceb5ee6b9a7fa5b646c993f0ced"
           )))
      for (msg dst len result) in vectors
      do (assert (= (OS2IP (expand_message_xmd (ASCII msg) (ASCII dst) len))
                    result)))

(assert
 (let* ((prk
          (HKDF-Extract
           (I2OSP #x000102030405060708090a0b0c 13)
           (I2OSP #x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b 22)))
        (okm (HKDF-Expand prk (I2OSP #xf0f1f2f3f4f5f6f7f8f9 10) 42)))
   (and
    (= (OS2IP prk)
       #x077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5)
    (= (OS2IP okm)
       (read-bytes
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34"
        "007208d5b887185865")))))

(assert (multiple-value-bind (pk sk) (KEM-Derive-Key-Pair
				      (I2OSP #x01 4)
				      (I2OSP #x02 4))
	  (multiple-value-bind (k c) (KEM-Encaps pk (ASCII "info"))
	    (= (OS2IP k) (OS2IP (KEM-Decaps sk c (ASCII "info")))))))

(let* ((app (make-app))
       (pk-bl (get-key-info app +hdk-root+))
       (pk-kem (delegate-key-creation app +hdk-root+)))
  (multiple-value-bind (salt kh) (KEM-Encaps pk-kem *ID*)
    (let ((pk-expected (BL-Blind-Public-Key pk-bl (HDK salt 0))))
      (accept-key app +hdk-root+ kh 0 pk-expected))))

(let* ((unit (make-unit))
       (doc (activate unit)))
  (let* ((reader (make-reader))
         (device-data (prove-possession unit doc (pk reader))))
    (assert (verify reader doc device-data)))
  (let ((pk-kem (request unit doc)))
    (multiple-value-bind (salt kh) (KEM-Encaps pk-kem *ID*)
      (let* ((range '(0 1 2 3 4 5 6 7 8))
             (docs (loop for i in range collect (make-document doc salt i))))
        (loop for i in range for d in docs do (accept unit doc kh i d))
        (assert (= 9 (length docs)))
        (loop for doc in docs do
          (let* ((reader (make-reader))
                 (device-data (prove-possession unit doc (pk reader))))
            (assert (verify reader doc device-data))))))))

(format t "Tests ran successfully~%")
