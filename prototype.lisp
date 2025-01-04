(defpackage #:prototype
  (:export #:KEM-Encap
           #:HDK
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

;; RFC 9180, DHKEM(P-256, HKDF-SHA256)
(defparameter *Nsecret* 32)
(defparameter *Nsk* 32)
(defparameter *suite_id* (|| (ASCII "KEM") (I2OSP #x0010 2)))
(defparameter *bitmask* #xff)
(labels
    ((labeled-extract (salt label ikm)
       (HKDF-Extract salt (|| (ASCII "HPKE-v1") *suite_id* (ASCII label) ikm)))
     (labeled-expand (prk label info L)
       (HKDF-Expand prk (|| (I2OSP L 2) (ASCII "HPKE-v1")
                            *suite_id* (ASCII label) info)
                    L))
     (extract-and-expand (dh kem_context)
       (let* ((eae_prk (labeled-extract (ASCII "") "eae_prk" dh))
              (shared_secret
                (labeled-expand eae_prk "shared_secret" kem_context *Nsecret*)))
         shared_secret))
     (generate-key-pair ()
       (let ((sk (EC-Random))) (values sk (EC-Scalar-Base-Mult sk))))
     (serialize-public-key (pk)
       (|| (I2OSP (getf (crypto:ec-destructure-point pk) :x) 32)
           (I2OSP (getf (crypto:ec-destructure-point pk) :y) 32)))
     (deserialize-public-key (b)
       (crypto:ec-make-point *EC* :x (OS2IP (subseq b 0 32))
                                  :y (OS2IP (subseq b 32)))))
  (defun KEM-Derive-Key-Pair (ikm)
    (loop with dkp_prk = (labeled-extract (ASCII "") "dkp_prk" ikm)
          for counter from 0 upto 254
          for bytes
            = (labeled-expand dkp_prk "candidate" (I2OSP counter 1) *Nsk*)
          for sk = (progn
                     (setf (aref bytes 0) (logand (aref bytes 0) *bitmask*))
                     (OS2IP bytes))
          when (not (= sk 0)) return (values sk (EC-Scalar-Base-Mult sk))))
  (defun KEM-Encap (pkR)
    (multiple-value-bind (skE pkE) (generate-key-pair)
      (let* ((dh (ECDH-Create-Shared-Secret skE pkR))
             (enc (serialize-public-key pkE))
             (pkRm (serialize-public-key pkR))
             (kem_context (|| enc pkRm))
             (shared_secret (extract-and-expand dh kem_context)))
        (values shared_secret enc))))
  (defun KEM-Decap (enc skR)
    (let* ((pkE (deserialize-public-key enc))
           (dh (ECDH-Create-Shared-Secret skR pkE))
           (pkRm (serialize-public-key (EC-Scalar-Base-Mult skR)))
           (kem_context (|| enc pkRm))
           (shared_secret (extract-and-expand dh kem_context)))
      shared_secret)))

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
           (fold salt (cdr path)
                 (if (null bf) bf-prime
                     (BL-Combine-Blinding-Factors bf bf-prime)))))
	(t (fold (KEM-Decap (car path) (KEM-Derive-Key-Pair salt)) (cdr path)
                 bf))))

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
  (KEM-Derive-Key-Pair (nth-value 1 (fold (seed app) hdk))))
(defun accept-key (app hdk kh index pk-expected)
  (multiple-value-bind (sk pk) (delegate-key-creation app hdk)
    (declare (ignore pk))
    (let ((salt (KEM-Decap kh sk))
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
  (nth-value 1 (delegate-key-creation (app unit) (unit-hdk unit doc-parent))))
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

(assert
 (= (KEM-Derive-Key-Pair
     (I2OSP
      #x4270e54ffd08d79d5928020af4686d8f6b7d35dbe470265f1f5aa22816ce860e 32))
    #x4995788ef4b9d6132b249ce59a77281493eb39af373d236a1fe415cb0c2d7beb))

(assert (multiple-value-bind (sk pk) (KEM-Derive-Key-Pair (I2OSP #x01 4))
	  (multiple-value-bind (k c) (KEM-Encap pk)
	    (= (OS2IP k) (OS2IP (KEM-Decap c sk))))))

(let* ((app (make-app))
       (pk-bl (get-key-info app +hdk-root+))
       (pk-kem (nth-value 1 (delegate-key-creation app +hdk-root+))))
  (multiple-value-bind (salt kh) (KEM-Encap pk-kem)
    (let ((pk-expected (BL-Blind-Public-Key pk-bl (HDK salt 0))))
      (accept-key app +hdk-root+ kh 0 pk-expected))))

(let* ((unit (make-unit))
       (doc (activate unit)))
  (let* ((reader (make-reader))
         (device-data (prove-possession unit doc (pk reader))))
    (assert (verify reader doc device-data)))
  (let ((pk-kem (request unit doc)))
    (multiple-value-bind (salt kh) (KEM-Encap pk-kem)
      (let* ((range '(0 1 2 3 4 5 6 7 8))
             (docs (loop for i in range collect (make-document doc salt i))))
        (loop for i in range for d in docs do (accept unit doc kh i d))
        (assert (= 9 (length docs)))
        (loop for doc in docs do
          (let* ((reader (make-reader))
                 (device-data (prove-possession unit doc (pk reader))))
            (assert (verify reader doc device-data))))))))

(format t "Tests ran successfully~%")
