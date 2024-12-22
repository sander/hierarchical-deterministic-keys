(ql:quickload "ironclad")

(defpackage :prototype
  (:use :common-lisp)
  (:import-from :crypto :+secp256r1-l+ :+secp256r1-g+ :EC-Scalar-Mult))

(in-package :prototype)

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
        for bi = (H b0 (I2OSP 1 1) dst)
          then (H (strxor b0 bi) (I2OSP i 1) dst)
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
  (let ((*DST* (|| *ID* ctx)) (*q* (EC-Order)))
    (hash_to_field msg)))
(defun BL-Blind-Public-Key (pk bf) (EC-Scalar-Mult pk bf))
(defun BL-Blind-Private-Key (sk bf) (mod (* sk bf) (EC-Order)))
(defun BL-Combine-Blinding-Factors (bf1 bf2) (mod (* bf1 bf2) (EC-Order)))

(defun ECDH-Create-Shared-Secret (sk pk)
  (crypto:ec-encode-scalar
   *EC* (getf (crypto:ec-destructure-point (EC-Scalar-Mult pk sk)) :x)))

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
        finally (return (coerce tb 'crypto::simple-octet-vector))))

(defun KEM-Derive-Key-Pair (msg ctx) ; TODO #80
  (let* ((*DST* (|| *ID* '(#x01) ctx))
	 (*q* (EC-Order))
	 (sk (hash_to_field msg)))
    (values (EC-Scalar-Base-Mult sk) sk)))
(defun KEM-Encaps (pk ctx)
  (multiple-value-bind (sk-prime pk-prime) (crypto:generate-key-pair *EC*)
    (let* ((k-prime (ECDH-Create-Shared-Secret
		     (crypto:ec-decode-scalar
		      *EC*
		      (getf (crypto:destructure-private-key sk-prime) :x))
		     pk))
	   (prk (HKDF-Extract (I2OSP 0 32) k-prime)))
      (values (HKDF-Expand prk (|| (ASCII "TMPKEM") ctx) 32) pk-prime))))
(defun KEM-Decaps (sk c ctx)
  (let* ((pk-prime (crypto:ec-decode-point
		    *EC*
		    (getf (crypto:destructure-public-key c) :y)))
	 (k-prime (ECDH-Create-Shared-Secret sk pk-prime))
	 (prk (HKDF-Extract (I2OSP 0 32) k-prime)))
    (HKDF-Expand prk (|| (ASCII "TMPKEM") ctx) 32)))

(defun Authenticate (sk_device reader_data bf)
  (let ((P-prime (EC-Scalar-Mult reader_data bf)))
    (ECDH-Create-Shared-Secret sk_device P-prime)))

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
	     (fold (KEM-Decaps sk (car path) *ID*) (cdr path) bf)))))
(defun delegate (salt path &optional bf)
  (multiple-value-bind (bf salt-prime) (fold salt path bf)
    (multiple-value-bind (pk) (KEM-Derive-Key-Pair salt-prime *ID*)
      pk)))

(assert
 (multiple-value-bind (bf salt) (fold (H1 (I2OSP #x01 1)) (list 1 2))
   (multiple-value-bind (pk sk) (KEM-Derive-Key-Pair salt *ID*)
     (multiple-value-bind (salt-issuer kh) (KEM-Encaps pk *ID*)
       (multiple-value-bind (bf-issuer salt-issuer-prime) (HDK salt-issuer 3)
	 (let ((salt-unit (KEM-Decaps sk kh *ID*)))
	   (multiple-value-bind (bf-unit salt-unit-prime) (HDK salt-unit 3)
	     (multiple-value-bind (bf-later salt-later)
		 (fold (H1 (I2OSP #x01 1)) (list 1 2 kh 3))
	       (and (= bf-issuer bf-unit)
		    (= (OS2IP salt-issuer) (OS2IP salt-unit))
		    (= (OS2IP salt-issuer-prime) (OS2IP salt-unit-prime))
		    (= (BL-Combine-Blinding-Factors bf bf-issuer)
		       bf-later))))))))))

(defclass unit ()
  ((seed :reader unit-seed :initform (crypto:random-data *Ns*))
   (device :reader unit-device
	   :initform (multiple-value-list (BL-Generate-Blinding-Key-Pair)))))
(defun unit-device-ecdh (u pk)
  (ECDH-Create-Shared-Secret (cdr (unit-device u)) pk))
			    
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
	   "c541708d3491184472c2c29bb749d4286b004ceb5ee6b9a7fa5b646c993f0ced")))
      for (msg dst len result) in vectors
      do (assert (= (OS2IP (expand_message_xmd (ASCII msg) (ASCII dst) len))
                    result)))

(assert (let* ((prk (HKDF-Extract (I2OSP #x000102030405060708090a0b0c 13)
                             (I2OSP #x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b 22)))
               (okm (HKDF-Expand prk (I2OSP #xf0f1f2f3f4f5f6f7f8f9 10) 42)))
          (and (= (OS2IP prk) #x077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5)
               (= (OS2IP okm) #x3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865))))

(assert (multiple-value-bind (pk sk) (KEM-Derive-Key-Pair
				      (I2OSP #x01 4)
				      (I2OSP #x02 4))
	  (multiple-value-bind (k c) (KEM-Encaps pk (ASCII "info"))
	    (= (OS2IP k) (OS2IP (KEM-Decaps sk c (ASCII "info")))))))
