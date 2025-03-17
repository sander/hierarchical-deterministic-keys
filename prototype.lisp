(defpackage #:prototype
  (:export #:kem #:encap
	   #:hdk
           #:make-unit #:activate #:prove-possession #:request #:accept
           #:make-reader #:pk #:verify
           #:make-document
	   #:+hdk-ecdh-p256+ #:+ecdh-p256+)
  (:use #:common-lisp)
  (:import-from #:crypto
   #:+secp256r1-l+ #:+secp256r1-g+ #:EC-Scalar-Mult #:EC-Point-Equal))

(in-package #:prototype)

(defun concat (&rest bs) (apply #'concatenate
                                '(vector (unsigned-byte 8)) bs))
(defun i2osp (i n) (crypto:integer-to-octets i :n-bits (* n 8)))
(defun os2ip (os) (crypto:octets-to-integer os))
(defun strxor (s1 s2) (map 'crypto::simple-octet-vector #'logxor s1 s2))
(defun ascii (s) (crypto:ascii-string-to-byte-array s))
(defun read-bytes (&rest hex-strings)
  (read-from-string (apply #'concatenate 'string "#x" hex-strings)))

(defclass ec () ((id :reader id :initarg :id)
                 (n :reader order :initarg :n)
                 (g :reader base :initarg :g)))
(defclass ec-kg (ec) ())

(defclass h () ((id :reader id :initarg :id)))
(defclass h2c () ((ec :reader ec :initarg :ec)
                  (h :reader hash :initarg :h)
                  (dst :reader dst :initarg :dst)))

(defclass dh () ((n-dh :reader output-length :initarg :n-dh)))
(defclass ec-dh (dh) ((ec :reader ec :initarg :ec)))

(defclass bl () ((id :reader id :initarg :id)))
(defclass ec-bl (bl) ((ec :reader ec :initarg :ec)
                      (h :reader hash :initarg :h)))
(defclass ec-bl-mul (ec-bl) ())
(defclass ec-bl-mul-dh (ec-bl-mul) ((ec-dh :reader ec-dh :initarg :ec-dh)))

(defclass hmac () ((id :reader id :initarg :id)))

(defclass hkdf () ((hmac :reader hmac :initarg :hmac)))

(defclass hdk () ((id :reader id :initarg :id)
                  (bl :reader bl :initarg :bl)
                  (kem :reader kem :initarg :kem)
                  (n-s :reader seed-length :initarg :n-s)
		  (h :reader hash :initarg :h)))

(defclass kem () ((n-secret :reader secret-length :initarg :n-secret)
                  (n-sk :reader private-key-length :initarg :n-sk)
                  (id :reader id :initarg :id)
                  (bitmask :reader bitmask :initarg :bitmask)))
(defclass dhkem (kem) ((dh :reader dh :initarg :dh)
                       (hkdf :reader hkdf :initarg :hkdf)))
(defclass ec-dhkem (dhkem) ((ec :reader ec :initarg :ec)))

(defmethod h ((h h) &rest bs)
  (loop with hash = (crypto:make-digest (id h))
        for b in bs do (crypto:update-digest hash b)
        finally (return (crypto:produce-digest hash))))
(defmethod expand-message-xmd ((h2c h2c) msg dst len)
  (loop with dst = (concat dst (i2osp (length dst) 1))
        with b = (make-array len :fill-pointer 0)
        with b0 = (h (hash h2c) (i2osp 0 64) msg (i2osp len 2) (i2osp 0 1) dst)
        for i from 1 upto (ceiling (/ len 32))
        for bi = (h (hash h2c) b0 (i2osp 1 1) dst)
        then (h (hash h2c) (strxor b0 bi) (i2osp i 1) dst)
        do (loop for j across bi do (vector-push j b))
        finally (return (coerce b 'crypto::simple-octet-vector))))
(defmethod hash-to-field ((h2c h2c) &rest msg)
  (mod (os2ip (expand-message-xmd h2c
                                  (apply #'concat msg) (dst h2c) 48))
       (order (ec h2c))))

(defmethod random-scalar ((ec ec)) (1+ (crypto:strong-random (1- (order ec)))))
(defmethod scalar-mult ((ec ec) el k) (crypto:ec-scalar-mult el k))
(defmethod scalar-base-mult ((ec ec) k) (scalar-mult ec +secp256r1-g+ k))

(defmethod generate-key-pair ((ec ec-kg))
  (let ((sk (random-scalar ec))) (values sk (scalar-base-mult ec sk))))
(defmethod serialize-public-key ((ec ec-kg) pk)
  (concat (i2osp (getf (crypto:ec-destructure-point pk) :x) 32)
          (i2osp (getf (crypto:ec-destructure-point pk) :y) 32)))
(defmethod deserialize-public-key ((ec ec-kg) b)
  (crypto:ec-make-point (id ec) :x (os2ip (subseq b 0 32))
                                :y (os2ip (subseq b 32))))

(defmethod create-shared-secret ((dh ec-dh) sk-x pk-y)
  (i2osp (getf (crypto:ec-destructure-point (scalar-mult (ec dh) pk-y sk-x)) :x)
         (output-length dh)))

(defmethod derive-blind-key ((bl ec-bl) ikm)
  (let ((h2c (make-instance 'h2c :ec (ec bl) :h (hash bl) :dst (id bl))))
    (i2osp (hash-to-field h2c ikm) 32)))
(defmethod derive-blinding-factor ((bl ec-bl) bk ctx)
  (let ((h2c (make-instance 'h2c :ec (ec bl) :h (hash bl) :dst (id bl))))
    (hash-to-field h2c bk '(#x00) ctx)))
(defmethod combine ((bl ec-bl-mul) bf1 bf2)
  (mod (* bf1 bf2) (order (ec bl))))
(defmethod blind-public-key ((bl ec-bl-mul) pk-s bk ctx)
  (scalar-mult (ec bl) pk-s (derive-blinding-factor bl bk ctx)))
(defmethod blind-dh ((bl ec-bl-mul-dh) sk-x bf pk-y)
  (create-shared-secret (ec-dh bl) sk-x (scalar-mult (ec bl) pk-y bf)))

(defmethod create-context ((hdk hdk) index) (concat (id hdk) (i2osp index 4)))
(defmethod derive-salt ((hdk hdk) salt ctx) (h (hash hdk) (id hdk) salt ctx))
(defmethod hdk-apply ((hdk hdk) index pk salt &optional bf)
  (let* ((bk (derive-blind-key (bl hdk) salt))
	 (ctx (create-context hdk index)))
    (values (blind-public-key (bl hdk) pk bk ctx)
	    (derive-salt hdk salt ctx)
	    (let ((bf2 (derive-blinding-factor (bl hdk) bk ctx)))
	      (if bf (combine (bl hdk) bf bf2) bf2)))))

(defmethod mac ((hmac hmac) key &rest bs)
  (loop with mac = (crypto:make-mac :hmac key (id hmac))
        for b in bs do (crypto:update-mac mac b)
        finally (return (crypto:produce-mac mac))))

(defmethod extract ((hkdf hkdf) salt ikm) (mac (hmac hkdf) salt ikm))
(defmethod expand ((hkdf hkdf) prk info len)
  (loop with tb = (make-array len :fill-pointer 0)
        for i from 1 upto (ceiling (/ len 32))
        for ti = (mac (hmac hkdf) prk (concat info (i2osp i 1)))
          then (mac (hmac hkdf) prk (concat ti info (i2osp i 1)))
        do (loop for j across ti do (vector-push j tb))
        finally (return (coerce tb '(vector (unsigned-byte 8))))))

(defmethod labeled-extract ((kem dhkem) salt label ikm)
  (extract (hkdf kem) salt (concat (ascii "HPKE-v1") (id kem)
                                   (ascii label) ikm)))
(defmethod labeled-expand ((kem dhkem) prk label info length)
  (expand (hkdf kem)
          prk
          (concat (i2osp length 2) (ascii "HPKE-v1") (id kem)
                  (ascii label) info)
          length))
(defmethod extract-and-expand ((kem kem) dh kem-context)
  (let ((eae-prk (labeled-extract kem (ascii "") "eae_prk" dh)))
    (labeled-expand
     kem eae-prk "shared_secret" kem-context (secret-length kem))))
(defmethod derive-key-pair ((kem ec-dhkem) ikm)
  (loop with dkp-prk = (labeled-extract kem (ascii "") "dkp_prk" ikm)
        for counter from 0 upto 254
        for bytes = (labeled-expand kem dkp-prk "candidate" (i2osp counter 1)
                                    (private-key-length kem))
        for sk = (progn
                   (setf (aref bytes 0) (logand (aref bytes 0) (bitmask kem)))
                   (os2ip bytes))
        when (not (= sk 0)) return (values sk (scalar-base-mult (ec kem) sk))))
(defmethod encap ((kem ec-dhkem) pk-r)
  (multiple-value-bind (sk-e pk-e) (generate-key-pair (ec kem))
    (let* ((dh (create-shared-secret (dh kem) sk-e pk-r))
           (enc (serialize-public-key (ec kem) pk-e))
           (pk-rm (serialize-public-key (ec kem) pk-r))
           (kem-context (concat enc pk-rm))
           (shared-secret (extract-and-expand kem dh kem-context)))
      (values shared-secret enc))))
(defmethod decap ((kem ec-dhkem) enc sk-r)
  (let* ((pk-e (deserialize-public-key (ec kem) enc))
         (dh (create-shared-secret (dh kem) sk-r pk-e))
         (pk-rm (serialize-public-key (ec kem)
                                      (scalar-base-mult (ec kem) sk-r)))
         (kem-context (concat enc pk-rm))
         (shared-secret (extract-and-expand kem dh kem-context)))
    shared-secret))

(defconstant +sha256+
  (make-instance 'h :id :sha256))
(defconstant +p256+
  (make-instance 'ec-kg :n +secp256r1-l+ :g +secp256r1-g+ :id :secp256r1))
(defconstant +ecdh-p256+
  (make-instance 'ec-dh :n-dh 32 :ec +p256+))
(defconstant +bl-ecdh-p256+
  (make-instance 'ec-bl-mul-dh :id (ascii "QUUX-V01-CS02-with-P256_XMD:SHA-256_SSWU_RO_")
                               :ec +p256+
                               :ec-dh +ecdh-p256+
                               :h +sha256+))
(defconstant +hmac-sha256+
  (make-instance 'hmac :id :sha256))
(defconstant +hkdf-sha256+
  (make-instance 'hkdf :hmac +hmac-sha256+))
(defconstant +dhkem-p256-hkdf-sha256+
  (make-instance 'ec-dhkem :id (concat (ascii "KEM") (i2osp #x0010 2))
                           :n-secret 32
                           :n-sk 32
                           :bitmask #xff
                           :dh +ecdh-p256+
                           :hkdf +hkdf-sha256+
                           :ec +p256+))
(defconstant +hdk-ecdh-p256+
  (make-instance 'hdk :id (ascii "HDK-ECDH-P256-v1")
                      :bl +bl-ecdh-p256+
                      :kem +dhkem-p256-hkdf-sha256+
                      :n-s 32
		      :h +sha256+))

(defmethod fold ((hdk hdk) path pk salt &optional bf)
  (cond ((null path) (values pk bf salt))
	((typep (car path) 'number)
	 (multiple-value-bind (pk salt bf)
	     (hdk-apply hdk (car path) pk salt bf)
	   (fold hdk (cdr path) pk salt bf)))
	(t (let* ((sk-r (derive-key-pair (kem hdk) salt))
                  (salt (decap (kem hdk) (car path) sk-r)))
             (fold hdk (cdr path) pk salt bf)))))

(defclass document () ((pk :reader pk :initarg :pk)))
(defun make-document (hdk doc salt index)
  (make-instance 'document :pk (hdk-apply hdk index (pk doc) salt)))

(defclass app ()
  ((hdk :reader hdk :initarg :hdk)
   (device :reader device :initarg :device)
   (seed :reader seed :initarg :seed)))
(defun make-app (hdk)
  (make-instance 'app
                 :hdk hdk
                 :device (multiple-value-list (generate-key-pair (ec (bl hdk))))
                 :seed (crypto:random-data (seed-length hdk))))
(defun sk-device (app) (car (device app)))
(defun pk-device (app) (cadr (device app)))
(defun fold-hdk (app hdk) (fold (hdk app) hdk (pk-device app) (seed app)))
(defun get-key-info (app hdk)
  (let ((pk (fold-hdk app hdk)))
    (values pk '(:agree-key) (make-instance 'document :pk pk))))
(defmethod create-shared-secret (app hdk reader-pk)
  (blind-dh (bl (hdk app))
	    (sk-device app)
            (nth-value 1 (fold-hdk app hdk))
            reader-pk))
(defun delegate-key-creation (app hdk)
  (derive-key-pair (kem (hdk app))
		   (nth-value 2 (fold-hdk app hdk))))
(defun accept-key (app hdk kh index pk-expected)
  (let* ((salt (decap (kem (hdk app)) kh (delegate-key-creation app hdk)))
         (pk (hdk-apply (hdk app) index (get-key-info app hdk) salt)))
    (assert (crypto:ec-point-equal pk-expected pk)))
  (append hdk (list kh index)))

(defconstant +hdk-root+ '(0))
(defclass unit ()
  ((app :reader app :initarg :app)
   (index :reader index :initform (make-hash-table :weakness :key))))
(defmacro unit-hdk (unit doc) (list 'gethash doc (list 'index unit)))
(defun make-unit (hdk) (make-instance 'unit :app (make-app hdk)))
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
(defmethod hdk ((unit unit)) (hdk (app unit)))
(defmethod kem ((unit unit)) (kem (hdk unit)))

(defclass reader ()
  ((sk :reader sk :initarg :sk)
   (dh :reader dh :initarg :dh)))
(defun make-reader (ec-dh)
  (make-instance 'reader :sk (random-scalar (ec ec-dh))
                         :dh ec-dh))
(defun verify (reader doc device-data)
  (= (os2ip device-data)
     (os2ip (create-shared-secret (dh reader) (sk reader) (pk doc)))))
(defmethod pk ((reader reader))
  (scalar-base-mult (ec (dh reader)) (sk reader)))

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
      do (assert
          (= (let ((h2c (make-instance 'h2c :ec +p256+
                                            :h +sha256+
                                            :dst dst)))
               (os2ip (expand-message-xmd h2c (ASCII msg) (ASCII dst) len))
               result))))

(assert
 (let* ((prk
          (extract +hkdf-sha256+
           (i2osp #x000102030405060708090a0b0c 13)
           (i2osp #x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b 22)))
        (okm (expand +hkdf-sha256+ prk (i2osp #xf0f1f2f3f4f5f6f7f8f9 10) 42)))
   (and
    (= (os2ip prk)
       #x077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5)
    (= (os2ip okm)
       (read-bytes
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34"
        "007208d5b887185865")))))

(assert
 (= (derive-key-pair +dhkem-p256-hkdf-sha256+
     (i2osp
      #x4270e54ffd08d79d5928020af4686d8f6b7d35dbe470265f1f5aa22816ce860e 32))
    #x4995788ef4b9d6132b249ce59a77281493eb39af373d236a1fe415cb0c2d7beb))

(assert (let ((kem +dhkem-p256-hkdf-sha256+))
          (multiple-value-bind (sk pk) (derive-key-pair kem (i2osp #x01 4))
	  (multiple-value-bind (k c) (encap kem pk)
	    (= (os2ip k) (os2ip (decap kem c sk)))))))

(let* ((bl +bl-ecdh-p256+)
       (ikm #(1 2 3))
       (bk (derive-blind-key bl ikm))
       (ctx #(4 5 6))
       (bf (derive-blinding-factor bl bk ctx)))
  (multiple-value-bind (sk-x pk-x) (generate-key-pair (ec bl))
    (multiple-value-bind (sk-y pk-y) (generate-key-pair (ec bl))
      (assert (= (os2ip (blind-dh bl sk-x bf pk-y))
		 (let ((pk-blinded (blind-public-key bl pk-x bk ctx)))
		   (os2ip (create-shared-secret
			   (ec-dh bl) sk-y pk-blinded))))))))

(let* ((bl +bl-ecdh-p256+)
       (ikm #(1 2 3))
       (bk (derive-blind-key bl ikm))
       (ctx1 #(4 5 6))
       (ctx2 #(7 8 9))
       (bf1 (derive-blinding-factor bl bk ctx1))
       (bf2 (derive-blinding-factor bl bk ctx2)))
  (multiple-value-bind (sk pk) (generate-key-pair (ec bl))
    (assert (= (os2ip
		(create-shared-secret
		 (ec-dh bl) 1
		 (blind-public-key bl
				   (blind-public-key bl pk bk ctx1)
				   bk ctx2)))
	       (os2ip
		(blind-dh
		 bl sk
		 (combine bl bf1 bf2)
		 +secp256r1-g+))))))

(let* ((app (make-app +hdk-ecdh-p256+))
       (hdk +hdk-root+)
       (pk-bl (get-key-info app hdk))
       (pk-kem (nth-value 1 (delegate-key-creation app hdk))))
  (multiple-value-bind (salt kh) (encap (kem (hdk app)) pk-kem)
    (let* ((bk (derive-blind-key (bl (hdk app)) salt))
	   (index 42)
	   (ctx (create-context (hdk app) index))
           (pk-expected (blind-public-key (bl (hdk app)) pk-bl bk ctx)))
      (accept-key app hdk kh index pk-expected))))

(let* ((unit (make-unit +hdk-ecdh-p256+))
       (doc (activate unit)))
  (let* ((reader (make-reader +ecdh-p256+))
         (device-data (prove-possession unit doc (pk reader))))
    (assert (verify reader doc device-data)))
  (let ((pk-kem (request unit doc)))
    (multiple-value-bind (salt kh) (encap (kem (hdk (app unit))) pk-kem)
      (let* ((range '(0 1 2 3 4 5 6 7 8))
             (docs (loop for i in range
			 collect (make-document (hdk (app unit)) doc salt i))))
        (loop for i in range for d in docs do (accept unit doc kh i d))
        (assert (= 9 (length docs)))
        (loop for doc in docs do
          (let* ((reader (make-reader +ecdh-p256+))
                 (device-data (prove-possession unit doc (pk reader))))
            (assert (verify reader doc device-data))))))))

(format t "Tests ran successfully~%")

(let* ((hdk +hdk-ecdh-p256+)
       (ec (ec (bl hdk)))
       (ikm-e (i2osp #x4270e54ffd08d79d5928020af4686d8f6b7d35dbe470265f1f5aa22816ce860e 32))
       (pk-em-b (i2osp #x04a92719c6195d5085104f469a8b9814d5838ff72b60501e2c4466e5e67b325ac98536d7b61a1af4b78e5b7f951c0900be863c403ce65c9bfcb9382657222d18c4 64))
       (pk-em (deserialize-public-key ec pk-em-b)))
  (flet ((render (desc pk) (format t "~a compressed: ~a~%" desc (crypto:byte-array-to-hex-string (serialize-public-key-compressed ec pk)))))
    (render "loc mul index=0 pk=pkEm salt=ikmE" (hdk-apply hdk 0 pk-em ikm-e))
    (render "loc mul index=1 pk=pkEm salt=ikmE" (hdk-apply hdk 1 pk-em ikm-e))))
(defconstant +ikm-e+ (i2osp #x4270e54ffd08d79d5928020af4686d8f6b7d35dbe470265f1f5aa22816ce860e 32))

(let* ((x (i2osp #x010203 3)))
  (setf (elt x 0) 4)
  x)
(defmethod serialize-public-key-compressed ((ec ec-kg) pk)
  (let* ((pk (crypto:ec-destructure-point pk))
         (res (i2osp (getf pk :x) 32)))
    (setf (elt res 0) (if (evenp (getf pk :y)) #x02 #x03))
    res))
            
(let* ((pk (deserialize-public-key +p256+ (i2osp #xb7aaadbe51ec7857da59df38e10574f45e2282623b3457749b31762e3605f8c00db6cf3370b2f3d53612accd8864208e91896184499feb602b69837079592e00 64))))
  (serialize-public-key-compressed +p256+ pk))
  ;;(pk (crypto:ec-destructure-point pk)))
  ;;(crypto:byte-array-to-hex-string (serialize-public-key +p256+ pk))
;;  (evenp (getf pk :y)))
