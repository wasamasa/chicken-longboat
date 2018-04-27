(use srfi-1 srfi-4 srfi-13 data-structures aes uri-common)

(define (random-bytes count) (list-tabulate count (lambda (_) (random 256))))

(define (pkcs7pad bytes block-size)
  (when (not (< block-size 256))
    (error "invalid block size"))
  (let ((padding-size (- block-size (modulo (length bytes) block-size))))
    (append bytes (make-list padding-size padding-size))))

(define (pkcs7unpad bytes)
  (let ((padding-size (last bytes))
        (size (length bytes)))
    (when (not (<= 0 padding-size 255))
      (error "invalid padding"))
    (receive
     (unpadded padding)
     (split-at bytes (- size padding-size))
     (when (not (every (lambda (b) (= b padding-size)) padding))
       (error "invalid padding"))
     unpadded)))

(define (xor-bytes bytes1 bytes2)
  (when (not (= (length bytes1) (length bytes2)))
    (error "buffers must be of equal length"))
  (map bitwise-xor bytes1 bytes2))

(define list->blob (o u8vector->blob list->u8vector))
(define blob->list (o u8vector->list blob->u8vector))

(define (wrap-aes constructor key)
  (let ((op (constructor (list->blob key))))
    (lambda (bytes)
      (blob->list (op (list->blob bytes))))))

(define (aes-cbc-encrypt bytes key iv)
  (let ((encryptor (wrap-aes make-aes128-encryptor key)))
    (let loop ((blocks (chop bytes 16))
               (last iv)
               (result '()))
      (if (null? blocks)
          (apply append (reverse result))
          (let ((last (encryptor (xor-bytes last (car blocks)))))
            (loop (cdr blocks)
                  last
                  (cons last result)))))))

(define (aes-cbc-decrypt bytes key iv)
  (let ((decryptor (wrap-aes make-aes128-decryptor key)))
    (let loop ((blocks (chop bytes 16))
               (last iv)
               (result '()))
      (if (null? blocks)
          (apply append (reverse result))
          (let ((output (xor-bytes last (decryptor (car blocks)))))
            (loop (cdr blocks)
                  (car blocks)
                  (cons output result)))))))

(define (str bytes)
  (list->string (map integer->char bytes)))

(define (bytes string)
  (map char->integer (string->list string)))

(define (hexencode bytes)
  (apply string-append
         (map (lambda (byte)
                (string-pad (number->string byte 16) 2 #\0))
              bytes)))

(define (update-at proc idx list)
  (let loop ((list list)
             (i 0)
             (result '()))
    (if (null? list)
        (reverse result)
        (if (= i idx)
            (loop (cdr list) (add1 i) (cons (proc (car list)) result))
            (loop (cdr list) (add1 i) (cons (car list) result))))))

(define key (random-bytes 16))
(define iv (random-bytes 16))
(define plaintext "comment=1234567890&uid=3")
(define ciphertext
  (aes-cbc-encrypt (pkcs7pad (bytes plaintext) 16) key iv))

(define (check ciphertext)
  (let* ((plaintext (str (pkcs7unpad (aes-cbc-decrypt ciphertext key iv))))
         (params (form-urldecode plaintext))
         (uid (alist-ref 'uid params)))
    (printf "checking ~s...\n" plaintext)
    (when (not uid)
      (error "invalid string"))
    (string->number uid)))

(define tampered-byte (bitwise-xor (char->integer #\3)
                                   (char->integer #\0)))
(define tampered
  (update-at (cut bitwise-xor <> tampered-byte) 7 ciphertext))

(printf "regular UID: ~a\n" (check ciphertext))
(printf "tampered UID: ~a\n" (check tampered))
