(use srfi-1 srfi-4 aes base64)

(define (str bytes)
  (list->string (map integer->char bytes)))

(define (bytes string)
  (map char->integer (string->list string)))

(define plaintext (bytes (base64-decode "VGhlIGV2b2x1dGlvbiBvZiBhIHByb2Nlc
3MgaXMgZGlyZWN0ZWQgYnkgYSBwYXR0ZXJuIG9mIHJ1bGVzIGNhbGxlZCBhIHByb2dyYW0uIFB
lb3BsZSBjcmVhdGUgcHJvZ3JhbXMgdG8gZGlyZWN0IHByb2Nlc3Nlcy4gSW4gZWZmZWN0LCB3Z
SBjb25qdXJlIHRoZSBzcGlyaXRzIG9mIHRoZSBjb21wdXRlciB3aXRoIG91ciBzcGVsbHMu")))

(define (long-bytes-le integer)
  (let loop ((n integer)
             (i 0)
             (result '()))
    (if (< i 8)
        (loop (quotient n 256) (add1 i) (cons (modulo n 256) result))
        (reverse result))))

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

(define (aes-ctr-encrypt bytes key nonce)
  (let ((encryptor (wrap-aes make-aes128-encryptor key))
        (nonce (long-bytes-le nonce)))
    (let loop ((blocks (chop bytes 16))
               (i 0)
               (result '()))
      (if (null? blocks)
          (apply append (reverse result))
          (let ((block (car blocks))
                (intermediate (encryptor (append nonce (long-bytes-le i)))))
            (loop (cdr blocks)
                  (add1 i)
                  (cons (xor-bytes block (take intermediate (length block)))
                        result)))))))

(define aes-ctr-decrypt aes-ctr-encrypt)

(define (random-bytes count) (list-tabulate count (lambda (_) (random 256))))

(define key (random-bytes 16))
(define nonce (random (expt 2 32)))
(define ciphertext (aes-ctr-encrypt plaintext key nonce))

(define (edit* ciphertext key nonce offset newtext)
  (let* ((decrypted (aes-ctr-decrypt ciphertext key nonce))
         (before (take decrypted offset))
         (after (drop decrypted (+ offset (length newtext))))
         (patched (append before newtext after)))
    (aes-ctr-encrypt patched key nonce)))

(define (edit ciphertext offset newtext)
  (edit* ciphertext key nonce offset newtext))

;; (define redacted-ciphertext (edit ciphertext 4 (bytes "xxxxxxxxx")))
;; (print (str (aes-ctr-decrypt redacted-ciphertext key nonce)))

(define (decrypt ciphertext)
  (let* ((our-plaintext (random-bytes (length ciphertext)))
         (our-ciphertext (edit ciphertext 0 our-plaintext)))
    (xor-bytes
     (xor-bytes ciphertext our-ciphertext)
     our-plaintext)))

(print (str (decrypt ciphertext)))
