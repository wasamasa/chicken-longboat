(use srfi-1 srfi-4 srfi-18 srfi-69 aes base64 ports zlib)

(define (str bytes)
  (list->string (map integer->char bytes)))

(define (bytes string)
  (map char->integer (string->list string)))

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

(define (random-bytes count #!key (from 0) (to 256))
  (list-tabulate count (lambda (_) (+ (random (- to from)) from))))

(define session-id "Q0hJQ0tFTiBTY2hlbWUgcmVpZ25zIHN1cHJlbWU=")

(define (format-request input)
  (format "POST / HTTP/1.1
Host: example.com
Cookie: sessionid=~a
Content-Length: ~a
~a
" session-id (string-length input) input))

(define (compress string)
  (call-with-output-string
   (lambda (out)
     (with-output-to-port (open-zlib-compressed-output-port out)
       (lambda ()
         (write-string string)
         (close-output-port (current-output-port)))))))

(define (oracle input)
  (let ((key (random-bytes 16))
        (nonce (random (expt 2 32))))
    (length (aes-ctr-encrypt (bytes (compress (format-request input)))
                             key nonce))))

(define charset
  (map char->integer
       (string->list (string-append "abcdefghijklmnopqrstuvwxyz"
                                    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                                    "0123456789+/="))))

(define (min-max-by proc list)
  (when (null? list)
    (error "List may not be empty"))
  (let loop ((minimum (car list))
             (maximum (car list))
             (list (cdr list)))
    (if (null? list)
        (values minimum maximum)
        (let ((value (car list)))
          (loop (if (< (proc value) (proc minimum)) value minimum)
                (if (> (proc value) (proc maximum)) value maximum)
                (cdr list))))))

(define (guess-byte known)
  (let ((guesses (make-hash-table))
        ;; this improves our chances considerably
        (suffix (random-bytes 10 from: 128 to: 256)))
    (for-each (lambda (byte)
                (let* ((guess (append known (list byte) suffix))
                       (input (format "sessionid=~a" (str guess))))
                  (hash-table-set! guesses byte (oracle input))))
              charset)
    (min-max-by cdr (hash-table->alist guesses))))

(define (report-progress string prefix)
  (printf " ~a~a\r~!" prefix string))

(define (guess-bytes)
  (let loop ((known '()))
    (receive (min max) (guess-byte known)
      (if (< (cdr min) (cdr max))
          (let ((known (append known (list (car min)))))
            (report-progress (str known) "guessed: ")
            (loop known))
          known))))

(printf "expected: ~a\n" session-id)
(guess-bytes)
(print)
