(use srfi-1 srfi-4 srfi-13 srfi-69 data-structures irregex)

(define (hexdecode string)
  (map (cut string->number <> 16)
       (string-chop string 2)))

(define (str bytes)
  (list->string (map integer->char bytes)))

(define (ascii? string)
  (every (lambda (char) (<= 0 (char->integer char) 127))
         (string->list string)))

(define english-histogram
  (alist->hash-table
   '((#\space . 0.14)
     (#\e . 0.12)
     (#\t . 0.09)
     (#\. . 0.09) ; other chars
     (#\a . 0.08)
     (#\o . 0.07)
     (#\i . 0.06)
     (#\n . 0.06)
     (#\s . 0.06)
     (#\h . 0.06)
     (#\r . 0.05)
     (#\d . 0.04)
     (#\l . 0.04)
     (#\u . 0.02)
     (#\c . 0.02)
     (#\m . 0.02)
     (#\w . 0.02)
     (#\f . 0.02)
     (#\g . 0.02)
     (#\y . 0.01)
     (#\p . 0.01)
     (#\b . 0.01)
     (#\v . 0.01)
     (#\k . 0.01)
     (#\j . 0.01)
     (#\x . 0.00)
     (#\q . 0.00)
     (#\z . 0.00))))

(define (frequencies string)
  (let ((ht (make-hash-table))
        (total (string-length string)))
    (for-each (lambda (char)
                (hash-table-update!/default ht char add1 0))
              (string->list string))
    (hash-table-walk ht (lambda (k v)
                          (hash-table-set! ht k (/ v total))))
    ht))

(define (chi-squared hist1 hist2)
  (hash-table-fold
   hist1
   (lambda (k v1 score)
     (let ((v2 (hash-table-ref/default hist2 k 0)))
       (if (zero? v1)
           score
           (+ score (/ (expt (- v1 v2) 2) v1)))))
   0))

(define (english-score string)
  (if (ascii? string)
      (let* ((input (string-downcase string))
             (input (irregex-replace/all "[^ a-z]" input "."))
             (hist (frequencies input))
             (score (/ 1 (chi-squared english-histogram hist))))
        (if (< (hash-table-ref/default hist #\. 0) 0.05)
            (* score 2)
            score))
      0))

(define ciphertext
  (hexdecode "48434248404e452b5868636e666e2b796e626c65782b787e7b796e666e"))


(define (xor-bytes-with-byte bytes byte)
  (map (lambda (b) (bitwise-xor b byte)) bytes))

(let loop ((byte 0)
           (best-score 0)
           (best-solution ""))
  (if (< byte 256)
      (let* ((solution (str (xor-bytes-with-byte ciphertext byte)))
             (score (english-score solution)))
        (if (> score best-score)
            (loop (add1 byte) score solution)
            (loop (add1 byte) best-score best-solution)))
      (begin
        (printf "Score: ~a\n" best-score)
        (print best-solution))))
