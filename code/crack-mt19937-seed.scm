(use extras posix (prefix random-mtzig mt19937:))

(define (random-number seed)
  (let ((rng (mt19937:init seed)))
    (mt19937:random! rng)))

(define now (inexact->exact (current-seconds)))
(define then (- now 123))
(define rng-output (random-number then))

(define (crack-it starting-time rng-output)
  (let loop ((seed starting-time))
    (if (= (random-number seed) rng-output)
        seed
        (loop (sub1 seed)))))

(printf "Predictable seed: ~a, output: ~a\n" then rng-output)
(printf "Cracked seed: ~a\n" (crack-it now rng-output))
