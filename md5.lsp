;;
;; based on RFC 1321
;; dumb and slow. Just for understanding md5.

(define (F x y z)
  (| (& x y) (& (& 0xffffffff (~ x)) z)))

(define (G x y z)
  (| (& x z) (& y (& 0xffffffff (~ z)))))

(define (H x y z)
  (^ x y z))

(define (I x y z)
  (^ y (| x (& 0xffffffff (~ z)))))

(define (rotate-left x n)
  (| (& 0xffffffff (<< x n)) (& 0xffffffff (>> x (- 32 n)))))

(define (FF a b c d x s ac)
  (set 'a (& 0xffffffff (+ a (F b c d) x ac)))
  (set 'a (rotate-left a s))
  (set 'a (& 0xffffffff (+ a b))))

(define (GG a b c d x s ac)
  (set 'a (& 0xffffffff (+ a (G b c d) x ac)))
  (set 'a (rotate-left a s))
  (set 'a (& 0xffffffff (+ a b))))

(define (HH a b c d x s ac)
  (set 'a (& 0xffffffff (+ a (H b c d) x ac)))
  (set 'a (rotate-left a s))
  (set 'a (& 0xffffffff (+ a b))))

(define (II a b c d x s ac)
  (set 'a (& 0xffffffff (+ a (I b c d) x ac)))
  (set 'a (rotate-left a s))
  (set 'a (& 0xffffffff (+ a b))))

(define (md5-init )
  (set 'md5-i '(0 0))
  (set 'md5-in (dup 0 64))
  (set 'md5-digest (dup 0 16))
  (set 'md5-buf '(0x67452301 0xefcdab89 0x98badcfe 0x10325476)))

(define (md5-update inbuf inlen)
  ;; compute number of bytes mod 64
  (set 'mdi (& (>> (md5-i 0) 3) 0x3f))

  ;; update number of bits
  (if (< (+ (md5-i 0)  (<< inlen 3)) (md5-i 0))
      (nth-set (md5-i 1) (+ 1 (md5-i 1))))

  (nth-set (md5-i 0) (+ (md5-i 0) (<< inlen 3)))
  (nth-set (md5-i 1) (+ (md5-i 1) (>> inlen 29)))

  (set 'inbuf-index 0)
  (while (> inlen 0)
    ;; add new character to buffer, increment mdi
    (nth-set (md5-in mdi) (inbuf inbuf-index))
    (set 'mdi (+ mdi 1))
    (set 'inbuf-index (+ inbuf-index 1))

    ;; transform if necessary
    (if (= mdi 0x40)
        (begin
          (set 'ii 0)
          (set 'in (dup 0 16))
          (for (i 0 15 1)
          (nth-set (in i) (| (<< (char->int (md5-in (+ ii 3))) 24)
                   (<< (char->int (md5-in (+ ii 2))) 16)
                   (<< (char->int (md5-in (+ ii 1))) 8)
                   (char->int (md5-in ii))))
          (set 'ii (+ ii 4)))
          (transform  in)
          (set 'mdi 0)))
    (set 'inlen (- inlen 1))))

(define (char->int x)
  (if (integer? x) x (char x)))

(define (md5-final)
  (set 'in (dup 0 16))

  ;; save number of bits
  (nth-set (in 14) (md5-i 0))
  (nth-set (in 15) (md5-i 1))

  ;; compute number of bytse mod 64
  (set 'mdi (& (>> (md5-i 0) 3) 0x3f))

  ;; pad out to 56 mod 64
  (if (< mdi 56)
      (set 'padlen (- 56 mdi))
      (set 'padlen (- 120 mdi)))

  (set 'padding (dup 0 64))
  (nth-set (padding 0) 0x80)
  (md5-update padding padlen)

  ;; append lenth in bits and transform
  (set 'ii 0)
  (for (i 0 13 1)
       (nth-set (in i) (| (<< (char->int (md5-in (+ ii 3))) 24)
           (<< (char->int (md5-in (+ ii 2))) 16)
           (<< (char->int (md5-in (+ ii 1))) 8) (char->int (md5-in ii))))
       (set 'ii (+ ii 4)))
  (transform in)

  ;; store buffer in digest
  (set 'ii 0)
  (for (i 0 3 1)
       (nth-set (md5-digest ii) (& (md5-buf i) 0xff))
       (nth-set (md5-digest (+ ii 1)) (& (>> (md5-buf i) 8) 0xff))
       (nth-set (md5-digest (+ ii 2)) (& (>> (md5-buf i) 16)  0xff))
       (nth-set (md5-digest (+ ii 3)) (& (>> (md5-buf i) 24)  0xff))
       (set 'ii (+ ii 4))))

(define (transform  in)
  (set 'a (md5-buf 0))
  (set 'b (md5-buf 1))
  (set 'c (md5-buf 2))
  (set 'd (md5-buf 3))

  ;; Round 1
  (set 'S11 7)
  (set 'S12 12)
  (set 'S13 17)
  (set 'S14 22)
  (set 'a (FF a b c d (in 0) S11 3614090360)) 
  (set 'd (FF d a b c (in 1) S12 3905402710)) 
  (set 'c (FF c d a b (in 2) S13  606105819)) 
  (set 'b (FF b c d a (in 3) S14 3250441966)) 
  (set 'a (FF a b c d (in 4) S11 4118548399)) 
  (set 'd (FF d a b c (in 5) S12 1200080426)) 
  (set 'c (FF c d a b (in 6) S13 2821735955)) 
  (set 'b (FF b c d a (in 7) S14 4249261313)) 
  (set 'a (FF a b c d (in 8) S11 1770035416)) 
  (set 'd (FF d a b c (in 9) S12 2336552879)) 
  (set 'c (FF c d a b (in 10) S13 4294925233))
  (set 'b (FF b c d a (in 11) S14 2304563134))
  (set 'a (FF a b c d (in 12) S11 1804603682))
  (set 'd (FF d a b c (in 13) S12 4254626195))
  (set 'c (FF c d a b (in 14) S13 2792965006))
  (set 'b (FF b c d a (in 15) S14 1236535329))

  ;; Round 2 
  (set 'S21 5)
  (set 'S22 9)
  (set 'S23 14)
  (set 'S24 20)
  (set 'a (GG a b c d (in 1) S21 4129170786)) 
  (set 'd (GG d a b c (in 6) S22 3225465664)) 
  (set 'c (GG c d a b (in 11) S23  643717713))
  (set 'b (GG b c d a (in 0) S24 3921069994)) 
  (set 'a (GG a b c d (in 5) S21 3593408605)) 
  (set 'd (GG d a b c (in 10) S22   38016083))
  (set 'c (GG c d a b (in 15) S23 3634488961))
  (set 'b (GG b c d a (in 4) S24 3889429448)) 
  (set 'a (GG a b c d (in 9) S21  568446438)) 
  (set 'd (GG d a b c (in 14) S22 3275163606))
  (set 'c (GG c d a b (in 3) S23 4107603335)) 
  (set 'b (GG b c d a (in 8) S24 1163531501)) 
  (set 'a (GG a b c d (in 13) S21 2850285829))
  (set 'd (GG d a b c (in 2) S22 4243563512)) 
  (set 'c (GG c d a b (in 7) S23 1735328473)) 
  (set 'b (GG b c d a (in 12) S24 2368359562))

  ;; Round 3 
  (set 'S31 4)
  (set 'S32 11)
  (set 'S33 16)
  (set 'S34 23)
  (set 'a (HH a b c d (in 5) S31 4294588738)) 
  (set 'd (HH d a b c (in 8) S32 2272392833)) 
  (set 'c (HH c d a b (in 11) S33 1839030562))
  (set 'b (HH b c d a (in 14) S34 4259657740))
  (set 'a (HH a b c d (in 1) S31 2763975236)) 
  (set 'd (HH d a b c (in 4) S32 1272893353)) 
  (set 'c (HH c d a b (in 7) S33 4139469664)) 
  (set 'b (HH b c d a (in 10) S34 3200236656))
  (set 'a (HH a b c d (in 13) S31  681279174))
  (set 'd (HH d a b c (in 0) S32 3936430074)) 
  (set 'c (HH c d a b (in 3) S33 3572445317)) 
  (set 'b (HH b c d a (in 6) S34   76029189)) 
  (set 'a (HH a b c d (in 9) S31 3654602809)) 
  (set 'd (HH d a b c (in 12) S32 3873151461))
  (set 'c (HH c d a b (in 15) S33  530742520))
  (set 'b (HH b c d a (in 2) S34 3299628645)) 

  ;; Round 4 
  (set 'S41 6)
  (set 'S42 10)
  (set 'S43 15)
  (set 'S44 21)
  (set 'a (II a b c d (in 0) S41 4096336452)) 
  (set 'd (II d a b c (in 7) S42 1126891415)) 
  (set 'c (II c d a b (in 14) S43 2878612391))
  (set 'b (II b c d a (in 5) S44 4237533241)) 
  (set 'a (II a b c d (in 12) S41 1700485571))
  (set 'd (II d a b c (in 3) S42 2399980690)) 
  (set 'c (II c d a b (in 10) S43 4293915773))
  (set 'b (II b c d a (in 1) S44 2240044497)) 
  (set 'a (II a b c d (in 8) S41 1873313359)) 
  (set 'd (II d a b c (in 15) S42 4264355552))
  (set 'c (II c d a b (in 6) S43 2734768916)) 
  (set 'b (II b c d a (in 13) S44 1309151649))
  (set 'a (II a b c d (in 4) S41 4149444226)) 
  (set 'd (II d a b c (in 11) S42 3174756917))
  (set 'c (II c d a b (in 2) S43  718787259)) 
  (set 'b (II b c d a (in 9) S44 3951481745)) 

  (nth-set (md5-buf 0) (+ a (md5-buf 0)))
  (nth-set (md5-buf 1) (+ b (md5-buf 1)))
  (nth-set (md5-buf 2) (+ c (md5-buf 2)))
  (nth-set (md5-buf 3) (+ d (md5-buf 3))))

(define (md5-string str)
  (md5-init)
  (md5-update str (length str))
  (md5-final)
  (set 'result "")
  (for (i 0 15 1)
       (set 'result (append result (format "%02x" (md5-digest i)))))
  result)
