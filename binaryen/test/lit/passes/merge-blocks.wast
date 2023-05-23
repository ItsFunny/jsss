;; NOTE: Assertions have been generated by update_lit_checks.py and should not be edited.
;; RUN: wasm-opt %s --remove-unused-names --merge-blocks -all -S -o - \
;; RUN:   | filecheck %s
;;
;; --remove-unused-names lets --merge-blocks assume blocks without names have no
;; branch targets.

(module
 (type $anyref_=>_none (func (param anyref)))

 ;; CHECK:      (type $struct (struct (field (mut i32))))
 (type $struct (struct (field (mut i32))))

 ;; CHECK:      (func $br_on_to_drop
 ;; CHECK-NEXT:  (nop)
 ;; CHECK-NEXT:  (drop
 ;; CHECK-NEXT:   (block $label$1 (result (ref null i31))
 ;; CHECK-NEXT:    (drop
 ;; CHECK-NEXT:     (br_on_i31 $label$1
 ;; CHECK-NEXT:      (ref.null any)
 ;; CHECK-NEXT:     )
 ;; CHECK-NEXT:    )
 ;; CHECK-NEXT:    (ref.null i31)
 ;; CHECK-NEXT:   )
 ;; CHECK-NEXT:  )
 ;; CHECK-NEXT: )
 (func $br_on_to_drop
  (nop) ;; ensure a block at the function level
  (drop
   (block $label$1 (result (ref null i31)) ;; this block type must stay, we
                                           ;; cannot remove it due to the br_on
    (drop
     (br_on_i31 $label$1
      (ref.null any)
     )
    )
    (ref.null i31) ;; this must not end up dropped
   )
  )
 )

 ;; CHECK:      (func $struct.set
 ;; CHECK-NEXT:  (nop)
 ;; CHECK-NEXT:  (drop
 ;; CHECK-NEXT:   (i32.const 1234)
 ;; CHECK-NEXT:  )
 ;; CHECK-NEXT:  (struct.set $struct 0
 ;; CHECK-NEXT:   (ref.null $struct)
 ;; CHECK-NEXT:   (i32.const 5)
 ;; CHECK-NEXT:  )
 ;; CHECK-NEXT:  (nop)
 ;; CHECK-NEXT: )
 (func $struct.set
  (block
   (nop)
   (struct.set $struct 0
    (block (result (ref null $struct))
     (drop (i32.const 1234))
     (ref.null $struct)
    )
    (i32.const 5)
   )
   (nop)
  )
 )

 ;; CHECK:      (func $struct.get
 ;; CHECK-NEXT:  (nop)
 ;; CHECK-NEXT:  (drop
 ;; CHECK-NEXT:   (i32.const 1234)
 ;; CHECK-NEXT:  )
 ;; CHECK-NEXT:  (drop
 ;; CHECK-NEXT:   (struct.get $struct 0
 ;; CHECK-NEXT:    (ref.null $struct)
 ;; CHECK-NEXT:   )
 ;; CHECK-NEXT:  )
 ;; CHECK-NEXT:  (nop)
 ;; CHECK-NEXT: )
 (func $struct.get
  (block
   (nop)
   (drop
    (struct.get $struct 0
     (block (result (ref null $struct))
      (drop (i32.const 1234))
      (ref.null $struct)
     )
    )
   )
   (nop)
  )
 )
)