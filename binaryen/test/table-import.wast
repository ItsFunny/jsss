(module
  (type $0 (func))
  (import "env" "table" (table 1 1 funcref))
  (elem (i32.const 0) $foo)
  (memory $0 0)
  (func $foo (type $0)
    (nop)
  )
)
