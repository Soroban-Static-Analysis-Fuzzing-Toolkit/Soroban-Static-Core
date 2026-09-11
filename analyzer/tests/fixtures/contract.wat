(module
  (import "l" "put_contract_data" (func $put (param i32) (result i32)))
  (import "l" "get_contract_data" (func $get (param i32) (result i32)))
  (memory 1)

  ;; State-changing entrypoint that never calls require_auth (SOR-101) and
  ;; grows memory inside a loop (SOR-106).
  (func (export "mint") (param i32) (result i32)
    (local i32)
    local.get 0
    call $put
    drop
    loop $l
      i32.const 1
      memory.grow
      drop
      local.get 1
      i32.const 1
      i32.add
      local.tee 1
      local.get 0
      i32.lt_s
      br_if $l
    end
    i32.const 0)

  ;; Read-only entrypoint.
  (func (export "read") (param i32) (result i32)
    local.get 0
    call $get))
