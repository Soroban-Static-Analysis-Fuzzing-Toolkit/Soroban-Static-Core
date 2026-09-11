(module
  (import "l" "put_contract_data" (func $put (param i32) (result i32)))
  (import "l" "require_auth" (func $auth (param i32)))

  ;; Authorization is delegated to $check, so the entrypoint must NOT be
  ;; flagged by SOR-101 even though it never calls require_auth directly.
  (func $check (param i32)
    local.get 0
    call $auth)

  (func $write (param i32) (result i32)
    local.get 0
    call $put)

  (func (export "store") (param i32) (result i32)
    local.get 0
    call $check
    local.get 0
    call $write))
