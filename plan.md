# Admin Organization Creation Plan

## 1. Service Layer Updates
- Remove `ContextOrgID` dependency from `Service.CreateOrganization`.
- Validate admin rights by checking existing active memberships (role admin) or ownership records.
- Ensure organization persistence captures `created_by` (align with YDB schema; add field if missing) and include description support.
- Create membership record marking creator as admin; log success/failure with user_id/org_name/timestamp.
- Handle duplicate organization names per user (case-insensitive) and map to validation error.

## 2. HTTP Endpoint
- Add handler `Server.CreateOrganization` parsing `{name, description}` with strict validation, wiring to service.
- Enforce AuthMiddleware (JWT) + role check (admin only) + Content-Type JSON.
- Map service errors to HTTP codes (400 validation, 401 auth missing, 403 role, 409 duplicates, 500 fallback).
- Register route POST `/api/v1/organization/create` in router with middleware chain.

## 3. Documentation
- README: document new endpoint, payload, responses, role restriction.
- Swagger (`docs/swagger.yaml`, regenerate JSON/docs.go) with schema definitions and path entry.
- Add Bruno examples under `docs/SellerProof API/organization/create` covering success and failure cases.

## 4. Tests
- Service unit tests covering:
  - Successful creation (org + membership persistence, logging).
  - Non-admin user (403).
  - Validation boundaries (name length, description length, sanitization errors).
  - Duplicate name detection.
- Handler tests (if feasible) verifying status codes; otherwise rely on service tests + manual verification.

## 5. Verification
- Run `go test ./...` to ensure all tests pass.
- If swagger generation requires a command, run it and verify JSON is updated consistently.
- Update TODO list statuses as tasks complete.
