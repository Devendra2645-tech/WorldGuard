# World Monitor Demo Target Application

**Controlled Local Security Benchmark Target for SIH 2026**

---

## 1. Overview & Purpose

The **World Monitor Demo Target Application** is an intentionally created, self-contained local web service representing the World Monitor system. It provides an authorized testbed for demonstrating WorldGuard's defensive security assessment capabilities.

### Defensive Guardrails & Safety Policy
- **Localhost Only:** Strictly configured to bind only to `127.0.0.1` / `localhost`.
- **Synthetic Data Only:** Contains no real credentials, real keys, production secrets, or personal data.
- **Controlled Vulnerability:** Contains a single, non-destructive, clearly documented Broken Access Control demonstration (CWE-862).
- **No Exploitation:** Does not provide remote command execution, file system access, network pivoting, credential harvesting, or denial-of-service vectors.
- **Independent Database:** Operates on its own isolated SQLite database, completely segregated from WorldGuard's scan history database.

---

## 2. Demo User Roles & Credentials

All credentials are for **local demonstration purposes only**:

| Role | Username | Password | Permitted Capabilities |
| :--- | :--- | :--- | :--- |
| **Admin** | `admin_demo` | `demo_admin_password` | Full system access: users, reports, analytics, admin control panel |
| **Analyst** | `analyst_demo` | `demo_analyst_password` | Read users, read/create reports, read analytics |
| **Operator** | `operator_demo` | `demo_operator_password` | Read reports, create reports |
| **Normal User** | `user_demo` | `demo_user_password` | Read reports only |

---

## 3. API Endpoints

### Authentication & Profile
- `POST /api/auth/login`: Authenticates demo credentials and returns a Bearer session token.
- `GET /api/auth/me`: Returns profile details of the authenticated token holder.

### Application Resources
- `GET /api/users`: Lists demo user records (RBAC: requires `Admin` or `Analyst`).
- `GET /api/reports`: Lists surveillance reports (Permitted for all authenticated users).
- `POST /api/reports`: Creates a new report (RBAC: requires `Admin`, `Analyst`, or `Operator`).
- `GET /api/analytics`: Retrieves sensor telemetry analytics (RBAC: requires `Admin` or `Analyst`).

---

## 4. Controlled Vulnerability: Missing Server-Side Authorization (CWE-862)

### Target Endpoint: `GET /api/admin`

The endpoint returns synthetic administrative control panel telemetry.

### Before Fix (Vulnerable State - Default)
- When `vulnerable_mode` is enabled, the endpoint authenticates the user, but fails to check whether the user has the `Admin` role.
- A **Normal User** (`user_demo`) requesting `GET /api/admin` receives **200 OK** and can see the administrative control telemetry.
- **Impact:** Illustrates OWASP Top 10 A01: Broken Access Control (horizontal/vertical privilege escalation).

```
Normal User (user_demo) ---> GET /api/admin ---> 200 OK ❌ (Vulnerability Demonstrated)
```

### After Fix (Secure / Fixed State)
- When `vulnerable_mode` is disabled, the endpoint strictly verifies `current_user['role'] == 'Admin'`.
- Any non-admin role (e.g. `Normal User`, `Operator`, `Analyst`) requesting `GET /api/admin` receives **403 Forbidden**.
- Only `admin_demo` receives **200 OK**.

```
Normal User (user_demo) ---> GET /api/admin ---> 403 Forbidden ✅ (Access Denied)
Admin (admin_demo)        ---> GET /api/admin ---> 200 OK ✅ (Access Authorized)
```

### Dynamic Vulnerability Toggling
You can switch between the vulnerable and secure state dynamically:
- **Inspect State:** `GET /api/admin/mode`
- **Toggle State:** `POST /api/admin/mode` with `{"vulnerable_mode": false}`
- **Per-Request Override:** Include query parameter `?fix=true` or header `X-Enforce-Auth: true`.

---

## 5. Running the Demo Application

Start the demo service on port 8001 (binding strictly to localhost):

```bash
uvicorn demo_app.main:app --host 127.0.0.1 --port 8001 --reload
```

Interactive documentation and testing interface:
- **Swagger UI:** `http://127.0.0.1:8001/docs`
- **Health Check:** `http://127.0.0.1:8001/health`

---

## 6. Running Tests

Run the demo application test suite:

```bash
.\.venv\Scripts\python.exe -m unittest tests/test_demo_app.py
```
