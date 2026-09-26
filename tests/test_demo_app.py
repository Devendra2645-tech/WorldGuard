import unittest
import os
import tempfile
from fastapi.testclient import TestClient

from demo_app.main import app
from demo_app.database import init_demo_db


class TestDemoApplication(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.temp_dir.name, "test_demo.db")
        os.environ["DEMO_APP_DB_PATH"] = self.db_path
        init_demo_db(self.db_path)
        app.state.vulnerable_mode = True
        self.client = TestClient(app)

    def tearDown(self):
        os.environ.pop("DEMO_APP_DB_PATH", None)
        self.temp_dir.cleanup()

    def _login(self, username: str, password: str) -> str:
        resp = self.client.post("/api/auth/login", json={"username": username, "password": password})
        self.assertEqual(resp.status_code, 200)
        return resp.json()["token"]

    def test_home_and_health(self):
        home_resp = self.client.get("/")
        self.assertEqual(home_resp.status_code, 200)
        self.assertTrue(home_resp.json()["localhost_only"])
        self.assertIn("demo_credentials", home_resp.json())

        health_resp = self.client.get("/health")
        self.assertEqual(health_resp.status_code, 200)
        self.assertEqual(health_resp.json()["status"], "healthy")

    def test_login_success_and_failure(self):
        # 1. Successful logins for all 4 demo roles
        for role, creds in [
            ("Admin", ("admin_demo", "demo_admin_password")),
            ("Analyst", ("analyst_demo", "demo_analyst_password")),
            ("Operator", ("operator_demo", "demo_operator_password")),
            ("Normal User", ("user_demo", "demo_user_password")),
        ]:
            with self.subTest(role=role):
                resp = self.client.post("/api/auth/login", json={"username": creds[0], "password": creds[1]})
                self.assertEqual(resp.status_code, 200)
                data = resp.json()
                self.assertIn("token", data)
                self.assertEqual(data["user"]["role"], role)

        # 2. Failure: Invalid password
        fail_pass = self.client.post("/api/auth/login", json={"username": "admin_demo", "password": "wrong_password"})
        self.assertEqual(fail_pass.status_code, 401)

        # 3. Failure: Unknown user
        fail_user = self.client.post("/api/auth/login", json={"username": "ghost_user", "password": "any_password"})
        self.assertEqual(fail_user.status_code, 401)

    def test_auth_me_endpoint(self):
        token = self._login("analyst_demo", "demo_analyst_password")
        resp = self.client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["username"], "analyst_demo")
        self.assertEqual(resp.json()["role"], "Analyst")

    def test_unauthenticated_request_rejected(self):
        resp = self.client.get("/api/reports")
        self.assertEqual(resp.status_code, 401)

    def test_users_endpoint_rbac(self):
        admin_token = self._login("admin_demo", "demo_admin_password")
        analyst_token = self._login("analyst_demo", "demo_analyst_password")
        operator_token = self._login("operator_demo", "demo_operator_password")
        user_token = self._login("user_demo", "demo_user_password")

        # Admin and Analyst are allowed
        resp_admin = self.client.get("/api/users", headers={"Authorization": f"Bearer {admin_token}"})
        self.assertEqual(resp_admin.status_code, 200)
        self.assertGreaterEqual(len(resp_admin.json()), 4)

        resp_analyst = self.client.get("/api/users", headers={"Authorization": f"Bearer {analyst_token}"})
        self.assertEqual(resp_analyst.status_code, 200)

        # Operator and Normal User are blocked (403)
        resp_op = self.client.get("/api/users", headers={"Authorization": f"Bearer {operator_token}"})
        self.assertEqual(resp_op.status_code, 403)

        resp_user = self.client.get("/api/users", headers={"Authorization": f"Bearer {user_token}"})
        self.assertEqual(resp_user.status_code, 403)

    def test_reports_endpoint_rbac(self):
        admin_token = self._login("admin_demo", "demo_admin_password")
        operator_token = self._login("operator_demo", "demo_operator_password")
        user_token = self._login("user_demo", "demo_user_password")

        # All roles can list reports
        for token in (admin_token, operator_token, user_token):
            resp = self.client.get("/api/reports", headers={"Authorization": f"Bearer {token}"})
            self.assertEqual(resp.status_code, 200)

        # Operator can create report (201)
        new_report = {
            "title": "Sector-7 Satellite Signal Check",
            "category": "Comms",
            "summary": "Signal strength nominal."
        }
        resp_create_op = self.client.post("/api/reports", json=new_report, headers={"Authorization": f"Bearer {operator_token}"})
        self.assertEqual(resp_create_op.status_code, 201)
        self.assertEqual(resp_create_op.json()["title"], "Sector-7 Satellite Signal Check")

        # Normal User CANNOT create report (403)
        resp_create_user = self.client.post("/api/reports", json=new_report, headers={"Authorization": f"Bearer {user_token}"})
        self.assertEqual(resp_create_user.status_code, 403)

    def test_analytics_endpoint_rbac(self):
        admin_token = self._login("admin_demo", "demo_admin_password")
        analyst_token = self._login("analyst_demo", "demo_analyst_password")
        user_token = self._login("user_demo", "demo_user_password")

        # Admin & Analyst can access analytics
        self.assertEqual(self.client.get("/api/analytics", headers={"Authorization": f"Bearer {admin_token}"}).status_code, 200)
        self.assertEqual(self.client.get("/api/analytics", headers={"Authorization": f"Bearer {analyst_token}"}).status_code, 200)

        # Normal User is blocked (403)
        self.assertEqual(self.client.get("/api/analytics", headers={"Authorization": f"Bearer {user_token}"}).status_code, 403)

    def test_vulnerable_authorization_behavior(self):
        """
        Tests the controlled demonstration vulnerability:
        When vulnerable_mode is True, a Normal User (user_demo) is able to access /api/admin.
        """
        app.state.vulnerable_mode = True
        user_token = self._login("user_demo", "demo_user_password")

        resp = self.client.get("/api/admin", headers={"Authorization": f"Bearer {user_token}"})
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertTrue(data["vulnerability_active"])
        self.assertEqual(data["authorized_as"], "Normal User")
        self.assertIn("VULNERABILITY DEMONSTRATED", data["message"])
        self.assertIn("admin_telemetry", data)

    def test_secure_fixed_authorization_behavior(self):
        """
        Tests the fixed/secure implementation:
        When vulnerable_mode is False, Normal User receives 403 Forbidden.
        Only Admin (admin_demo) receives 200 OK.
        """
        # Toggle to secure mode
        app.state.vulnerable_mode = False
        user_token = self._login("user_demo", "demo_user_password")
        admin_token = self._login("admin_demo", "demo_admin_password")

        # Normal User is blocked with 403 Forbidden
        user_resp = self.client.get("/api/admin", headers={"Authorization": f"Bearer {user_token}"})
        self.assertEqual(user_resp.status_code, 403)
        self.assertIn("Admin role required", user_resp.json()["detail"])

        # Admin is permitted with 200 OK
        admin_resp = self.client.get("/api/admin", headers={"Authorization": f"Bearer {admin_token}"})
        self.assertEqual(admin_resp.status_code, 200)
        self.assertFalse(admin_resp.json()["vulnerability_active"])
        self.assertEqual(admin_resp.json()["authorized_as"], "Admin")

    def test_vulnerability_toggle_endpoint(self):
        # 1. Query mode
        resp_mode = self.client.get("/api/admin/mode")
        self.assertEqual(resp_mode.status_code, 200)

        # 2. Toggle to False
        self.client.post("/api/admin/mode", json={"vulnerable_mode": False})
        self.assertFalse(app.state.vulnerable_mode)

        # 3. Toggle back to True
        self.client.post("/api/admin/mode", json={"vulnerable_mode": True})
        self.assertTrue(app.state.vulnerable_mode)

    def test_per_request_override_flags(self):
        app.state.vulnerable_mode = True
        user_token = self._login("user_demo", "demo_user_password")

        # Without flag: 200 OK (vulnerable)
        self.assertEqual(self.client.get("/api/admin", headers={"Authorization": f"Bearer {user_token}"}).status_code, 200)

        # With query parameter ?fix=true: 403 Forbidden (secure)
        self.assertEqual(self.client.get("/api/admin?fix=true", headers={"Authorization": f"Bearer {user_token}"}).status_code, 403)

        # With header X-Enforce-Auth: true: 403 Forbidden (secure)
        self.assertEqual(self.client.get("/api/admin", headers={"Authorization": f"Bearer {user_token}", "X-Enforce-Auth": "true"}).status_code, 403)


if __name__ == "__main__":
    unittest.main()
