import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

import proxy_lint

SAMPLES_DIR = Path(__file__).resolve().parent.parent / "samples"


class TestProxyDetection(unittest.TestCase):
    def test_detect_nginx_by_extension(self):
        self.assertEqual(proxy_lint.detect_proxy_type(Path("nginx.conf"), ""), "nginx")

    def test_detect_haproxy_by_extension(self):
        self.assertEqual(proxy_lint.detect_proxy_type(Path("haproxy.cfg"), ""), "haproxy")

    def test_detect_envoy_by_extension(self):
        self.assertEqual(proxy_lint.detect_proxy_type(Path("envoy.yaml"), ""), "envoy")

    def test_detect_envoy_by_content_fallback(self):
        self.assertEqual(
            proxy_lint.detect_proxy_type(Path("unknown.txt"), "static_resources:\n  listeners:"),
            "envoy",
        )

    def test_detect_haproxy_by_content_fallback(self):
        self.assertEqual(
            proxy_lint.detect_proxy_type(Path("unknown.txt"), "frontend web\n  bind *:80"),
            "haproxy",
        )


class TestNginxRules(unittest.TestCase):
    def test_nginx_weak_sample_triggers_all_expected_rules(self):
        findings = proxy_lint.lint_file(SAMPLES_DIR / "nginx_weak.conf")
        rule_ids = {f.rule_id for f in findings}
        self.assertEqual(
            rule_ids,
            {"NGX001", "NGX002", "NGX003", "NGX004", "NGX005", "NGX006", "NGX007", "NGX008"},
        )

    def test_nginx_hardened_sample_has_zero_findings(self):
        findings = proxy_lint.lint_file(SAMPLES_DIR / "nginx_hardened.conf")
        self.assertEqual(findings, [])

    def test_ngx001_deprecated_tlsv1_1(self):
        cfg = "server { ssl_protocols TLSv1.1 TLSv1.2; }"
        ids = {f.rule_id for f in proxy_lint.lint_nginx("a.conf", cfg)}
        self.assertIn("NGX001", ids)

    def test_ngx001_tlsv1_2_and_1_3_ok(self):
        cfg = "server { ssl_protocols TLSv1.2 TLSv1.3; }"
        ids = {f.rule_id for f in proxy_lint.lint_nginx("a.conf", cfg)}
        self.assertNotIn("NGX001", ids)

    def test_ngx002_server_tokens_off_ok(self):
        cfg = "http { server_tokens off; }"
        ids = {f.rule_id for f in proxy_lint.lint_nginx("a.conf", cfg)}
        self.assertNotIn("NGX002", ids)

    def test_ngx004_non_api_location_does_not_trigger(self):
        cfg = "server { location /static/ { root /var/www; } }"
        ids = {f.rule_id for f in proxy_lint.lint_nginx("a.conf", cfg)}
        self.assertNotIn("NGX004", ids)

    def test_ngx007_wildcard_cors_without_creds_ok(self):
        cfg = "server { add_header Access-Control-Allow-Origin *; }"
        ids = {f.rule_id for f in proxy_lint.lint_nginx("a.conf", cfg)}
        self.assertNotIn("NGX007", ids)

    def test_ngx008_brotli_on_satisfies_compression(self):
        cfg = "http { brotli on; }"
        ids = {f.rule_id for f in proxy_lint.lint_nginx("a.conf", cfg)}
        self.assertNotIn("NGX008", ids)

    def test_comments_are_ignored(self):
        cfg = "# ssl_protocols TLSv1;\nhttp { server_tokens off; }"
        ids = {f.rule_id for f in proxy_lint.lint_nginx("a.conf", cfg)}
        self.assertNotIn("NGX001", ids)


class TestHAProxyRules(unittest.TestCase):
    def test_haproxy_weak_sample_triggers_all_expected_rules(self):
        findings = proxy_lint.lint_file(SAMPLES_DIR / "haproxy_weak.cfg")
        rule_ids = {f.rule_id for f in findings}
        self.assertEqual(rule_ids, {"HAP001", "HAP002", "HAP003", "HAP004", "HAP005"})

    def test_haproxy_hardened_config_clean(self):
        cfg = """
        global
            ssl-default-bind-options ssl-min-ver TLSv1.2 no-tls-tickets
        defaults
            option httplog
            timeout connect 5s
            timeout client 30s
            timeout server 30s
        frontend https_in
            stick-table type ip size 100k expire 30s store http_req_rate(10s)
            http-response set-header Strict-Transport-Security "max-age=31536000"
        """
        findings = proxy_lint.lint_haproxy("haproxy.cfg", cfg)
        self.assertEqual(findings, [])


class TestEnvoyRules(unittest.TestCase):
    def test_envoy_weak_sample_triggers_all_expected_rules(self):
        findings = proxy_lint.lint_file(SAMPLES_DIR / "envoy_weak.yaml")
        rule_ids = {f.rule_id for f in findings}
        self.assertEqual(rule_ids, {"ENV001", "ENV002", "ENV003", "ENV004", "ENV005"})

    def test_envoy_hardened_config_clean(self):
        cfg = """
        static_resources:
          listeners:
            - name: l0
              filter_chains:
                - transport_socket:
                    typed_config:
                      common_tls_context:
                        tls_params:
                          tls_minimum_protocol_version: TLSv1_2
                  filters:
                    - name: envoy.filters.network.http_connection_manager
                      typed_config:
                        http_filters:
                          - name: envoy.filters.http.local_ratelimit
                          - name: envoy.filters.http.compressor
          clusters:
            - name: svc
              connect_timeout: 5s
        """
        findings = proxy_lint.lint_envoy("envoy.yaml", cfg)
        self.assertEqual(findings, [])


class TestCLIAndFormatting(unittest.TestCase):
    def test_format_json_structure(self):
        findings = proxy_lint.lint_file(SAMPLES_DIR / "nginx_weak.conf")
        raw = proxy_lint.format_json(findings)
        data = json.loads(raw)
        self.assertEqual(data["tool"], "nginx-envoy-haproxy-ratelimit-cli-lite")
        self.assertEqual(data["total_findings"], len(findings))
        self.assertIsInstance(data["findings"], list)

    def test_format_markdown_empty(self):
        md = proxy_lint.format_markdown([])
        self.assertIn("No issues found.", md)

    def test_format_markdown_table(self):
        findings = proxy_lint.lint_file(SAMPLES_DIR / "haproxy_weak.cfg")
        md = proxy_lint.format_markdown(findings)
        self.assertIn("| Severity | Rule |", md)
        self.assertIn("HAP001", md)

    def test_cli_fail_on_critical_returns_1(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = proxy_lint.main([str(SAMPLES_DIR / "nginx_weak.conf"), "--fail-on", "CRITICAL"])
        self.assertEqual(code, 1)

    def test_cli_hardened_returns_0(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = proxy_lint.main([str(SAMPLES_DIR / "nginx_hardened.conf"), "--fail-on", "LOW"])
        self.assertEqual(code, 0)

    def test_cli_missing_file_returns_2(self):
        err = io.StringIO()
        with redirect_stderr(err):
            code = proxy_lint.main(["nonexistent_file_12345.conf"])
        self.assertEqual(code, 2)

    def test_cli_json_output_via_main(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = proxy_lint.main([str(SAMPLES_DIR / "envoy_weak.yaml"), "--format", "json"])
        self.assertEqual(code, 0)
        parsed = json.loads(buf.getvalue())
        self.assertEqual(parsed["total_findings"], 5)

    def test_cli_type_override(self):
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False, encoding="utf-8") as tmp:
            tmp.write("http { server_tokens off; gzip on; }")
            tmp_path = tmp.name
        try:
            buf = io.StringIO()
            with redirect_stdout(buf):
                code = proxy_lint.main([tmp_path, "--type", "nginx", "--format", "json"])
            self.assertEqual(code, 0)
            parsed = json.loads(buf.getvalue())
            self.assertEqual(parsed["findings"][0]["proxy_type"], "nginx")
        finally:
            Path(tmp_path).unlink(missing_ok=True)

    def test_should_fail_threshold_logic(self):
        low_only = [
            proxy_lint.Finding("NGX008", "LOW", "nginx", "a.conf", 1, "msg", "fix")
        ]
        self.assertFalse(proxy_lint.should_fail(low_only, "MEDIUM"))
        self.assertTrue(proxy_lint.should_fail(low_only, "LOW"))
        self.assertFalse(proxy_lint.should_fail(low_only, None))

    def test_unsupported_proxy_type_raises(self):
        with self.assertRaises(ValueError):
            proxy_lint.lint_file(SAMPLES_DIR / "nginx_weak.conf", proxy_type="traefik")


if __name__ == "__main__":
    unittest.main()
