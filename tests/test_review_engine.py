import json
import os
import unittest
from unittest.mock import MagicMock, patch

from prufgate.review import (
    PRComment,
    detect_ai_provider,
    format_review_github,
    format_review_reviewdog,
    format_review_sarif,
    is_valid_code_suggestion,
    review_diff_with_ai,
    run_hybrid_review,
    run_self_check,
)


class TestReviewEngine(unittest.TestCase):
    def test_self_check_passes(self) -> None:
        self.assertEqual(run_self_check(), 0)

    def test_suggestion_validation_filters_comment_placeholders(self) -> None:
        # Pure comment placeholders must never be emitted as GitHub suggestion blocks
        self.assertFalse(is_valid_code_suggestion(None))
        self.assertFalse(is_valid_code_suggestion(""))
        self.assertFalse(is_valid_code_suggestion("   // Redact sensitive credential before logging"))
        self.assertFalse(is_valid_code_suggestion("# TODO: replace with parameterized query"))
        self.assertFalse(is_valid_code_suggestion("/* placeholder */"))
        # Unbalanced delimiters must be rejected
        self.assertFalse(is_valid_code_suggestion("const x = fn(a, b;"))
        # Valid executable replacement code must be accepted
        self.assertTrue(
            is_valid_code_suggestion("const agent = new https.Agent({ rejectUnauthorized: true });")
        )

    def test_github_sarif_and_reviewdog_formats(self) -> None:
        comments = [
            PRComment(
                file_path="src/tls.ts",
                line=12,
                severity="P1",
                title="Disabled TLS Certificate Verification",
                message="Keep certificate validation enabled.",
                suggestion="const agent = new https.Agent({ rejectUnauthorized: true });",
            ),
            PRComment(
                file_path="src/auth.ts",
                line=25,
                severity="P1",
                title="Credential Logging in Console",
                message="Do not log secrets.",
                suggestion="  // Redact sensitive credential before logging",
            ),
        ]

        gh_out = format_review_github(comments)
        self.assertIn("::error file=src/tls.ts,line=12", gh_out)
        self.assertIn("::error file=src/auth.ts,line=25", gh_out)
        # Only the valid code replacement in src/tls.ts gets a ```suggestion block
        self.assertEqual(gh_out.count("```suggestion"), 1)
        self.assertIn("rejectUnauthorized: true", gh_out)

        sarif_out = json.loads(format_review_sarif(comments))
        self.assertEqual(len(sarif_out["runs"][0]["results"]), 2)

        rd_out = json.loads(format_review_reviewdog(comments))
        self.assertEqual(len(rd_out["diagnostics"]), 2)
        self.assertIn("suggestions", rd_out["diagnostics"][0])
        self.assertNotIn("suggestions", rd_out["diagnostics"][1])

    def test_ai_adapter_graceful_fallback_and_mocked_cli(self) -> None:
        sample_diff = (
            "diff --git a/src/api.py b/src/api.py\n"
            "--- a/src/api.py\n"
            "+++ b/src/api.py\n"
            "@@ -1,1 +1,2 @@\n"
            "+return db.query(User).filter_by(id=user_id).first()\n"
        )

        # 1. When no CLI or env key is available -> graceful skipped status
        with patch.dict(os.environ, {}, clear=True), patch("shutil.which", return_value=None):
            self.assertIsNone(detect_ai_provider("auto"))
            res_skip = review_diff_with_ai(sample_diff, provider="auto")
            self.assertEqual(res_skip.status, "skipped")
            self.assertEqual(res_skip.comments, [])

        # 2. When mocked local CLI returns fenced JSON array -> parsed and merged into hybrid review
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = (
            "Here are the findings:\n```json\n"
            '[{"file": "src/api.py", "line": 1, "severity": "P0", '
            '"title": "Unscoped User Lookup", "message": "Filter by tenant_id."}]\n```'
        )
        with patch("shutil.which", return_value="/usr/local/bin/claude"), patch(
            "subprocess.run", return_value=mock_proc
        ):
            comments = run_hybrid_review(sample_diff, enable_ai=True, ai_provider="claude")
            self.assertEqual(len(comments), 1)
            self.assertEqual(comments[0].title, "[AI] Unscoped User Lookup")
            self.assertEqual(comments[0].severity, "P0")


if __name__ == "__main__":
    unittest.main()
