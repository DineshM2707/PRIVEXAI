import unittest

from app.detection import assess_risk, contextual_risk_cues, explain_findings, scan_text


class DetectionTests(unittest.TestCase):
    def test_detects_required_categories_and_masks_sample(self):
        sample = (
            "Reach demo.user@example.test at 9876543210. "
            "ID ABCDE1234F; account 123456789012; key sk_test_1234567890abcdef."
        )
        matches, protected = scan_text(sample)

        self.assertEqual(
            set(matches),
            {"email", "phone", "pan_like_id", "account_number", "api_secret"},
        )
        self.assertNotIn("demo.user@example.test", protected)
        self.assertNotIn("9876543210", protected)
        self.assertNotIn("sk_test_1234567890abcdef", protected)
        self.assertIn("[EMAIL REDACTED]", protected)
        self.assertIn("[SECRET REDACTED]", protected)

    def test_detects_aadhaar_like_id(self):
        matches, protected = scan_text("Synthetic ID 1234 5678 9012")
        self.assertIn("aadhaar_like_id", matches)
        self.assertNotIn("1234 5678 9012", protected)

    def test_detects_and_masks_synthetic_student_record(self):
        sample = (
            "Student name: Jamie Rivera; email jamie.rivera@example.test; "
            "phone 9876543210; Student ID: STU-2048; GPA: 3.8"
        )
        matches, protected = scan_text(sample)

        self.assertTrue(
            {"student_name", "email", "phone", "student_id", "academic_record"}.issubset(matches)
        )
        self.assertNotIn("Jamie Rivera", protected)
        self.assertNotIn("jamie.rivera@example.test", protected)
        self.assertNotIn("9876543210", protected)
        self.assertNotIn("STU-2048", protected)
        self.assertNotIn("3.8", protected)

    def test_detects_unlabeled_account_numbers_without_reclassifying_phone(self):
        matches, protected = scan_text(
            "Wire transfer 1234567890123456; contact 9876543210."
        )
        self.assertIn("account_number", matches)
        self.assertIn("phone", matches)
        self.assertNotIn("1234567890123456", protected)
        self.assertNotIn("9876543210", protected)
        self.assertEqual(len(matches["account_number"]), 1)

    def test_ordinary_numbers_are_not_classified_as_account_numbers_without_context(self):
        matches, _ = scan_text("Quarterly report: 2024 students, batch 12345678.")
        self.assertNotIn("account_number", matches)

    def test_explanation_strength_increases_with_matching_context(self):
        labeled, _ = scan_text("PAN: ABCDE1234F")
        unlabeled, _ = scan_text("ABCDE1234F")
        labeled_explanation = explain_findings("PAN: ABCDE1234F", labeled)["pan_like_id"]
        unlabeled_explanation = explain_findings("ABCDE1234F", unlabeled)["pan_like_id"]
        self.assertGreater(labeled_explanation["confidence"], unlabeled_explanation["confidence"])
        self.assertIn("context strengthens", labeled_explanation["explanation"])
        self.assertIn("verify", unlabeled_explanation["explanation"])

    def test_ignores_plain_text_without_sensitive_patterns(self):
        matches, protected = scan_text("Synthetic quarterly report for internal review.")
        self.assertEqual(matches, {})
        self.assertEqual(protected, "Synthetic quarterly report for internal review.")

    def test_limits_preview_and_occurrence_count(self):
        repeated = "a@example.test " * 25
        matches, protected = scan_text(repeated)
        self.assertEqual(len(matches["email"]), 20)
        self.assertLessEqual(len(protected), 500)

    def test_extracts_contextual_sharing_cues(self):
        cues = contextual_risk_cues("Please upload this externally and share the API key.")
        self.assertEqual([cue["points"] for cue in cues], [15, 10])

    def test_plain_context_does_not_add_risk_cues(self):
        self.assertEqual(contextual_risk_cues("Internal quarterly report."), [])

    def test_block_policy_increases_score_and_blocks_unapproved_transfer(self):
        score, severity, decision, factors = assess_risk(
            {"pan_like_id": ["ABCDE1234F"]},
            {"pan_like_id": {"action": "block", "weight": 35}},
            False,
            "internal",
            "ABCDE1234F",
        )
        self.assertEqual((score, severity, decision), (60, "high", "block"))
        self.assertEqual(len(factors), 2)

    def test_mask_policy_masks_even_at_low_authorized_risk(self):
        score, severity, decision, _ = assess_risk(
            {"email": ["analyst@example.test"]},
            {"email": {"action": "mask", "weight": 15}},
            True,
            "internal",
            "analyst@example.test",
        )
        self.assertEqual((score, severity, decision), (5, "low", "mask"))

    def test_scores_are_capped_and_clean_authorized_sample_is_allowed(self):
        score, _, decision, _ = assess_risk(
            {category: ["value"] * 3 for category in ("api_secret", "email", "phone")},
            {
                "api_secret": {"action": "block", "weight": 100},
                "email": {"action": "block", "weight": 100},
                "phone": {"action": "mask", "weight": 100},
            },
            False,
            "public",
            "publicly upload",
        )
        self.assertEqual((score, decision), (100, "block"))
        clean_score, clean_severity, clean_decision, _ = assess_risk(
            {}, {}, True, "internal", "Quarterly report."
        )
        self.assertEqual((clean_score, clean_severity, clean_decision), (0, "low", "allow"))

    def test_high_contextual_risk_without_findings_requires_review(self):
        score, severity, decision, _ = assess_risk(
            {},
            {},
            False,
            "public",
            "Please share this synthetic report publicly.",
        )
        self.assertEqual((score, severity, decision), (60, "high", "review"))


if __name__ == "__main__":
    unittest.main()
