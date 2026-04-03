# Copyright The Cloud Custodian Authors.
# SPDX-License-Identifier: Apache-2.0
import io
from datetime import datetime
from unittest.mock import MagicMock

from c7n.reports.csvout import Formatter, _policy_report_fields, report, strip_output_path
from .common import BaseTest, load_data


class TestEC2Report(BaseTest):

    def setUp(self):
        data = load_data("report.json")
        self.records = data["ec2"]["records"]
        self.headers = data["ec2"]["headers"]
        self.rows = data["ec2"]["rows"]
        self.p = self.load_policy({"name": "report-test-ec2", "resource": "ec2"})

    def test_default_csv(self):
        self.patch(self.p.resource_manager.resource_type,
                   'default_report_fields', ())
        formatter = Formatter(self.p.resource_manager.resource_type)
        self.assertEqual(
            formatter.to_csv([self.records['full']]),
            [['InstanceId-1', '', 'LaunchTime-1']])

    def test_csv(self):
        p = self.load_policy({"name": "report-test-ec2", "resource": "ec2"})
        formatter = Formatter(p.resource_manager.resource_type)
        tests = [
            (["full"], ["full"]),
            (["minimal"], ["minimal"]),
            (["full", "minimal"], ["full", "minimal"]),
            (["full", "duplicate", "minimal"], ["full", "minimal"]),
        ]
        for rec_ids, row_ids in tests:
            recs = list(map(lambda x: self.records[x], rec_ids))
            rows = list(map(lambda x: self.rows[x], row_ids))
            self.assertEqual(formatter.to_csv(recs), rows)

    def test_custom_fields(self):
        # Test the ability to include custom fields.
        extra_fields = [
            "custom_field=CustomField",
            "missing_field=MissingField",
            "custom_tag=tag:CustomTag",
        ]

        # First do a test with adding custom fields to the normal ones
        formatter = Formatter(
            self.p.resource_manager.resource_type, extra_fields=extra_fields
        )
        recs = [self.records["full"]]
        rows = [self.rows["full_custom"]]
        self.assertEqual(formatter.to_csv(recs), rows)

        # Then do a test with only having custom fields
        formatter = Formatter(
            self.p.resource_manager.resource_type,
            extra_fields=extra_fields,
            include_default_fields=False,
        )
        recs = [self.records["full"]]
        rows = [self.rows["minimal_custom"]]
        self.assertEqual(formatter.to_csv(recs), rows)

    def test_formatter_jmespath_key(self):
        # models a k8s resource, or any that has a jmespath expression for
        # their id and name
        class FakeResource:
            class TypeInfo:
                id = 'metadata.uid'
                name = 'metadata.name'

        formatter = Formatter(
            resource_type=FakeResource.TypeInfo
        )
        records = [
            {'metadata': {'uid': 'foo', 'name': 'bar'}},
            {'metadata': {'uid': 'foo', 'name': 'bar'}}
        ]
        result = formatter.uniq_by_id(records=records)
        self.assertEqual(len(result), 1)


class TestPolicyReportFields(BaseTest):
    """Tests for extracting report fields defined in the policy YAML."""

    def _make_policy(self, report_cfg):
        """Return a minimal mock policy with the given ``report`` config."""
        p = MagicMock()
        p.data = {'report': report_cfg} if report_cfg is not None else {}
        return p

    def test_no_report_config(self):
        p = self._make_policy(None)
        self.assertEqual(_policy_report_fields(p), [])

    def test_empty_fields(self):
        p = self._make_policy({'fields': []})
        self.assertEqual(_policy_report_fields(p), [])

    def test_plain_string_field(self):
        # A plain string without '=' should expand to "Name=Name".
        p = self._make_policy({'fields': ['VpcId']})
        self.assertEqual(_policy_report_fields(p), ['VpcId=VpcId'])

    def test_string_field_with_equals(self):
        # A string already in HEADER=jmespath format must pass through as-is.
        p = self._make_policy({'fields': ['Email=Tags[?Key==`Email`].Value | [0]']})
        self.assertEqual(
            _policy_report_fields(p),
            ['Email=Tags[?Key==`Email`].Value | [0]'],
        )

    def test_dict_field(self):
        # A single-key dict should become "Header=jmespath".
        p = self._make_policy({'fields': [{'AccessKey0Active': '"c7n:matched-keys"[0].active'}]})
        self.assertEqual(
            _policy_report_fields(p),
            ['AccessKey0Active="c7n:matched-keys"[0].active'],
        )

    def test_mixed_fields(self):
        p = self._make_policy({
            'fields': [
                'VpcId',
                'Email=Tags[?Key==`Email`].Value | [0]',
                {'AccessKey0Active': '"c7n:matched-keys"[0].active'},
            ]
        })
        self.assertEqual(
            _policy_report_fields(p),
            [
                'VpcId=VpcId',
                'Email=Tags[?Key==`Email`].Value | [0]',
                'AccessKey0Active="c7n:matched-keys"[0].active',
            ],
        )


class TestPolicyReportIntegration(BaseTest):
    """Integration tests for the report() function using policy-level fields."""

    def _make_options(self, field=(), no_default_fields=False, all_findings=False,
                      format='csv', raw=None):
        opts = MagicMock()
        opts.field = list(field)
        opts.no_default_fields = no_default_fields
        opts.all_findings = all_findings
        opts.format = format
        opts.raw = raw
        return opts

    def test_report_uses_policy_fields(self):
        """Fields defined in ``report.fields`` appear in the CSV output."""
        data = load_data("report.json")
        record = data["ec2"]["records"]["full"]

        p = self.load_policy({
            "name": "report-policy-fields",
            "resource": "ec2",
            "report": {
                "fields": [
                    "CustomField",
                    {"custom_tag": "tag:CustomTag"},
                ],
            },
        })

        from c7n.reports import csvout
        self.patch(csvout, 'fs_record_set', lambda *a, **kw: [record])

        p.ctx.initialize()
        options = self._make_options()
        out = io.StringIO()
        report([p], datetime(2000, 1, 1), options, out)

        output = out.getvalue()
        # Default EC2 fields should still appear.
        self.assertIn("InstanceId", output)
        # Policy-level custom fields should also appear.
        self.assertIn("CustomField", output)
        self.assertIn("custom_tag", output)
        self.assertIn("CustomValue", output)
        self.assertIn("Custom-1", output)

    def test_report_default_fields_false(self):
        """Setting ``default_fields: false`` in the policy excludes default columns."""
        data = load_data("report.json")
        record = data["ec2"]["records"]["full"]

        p = self.load_policy({
            "name": "report-no-defaults",
            "resource": "ec2",
            "report": {
                "default_fields": False,
                "fields": [{"CustomField": "CustomField"}],
            },
        })

        from c7n.reports import csvout
        self.patch(csvout, 'fs_record_set', lambda *a, **kw: [record])

        p.ctx.initialize()
        options = self._make_options()
        out = io.StringIO()
        report([p], datetime(2000, 1, 1), options, out)

        output = out.getvalue()
        # Only the custom column header should be present.
        self.assertIn("CustomField", output)
        # The default EC2 InstanceId column must NOT appear.
        self.assertNotIn("InstanceId", output)

    def test_cli_field_supplements_policy_fields(self):
        """CLI ``--field`` args are appended after policy-level fields."""
        data = load_data("report.json")
        record = data["ec2"]["records"]["full"]

        p = self.load_policy({
            "name": "report-cli-supplement",
            "resource": "ec2",
            "report": {
                "fields": [{"CustomField": "CustomField"}],
            },
        })

        from c7n.reports import csvout
        self.patch(csvout, 'fs_record_set', lambda *a, **kw: [record])

        p.ctx.initialize()
        # Pass an additional field via options (simulating --field).
        options = self._make_options(field=["custom_tag=tag:CustomTag"])
        out = io.StringIO()
        report([p], datetime(2000, 1, 1), options, out)

        output = out.getvalue()
        self.assertIn("CustomField", output)
        self.assertIn("custom_tag", output)

    def test_policy_report_schema_valid(self):
        """A policy with a ``report`` block passes schema validation."""
        p = self.load_policy({
            "name": "report-schema-check",
            "resource": "ec2",
            "report": {
                "default_fields": True,
                "fields": [
                    "VpcId",
                    "Email=Tags[?Key==`Email`].Value | [0]",
                    {"AccessKey0Active": '"c7n:matched-keys"[0].active'},
                ],
            },
        })
        self.assertIsNotNone(p)


class TestASGReport(BaseTest):

    def setUp(self):
        data = load_data("report.json")
        self.records = data["asg"]["records"]
        self.headers = data["asg"]["headers"]
        self.rows = data["asg"]["rows"]

    def test_csv(self):
        p = self.load_policy({"name": "report-test-asg", "resource": "asg"})
        formatter = Formatter(p.resource_manager.resource_type)
        tests = [
            (["full"], ["full"]),
            (["minimal"], ["minimal"]),
            (["full", "minimal"], ["full", "minimal"]),
            (["full", "duplicate", "minimal"], ["full", "minimal"]),
        ]
        for rec_ids, row_ids in tests:
            recs = list(map(lambda x: self.records[x], rec_ids))
            rows = list(map(lambda x: self.rows[x], row_ids))
            self.assertEqual(formatter.to_csv(recs), rows)


class TestELBReport(BaseTest):

    def setUp(self):
        data = load_data("report.json")
        self.records = data["elb"]["records"]
        self.headers = data["elb"]["headers"]
        self.rows = data["elb"]["rows"]

    def test_csv(self):
        p = self.load_policy({"name": "report-test-elb", "resource": "elb"})
        formatter = Formatter(p.resource_manager.resource_type)
        tests = [
            (["full"], ["full"]),
            (["minimal"], ["minimal"]),
            (["full", "minimal"], ["full", "minimal"]),
            (["full", "duplicate", "minimal"], ["full", "minimal"]),
        ]
        for rec_ids, row_ids in tests:
            recs = list(map(lambda x: self.records[x], rec_ids))
            rows = list(map(lambda x: self.rows[x], row_ids))
            self.assertEqual(formatter.to_csv(recs), rows)


class TestMultiReport(BaseTest):

    def setUp(self):
        data = load_data("report.json")
        self.records = data["ec2"]["records"]
        self.headers = data["ec2"]["headers"]
        self.rows = data["ec2"]["rows"]

    def test_csv(self):
        # Test the extra headers for multi-policy
        p = self.load_policy({"name": "report-test-ec2", "resource": "ec2"})
        formatter = Formatter(
            p.resource_manager.resource_type,
            include_region=True,
            include_policy=True,
        )
        tests = [(["minimal"], ["minimal_multipolicy"])]
        for rec_ids, row_ids in tests:
            recs = list(map(lambda x: self.records[x], rec_ids))
            rows = list(map(lambda x: self.rows[x], row_ids))
            self.assertEqual(formatter.to_csv(recs), rows)

    def test_s3_base_output_path(self):
        """When searching S3 to populate a report, the base output path
        should end with the policy name."""

        policy_name = "my_c7n_policy"
        output_paths = [
            f"logs/{policy_name}",
            f"/logs/{policy_name}",
            f"logs/{policy_name}/2021/01/01/01/",
            f"/logs/{policy_name}/with/more/extra/path/segments",
        ]

        self.assertTrue(all(
            strip_output_path(p, policy_name) == f"logs/{policy_name}"
            for p in output_paths
        ))

