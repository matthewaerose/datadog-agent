import unittest

from pydantic import ValidationError

from tasks.libs.gpu.types import GPUConfig, GPUConfigValidationResult, GPUConfigValidationState, Metric, MetricValidator
from tasks.libs.gpu.validation import determine_result_state


class TestMetricValidatorSchema(unittest.TestCase):
    def test_accepts_range_validator(self):
        metric = Metric.model_validate(
            {
                "tagsets": ["device"],
                "support": {"device_modes": {"physical": True}},
                "validator": {"range": {"min": 0, "max": 100}},
            }
        )
        self.assertIsNotNone(metric.validator)
        self.assertIsNone(metric.validator.validate(50))
        self.assertIsNotNone(metric.validator.validate(101))

    def test_accepts_values_validator(self):
        metric = Metric.model_validate(
            {
                "tagsets": ["device"],
                "support": {"device_modes": {"physical": True}},
                "validator": {"values": [0, 1]},
            }
        )
        self.assertIsNotNone(metric.validator)
        self.assertIsNone(metric.validator.validate(1))
        self.assertIsNotNone(metric.validator.validate(2))

    def test_rejects_both_range_and_values(self):
        with self.assertRaises(ValidationError):
            Metric.model_validate(
                {
                    "tagsets": ["device"],
                    "support": {"device_modes": {"physical": True}},
                    "validator": {"range": {"min": 0, "max": 1}, "values": [0, 1]},
                }
            )

    def test_rejects_empty_validator(self):
        with self.assertRaises(ValidationError):
            Metric.model_validate(
                {
                    "tagsets": ["device"],
                    "support": {"device_modes": {"physical": True}},
                    "validator": {},
                }
            )


class TestValidationState(unittest.TestCase):
    def test_metric_value_failures_mark_result_as_failed(self):
        result = GPUConfigValidationResult(
            config=GPUConfig(architecture="hopper", device_mode="physical"),
            device_count=1,
            expected_metrics={"gpu.sm_active"},
            present_metrics={"gpu.sm_active"},
            metric_value_failures={"gpu.sm_active": ["value 101 is outside inclusive range [0, 100]"]},
        )

        self.assertTrue(result.has_failures)
        self.assertEqual(determine_result_state(result), GPUConfigValidationState.FAIL)


class TestMetricValidatorLogic(unittest.TestCase):
    def test_values_validator_returns_human_readable_failure(self):
        validator = MetricValidator.model_validate({"values": [0, 1]})

        self.assertEqual(
            validator.validate(2),
            "value 2 is not one of the allowed values [0.0, 1.0]",
        )


if __name__ == "__main__":
    unittest.main()
