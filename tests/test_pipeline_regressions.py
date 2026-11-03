from __future__ import annotations

from io import StringIO
import importlib.util
import csv
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from steps import step_01_collection as collection
from steps import step_02_parsing as parsing
from steps import step_03_normalize as normalize
from steps import step_04_clean as clean
from steps import step_05_features as features
from steps import step_06_dataset as dataset
from steps import step_07_model as model_menu
from steps import step_07_train as train
from steps import step_08_evaluate as evaluate
from url_detector.model_runtime import ModelRuntime
from url_detector.thresholded import ThresholdManager


class PipelineRegressions(unittest.TestCase):
    @unittest.skipUnless(importlib.util.find_spec("openpyxl"), "openpyxl is not installed in this interpreter")
    def test_excel_parsing_preserves_comma_url(self):
        import openpyxl

        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            source = root / "source.xlsx"
            output = root / "parsed.csv"
            book = openpyxl.Workbook()
            sheet = book.active
            sheet.append(["url", "label"])
            sheet.append(["https://example.test/a,b", "phishing"])
            book.save(source)
            with output.open("w", encoding="utf-8", newline="") as handle:
                count = parsing._process_excel(source, handle, "sample", "agent", None)
            with output.open(encoding="utf-8", newline="") as handle:
                rows = list(csv.reader(handle))
            self.assertEqual(count, 1)
            self.assertEqual(rows[0][:2], ["https://example.test/a,b", "phishing"])

    def test_collection_zip_stream_keeps_first_data_row(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            archive = root / "source.zip"
            with zipfile.ZipFile(archive, "w") as handle:
                handle.writestr("urls.csv", "url,label\nhttps://a.test,benign\n")
            output = root / "collected.jsonl"
            self.assertEqual(collection.collect_single_file(archive, output, 10), 1)
            self.assertIn("https://a.test", output.read_text(encoding="utf-8"))

    def test_headerless_csv_and_comma_url(self):
        output = StringIO()
        count = parsing._process_stream(StringIO('"https://one.test/a,b",phishing\nhttps://two.test/path,benign\n'), output, "source", "agent", None)
        rows = list(csv.reader(StringIO(output.getvalue())))
        self.assertEqual(count, 2)
        self.assertEqual(rows[0][:2], ["https://one.test/a,b", "phishing"])
        self.assertEqual(rows[1][:2], ["https://two.test/path", "benign"])
        output = StringIO()
        parsing._process_stream(StringIO('url,label\n"https://three.test/a,b",malware\n'), output, "source", "agent", None)
        self.assertEqual(list(csv.reader(StringIO(output.getvalue())))[0][:2], ["https://three.test/a,b", "malware"])

    def test_parallel_byte_boundary_and_clean_features(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            parsed = root / "parsed.csv"
            with parsed.open("w", encoding="utf-8", newline="") as handle:
                writer = csv.writer(handle)
                writer.writerow(["url_raw", "label_raw", "url", "label", "_aic211_ipv4", "channel", "source", "source_split"])
                writer.writerows([
                    ["https://a.test/a,b", "benign", "https://a.test/a,b", "benign", "", "agent", "first", ""],
                    ["https://b.test/", "malware", "https://b.test/", "malware", "", "syslog", "second", ""],
                ])
            raw = parsed.read_bytes()
            boundary = raw.rfind(b"\n", 0, raw.find(b"https://b.test/")) + 1
            self.assertGreater(boundary, 0)
            pieces = [root / "a.csv", root / "b.csv"]
            normalize._normalize_slice((str(parsed), 0, boundary, str(pieces[0]), "now"))
            normalize._normalize_slice((str(parsed), boundary, len(raw), str(pieces[1]), "now"))
            rows = []
            for piece in pieces:
                with piece.open(encoding="utf-8", newline="") as handle:
                    rows.extend(csv.reader(handle))
            self.assertEqual(len(rows), 2)
            self.assertEqual(len({row[0] for row in rows}), 2)
            self.assertEqual(rows[0][1], "https://a.test/a,b")

            normalized = root / "normalized.csv"
            with normalized.open("w", encoding="utf-8", newline="") as handle:
                writer = csv.writer(handle)
                writer.writerow(["_aic211_source_row", "url", "label", "timestamp_utc", "channel", "source", "_aic211_ipv4", "source_split"])
                writer.writerows(rows)
                writer.writerow(["9", "https://a.test/a,b", "malicious", "now", "syslog", "other", "", ""])
            cleaned, rejected = root / "cleaned.csv", root / "rejected.csv"
            clean.run_clean(str(normalized), str(cleaned), str(rejected))
            with cleaned.open(encoding="utf-8", newline="") as handle:
                accepted_rows = list(csv.DictReader(handle))
            with rejected.open(encoding="utf-8", newline="") as handle:
                rejected_rows = list(csv.DictReader(handle))
            self.assertEqual(len(accepted_rows), 1)
            self.assertEqual(accepted_rows[0]["url"], "https://b.test/")
            self.assertEqual([row["_aic211_reject_reason"] for row in rejected_rows], ["conflicting_labels", "conflicting_labels"])

            feature_file = root / "features.csv"
            features.run_features(str(cleaned), str(feature_file), max_samples=2)
            with feature_file.open(encoding="utf-8", newline="") as handle:
                feature_rows = list(csv.DictReader(handle))
            self.assertEqual(feature_rows[0]["url"], "https://b.test/")
            self.assertEqual(feature_rows[0]["source"], "second")
            feature_boundary = cleaned.read_bytes().find(b"https://b.test/")
            feature_boundary = cleaned.read_bytes().rfind(b"\n", 0, feature_boundary) + 1
            left, right = root / "features_left.csv", root / "features_right.csv"
            features._features_slice((str(cleaned), 0, feature_boundary, str(left)))
            features._features_slice((str(cleaned), feature_boundary, cleaned.stat().st_size, str(right)))
            with left.open(encoding="utf-8", newline="") as handle:
                left_rows = list(csv.reader(handle))
            with right.open(encoding="utf-8", newline="") as handle:
                right_rows = list(csv.reader(handle))
            self.assertEqual(len(left_rows) + len(right_rows), 1)

    def test_split_groups_and_label_ids(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            source = root / "features.csv"
            with source.open("w", encoding="utf-8", newline="") as handle:
                writer = csv.writer(handle)
                writer.writerow(["url", "label", "label_id", "source_split"])
                writer.writerows([
                    ["http://www.same.test/path/", "benign", "999", ""],
                    ["https://same.test/path", "malware", "999", "test"],
                    ["https://other.test", "defacement", "999", ""],
                    ["https://alias.test", "bad", "999", "train"],
                ])
            with patch.object(dataset, "DATA_PROCESSED_DIR", root):
                meta = dataset.run_dataset_split(str(source), seed=10)
            with (root / "test.csv").open(encoding="utf-8", newline="") as handle:
                test_rows = list(csv.DictReader(handle))
            self.assertEqual(len(test_rows), 2)
            self.assertEqual({row["label_id"] for row in test_rows}, {str(dataset.LABEL_IDS["benign"]), str(dataset.LABEL_IDS["malware"])})
            with (root / "train.csv").open(encoding="utf-8", newline="") as handle:
                train_rows = list(csv.DictReader(handle))
            self.assertEqual(train_rows[0]["label"], "malicious")
            self.assertEqual(train_rows[0]["label_id"], str(dataset.LABEL_IDS["malicious"]))
            self.assertEqual(meta["skipped_rows"]["unknown_label"], 1)

    def test_evaluation_interval_and_no_test_fallback(self):
        low, high = evaluate.wilson_interval(50, 100)
        self.assertLess(low, 0.5)
        self.assertGreater(high, 0.5)
        with tempfile.TemporaryDirectory() as root, patch.object(evaluate, "DATA_PROCESSED_DIR", Path(root)):
            (Path(root) / "val.csv").write_text("url,label\nhttps://a.test,benign\n", encoding="utf-8")
            with self.assertRaises(FileNotFoundError):
                evaluate.run_evaluate()

    def test_train_requires_explicit_train_file_and_menu_uses_all(self):
        with tempfile.TemporaryDirectory() as root, patch.object(train, "DATA_PROCESSED_DIR", Path(root)):
            (Path(root) / "04_features.csv").write_text("url,label\nhttps://a.test,benign\n", encoding="utf-8")
            with self.assertRaises(FileNotFoundError):
                train.run_train()
        with patch("builtins.input", side_effect=["1"]), patch.object(model_menu, "run_train") as run_train, patch.object(train, "prompt_menu_input", return_value=("train.csv", "models", "all", 10, False)) as prompt:
            model_menu.main_interactive()
        prompt.assert_called_once_with(ask_model=False)
        self.assertEqual(run_train.call_args.kwargs["model_choice"], "all")

    def test_runtime_registry_and_threshold_levels(self):
        models = ModelRuntime().list_available_models()
        self.assertEqual(len(models), 3)
        manager = ThresholdManager()
        self.assertEqual(manager.determine_threat_level(0.2)["level"], "safe")
        self.assertEqual(manager.determine_threat_level(0.45)["level"], "suspicious")
        self.assertEqual(manager.determine_threat_level(0.6)["level"], "dangerous")
        self.assertEqual(manager.determine_threat_level(0.9)["level"], "critical")
        with self.assertRaises(ValueError):
            manager.determine_threat_level(float("nan"))

    def test_evaluation_writes_one_plot_and_extended_report(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            metrics = {
                "model": "svm", "accuracy": 0.5, "accuracy_ci95": [0.4, 0.6],
                "threat_detection_rate": 0.8, "false_benign_alarm_rate": 0.1,
                "threat_detection_ci95": [0.7, 0.9], "false_benign_alarm_ci95": [0.05, 0.15],
                "precision_weighted": 0.5, "recall_weighted": 0.5, "weighted_f1": 0.5,
                "macro_precision": 0.5, "macro_recall": 0.5, "macro_f1": 0.5,
                "confusion_matrix": [[1, 0, 0, 0], [0, 1, 0, 0], [0, 0, 1, 0], [0, 0, 0, 1]],
            }
            with patch.object(evaluate, "FIGURES_DIR", root / "figures"), patch.object(evaluate, "METRICS_DIR", root / "metrics"), patch.object(evaluate, "TABLES_DIR", root / "tables"), patch.object(evaluate, "extra_report_dirs", return_value=[]), patch.dict("os.environ", {"AIC_SAVE_LEGACY_CM": ""}):
                evaluate.save_confusion_matrix_plot("svm", metrics)
                evaluate.save_summary_reports([metrics], "test.csv", 4, {"benign": 1})
            self.assertEqual([p.name for p in (root / "figures").glob("*.png")], ["cm_svm.png"])
            report = json.loads((root / "metrics" / "multiclass_summary.json").read_text(encoding="utf-8"))
            self.assertEqual(report["models"][0]["accuracy_ci95"], [0.4, 0.6])
            self.assertIn("Threat_Detection_Rate", (root / "tables" / "models_comparison.csv").read_text(encoding="utf-8"))

    def test_evaluation_threat_and_false_alarm_rates(self):
        class Pipeline:
            def predict(self, urls):
                return [0, 2, 0, 3]

        class Runtime:
            def load_model(self, name):
                return {"pipeline": Pipeline(), "classes": ["benign", "malicious", "phishing", "malware"]}

        with patch.object(evaluate, "save_confusion_matrix_plot"):
            result = evaluate.evaluate_single_model(Runtime(), "svm", ["a", "b", "c", "d"], ["benign", "benign", "malware", "malware"])
        self.assertEqual(result["threat_detection_rate"], 0.5)
        self.assertEqual(result["false_benign_alarm_rate"], 0.5)


if __name__ == "__main__":
    unittest.main()
