"""Regression checks for feature accuracy and host-scoped decisions.

No native ML imports: a fixed detector isolates packet/rule behaviour and does
not claim to measure model accuracy. Firewall commands are never executed.
"""
import importlib
import json
import random
import sys
import types
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from scapy.layers.inet import IP, TCP

from packetwatch import config
from packetwatch.features import DST_CAP, PORT_CAP, SourceWindow
from packetwatch.pipeline import Pipeline
from packetwatch.response import Alerter, FirewallBlocker
from packetwatch.thresholds import CEILINGS, FLOORS, load_thresholds
from packetwatch.verify import verify_vector

HOST = "192.168.50.10"
REMOTE = "192.168.50.66"


class DistinctFeatureTests(unittest.TestCase):
    def test_repeated_ports_across_seconds_do_not_saturate(self):
        window = SourceWindow()
        for second in range(1000, 1010):
            for port in range(2000, 2030):
                window.add(second, port, HOST, 6, False, 100)
        self.assertEqual(window.unique_dst_ports(), 30)
        with patch.object(config, "PORT_SCAN_THRESHOLD", 200):
            self.assertNotIn("port_scan", [hit.rule for hit in verify_vector(window.extract())])

    def test_repeated_destinations_across_seconds_are_deduplicated(self):
        window = SourceWindow()
        for second in range(1000, 1010):
            for host in range(1, 9):
                window.add(second, 80, f"10.0.0.{host}", 6, False, 100)
        self.assertEqual(window.extract()[3], 8)

    def test_saturation_expires_without_new_packets(self):
        window = SourceWindow()
        for port in range(PORT_CAP + 20):
            window.add(1000, port, f"10.0.{port // 256}.{port % 256}", 6, True, 40)
        self.assertEqual(window.unique_dst_ports(), PORT_CAP)
        self.assertEqual(window.extract()[3], DST_CAP)
        window.prune(1011)
        self.assertEqual(window.extract(), [0] * 10)

    def test_expired_saturated_bucket_does_not_hide_quiet_bucket(self):
        window = SourceWindow()
        for port in range(PORT_CAP + 20):
            window.add(1000, port, HOST, 6, True, 40)
        window.add(1009, 443, HOST, 6, False, 100)
        window.prune(1010)
        self.assertEqual(window.unique_dst_ports(), 1)
        self.assertEqual(window.dst_ports(), {443})

    def test_counts_match_reference_under_rotation_and_saturation(self):
        rng = random.Random(18)
        window = SourceWindow()
        packets = []
        for second in range(1000, 1035):
            for _ in range(rng.randint(5, 400)):
                port = rng.randrange(400)
                dst = f"10.0.0.{rng.randrange(100)}"
                window.add(second, port, dst, 6, False, 100)
                packets.append((second, port, dst))
            current = [p for p in packets if p[0] >= second - 9]
            self.assertEqual(window.extract()[2], min(PORT_CAP, len({p[1] for p in current})))
            self.assertEqual(window.extract()[3], min(DST_CAP, len({p[2] for p in current})))
            self.assertLessEqual(sum(map(len, window._ports)), 10 * PORT_CAP)
            self.assertLessEqual(sum(map(len, window._dsts)), 10 * DST_CAP)


class AlwaysFlags:
    def predict_many(self, vectors):
        return [{"dt": True, "nb": False, "dt_proba": 1.0,
                 "nb_proba": 0.0, "flagged": True} for _ in vectors]


class HostScopeTests(unittest.TestCase):
    def make_pipeline(self, destinations):
        self.runner = Mock(side_effect=AssertionError("must never call netsh"))
        blocker = FirewallBlocker(dry_run=True, ttl_min=0, runner=self.runner)
        return Pipeline(AlwaysFlags(), blocker, Alerter(log_path=None, console=False),
                        own_addresses={HOST}, destination_addresses=destinations,
                        clock=lambda: 1000.0)

    def scan(self, pipeline, destination):
        for port in range(2000, 2020):
            pipeline.handle(IP(src=REMOTE, dst=destination) / TCP(dport=port, flags="S"))
        pipeline.sweep(force=True)

    def test_unrelated_and_broadcast_traffic_is_not_judged(self):
        for destination in ("192.168.50.20", "192.168.50.1", "255.255.255.255", "224.0.0.1"):
            with self.subTest(destination=destination):
                pipeline = self.make_pipeline({HOST})
                self.scan(pipeline, destination)
                self.assertFalse(pipeline.windows)
                self.assertEqual(pipeline.stats["judged"], 0)
                self.assertFalse(pipeline.blocker.blocked)

    def test_scan_to_host_still_confirms(self):
        pipeline = self.make_pipeline({HOST})
        self.scan(pipeline, HOST)
        self.assertIn(REMOTE, pipeline.blocker.blocked)
        self.runner.assert_not_called()

    def test_all_explicit_host_addresses_are_accepted(self):
        secondary = "10.0.0.10"
        pipeline = self.make_pipeline({HOST, secondary})
        self.scan(pipeline, secondary)
        self.assertIn(REMOTE, pipeline.blocker.blocked)

    def test_empty_scope_does_not_fall_back_to_all_traffic(self):
        pipeline = self.make_pipeline(set())
        self.scan(pipeline, HOST)
        self.assertFalse(pipeline.windows)

    def test_offline_unscoped_api_is_preserved(self):
        pipeline = self.make_pipeline(None)
        self.scan(pipeline, "192.168.50.20")
        self.assertIn(REMOTE, pipeline.blocker.blocked)


class CalibrationLoadingTests(unittest.TestCase):
    def load(self, values):
        path = Mock()
        path.read_text.return_value = json.dumps(values)
        return load_thresholds(path)

    def test_valid_boundaries_and_metadata_survive(self):
        for limits in (FLOORS, CEILINGS):
            values = dict(limits, calibrated_at="example")
            self.assertEqual(self.load(values), values)

    def test_invalid_field_rejects_entire_file(self):
        for value in (0, -1, True, None, "10", 10.5, 201):
            with self.subTest(value=value), self.assertLogs("packetwatch.config", "WARNING"):
                self.assertEqual(self.load(dict(FLOORS, port_scan=value)), {})

    def test_missing_fields_and_non_objects_rejected(self):
        for value in ({"port_scan": 10}, [], None, "invalid"):
            with self.subTest(value=value), self.assertLogs("packetwatch.config", "WARNING"):
                self.assertEqual(self.load(value), {})

    def test_malformed_or_unreadable_file_uses_defaults(self):
        for error in (OSError("unreadable"), UnicodeError("bad encoding")):
            path = Mock()
            path.read_text.side_effect = error
            with self.assertLogs("packetwatch.config", "WARNING"):
                self.assertEqual(load_thresholds(path), {})
        path = Mock()
        path.read_text.return_value = "{invalid"
        with self.assertLogs("packetwatch.config", "WARNING"):
            self.assertEqual(load_thresholds(path), {})

    def test_partial_file_cannot_partially_replace_config(self):
        try:
            with patch.object(Path, "exists", return_value=True), patch.object(
                Path, "read_text", return_value='{"port_scan": 50, "flood_pps": "bad"}'
            ), self.assertLogs("packetwatch.config", "WARNING"):
                importlib.reload(config)
            self.assertEqual((config.PORT_SCAN_THRESHOLD, config.FLOOD_PPS_THRESHOLD,
                              config.SUSPICIOUS_PORT_THRESHOLD), (10, 100, 3))
            self.assertEqual(config.CALIBRATED, {})
        finally:
            importlib.reload(config)


class LiveScopeWiringTests(unittest.TestCase):
    def test_cli_separates_gateway_whitelist_from_host_destinations(self):
        from packetwatch.__main__ import main

        gateway = "192.168.50.1"
        fake_model = types.ModuleType("packetwatch.model")
        fake_model.Detector = Mock()
        with patch.dict(sys.modules, {"packetwatch.model": fake_model}), patch(
            "packetwatch.capture.preflight"
        ), patch("packetwatch.capture.start_capture"), patch(
            "packetwatch.response.local_addresses", side_effect=[{HOST, gateway}, {HOST}]
        ) as addresses, patch("packetwatch.pipeline.Pipeline") as pipeline, patch(
            "packetwatch.__main__.threading.Thread"
        ), patch("builtins.print"):
            main(["--dry-run", "--timeout", "1"])
            self.assertEqual(pipeline.call_args.kwargs["destination_addresses"], {HOST})
            self.assertIn(gateway, pipeline.call_args.args[1].whitelist)
            self.assertEqual(addresses.call_args_list[1].kwargs, {"include_gateway": False})

    def test_cli_refuses_empty_host_scope_before_loading_models(self):
        from packetwatch.__main__ import main

        with patch("packetwatch.capture.preflight"), patch(
            "packetwatch.response.local_addresses", return_value=set()
        ), self.assertRaisesRegex(SystemExit, "could not identify"):
            main(["--dry-run"])


class CalibrationScopeTests(unittest.TestCase):
    def test_calibration_excludes_outgoing_and_unrelated_traffic(self):
        from packetwatch.calibrate import Collector

        collector = Collector(clock=lambda: 1000.0, own_addresses={HOST},
                              destination_addresses={HOST})
        for source, destination in ((HOST, REMOTE), (REMOTE, "192.168.50.20")):
            collector.handle(IP(src=source, dst=destination) / TCP(dport=22))
        self.assertFalse(collector.windows)
        self.assertFalse(collector.samples)

    def test_calibration_collects_inbound_host_traffic(self):
        from packetwatch.calibrate import Collector

        collector = Collector(clock=lambda: 1000.0, own_addresses={HOST},
                              destination_addresses={HOST})
        collector.handle(IP(src=REMOTE, dst=HOST) / TCP(dport=443))
        self.assertIn(REMOTE, collector.windows)
        self.assertEqual(collector.samples[0][0], 1)


if __name__ == "__main__":
    unittest.main()
