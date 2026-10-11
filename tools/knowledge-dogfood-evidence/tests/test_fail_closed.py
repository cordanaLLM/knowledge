#!/usr/bin/env python3
"""Fail-closed tests: an unavailable signal is recorded as unavailable, not zero."""

from __future__ import annotations

import hashlib
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import collect  # noqa: E402


class DeadCluster(collect.Cluster):
    """Every signal fails. Models a lost cluster / missing kubectl.

    Only kubectl_json and broker_session are stubbed: every other read is
    expected to funnel through kubectl_json, so a probe that bypasses the
    guard shows up here as an unexpected live cluster call.
    """

    def __init__(self, reason: str = "cluster unreachable") -> None:
        super().__init__(kubectl=True)
        self.reason = reason

    def kubectl_json(self, args, timeout: int = 30):
        raise collect.ProbeError(self.reason)

    def broker_session(self, pod, args, session, drive):
        raise collect.ProbeError(self.reason)


class DeadRepo(collect.Repo):
    """The local clone is unreadable. Models a detached or missing checkout."""

    def __init__(self, reason: str = "repository unreadable") -> None:
        super().__init__(enabled=True)
        self.reason = reason

    def read_bytes(self, relative):
        raise collect.ProbeError(self.reason)

    def git(self, args, timeout: int = 60):
        raise collect.ProbeError(self.reason)

    def verify_sshsig(self, payload, signature, trust_root, actor, namespace):
        raise collect.ProbeError(self.reason)


POD = {
    "metadata": {"name": "knowledge-mcp-test"},
    "spec": {
        "nodeName": "k8s-worker-office-3",
        "volumes": [{"name": "repo", "emptyDir": {}}],
        "containers": [
            {
                "name": "git-sync",
                "args": ["--repo=git@example:x.git", "--ref=main", "--period=60s"],
            }
        ],
    },
    "status": {
        # node-exporter series are labelled by this IP, not by nodeName.
        "hostIP": "198.51.100.102",
        "containerStatuses": [
            {
                "name": "knowledge-mcp",
                "image": "sha256:" + "a" * 64,
                "imageID": "harbor/knowledge-mcp@sha256:" + "b" * 64,
                "state": {"running": {"startedAt": "2026-07-20T09:00:00Z"}},
            }
        ],
    },
}


class PodOnlyCluster(DeadCluster):
    """The Pod is visible but the broker itself does not answer."""

    POD = POD

    def kubectl_json(self, args, timeout: int = 30):
        if args[:2] == ["get", "pods"]:
            return {"items": [dict(self.POD, status=dict(self.POD["status"], phase="Running"))]}
        raise collect.ProbeError(self.reason)


FILE_BODY = "alpha\nbeta\ngamma\n"
FILE_LINES = "alpha\nbeta\ngamma"
FILE_SHA = "sha256:" + hashlib.sha256(FILE_BODY.encode()).hexdigest()
INDEXED_PATH = "docs/example.md"


def evidence(path=INDEXED_PATH, start=1, end=3, sha=FILE_SHA, snippet=FILE_LINES):
    return {
        "path": path,
        "start_line": start,
        "end_line": end,
        "sha256": sha,
        "snippet": snippet,
        "truncated": False,
    }


class ServingCluster(PodOnlyCluster):
    """A broker that answers every planned call with a well-formed result."""

    def __init__(self, reason: str = "cluster unreachable") -> None:
        super().__init__(reason)
        self.calls: list[str] = []
        self.forbidden_paths: set[str] | None = None
        self.hit_sha = FILE_SHA
        self.hit_snippet = FILE_LINES

    def _forbidden(self, path: str) -> bool:
        if self.forbidden_paths is not None:
            return path in self.forbidden_paths
        return path not in collect.ACL_POSITIVE_CONTROLS and path != INDEXED_PATH

    def _answer(self, call):
        if call["name"] == "knowledge_status":
            return False, {
                "repository": {
                    "index_usage": {
                        "token_occurrences": 4790000,
                        "chunks": 43681,
                        "unique_terms": 123000,
                        "files_indexed": 4462,
                        "source_bytes": 39100000,
                    },
                    "index_limits": {"token_occurrences": 8000000},
                },
                "process_memory": {"vmrss_bytes": 457000000, "go_heap_inuse_bytes": 301000000},
                "registry": {"state": "disabled"},
            }
        if call["name"] == "knowledge_search":
            return False, {
                "hits": [evidence(sha=self.hit_sha, snippet=self.hit_snippet)],
                "result_count": 1,
            }
        path = call["arguments"]["path"]
        if self._forbidden(path):
            return True, {"state": "forbidden", "message": "path is not an indexed file"}
        return False, {
            "evidence": evidence(
                path=path,
                start=call["arguments"].get("start_line", 1),
                end=call["arguments"].get("end_line") or 3,
                sha=self.hit_sha,
                snippet=self.hit_snippet,
            ),
            "line_count": 3,
            "size_bytes": len(FILE_BODY),
        }

    def broker_session(self, pod, args, session, drive):
        session.initialize_seconds = 10.5
        while True:
            call = drive(session)
            if call is None:
                return
            self.calls.append(call["key"])
            is_error, structured = self._answer(call)
            session.results.append(
                {
                    "key": call["key"],
                    "name": call["name"],
                    "arguments": call["arguments"],
                    "elapsed_seconds": 0.1 + len(session.results) * 0.01,
                    "structured": structured,
                    "is_error": is_error,
                    "failure": None,
                }
            )

    def prom_query(self, query):
        return []


class StaticRepo(collect.Repo):
    """A local clone that answers the exact reads the collector performs."""

    def __init__(self, tracked=None, values_digest="sha256:" + "b" * 64) -> None:
        super().__init__(enabled=True)
        self.tracked = tracked if tracked is not None else [
            "sealed-secrets/sealed/pg.sealed.yaml",
            "terraform/vms.auto.tfvars",
            "ansible/vault.yml",
            "cluster/tls/ca.pem",
            "kubeconfig",
            "knowledge/registry/x/sha256/ab/abc.json",
            INDEXED_PATH,
        ]
        self.values_digest = values_digest
        self.receipt = {
            "receipt_id": "retrieval-multidomain-evaluation-receipt:sha256:" + "f" * 64,
            "receipt_kind": "retrieval_multidomain_evaluation_receipt",
            "state": "passed",
            "evaluated_at": "2026-07-18T00:00:00Z",
            "evaluator_revision": "retrieval-multidomain-evaluator@1.0.0",
            "suite_id": "multidomain-evaluation-suite:sha256:" + "5" * 64,
            "metric_algorithm": "macro-recall-mrr-ndcg-fixed-point@1.0.0",
            "metric_scale": 1000000,
            "cutoff_k": 10,
            "promotable": False,
            "execution_authorized": False,
            "gates": {"held_out_quality": True},
            "aggregate_metrics": [
                {
                    "class": "cilium",
                    "profile": "baseline",
                    "query_count": 4,
                    "recall_ppm": 1000000,
                    "mrr_ppm": 1000000,
                    "ndcg_ppm": 1000000,
                    "threshold_passed": True,
                }
            ],
            "authorization": {
                "actor": "evaluator@example.com",
                "namespace": "archeion-retrieval-multidomain-evaluation-v1",
                "key_id": "SHA256:test",
                "method": "sshsig-ed25519-detached",
                "allowed_signers_sha256": "sha256:"
                + hashlib.sha256(b"trust-root\n").hexdigest(),
            },
        }

    def read_bytes(self, relative):
        if relative == collect.CORRECTNESS_RECEIPT:
            return json.dumps(self.receipt).encode()
        if relative == collect.CORRECTNESS_TRUST_ROOT:
            return b"trust-root\n"
        if relative == collect.CORRECTNESS_AUDIT:
            return b"| kubernetes | 1.000/1.000/1.000 |\n"
        raise collect.ProbeError(f"unexpected read of {relative}")

    def git(self, args, timeout: int = 60):
        if args[:1] == ["rev-parse"]:
            return "1" * 40 + "\n"
        if args[:1] == ["ls-tree"]:
            return "\n".join(self.tracked) + "\n"
        if args[:1] == ["show"]:
            return (
                "image:\n"
                "  repository: registry.example.com/library/knowledge-mcp\n"
                f'  digest: "{self.values_digest}"\n'
            )
        raise collect.ProbeError(f"unexpected git {args}")

    def verify_sshsig(self, payload, signature, trust_root, actor, namespace):
        return f'Good "{namespace}" signature for {actor}'


class ArgoCluster(ServingCluster):
    """Adds the ArgoCD Application the rollback category reads."""

    def __init__(self, revisions=None) -> None:
        super().__init__()
        self.revisions = revisions if revisions is not None else ["aaa", "bbb", "ccc"]

    def kubectl_json(self, args, timeout: int = 30):
        if args[:3] == ["get", "application.argoproj.io", collect.BROKER_APPLICATION]:
            return {
                "spec": {
                    "source": {"targetRevision": "main", "path": "apps/ai/knowledge-mcp"},
                    "syncPolicy": {"automated": {"prune": True, "selfHeal": True}},
                },
                "status": {
                    "sync": {"status": "Synced", "revision": self.revisions[-1]},
                    "health": {"status": "Healthy"},
                    "history": [
                        {"revision": revision, "deployedAt": f"2026-07-{20 + index:02d}T00:00:00Z"}
                        for index, revision in enumerate(self.revisions)
                    ],
                },
            }
        return super().kubectl_json(args, timeout)


def signals(artifact, category):
    return artifact["categories"][category]["signals"]


class TestFailClosed(unittest.TestCase):
    def build(self, cluster, repo=None):
        artifact = collect.build(cluster, ["--mcp-sdk"], local=False, repo=repo or DeadRepo())
        collect.validate(artifact)
        return artifact

    def test_total_outage_records_every_signal_unavailable(self):
        artifact = self.build(DeadCluster())
        for category in collect.CATEGORIES:
            for key, entry in signals(artifact, category).items():
                with self.subTest(category=category, signal=key):
                    if key == "index_refresh_mechanism":
                        continue  # a code-derived constant, not a probed signal
                    self.assertEqual(entry["state"], "unavailable")
                    self.assertIsNone(entry["value"])
                    self.assertTrue(entry["reason"])
                    self.assertTrue(entry["provenance"])

    def test_unavailable_is_never_zero(self):
        """The regression this suite exists for: absent must not read as 0."""
        artifact = self.build(DeadCluster())
        for category in collect.CATEGORIES:
            for key, entry in signals(artifact, category).items():
                with self.subTest(category=category, signal=key):
                    if entry["state"] != "unavailable":
                        continue
                    self.assertNotEqual(entry["value"], 0)
                    self.assertNotEqual(entry["value"], "0")
                    self.assertNotEqual(entry["value"], [])
                    self.assertNotEqual(entry["value"], {})

    def test_every_category_has_an_unavailable_path(self):
        """Each of the ten categories must survive a total outage with signals."""
        artifact = self.build(DeadCluster())
        for category in collect.CATEGORIES:
            with self.subTest(category=category):
                entries = signals(artifact, category)
                self.assertTrue(entries)
                self.assertTrue(
                    any(entry["state"] == "unavailable" for entry in entries.values())
                )

    def test_no_signal_is_silently_omitted(self):
        """Every category keeps its full signal set even in total outage."""
        live = collect.build(PodOnlyCluster(), ["--mcp-sdk"], local=False, repo=StaticRepo())
        dead = collect.build(DeadCluster(), ["--mcp-sdk"], local=False, repo=DeadRepo())
        for category in collect.CATEGORIES:
            with self.subTest(category=category):
                self.assertTrue(set(signals(dead, category)))
                self.assertTrue(set(signals(live, category)))

    def test_outage_reason_is_propagated(self):
        artifact = self.build(DeadCluster("apiserver timeout"))
        entry = signals(artifact, "token")["indexed_token_occurrences"]
        self.assertIn("apiserver timeout", entry["reason"])

    def test_run_target_records_unavailable_broker(self):
        artifact = self.build(DeadCluster())
        self.assertEqual(artifact["run_target"]["mode"], "unavailable")
        self.assertIsNone(artifact["run_target"]["pod"])

    def test_local_binary_mode_is_marked_not_dogfooding(self):
        artifact = collect.build(DeadCluster(), ["--mcp-sdk"], local=True, repo=DeadRepo())
        collect.validate(artifact)
        self.assertEqual(artifact["run_target"]["mode"], "local_binary")
        self.assertIn("does NOT count as dogfooding", artifact["run_target"]["note"])

    def test_pod_visible_but_broker_silent_keeps_index_signals_unavailable(self):
        artifact = self.build(PodOnlyCluster(), repo=StaticRepo())
        for key, entry in signals(artifact, "token").items():
            with self.subTest(signal=key):
                self.assertEqual(entry["state"], "unavailable")
        # Pod-derived backup signals remain readable in the same run.
        inventory = signals(artifact, "backup")["broker_volume_inventory"]
        self.assertEqual(inventory["state"], "available")
        self.assertTrue(inventory["value"]["stateless"])

    def test_no_cluster_flag_disables_access_without_faking_values(self):
        artifact = self.build(collect.Cluster(kubectl=False))
        entry = signals(artifact, "storage")["corpus_source_bytes"]
        self.assertEqual(entry["state"], "unavailable")
        self.assertIn("--no-cluster", entry["reason"])

    def test_no_repo_flag_disables_local_reads_without_faking_values(self):
        artifact = self.build(DeadCluster(), repo=collect.Repo(enabled=False))
        entry = signals(artifact, "correctness")["retrieval_evaluation_receipt"]
        self.assertEqual(entry["state"], "unavailable")
        self.assertIn("--no-repo", entry["reason"])


class TestEnergyHonesty(unittest.TestCase):
    """Energy must never be fabricated, and must never silently become a proxy."""

    def test_absent_power_metrics_yield_unavailable_not_a_proxy(self):
        artifact = collect.build(DeadCluster(), ["--mcp-sdk"], local=False, repo=DeadRepo())
        collect.validate(artifact)
        entry = signals(artifact, "energy")["broker_attributable_energy"]
        self.assertEqual(entry["state"], "unavailable")
        self.assertIsNone(entry["value"])

    def test_metric_present_on_other_nodes_is_not_attributed_to_broker(self):
        class OtherNodeEnergy(PodOnlyCluster):
            def prom_query(self, query):
                if query != "node_hwmon_energy_joule_total":
                    return []
                return [
                    {"metric": {"instance": "192.0.2.101:9100"}, "value": [0, "1"]},
                    {"metric": {"instance": "192.0.2.102:9100"}, "value": [0, "2"]},
                ]

        artifact = collect.build(OtherNodeEnergy(), ["--mcp-sdk"], local=False, repo=DeadRepo())
        collect.validate(artifact)
        probe = signals(artifact, "energy")["node_hwmon_energy_joule_total"]
        self.assertEqual(probe["state"], "unavailable")
        self.assertIn("none on the node running the broker", probe["reason"])
        attributed = signals(artifact, "energy")["broker_attributable_energy"]
        self.assertEqual(attributed["state"], "unavailable")

    def test_metric_on_broker_node_still_refuses_to_attribute(self):
        """Even a node-local counter is not pod-level energy; refuse to attribute."""

        class BrokerNodeEnergy(PodOnlyCluster):
            def prom_query(self, query):
                if query != "node_hwmon_energy_joule_total":
                    return []
                return [{"metric": {"instance": "198.51.100.102:9100"}, "value": [0, "9"]}]

        artifact = collect.build(
            BrokerNodeEnergy(), ["--mcp-sdk"], local=False, repo=DeadRepo()
        )
        collect.validate(artifact)
        attributed = signals(artifact, "energy")["broker_attributable_energy"]
        self.assertEqual(attributed["state"], "unavailable")
        self.assertIn("per-process power accounting", attributed["reason"])


class TestLatency(unittest.TestCase):
    """Latency is measured, so it must carry sample counts and percentiles."""

    def test_measured_latency_reports_samples_and_percentiles(self):
        artifact = collect.build(ArgoCluster(), ["--mcp-sdk"], local=False, repo=StaticRepo())
        collect.validate(artifact)
        entry = signals(artifact, "latency")["knowledge_search_latency_seconds"]
        self.assertEqual(entry["state"], "available")
        self.assertEqual(
            entry["value"]["samples"], len(collect.LATENCY_QUERIES) * collect.LATENCY_REPEATS
        )
        for fraction in collect.LATENCY_PERCENTILES:
            self.assertIn(f"p{int(fraction * 100)}", entry["value"])
        self.assertIn("upper bound", entry["provenance"])

    def test_startup_sample_is_recorded_as_one_sample(self):
        artifact = collect.build(ArgoCluster(), ["--mcp-sdk"], local=False, repo=StaticRepo())
        entry = signals(artifact, "latency")["startup_to_first_response_seconds"]
        self.assertEqual(entry["state"], "available")
        self.assertIn("1 sample", entry["provenance"])

    def test_absent_server_side_histogram_is_unavailable_not_zero(self):
        artifact = collect.build(ArgoCluster(), ["--mcp-sdk"], local=False, repo=StaticRepo())
        entry = signals(artifact, "latency")["server_side_latency_histogram"]
        self.assertEqual(entry["state"], "unavailable")
        self.assertIsNone(entry["value"])
        self.assertIn("client-measured", entry["reason"])

    def test_outage_leaves_every_latency_signal_unavailable(self):
        artifact = collect.build(DeadCluster(), ["--mcp-sdk"], local=False, repo=DeadRepo())
        for key, entry in signals(artifact, "latency").items():
            with self.subTest(signal=key):
                self.assertEqual(entry["state"], "unavailable")

    def test_percentile_refuses_an_empty_sample_set(self):
        with self.assertRaises(collect.ProbeError):
            collect.percentile([], 0.5)


class TestCitation(unittest.TestCase):
    """Citations must be shown to resolve, not asserted to."""

    def test_resolving_citations_are_counted_and_reconstructed(self):
        artifact = collect.build(ArgoCluster(), ["--mcp-sdk"], local=False, repo=StaticRepo())
        collect.validate(artifact)
        resolution = signals(artifact, "citation")["citation_resolution"]
        self.assertEqual(resolution["state"], "available")
        self.assertEqual(resolution["value"]["citations_checked"], 1)
        self.assertEqual(resolution["value"]["citations_resolved"], 1)
        self.assertEqual(resolution["value"]["mismatches"], [])
        rebuilt = signals(artifact, "citation")["citation_byte_reconstruction"]
        self.assertEqual(rebuilt["value"]["byte_reconstructible"], 1)
        self.assertEqual(rebuilt["value"]["digest_matches"], 1)

    def test_a_wrong_digest_is_reported_not_hidden(self):
        cluster = ArgoCluster()
        cluster.hit_sha = "sha256:" + "0" * 64
        artifact = collect.build(cluster, ["--mcp-sdk"], local=False, repo=StaticRepo())
        collect.validate(artifact)
        rebuilt = signals(artifact, "citation")["citation_byte_reconstruction"]
        self.assertEqual(rebuilt["value"]["digest_matches"], 0)
        self.assertEqual(rebuilt["value"]["digest_mismatch_paths"], [INDEXED_PATH])

    def test_cross_process_stability_is_recorded_as_unevidenced(self):
        artifact = collect.build(ArgoCluster(), ["--mcp-sdk"], local=False, repo=StaticRepo())
        entry = signals(artifact, "citation")["citation_stability_across_processes"]
        self.assertEqual(entry["state"], "unavailable")
        self.assertIn("two-run protocol", entry["reason"])

    def test_outage_leaves_every_citation_signal_unavailable(self):
        artifact = collect.build(DeadCluster(), ["--mcp-sdk"], local=False, repo=DeadRepo())
        for key, entry in signals(artifact, "citation").items():
            with self.subTest(signal=key):
                self.assertEqual(entry["state"], "unavailable")


class TestTimeFreshness(unittest.TestCase):
    """Freshness must be derived from the configured period, not from a README."""

    def test_bound_is_index_age_plus_the_real_period(self):
        artifact = collect.build(ArgoCluster(), ["--mcp-sdk"], local=False, repo=StaticRepo())
        collect.validate(artifact)
        entries = signals(artifact, "time_freshness")
        self.assertEqual(entries["git_sync_period_seconds"]["value"], 60.0)
        self.assertIn("--period=60s", entries["git_sync_period_seconds"]["provenance"])
        age = entries["serving_index_age_seconds"]["value"]
        bound = entries["worst_case_served_content_staleness_seconds"]["value"]
        self.assertAlmostEqual(bound, age + 60.0, places=1)

    def test_index_is_recorded_as_never_rebuilt_after_start(self):
        artifact = collect.build(ArgoCluster(), ["--mcp-sdk"], local=False, repo=StaticRepo())
        entry = signals(artifact, "time_freshness")["index_refresh_mechanism"]
        self.assertFalse(entry["value"]["rebuilt_after_start"])

    def test_outage_leaves_the_bound_unavailable_rather_than_zero(self):
        artifact = collect.build(DeadCluster(), ["--mcp-sdk"], local=False, repo=DeadRepo())
        entry = signals(artifact, "time_freshness")[
            "worst_case_served_content_staleness_seconds"
        ]
        self.assertEqual(entry["state"], "unavailable")
        self.assertIsNone(entry["value"])

    def test_duration_parser_rejects_nonsense(self):
        self.assertEqual(collect.parse_duration_seconds("1m30s"), 90.0)
        self.assertEqual(collect.parse_duration_seconds("500ms"), 0.5)
        with self.assertRaises(collect.ProbeError):
            collect.parse_duration_seconds("soon")


class TestAclDeletion(unittest.TestCase):
    """Exclusions must be exercised against the live index, never asserted."""

    def test_every_excluded_class_is_probed_and_refused(self):
        artifact = collect.build(ArgoCluster(), ["--mcp-sdk"], local=False, repo=StaticRepo())
        collect.validate(artifact)
        entries = signals(artifact, "acl_deletion")
        self.assertEqual(entries[collect.ACL_CONTROL_SIGNAL]["state"], "available")
        for name, _pattern in collect.ACL_EXCLUSION_CLASSES:
            with self.subTest(exclusion=name):
                entry = entries[f"excluded_{name}"]
                self.assertEqual(entry["state"], "available")
                self.assertEqual(entry["value"]["indexed_paths"], [])
                self.assertGreaterEqual(entry["value"]["paths_refused"], 1)

    def test_a_leaked_path_is_recorded_by_name_only(self):
        cluster = ArgoCluster()
        cluster.forbidden_paths = set()  # nothing is refused: every probe resolves
        artifact = collect.build(cluster, ["--mcp-sdk"], local=False, repo=StaticRepo())
        collect.validate(artifact)
        entry = signals(artifact, "acl_deletion")["excluded_terraform_variable_values"]
        self.assertEqual(entry["value"]["indexed_paths"], ["terraform/vms.auto.tfvars"])
        # The artifact must never carry file contents, only path names.
        self.assertNotIn("snippet", json.dumps(entry))

    def test_failed_positive_control_voids_every_exclusion_claim(self):
        cluster = ArgoCluster()
        cluster.forbidden_paths = set(collect.ACL_POSITIVE_CONTROLS)
        artifact = collect.build(cluster, ["--mcp-sdk"], local=False, repo=StaticRepo())
        collect.validate(artifact)
        entries = signals(artifact, "acl_deletion")
        self.assertEqual(entries[collect.ACL_CONTROL_SIGNAL]["state"], "unavailable")
        for name, _pattern in collect.ACL_EXCLUSION_CLASSES:
            with self.subTest(exclusion=name):
                self.assertEqual(entries[f"excluded_{name}"]["state"], "unavailable")

    def test_untracked_and_deletion_are_recorded_as_unexercised(self):
        artifact = collect.build(ArgoCluster(), ["--mcp-sdk"], local=False, repo=StaticRepo())
        entries = signals(artifact, "acl_deletion")
        self.assertEqual(entries["untracked_exclusion"]["state"], "unavailable")
        self.assertEqual(entries["deletion_exercised"]["state"], "unavailable")
        self.assertIn("no delete-then-observe cycle", entries["deletion_exercised"]["reason"])

    def test_outage_leaves_every_exclusion_signal_unavailable(self):
        artifact = collect.build(DeadCluster(), ["--mcp-sdk"], local=False, repo=DeadRepo())
        for key, entry in signals(artifact, "acl_deletion").items():
            with self.subTest(signal=key):
                self.assertEqual(entry["state"], "unavailable")


class TestCorrectness(unittest.TestCase):
    """The retained evaluation must be re-verified, not transcribed."""

    def test_receipt_and_signature_are_verified_at_collection_time(self):
        artifact = collect.build(ArgoCluster(), ["--mcp-sdk"], local=False, repo=StaticRepo())
        collect.validate(artifact)
        entries = signals(artifact, "correctness")
        self.assertEqual(entries["retrieval_evaluation_receipt"]["value"]["state"], "passed")
        self.assertFalse(entries["retrieval_evaluation_receipt"]["value"]["promotable"])
        self.assertTrue(entries["retrieval_evaluation_signature"]["value"]["verified"])
        metrics = entries["retrieval_held_out_metrics"]["value"]
        self.assertEqual(metrics["aggregates"][0]["recall"], 1.0)
        self.assertEqual(metrics["total_queries"], 4)

    def test_a_substituted_trust_root_is_rejected(self):
        repo = StaticRepo()
        repo.receipt["authorization"]["allowed_signers_sha256"] = "sha256:" + "9" * 64
        artifact = collect.build(ArgoCluster(), ["--mcp-sdk"], local=False, repo=repo)
        collect.validate(artifact)
        entry = signals(artifact, "correctness")["retrieval_evaluation_signature"]
        self.assertEqual(entry["state"], "unavailable")
        self.assertIn("cannot select its own trust root", entry["reason"])

    def test_a_drifted_audit_reference_becomes_unavailable(self):
        class DriftedRepo(StaticRepo):
            def read_bytes(self, relative):
                if relative == collect.CORRECTNESS_AUDIT:
                    return b"the results table was rewritten\n"
                return super().read_bytes(relative)

        artifact = collect.build(ArgoCluster(), ["--mcp-sdk"], local=False, repo=DriftedRepo())
        collect.validate(artifact)
        entry = signals(artifact, "correctness")["held_out_quality_audit_reference"]
        self.assertEqual(entry["state"], "unavailable")
        self.assertIn("drifted", entry["reason"])

    def test_broker_lexical_correctness_is_recorded_as_unevidenced(self):
        artifact = collect.build(ArgoCluster(), ["--mcp-sdk"], local=False, repo=StaticRepo())
        entry = signals(artifact, "correctness")["broker_lexical_search_correctness"]
        self.assertEqual(entry["state"], "unavailable")
        self.assertIn("scorer-blind qrels suite", entry["reason"])

    def test_outage_leaves_every_correctness_signal_unavailable(self):
        artifact = collect.build(ArgoCluster(), ["--mcp-sdk"], local=False, repo=DeadRepo())
        for key, entry in signals(artifact, "correctness").items():
            with self.subTest(signal=key):
                self.assertEqual(entry["state"], "unavailable")


class TestRollback(unittest.TestCase):
    """Rollback evidence must not imply an exercise that never happened."""

    def test_mechanism_is_evidenced_and_the_act_is_not(self):
        artifact = collect.build(ArgoCluster(), ["--mcp-sdk"], local=False, repo=StaticRepo())
        collect.validate(artifact)
        entries = signals(artifact, "rollback")
        self.assertTrue(
            entries["deployed_image_matches_git_declaration"]["value"]["matches"]
        )
        self.assertTrue(entries["argocd_reconcile_state"]["value"]["self_heal"])
        self.assertEqual(entries["rollback_exercised"]["state"], "unavailable")
        self.assertIn("no rollback has been exercised", entries["rollback_exercised"]["reason"])

    def test_a_repeated_revision_is_reported_as_an_exercised_rollback(self):
        artifact = collect.build(
            ArgoCluster(revisions=["aaa", "bbb", "aaa"]),
            ["--mcp-sdk"],
            local=False,
            repo=StaticRepo(),
        )
        collect.validate(artifact)
        entry = signals(artifact, "rollback")["rollback_exercised"]
        self.assertEqual(entry["state"], "available")
        self.assertEqual(entry["value"]["repeated_revisions"], ["aaa"])

    def test_digest_drift_is_reported_not_smoothed(self):
        artifact = collect.build(
            ArgoCluster(),
            ["--mcp-sdk"],
            local=False,
            repo=StaticRepo(values_digest="sha256:" + "c" * 64),
        )
        collect.validate(artifact)
        entry = signals(artifact, "rollback")["deployed_image_matches_git_declaration"]
        self.assertFalse(entry["value"]["matches"])

    def test_outage_leaves_every_rollback_signal_unavailable(self):
        artifact = collect.build(DeadCluster(), ["--mcp-sdk"], local=False, repo=DeadRepo())
        for key, entry in signals(artifact, "rollback").items():
            with self.subTest(signal=key):
                self.assertEqual(entry["state"], "unavailable")


class TestValidator(unittest.TestCase):
    """The validator is the gate; prove it rejects the shapes we care about."""

    def good(self):
        return collect.build(DeadCluster(), ["--mcp-sdk"], local=False, repo=DeadRepo())

    def live(self):
        return collect.build(ArgoCluster(), ["--mcp-sdk"], local=False, repo=StaticRepo())

    def test_accepts_a_well_formed_artifact(self):
        collect.validate(self.good())
        collect.validate(self.live())

    def test_rejects_unavailable_signal_carrying_a_value(self):
        artifact = self.good()
        signals(artifact, "token")["indexed_token_occurrences"]["value"] = 0
        with self.assertRaises(ValueError):
            collect.validate(artifact)

    def test_rejects_available_signal_with_null_value(self):
        artifact = self.good()
        entry = signals(artifact, "token")["indexed_token_occurrences"]
        entry.update({"state": "available", "value": None})
        with self.assertRaises(ValueError):
            collect.validate(artifact)

    def test_rejects_signal_without_provenance(self):
        artifact = self.good()
        del signals(artifact, "storage")["corpus_source_bytes"]["provenance"]
        with self.assertRaises(ValueError):
            collect.validate(artifact)

    def test_rejects_unavailable_signal_without_reason(self):
        artifact = self.good()
        del signals(artifact, "backup")["corpus_origin"]["reason"]
        with self.assertRaises(ValueError):
            collect.validate(artifact)

    def test_rejects_missing_category(self):
        artifact = self.good()
        del artifact["categories"]["energy"]
        with self.assertRaises(ValueError):
            collect.validate(artifact)

    def test_rejects_emptied_signal_set(self):
        artifact = self.good()
        artifact["categories"]["backup"]["signals"] = {}
        with self.assertRaises(ValueError):
            collect.validate(artifact)

    def test_rejects_a_derived_number_whose_input_is_unavailable(self):
        artifact = self.live()
        signals(artifact, "time_freshness")["git_sync_period_seconds"] = collect.unavailable(
            "period unreadable", "probe"
        )
        with self.assertRaises(ValueError):
            collect.validate(artifact)

    def test_rejects_an_exclusion_claim_without_a_positive_control(self):
        artifact = self.live()
        signals(artifact, "acl_deletion")[collect.ACL_CONTROL_SIGNAL] = collect.unavailable(
            "control not probed", "probe"
        )
        with self.assertRaises(ValueError):
            collect.validate(artifact)

    def test_helper_refuses_provenance_free_signals(self):
        with self.assertRaises(ValueError):
            collect.available(1, "bytes", "")
        with self.assertRaises(ValueError):
            collect.unavailable("", "probe")
        with self.assertRaises(ValueError):
            collect.unavailable("reason", "")


class TestRender(unittest.TestCase):
    def test_renders_markdown_with_embedded_canonical_json(self):
        artifact = collect.build(DeadCluster(), ["--mcp-sdk"], local=False, repo=DeadRepo())
        document = collect.render(artifact)
        self.assertIn("# Knowledge broker dogfooding evidence", document)
        for category in collect.CATEGORIES:
            self.assertIn(f"## {category}", document)
        self.assertIn("_unavailable_", document)
        payload = document.split("```json", 1)[1].split("```", 1)[0]
        self.assertEqual(json.loads(payload)["artifact_kind"], collect.ARTIFACT_KIND)

    def test_render_never_prints_a_zero_for_an_unavailable_signal(self):
        document = collect.render(
            collect.build(DeadCluster(), ["--mcp-sdk"], local=False, repo=DeadRepo())
        )
        table = [line for line in document.splitlines() if line.startswith("| `")]
        self.assertTrue(table)
        for row in table:
            if "`index_refresh_mechanism`" in row:
                continue
            self.assertIn("unavailable", row)
            self.assertNotIn("| 0 |", row)


if __name__ == "__main__":
    unittest.main(verbosity=2)
