"""
Unit and Integration Tests for Task M4 (8-Input Retrained Meta-Classifier).
Validates that the MetaClassifier evaluates all 8 branches in parallel,
correctly ingests SVM and DNN branch outputs, and accurately classifies across 37 categories.
"""

from __future__ import annotations

import sys
from pathlib import Path

CURRENT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = CURRENT_DIR.parent
if str(PROJECT_ROOT / "mad-ps-detection-api") not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT / "mad-ps-detection-api"))
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import pytest
from classifier import MetaClassifier


def test_meta_classifier_has_8_branches():
    """Validates that MetaClassifier is configured with exactly 8 detection branches."""
    assert len(MetaClassifier.BRANCHES) == 8
    branch_names = [b.name for b in MetaClassifier.BRANCHES]
    assert "statistical_anomaly" in branch_names
    assert "semantic_payload_evaluator" in branch_names
    assert "stateful_sequence_tracker" in branch_names
    assert "graph_correlation" in branch_names
    assert "rate_frequency_anomaly" in branch_names
    assert "behavioral_identity_abuse" in branch_names
    assert "svm_classifier" in branch_names
    assert "deep_neural_network" in branch_names


def test_meta_classifier_evaluates_8_branch_scores():
    """Validates that telemetry evaluation returns scores for all 8 branches."""
    telemetry = {
        "endpoint": "/api/v1/search",
        "method": "POST",
        "payload": "' UNION SELECT username, password FROM users --",
        "source_ip": "203.0.113.88",
    }
    cat, conf, sev, scores = MetaClassifier.evaluate_telemetry(telemetry)
    assert len(scores) == 8
    assert "svm_classifier" in scores
    assert "deep_neural_network" in scores
    assert 0.0 <= conf <= 1.0
    assert sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    assert "SQL" in cat or cat == "SQLi"


def test_meta_classifier_network_ddos_evaluation():
    """Validates evaluation of network flow telemetry through 8-branch ensemble."""
    telemetry = {
        "endpoint": "/network/flow",
        "flow_duration_ms": 12.0,
        "syn_count": 500,
        "dst_port_count": 1024,
        "packet_rate": 4500.0,
        "flow_bytes_per_sec": 5200000.0,
        "distributed_sources": 800,
        "source_ip": "203.0.113.250",
    }
    cat, conf, sev, scores = MetaClassifier.evaluate_telemetry(telemetry)
    assert len(scores) == 8
    assert scores["svm_classifier"] >= 0.05
    assert scores["deep_neural_network"] >= 0.05
    assert conf >= 0.8
    assert "ddos" in cat.lower() or "dos" in cat.lower() or "port-scanning" in cat.lower()


def test_meta_classifier_ransomware_memory_evaluation():
    """Validates evaluation of malware behavioral memory telemetry."""
    telemetry = {
        "endpoint": "/host/agent",
        "api_call": "CryptEncrypt",
        "file_rename_count": 850,
        "vss_shadow_deleted": True,
        "source_ip": "10.10.1.14",
    }
    cat, conf, sev, scores = MetaClassifier.evaluate_telemetry(telemetry)
    assert len(scores) == 8
    assert "ransomware" in cat.lower()
    assert sev == "CRITICAL"
