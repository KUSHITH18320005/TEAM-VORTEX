"""
Unit and Integration Tests for Task M1 (SVM Service) and Task M2 (DNN Service).
Tests kernel competition, StandardScaler verification, M2a Deep MLP, and M2b 1D-CNN.
"""

from __future__ import annotations

import pytest
from models.svm_engine import svm_engine, SVMEngine
from models.dnn_engine import dnn_engine, DNNEngine


def test_svm_kernel_competition_and_scaler():
    """Validates SVM kernel competition (Linear vs RBF) and StandardScaler verification."""
    comp = svm_engine.train_and_compare_kernels()
    assert comp["scaler_verified"] is True
    assert "web_branch" in comp
    assert "network_branch" in comp

    web_comp = comp["web_branch"]
    net_comp = comp["network_branch"]

    assert "linear_score" in web_comp and "rbf_score" in web_comp
    assert web_comp["winning_kernel"] in ["linear", "rbf"]

    assert "linear_score" in net_comp and "rbf_score" in net_comp
    assert net_comp["winning_kernel"] in ["rbf", "linear"]


def test_svm_scoring_web_payload():
    """Tests SVM probability score output on web injection telemetry."""
    telemetry = {
        "endpoint": "/api/v1/search",
        "method": "POST",
        "payload": "' UNION SELECT username, password FROM users --",
        "source_ip": "203.0.113.88",
    }
    result = svm_engine.score_telemetry(telemetry)
    assert result["service"] == "svm-service"
    assert "score" in result
    assert 0.0 <= result["score"] <= 1.0
    assert result["features_scaled"] is True
    assert isinstance(result["probability_distribution"], dict)


def test_svm_scoring_network_flow():
    """Tests SVM probability score output on network flow telemetry."""
    flow = {
        "endpoint": "/network/flow",
        "flow_duration_ms": 12.0,
        "syn_count": 450,
        "dst_port_count": 1024,
        "packet_rate": 890.0,
        "flow_bytes_per_sec": 5200000.0,
        "source_ip": "10.0.2.15",
    }
    result = svm_engine.score_telemetry(flow)
    assert result["service"] == "svm-service"
    assert result["branch"] == "network_flow_svm"
    assert 0.0 <= result["score"] <= 1.0
    assert result["features_scaled"] is True


def test_dnn_models_training_and_architecture():
    """Validates M2a Deep MLP and M2b 1D-CNN initialization and forward passes."""
    if not dnn_engine.is_trained:
        dnn_engine.train_models(epochs=5)

    assert dnn_engine.mlp_model is not None
    assert dnn_engine.cnn_model is not None
    assert len(dnn_engine.cnn_classes) > 0
    assert len(dnn_engine.mlp_classes) > 0


def test_dnn_1dcnn_scoring_obfuscated_payload():
    """Tests M2b 1D-CNN scoring on obfuscated SQLi payload."""
    telemetry = {
        "endpoint": "/api/v1/search",
        "method": "POST",
        "payload": "%27%20%55%4E%49%4F%4E%20%53%45%4C%45%43%54%201%2C2--",
        "source_ip": "198.51.100.210",
    }
    result = dnn_engine.score_telemetry(telemetry)
    assert result["service"] == "dnn-service"
    assert "cnn_score" in result
    assert 0.0 <= result["score"] <= 1.0
    assert 0.0 <= result["cnn_score"] <= 1.0


def test_dnn_mlp_scoring_network_flow():
    """Tests M2a Deep MLP scoring on network DDoS flow."""
    flow = {
        "endpoint": "/network/flow",
        "flow_duration_ms": 50.0,
        "packet_rate": 5100.0,
        "flow_bytes_per_sec": 6100000.0,
        "asymmetric_ratio": 0.99,
        "source_ip": "172.16.0.6",
    }
    result = dnn_engine.score_telemetry(flow)
    assert result["service"] == "dnn-service"
    assert "mlp_score" in result
    assert 0.0 <= result["mlp_score"] <= 1.0
