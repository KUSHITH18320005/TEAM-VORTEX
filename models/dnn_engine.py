"""
Deep Neural Network Engine for MAD-PS Detection Mesh (Task M2).
Implements:
- M2a: Deep MLP (input -> 256 -> 128 -> 64 -> 32 -> softmax) with BatchNorm + Dropout(0.3) + ReduceLROnPlateau
- M2b: 1D-CNN over raw character payload sequences (Embedding -> Multi-Kernel Conv1D [3, 5, 7] -> GlobalMaxPool -> Dense -> Softmax)
"""

from __future__ import annotations

import logging
import math
import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F
from typing import Any, Dict, List, Optional, Tuple
from sklearn.preprocessing import StandardScaler
from data.datasets.manifest_37_categories import DATASET_MANIFEST_37

logger = logging.getLogger("mad_ps.dnn_engine")


class DeepMLPNet(nn.Module):
    """
    Task M2a: 4-Layer Deep Regularized MLP for Network Flow & Behavioral Telemetry.
    input -> 256 -> 128 -> 64 -> 32 -> num_classes.
    Includes BatchNorm1d + Dropout(0.3) between all intermediate layers.
    """

    def __init__(self, input_dim: int, num_classes: int, dropout_rate: float = 0.3):
        super().__init__()
        self.fc1 = nn.Linear(input_dim, 256)
        self.bn1 = nn.BatchNorm1d(256)
        self.drop1 = nn.Dropout(dropout_rate)

        self.fc2 = nn.Linear(256, 128)
        self.bn2 = nn.BatchNorm1d(128)
        self.drop2 = nn.Dropout(dropout_rate)

        self.fc3 = nn.Linear(128, 64)
        self.bn3 = nn.BatchNorm1d(64)
        self.drop3 = nn.Dropout(dropout_rate)

        self.fc4 = nn.Linear(64, 32)
        self.bn4 = nn.BatchNorm1d(32)
        self.drop4 = nn.Dropout(dropout_rate)

        self.out = nn.Linear(32, num_classes)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        x = self.drop1(F.relu(self.bn1(self.fc1(x))))
        x = self.drop2(F.relu(self.bn2(self.fc2(x))))
        x = self.drop3(F.relu(self.bn3(self.fc3(x))))
        x = self.drop4(F.relu(self.bn4(self.fc4(x))))
        return self.out(x)


class Payload1DCNN(nn.Module):
    """
    Task M2b: Character-level Multi-Kernel 1D-CNN over raw request payloads.
    Embedding -> Conv1D (parallel kernel sizes 3, 5, 7) -> GlobalMaxPooling -> Dense -> Softmax.
    Catches obfuscated/polyglot SQLi, XSS, XXE structural patterns beyond token bag-of-words.
    """

    def __init__(self, vocab_size: int = 128, embed_dim: int = 64, num_filters: int = 64, num_classes: int = 19):
        super().__init__()
        self.embedding = nn.Embedding(vocab_size, embed_dim, padding_idx=0)
        
        # Parallel multi-scale convolutional filters
        self.conv_k3 = nn.Conv1d(in_channels=embed_dim, out_channels=num_filters, kernel_size=3, padding=1)
        self.conv_k5 = nn.Conv1d(in_channels=embed_dim, out_channels=num_filters, kernel_size=5, padding=2)
        self.conv_k7 = nn.Conv1d(in_channels=embed_dim, out_channels=num_filters, kernel_size=7, padding=3)

        self.dense1 = nn.Linear(num_filters * 3, 64)
        self.bn = nn.BatchNorm1d(64)
        self.dropout = nn.Dropout(0.3)
        self.out = nn.Linear(64, num_classes)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        # x shape: (Batch, Seq_Len)
        emb = self.embedding(x)  # (Batch, Seq_Len, Embed_Dim)
        emb = emb.transpose(1, 2)  # (Batch, Embed_Dim, Seq_Len) for Conv1D

        c3 = F.relu(self.conv_k3(emb))  # (Batch, Filters, Seq_Len)
        c5 = F.relu(self.conv_k5(emb))
        c7 = F.relu(self.conv_k7(emb))

        # Global Max Pooling along sequence length
        p3 = F.adaptive_max_pool1d(c3, 1).squeeze(-1)  # (Batch, Filters)
        p5 = F.adaptive_max_pool1d(c5, 1).squeeze(-1)
        p7 = F.adaptive_max_pool1d(c7, 1).squeeze(-1)

        merged = torch.cat([p3, p5, p7], dim=1)  # (Batch, Filters * 3)
        feat = self.dropout(F.relu(self.bn(self.dense1(merged))))
        return self.out(feat)


class DNNEngine:
    """Enterprise Dual-Branch DNN Controller."""

    MAX_SEQ_LEN = 256

    def __init__(self):
        self.mlp_model: Optional[DeepMLPNet] = None
        self.cnn_model: Optional[Payload1DCNN] = None
        self.mlp_scaler = StandardScaler()
        
        self.mlp_classes: List[str] = []
        self.cnn_classes: List[str] = []
        self.is_trained: bool = False

    @classmethod
    def char_tokenize(cls, text: str) -> np.ndarray:
        """Converts raw string to fixed-length ASCII index sequence (0=pad)."""
        seq = np.zeros(cls.MAX_SEQ_LEN, dtype=np.int64)
        for i, ch in enumerate(text[:cls.MAX_SEQ_LEN]):
            code = ord(ch)
            seq[i] = code if code < 128 else 127
        return seq

    def train_models(self, epochs: int = 4):
        """Trains both Deep MLP (M2a) and 1D-CNN (M2b) on verified dataset manifests."""
        # 1. Prepare M2a (Network & Behavioral MLP) dataset
        mlp_feats = []
        mlp_labels = []
        
        # 2. Prepare M2b (Web 1D-CNN) dataset
        cnn_seqs = []
        cnn_labels = []

        reps = 3 if epochs <= 5 else 12
        for cat, data in DATASET_MANIFEST_37.items():
            samples = data.get("samples", [])
            family = data.get("family", "")

            if "Web/App" in family:
                if cat not in self.cnn_classes:
                    self.cnn_classes.append(cat)
                cat_idx = self.cnn_classes.index(cat)
                for s in samples:
                    raw_text = f"{s.get('endpoint', '')} {s.get('method', '')} {s.get('payload', '')} {s.get('query', '')} {s.get('redirect_url', '')} {s.get('target_url', '')} {s.get('jwt_header', '')}"
                    for rep in range(reps):
                        # Slight augmentation
                        seq = self.char_tokenize(f"{raw_text} #{rep}")
                        cnn_seqs.append(seq)
                        cnn_labels.append(cat_idx)
            
            if "Network" in family or "IoT" in family or "Malware" in family:
                if cat not in self.mlp_classes:
                    self.mlp_classes.append(cat)
                cat_idx = self.mlp_classes.index(cat)
                for s in samples:
                    feat = [
                        float(s.get("flow_duration_ms", 10.0)),
                        float(s.get("syn_count", 0)),
                        float(s.get("dst_port_count", 1)),
                        float(s.get("packet_rate", 10.0)),
                        float(s.get("flow_bytes_per_sec", 1000.0)),
                        float(s.get("asymmetric_ratio", 0.1)),
                        float(s.get("rst_count", 0)),
                        float(s.get("beacon_interval_sec", 0.0)),
                        float(s.get("distributed_sources", 1)),
                        float(s.get("ttl", 64)),
                        float(s.get("file_rename_count", 0)),
                        float(s.get("section_entropy", 4.0)),
                    ]
                    for rep in range(reps):
                        pert = [f * (1.0 + (rep * 0.02)) for f in feat]
                        mlp_feats.append(pert)
                        mlp_labels.append(cat_idx)

        # 3. Train M2a: Deep MLP
        X_mlp = self.mlp_scaler.fit_transform(np.array(mlp_feats, dtype=np.float32))
        y_mlp = np.array(mlp_labels, dtype=np.int64)

        t_X_mlp = torch.tensor(X_mlp, dtype=torch.float32)
        t_y_mlp = torch.tensor(y_mlp, dtype=torch.long)

        self.mlp_model = DeepMLPNet(input_dim=X_mlp.shape[1], num_classes=len(self.mlp_classes))
        mlp_opt = torch.optim.Adam(self.mlp_model.parameters(), lr=0.001, weight_decay=1e-4)
        mlp_sched = torch.optim.lr_scheduler.ReduceLROnPlateau(mlp_opt, mode="min", factor=0.5, patience=3)
        loss_fn = nn.CrossEntropyLoss()

        self.mlp_model.train()
        for ep in range(epochs):
            mlp_opt.zero_grad()
            out = self.mlp_model(t_X_mlp)
            loss = loss_fn(out, t_y_mlp)
            loss.backward()
            mlp_opt.step()
            mlp_sched.step(loss.item())

        self.mlp_model.eval()

        # 4. Train M2b: 1D-CNN
        t_X_cnn = torch.tensor(np.array(cnn_seqs), dtype=torch.long)
        t_y_cnn = torch.tensor(np.array(cnn_labels), dtype=torch.long)

        self.cnn_model = Payload1DCNN(num_classes=len(self.cnn_classes))
        cnn_opt = torch.optim.Adam(self.cnn_model.parameters(), lr=0.002, weight_decay=1e-4)
        cnn_sched = torch.optim.lr_scheduler.ReduceLROnPlateau(cnn_opt, mode="min", factor=0.5, patience=3)

        self.cnn_model.train()
        for ep in range(epochs):
            cnn_opt.zero_grad()
            out = self.cnn_model(t_X_cnn)
            loss = loss_fn(out, t_y_cnn)
            loss.backward()
            cnn_opt.step()
            cnn_sched.step(loss.item())

        self.cnn_model.eval()
        self.is_trained = True
        logger.info("DNN Engine training completed. MLP classes: %d, CNN classes: %d", len(self.mlp_classes), len(self.cnn_classes))

    def score_telemetry(self, telemetry: Dict[str, Any]) -> Dict[str, Any]:
        """
        Routes telemetry to M2a Deep MLP, M2b 1D-CNN, or joint ensemble and returns calibrated scores.
        """
        if not self.is_trained:
            self.train_models()

        endpoint = str(telemetry.get("endpoint", ""))
        payload = str(telemetry.get("payload", "")) + " " + str(telemetry.get("body", "")) + " " + str(telemetry.get("query", ""))
        
        is_flow = "flow" in endpoint or "flow_duration_ms" in telemetry or "packet_rate" in telemetry or "api_call" in telemetry

        mlp_score = 0.05
        cnn_score = 0.05
        best_cat = "BENIGN_TELEMETRY"
        prob_dist: Dict[str, float] = {}

        # 1. Evaluate M2b 1D-CNN (Web/Payload)
        if self.cnn_model is not None:
            raw_text = f"{endpoint} {telemetry.get('method', 'GET')} {payload} {telemetry.get('target_url', '')} {telemetry.get('jwt_header', '')}"
            seq = torch.tensor(np.array([self.char_tokenize(raw_text)]), dtype=torch.long)
            with torch.no_grad():
                logits = self.cnn_model(seq)
                probs = F.softmax(logits, dim=1).squeeze(0).numpy()
                best_cnn_idx = int(np.argmax(probs))
                cnn_score = float(probs[best_cnn_idx])
                best_cat = self.cnn_classes[best_cnn_idx]
                for idx, cname in enumerate(self.cnn_classes):
                    prob_dist[f"cnn_{cname}"] = round(float(probs[idx]), 4)

        # 2. Evaluate M2a Deep MLP (Flow/Behavioral)
        if self.mlp_model is not None and is_flow:
            feat = [
                float(telemetry.get("flow_duration_ms", 10.0)),
                float(telemetry.get("syn_count", 0)),
                float(telemetry.get("dst_port_count", 1)),
                float(telemetry.get("packet_rate", 10.0)),
                float(telemetry.get("flow_bytes_per_sec", 1000.0)),
                float(telemetry.get("asymmetric_ratio", 0.1)),
                float(telemetry.get("rst_count", 0)),
                float(telemetry.get("beacon_interval_sec", 0.0)),
                float(telemetry.get("distributed_sources", 1)),
                float(telemetry.get("ttl", 64)),
                float(telemetry.get("file_rename_count", 0)),
                float(telemetry.get("section_entropy", 4.0)),
            ]
            scaled = self.mlp_scaler.transform(np.array([feat], dtype=np.float32))
            with torch.no_grad():
                logits = self.mlp_model(torch.tensor(scaled, dtype=torch.float32))
                probs = F.softmax(logits, dim=1).squeeze(0).numpy()
                best_mlp_idx = int(np.argmax(probs))
                mlp_score = float(probs[best_mlp_idx])
                best_cat = self.mlp_classes[best_mlp_idx]
                for idx, cname in enumerate(self.mlp_classes):
                    prob_dist[f"mlp_{cname}"] = round(float(probs[idx]), 4)

        final_score = round(max(mlp_score if is_flow else 0.05, cnn_score), 3)
        final_score = max(0.05, min(0.99, final_score))

        return {
            "service": "dnn-service",
            "model_type": "deep_mlp_and_1dcnn",
            "mlp_score": round(mlp_score, 3),
            "cnn_score": round(cnn_score, 3),
            "score": final_score,
            "confidence": final_score,
            "predicted_category": best_cat,
            "probability_distribution": prob_dist,
        }


# Singleton instance
dnn_engine = DNNEngine()
