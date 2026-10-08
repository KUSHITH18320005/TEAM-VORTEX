"""
Unit test for Task M3: Halt-on-Gap validation guarantee.
Proves that DatasetTrainingMapper genuinely halts and raises DatasetVerificationError
when a category is missing or has zero verified training examples.
"""

from __future__ import annotations

import copy
import pytest
from models.generate_dataset_map import DatasetTrainingMapper, DatasetVerificationError
from data.datasets.manifest_37_categories import DATASET_MANIFEST_37


def test_halt_on_gap_passes_on_full_verified_manifest():
    """Confirms that the complete, untouched manifest passes validation without error."""
    is_valid, gaps = DatasetTrainingMapper.verify_manifest(DATASET_MANIFEST_37)
    assert is_valid is True
    assert len(gaps) == 0


def test_halt_on_gap_fires_on_deliberately_missing_category():
    """
    Proves that deleting a category from the manifest causes the halt-on-gap check
    to immediately raise DatasetVerificationError with a descriptive gap listing.
    """
    # Create corrupted copy with 'ssrf' deliberately removed
    corrupted_manifest = copy.deepcopy(DATASET_MANIFEST_37)
    del corrupted_manifest["ssrf"]

    with pytest.raises(DatasetVerificationError) as exc_info:
        DatasetTrainingMapper.verify_manifest(corrupted_manifest)

    err_str = str(exc_info.value)
    assert "[DATASET VERIFICATION HALT]" in err_str
    assert "MISSING_FROM_MANIFEST: 'ssrf'" in err_str


def test_halt_on_gap_fires_on_zero_sample_count():
    """
    Proves that a category with 0 samples causes the halt-on-gap check
    to immediately raise DatasetVerificationError.
    """
    corrupted_manifest = copy.deepcopy(DATASET_MANIFEST_37)
    corrupted_manifest["nosql-injection"]["sample_count"] = 0
    corrupted_manifest["nosql-injection"]["samples"] = []

    with pytest.raises(DatasetVerificationError) as exc_info:
        DatasetTrainingMapper.verify_manifest(corrupted_manifest)

    err_str = str(exc_info.value)
    assert "[DATASET VERIFICATION HALT]" in err_str
    assert "ZERO_VERIFIED_DATA: 'nosql-injection'" in err_str


def test_dataset_training_map_file_exists():
    """Ensures DATASET_TRAINING_MAP.md exists and contains all 37 categories."""
    from pathlib import Path
    map_file = Path(__file__).resolve().parent.parent / "models" / "DATASET_TRAINING_MAP.md"
    assert map_file.exists(), "DATASET_TRAINING_MAP.md must be generated"
    content = map_file.read_text(encoding="utf-8")
    for cat in DatasetTrainingMapper.ALL_37_CATEGORIES:
        assert f"`{cat}`" in content, f"Category '{cat}' missing from DATASET_TRAINING_MAP.md"
