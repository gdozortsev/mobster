from mobster.sbom.enrich import enrich_sbom
from pathlib import Path
import asyncio
import json

import pytest

@pytest.fixture
def data_dir() -> Path:
    """Path to the directory for storing SBOM sample test data."""
    return Path(__file__).parent / "test_enrich_data"

@pytest.mark.asyncio
@pytest.mark.parametrize(
    "original_sbom, owasp_sbom",
    [
        (Path("llm_compress_spdx.json"), Path("TinyLlama_TinyLlama-1.1B-Chat-v1.0_aibom.json")),
    ],
)

async def test_enrich_sboms_spdx_cdx(
    original_sbom: Path,
    owasp_sbom:Path,
    data_dir: Path,
    monkeypatch: pytest.MonkeyPatch,     
):
    monkeypatch.chdir(data_dir)
    original_sbom_path = data_dir / original_sbom
    owasp_sbom_path = data_dir / owasp_sbom

    
    new_sbom = await enrich_sbom(original_sbom_path, owasp_sbom_path)
    with open('enriched_sbom.json', 'w') as f:
        json.dump(new_sbom, f, indent=2)

@pytest.mark.asyncio
@pytest.mark.parametrize(
    "gemma_cdx, owasp_gemma_sbom",
    [
        (Path("original_gemma.json"), Path("gemma_owasp.json")),
    ],
)
async def test_enrich_sboms_cdx_cdx(
    gemma_cdx: Path,
    owasp_gemma_sbom:Path,
    data_dir: Path,
    monkeypatch: pytest.MonkeyPatch,     
):
    monkeypatch.chdir(data_dir)
    original_sbom_path = data_dir / gemma_cdx
    owasp_sbom_path = data_dir / owasp_gemma_sbom
    
    new_sbom = await enrich_sbom(original_sbom_path, owasp_sbom_path)
    with open('enriched_sbom_gemma.json', 'w') as f:
        json.dump(new_sbom, f, indent=2)

@pytest.mark.asyncio
@pytest.mark.parametrize(
    "mock_cdx, mock",
    [
        (Path("mock_cdx.json"), Path("mock_enrichment_format.json")),
    ],
)
async def test_enrich_sboms_cdx_json(
    mock_cdx: Path,
    mock:Path,
    data_dir: Path,
    monkeypatch: pytest.MonkeyPatch,     
):
    monkeypatch.chdir(data_dir)
    original_sbom_path = data_dir / mock_cdx
    owasp_sbom_path = data_dir / mock
    
    new_sbom = await enrich_sbom(original_sbom_path, owasp_sbom_path)
    with open('enriched_sbom_mock.json', 'w') as f:
        json.dump(new_sbom, f, indent=2)

