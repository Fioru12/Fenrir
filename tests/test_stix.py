import pytest
from core.stix_exporter import export_to_stix21

def test_stix21_export_cve_and_ip():
    indicators = [
        {
            "indicator_type": "CVE",
            "indicator": "CVE-2023-23397",
            "name": "Microsoft Outlook Elevation of Privilege",
            "description": "Critical vulnerability",
            "source": "CISA KEV"
        },
        {
            "indicator_type": "IP",
            "indicator": "198.51.100.1",
            "name": "Malicious Scanner IP",
            "source": "OTX"
        }
    ]

    bundle = export_to_stix21(indicators)
    assert bundle["type"] == "bundle"
    assert bundle["spec_version"] == "2.1"
    assert len(bundle["objects"]) == 2

    cve_obj = bundle["objects"][0]
    assert cve_obj["type"] == "vulnerability"
    assert cve_obj["external_references"][0]["external_id"] == "CVE-2023-23397"

    ip_obj = bundle["objects"][1]
    assert ip_obj["type"] == "indicator"
    assert "[ipv4-addr:value = '198.51.100.1']" in ip_obj["pattern"]
