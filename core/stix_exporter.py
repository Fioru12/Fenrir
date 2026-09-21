import uuid
import datetime
from typing import List, Dict, Any

def export_to_stix21(indicators: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Converts Fenrir threat intelligence indicators into a valid STIX 2.1 Bundle.
    """
    bundle_id = f"bundle--{uuid.uuid4()}"
    now_iso = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    stix_objects = []

    for item in indicators:
        ind_type = item.get("indicator_type", "UNKNOWN").upper()
        ind_val = item.get("indicator", "")
        name = item.get("name", "Fenrir Threat Indicator")
        desc = item.get("description", "")
        source = item.get("source", "Fenrir CTI")

        if ind_type == "CVE":
            vuln_obj = {
                "type": "vulnerability",
                "spec_version": "2.1",
                "id": f"vulnerability--{uuid.uuid5(uuid.NAMESPACE_DNS, ind_val)}",
                "created": now_iso,
                "modified": now_iso,
                "name": name,
                "description": desc or f"Known Exploited Vulnerability {ind_val}",
                "external_references": [
                    {
                        "source_name": "cve",
                        "external_id": ind_val
                    }
                ]
            }
            stix_objects.append(vuln_obj)
        else:
            if ind_type == "IP":
                pattern = f"[ipv4-addr:value = '{ind_val}']"
            elif ind_type == "DOMAIN":
                pattern = f"[domain-name:value = '{ind_val}']"
            elif ind_type in ("HASH", "FILE_HASH"):
                pattern = f"[file:hashes.'SHA-256' = '{ind_val}']"
            else:
                pattern = f"[custom-object:value = '{ind_val}']"

            indicator_obj = {
                "type": "indicator",
                "spec_version": "2.1",
                "id": f"indicator--{uuid.uuid5(uuid.NAMESPACE_DNS, f'{ind_type}:{ind_val}')}",
                "created": now_iso,
                "modified": now_iso,
                "name": name,
                "description": desc or f"Indicator from {source}",
                "indicator_types": ["malicious-activity"],
                "pattern": pattern,
                "pattern_type": "stix",
                "valid_from": now_iso
            }
            stix_objects.append(indicator_obj)

    return {
        "type": "bundle",
        "id": bundle_id,
        "spec_version": "2.1",
        "objects": stix_objects
    }
