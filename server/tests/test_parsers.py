import gzip
from datetime import date

from bearwatch.intel import epss, kev, msrc, nvd, vulnrichment


def test_kev_cisa():
    rows = kev.parse_cisa(
        {
            "vulnerabilities": [
                {
                    "cveID": "CVE-2024-3400",
                    "vendorProject": "Palo Alto Networks",
                    "product": "PAN-OS",
                    "vulnerabilityName": "PAN-OS Command Injection",
                    "dateAdded": "2024-04-12",
                    "dueDate": "2024-04-19",
                    "knownRansomwareCampaignUse": "Known",
                },
                {"cveID": "not-a-cve"},
            ]
        }
    )
    assert len(rows) == 1
    assert rows[0]["source"] == "cisa" and rows[0]["ransomware"] is True
    assert rows[0]["date_added"] == date(2024, 4, 12)


def test_epss():
    raw = gzip.compress(b"#model_version:v2025.03.14,score_date:2026-11-03T00:00:00+0000\ncve,epss,percentile\nCVE-2024-3400,0.94,0.999\n")
    rows = epss.parse(raw)
    assert rows == [{"cve_id": "CVE-2024-3400", "score": 0.94, "percentile": 0.999, "score_date": date(2026, 11, 3)}]


def test_nvd_item():
    item = {
        "cve": {
            "id": "CVE-2023-0001",
            "published": "2023-01-02T10:00:00.000",
            "lastModified": "2024-02-03T10:00:00.000",
            "vulnStatus": "Analyzed",
            "cisaExploitAdd": "2023-05-01",
            "descriptions": [{"lang": "en", "value": "bad thing"}],
            "metrics": {
                "cvssMetricV31": [
                    {"type": "Secondary", "cvssData": {"version": "3.1", "baseScore": 5.0, "vectorString": "x", "baseSeverity": "MEDIUM"}},
                    {"type": "Primary", "cvssData": {"version": "3.1", "baseScore": 9.8, "vectorString": "y", "baseSeverity": "CRITICAL"}},
                ]
            },
            "configurations": [
                {
                    "nodes": [
                        {
                            "cpeMatch": [
                                {"vulnerable": True, "criteria": "cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*", "versionEndExcluding": "120.0.6099.109"},
                                {"vulnerable": False, "criteria": "cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*"},
                            ]
                        }
                    ]
                }
            ],
        }
    }
    row, matches = nvd.parse_item(item)
    assert row["cvss_score"] == 9.8 and row["severity"] == "CRITICAL"
    assert row["nvd_kev_added"] == date(2023, 5, 1)
    assert len(matches) == 1
    assert matches[0]["vendor"] == "google" and matches[0]["version_end_excl"] == "120.0.6099.109"
    assert matches[0]["platforms"] == []

    item["cve"]["configurations"][0]["operator"] = "AND"
    _, matches = nvd.parse_item(item)
    assert matches[0]["platforms"] == ["microsoft:windows"]


MSRC_DOC = {
    "ProductTree": {
        "FullProductName": [
            {"ProductID": "12390", "Value": "Windows 11 Version 24H2 for x64-based Systems", "CPE": "cpe:2.3:o:microsoft:windows_11_24H2:*"},
        ]
    },
    "Vulnerability": [
        {
            "CVE": "CVE-2026-100200",
            "Title": {"Value": "Windows Thing Elevation of Privilege"},
            "Threats": [
                {"Type": 0, "Description": {"Value": "Elevation of Privilege"}, "ProductID": ["12390"]},
                {"Type": 1, "Description": {"Value": "Publicly Disclosed:No;Exploited:Yes;Latest Software Release:Exploitation Detected"}},
                {"Type": 3, "Description": {"Value": "Important"}, "ProductID": ["12390"]},
            ],
            "CVSSScoreSets": [{"BaseScore": 7.0, "ProductID": ["12390"]}],
            "Remediations": [
                {"Type": 2, "Description": {"Value": "5127648"}, "Supercedence": "5124008", "ProductID": ["12390"], "SubType": "Security Update", "FixedBuild": "10.0.26100.9711"},
                {"Type": 3, "SubType": "5127648", "ProductID": ["12390"]},
            ],
        }
    ],
}


def test_msrc_parse():
    products, vulns, fixes = msrc.parse_document("2026-Oct", MSRC_DOC)
    assert products[0]["product_id"] == "12390"
    assert vulns[0]["exploited"] is True and vulns[0]["publicly_disclosed"] is False
    assert len(fixes) == 1
    f = fixes[0]
    assert f["kb"] == "5127648" and f["supersedes"] == ["5124008"]
    assert f["fixed_build"] == "10.0.26100.9711" and f["severity"] == "Important" and f["cvss_score"] == 7.0


def test_vulnrichment():
    assert vulnrichment.path_for("CVE-2024-3400").endswith("/2024/3xxx/CVE-2024-3400.json")
    assert vulnrichment.path_for("CVE-2021-44228").endswith("/2021/44xxx/CVE-2021-44228.json")
    doc = {
        "containers": {
            "adp": [
                {
                    "providerMetadata": {"shortName": "CISA-ADP"},
                    "metrics": [
                        {
                            "other": {
                                "type": "ssvc",
                                "content": {"options": [{"Exploitation": "active"}, {"Automatable": "yes"}, {"Technical Impact": "total"}]},
                            }
                        }
                    ],
                }
            ]
        }
    }
    assert vulnrichment.parse(doc) == {"found": True, "exploitation": "active", "automatable": "yes", "technical_impact": "total"}
    assert vulnrichment.parse({})["found"] is False
