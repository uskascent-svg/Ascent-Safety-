from app.detection.core_rules import load_catalog


def test_catalog_has_300_unique_disabled_draft_candidates():
    catalog = load_catalog()
    assert len(catalog) == 300
    assert len(set(catalog)) == 300
    assert all(rule.lifecycle == "draft" and not rule.enabled for rule in catalog.values())
    assert {rule.source for rule in catalog.values()} == {
        "auth", "endpoint", "network", "web", "cloud", "dns"
    }
