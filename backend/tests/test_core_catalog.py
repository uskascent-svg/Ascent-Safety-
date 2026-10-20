from app.detection.core_rules import load_catalog


def test_catalog_has_303_unique_disabled_draft_candidates():
    catalog = load_catalog()
    assert len(catalog) == 303
    assert len(set(catalog)) == 303
    assert all(rule.lifecycle == "draft" and not rule.enabled for rule in catalog.values())
    assert {rule.source for rule in catalog.values()} == {
        "auth", "endpoint", "network", "web", "cloud", "dns"
    }
