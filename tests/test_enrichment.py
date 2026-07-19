from domainrecon.enrichment import EnrichmentCollector, integration_status


def test_integration_status_does_not_expose_credentials(monkeypatch):
    monkeypatch.setenv("SHODAN_API_KEY", "super-secret")
    status = integration_status()
    shodan = next(item for item in status if item["name"] == "Shodan")
    assert shodan["configured"] is True
    assert "super-secret" not in str(status)


def test_extracts_rdap_registrar_name():
    payload = {
        "entities": [
            {
                "roles": ["registrar"],
                "vcardArray": ["vcard", [["fn", {}, "text", "Example Registrar"]]],
            }
        ]
    }
    assert EnrichmentCollector._registrar(payload) == "Example Registrar"


def test_extracts_public_rdap_entities_without_contact_details():
    payload = {
        "entities": [
            {
                "roles": ["registrant"],
                "vcardArray": [
                    "vcard",
                    [
                        ["fn", {}, "text", "Example Owner"],
                        ["org", {}, "text", "Example Limited"],
                        ["email", {}, "text", "private@example.test"],
                    ],
                ],
            }
        ]
    }
    entities = EnrichmentCollector._public_entities(payload)
    assert entities[0]["organization"] == "Example Limited"
    assert "private@example.test" not in str(entities)
