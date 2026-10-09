from backend.platforms.mendix.risk import RiskEngine, RiskInputs


def test_risk_calculation_combines_grouped_factors():
    result = RiskEngine().calculate(
        RiskInputs(
            base_score=20,
            sensitive=True,
            sensitivity_severity="high",
            create=True,
            broad_roles=True,
        )
    )

    assert result == {"score": 90, "severity": "critical"}


def test_risk_calculation_caps_score_and_accounts_for_access_bypass():
    result = RiskEngine().calculate(
        RiskInputs(base_score=40, bypasses_entity_access=True)
    )

    assert result == {"score": 65, "severity": "high"}
