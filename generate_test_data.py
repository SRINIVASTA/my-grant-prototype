import pytest
import zipfile
import io
import os
import numpy as np
from app import TechDebtUnderwriter, bootstrap_trained_xgboost_model

# ===================================================================== 
# PYTEST REUSABLE FIXTURES LAYER
# ===================================================================== 
@pytest.fixture
def base_underwriter():
    """Provides a fresh, standard instance of TechDebtUnderwriter for tests."""
    # Instantiated with standard defaults: SQLi=500k, Secret=250k, TechDebt=50k, labor=1500
    return TechDebtUnderwriter(500000, 250000, 50000, 1500)


@pytest.fixture
def trained_model():
    """Provides the process memory weights of the XGBoost classifier model."""
    return bootstrap_trained_xgboost_model()


# ===================================================================== 
# FORMAL PYTEST ASSERTION TEST SUITE
# ===================================================================== 

def test_sql_injection_detection(base_underwriter):
    """Verifies that dynamic string concatenation in query calls triggers AST alarms."""
    sqli_payload = "def query(uid):\n    cursor.execute(f'SELECT * FROM clients WHERE id = {uid}')"
    flaws, metrics = base_underwriter.scan_code_with_ast("auth_file.py", sqli_payload)
    
    # Assertions check the structural results dictionary directly
    assert any(flaw_type == "SQL_INJECTION" for flaw_type, _ in flaws), "AST failed to catch SQL Injection payload!"
    assert metrics[1] == 1, "Metrics layout failed to record the insecure database call vector."


def test_selenium_false_positive_mitigation(base_underwriter):
    """Ensures browser automation scripts are successfully white-listed by exact naming matches."""
    selenium_payload = "def wake_container():\n    driver.execute_script('arguments[0].click();', btn)"
    flaws, metrics = base_underwriter.scan_code_with_ast("wake_app.py", selenium_payload)
    
    has_false_alert = any(flaw_type == "SQL_INJECTION" for flaw_type, _ in flaws)
    assert not has_false_alert, "Selenium driver commands are triggering algorithmic false positives!"
    assert metrics[1] == 0, "Insecure database metric layout column should read exactly 0."


def test_monetary_exposure_waterfall(base_underwriter):
    """Validates the financial risk cost matrix calculations against rule models."""
    sample_flaws = [("SQL_INJECTION", "Dynamic string execution vulnerability.")]
    total_liability, total_hours, breakdown = base_underwriter.evaluate_monetary_exposure(sample_flaws)
    
    # Mathematical Validation Check: Base Penalty (500k) + Labor (12 hours * 1,500/hr = 18k) = 518,000
    expected_liability = 518000
    assert total_liability == expected_liability, f"Cost mismatch. Expected {expected_liability}, evaluated {total_liability}."
    assert total_hours == 12, "Remediation workforce target hours are configured incorrectly."


def test_xgboost_pipeline_inference(trained_model):
    """Verifies the underlying ML node engine accepts vector array coordinates and infers safely."""
    # Test an input profile vector: [Lines, Insecure_Calls, Secrets, Char_Length]
    mock_clean_vector = [10, 0, 0, 120]
    input_data = np.array([mock_clean_vector])
    
    prediction = trained_model.predict(input_data)[0]
    # Predict output classifications: 0 = Low Risk, 1 = High Risk
    assert prediction in [0, 1], "XGBoost engine returned an invalid categorical distribution prediction boundary."
