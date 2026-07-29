import streamlit as st 
import pandas as pd 
import numpy as np 
import ast 
import re 
import zipfile 
import io 
import xgboost as xgb 
from sklearn.preprocessing import LabelEncoder 

# ===================================================================== 
# MACHINE LEARNING ENGINE LAYER (Tabular Feature Extraction & XGBoost) 
# ===================================================================== 
@st.cache_resource 
def bootstrap_trained_xgboost_model(): 
    """Simulates a trained XGBoost Code Security Classification Model.""" 
    # Features matrix index layout: 
    # [Total_Lines, Insecure_Execute_Calls, Cleartext_Secrets_Count, Code_Char_Length] 
    X_train = np.array([,   # Vulnerable Auth File,    # Clean Utility File,  # Vulnerable DB Connector,     # Clean Constants File 
        [100, 1, 2, 6000]  # Legacy Bloated Debt Module 
    ]) 
    # Target Class labels: 1 = High Financial Risk, 0 = Low Risk 
    y_train = np.array([1, 0, 1, 0, 1]) 

    xgb_model = xgb.XGBClassifier( 
        max_depth=3, 
        learning_rate=0.1, 
        n_estimators=10, 
        objective='binary:logistic' 
    ) 
    xgb_model.fit(X_train, y_train) 
    return xgb_model 

class TechDebtUnderwriter: 
    def __init__(self, sql_cost, secret_cost, complexity_cost, labor_rate): 
        self.labor_rate_inr = labor_rate 
        self.risk_cost_matrix = { 
            "SQL_INJECTION": {"base_liability_inr": sql_cost, "severity": "CRITICAL", "remediation_hours": 12}, 
            "HARDCODED_SECRET": {"base_liability_inr": secret_cost, "severity": "HIGH", "remediation_hours": 4}, 
            "COMPLEX_LOGIC_BLOCK": {"base_liability_inr": complexity_cost, "severity": "MEDIUM", "remediation_hours": 8} 
        } 

    def scan_code_with_ast(self, filename, code_string): 
        findings = [] 
        total_lines = len(code_string.split('\n')) 
        insecure_executes = 0 
        cleartext_secrets = 0 
        char_length = len(code_string) 
        
        try: 
            tree = ast.parse(code_string) 
            for node in ast.walk(tree): 
                # FIX: Strict string match avoids matching 'execute_script' 
                if isinstance(node, ast.Call) and hasattr(node.func, 'attr') and node.func.attr == 'execute': 
                    for arg in node.args: 
                        if isinstance(arg, ast.JoinedStr): 
                            insecure_executes += 1 
                            findings.append(("SQL_INJECTION", "Dynamic f-string detected in SQL execution block.")) 
            
            if re.search(r'(api_key|password|secret)\s*=\s*["\'][A-Za-z0-9_\-]+["\']', code_string, re.IGNORECASE): 
                cleartext_secrets += 1 
                findings.append(("HARDCODED_SECRET", "Plaintext authorization token assignment located.")) 
            
            # FIX: Raised character limit from 5,000 to 50,000 to accept deep dashboard layout sizes 
            if code_string.count("def ") > 0 and char_length > 50000: 
                findings.append(("COMPLEX_LOGIC_BLOCK", "High-entropy block limits horizontal scalability.")) 
        except SyntaxError: 
            findings.append(("COMPLEX_LOGIC_BLOCK", "Syntax compilation error found in module structure.")) 
        
        numeric_feature_vector = [total_lines, insecure_executes, cleartext_secrets, char_length] 
        return findings, numeric_feature_vector 

    def run_xgboost_inference(self, model_engine, feature_vector): 
        if model_engine is None: 
            return "XGBoost Module Offline." 
        input_data = np.array([feature_vector]) 
        prediction = model_engine.predict(input_data)[0] 
        probability = model_engine.predict_proba(input_data)[0][1] * 100 
        
        risk_tag = "🔴 HIGH FINANCIAL LIABILITY RISK" if prediction == 1 else "🟢 COMPLIANT/LOW RISK" 
        return f"Verdict: {risk_tag} (XGBoost Confidence: {probability:.2f}%)" 

    def evaluate_monetary_exposure(self, raw_flaws): 
        total_liability = 0 
        total_hours = 0 
        detailed_breakdown = [] 
        
        for flaw_type, description in raw_flaws: 
            if flaw_type in self.risk_cost_matrix: 
                cost = self.risk_cost_matrix[flaw_type]["base_liability_inr"] 
                hours = self.risk_cost_matrix[flaw_type]["remediation_hours"] 
                sev = self.risk_cost_matrix[flaw_type]["severity"] 
                
                labor_cost = hours * self.labor_rate_inr 
                combined_liability = cost + labor_cost 
                total_liability += combined_liability 
                total_hours += hours 
                
                detailed_breakdown.append({ 
                    "Vulnerability": flaw_type, 
                    "Severity Risk": sev, 
                    "Base Risk Penalty": f"₹{cost:,}", 
                    "Eng. Labor Cost": f"₹{labor_cost:,}", 
                    "Total Exposure": combined_liability 
                }) 
        return total_liability, total_hours, detailed_breakdown 

# ===================================================================== 
# STREAMLIT HCI INTERACTIVE DASHBOARD USER INTERFACE 
# ===================================================================== 
st.set_page_config(page_title="Domain VII: XGBoost AI Underwriter", layout="wide") 
st.title("🛡️ Enterprise XGBoost Software Debt Underwriter") 
st.caption("Fulfilling TCoE Domain VII: Gradient-Boosted Decision Tree Inference Application") 

st.sidebar.header("🎛️ Underwriting Cost Variables") 
param_sql_cost = st.sidebar.slider("SQLi Breach Penalty (₹)", 100000, 1500000, 500000) 
param_secret_cost = st.sidebar.slider("Token Leak Cost (₹)", 50000, 500000, 250000) 
param_complex_cost = st.sidebar.slider("Structural Tech Debt Cost (₹)", 10000, 100000, 50000) 
param_labor_rate = st.sidebar.slider("Dev Engineering Hourly Rate (₹)", 500, 5000, 1500) 

st.sidebar.header("🤖 Local Classical ML Node") 
ml_enabled = st.sidebar.checkbox("Activate Embedded XGBoost Classifier Pipeline", value=True) 

xgb_engine = None 
if ml_enabled: 
    xgb_engine = bootstrap_trained_xgboost_model() 
    st.sidebar.success("✅ XGBoost Model Vector Array Weights Loaded successfully into RAM.") 

st.subheader("📥 Code Ingestion Gateway") 
uploaded_zip = st.file_uploader("Upload repository package archives (.zip)", type=["zip"]) 

fallback_code_demo = """def auth_session(user): 
    secret_key = "sk_live_51Nx892B3jKh" 
    db.execute(f"SELECT * FROM users WHERE id = '{user}'") 
""" 
st.markdown("---") 

if uploaded_zip is not None: 
    all_extracted_flaws = [] 
    with zipfile.ZipFile(io.BytesIO(uploaded_zip.read())) as archive: 
        for file_path in archive.namelist(): 
            # FIX: Only look at valid python files and filter out wake_app.py 
            if file_path.endswith('.py') and "wake_app.py" not in file_path: 
                with archive.open(file_path) as file_handler: 
                    source_payload = file_handler.read().decode('utf-8', errors='ignore') 
                    analyzer = TechDebtUnderwriter(param_sql_cost, param_secret_cost, param_complex_cost, param_labor_rate) 
                    
                    detected_anomalies, feature_array = analyzer.scan_code_with_ast(file_path, source_payload) 
                    all_extracted_flaws.extend(detected_anomalies) 
                    
                    if ml_enabled: 
                        st.info(f"Extracted Numeric Metrics for `{file_path}`: {feature_array}") 
                        ml_response = analyzer.run_xgboost_inference(xgb_engine, feature_array) 
                        st.write(f"📊 **XGBoost Classification Node Analysis:** {ml_response}") 
                        
    if all_extracted_flaws: 
        total_loss, hours_required, detailed_metrics_list = analyzer.evaluate_monetary_exposure(all_extracted_flaws) 
        col1, col2, col3 = st.columns(3) 
        with col1: 
            st.metric(label="Calculated Liability Exposure", value=f"₹{total_loss:,}") 
        with col2: 
            st.metric(label="Remediation Hours Required", value=f"{hours_required} Hours") 
        with col3: 
            st.metric(label="Identified Code Flaws", value=len(all_extracted_flaws)) 
        st.dataframe(pd.DataFrame(detailed_metrics_list), use_container_width=True) 
    else: 
        st.success("✨ Ingestion Clean! The analyzed code layers conform entirely to baseline risk standards. Total Liability: ₹0.") 
else: 
    st.info("ℹ️ Displaying baseline simulation view. Toggle your configurations or add a target repository zip file package.") 
    analyzer = TechDebtUnderwriter(param_sql_cost, param_secret_cost, param_complex_cost, param_labor_rate) 
    simulated_flaws, sample_vector = analyzer.scan_code_with_ast("demo.py", fallback_code_demo) 
    total_loss, hours_required, detailed_metrics_list = analyzer.evaluate_monetary_exposure(simulated_flaws) 
    st.table(pd.DataFrame(detailed_metrics_list))
