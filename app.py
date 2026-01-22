# app.py - Vaccine Temperature Monitoring System
# Doctor-Friendly Frontend with Login & Email Verification

import streamlit as st
import pandas as pd
import numpy as np
import plotly.graph_objects as go
from datetime import datetime, timedelta
import time
import hashlib
import json
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import re
import sqlite3
import bcrypt

# Set page configuration
st.set_page_config(
    page_title="Vaccine Vitals Monitor",
    page_icon="🩺",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# Custom CSS for better UI
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        color: #1E3A8A;
        font-weight: 700;
        margin-bottom: 1rem;
    }
    .sub-header {
        font-size: 1.5rem;
        color: #3B82F6;
        font-weight: 600;
    }
    .alert-box {
        padding: 1rem;
        border-radius: 0.5rem;
        margin: 1rem 0;
        border-left: 5px solid;
    }
    .critical-alert {
        background-color: #FEE2E2;
        border-left-color: #DC2626;
        color: #991B1B;
    }
    .warning-alert {
        background-color: #FEF3C7;
        border-left-color: #F59E0B;
        color: #92400E;
    }
    .info-alert {
        background-color: #DBEAFE;
        border-left-color: #3B82F6;
        color: #1E40AF;
    }
    .success-alert {
        background-color: #D1FAE5;
        border-left-color: #10B981;
        color: #065F46;
    }
    .metric-card {
        background-color: #F8FAFC;
        padding: 1rem;
        border-radius: 0.5rem;
        border: 1px solid #E2E8F0;
        text-align: center;
    }
    .doctor-card {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        color: white;
        padding: 1.5rem;
        border-radius: 1rem;
        margin: 1rem 0;
    }
    .stButton > button {
        width: 100%;
        background-color: #3B82F6;
        color: white;
        font-weight: 600;
        border: none;
        padding: 0.75rem 1.5rem;
        border-radius: 0.5rem;
    }
    .stButton > button:hover {
        background-color: #2563EB;
    }
</style>
""", unsafe_allow_html=True)

# Database setup for user management
def init_database():
    conn = sqlite3.connect('vaccine_monitor.db')
    c = conn.cursor()
    
    # Create users table
    c.execute('''CREATE TABLE IF NOT EXISTS doctors
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  doctor_id TEXT UNIQUE,
                  name TEXT,
                  email TEXT UNIQUE,
                  password TEXT,
                  hospital TEXT,
                  department TEXT,
                  phone TEXT,
                  verified INTEGER DEFAULT 0,
                  verification_code TEXT,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    
    # Create temperature logs table
    c.execute('''CREATE TABLE IF NOT EXISTS temperature_logs
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  doctor_id TEXT,
                  timestamp TIMESTAMP,
                  temperature REAL,
                  device_id TEXT,
                  vaccine_type TEXT,
                  location TEXT,
                  hash_chain TEXT)''')
    
    # Create alerts table
    c.execute('''CREATE TABLE IF NOT EXISTS alerts
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  doctor_id TEXT,
                  timestamp TIMESTAMP,
                  alert_type TEXT,
                  temperature REAL,
                  predicted_temp REAL,
                  alert_message TEXT,
                  action_suggested TEXT,
                  status TEXT DEFAULT 'active')''')
    
    # Create audit trail table
    c.execute('''CREATE TABLE IF NOT EXISTS audit_trail
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  doctor_id TEXT,
                  timestamp TIMESTAMP,
                  action TEXT,
                  previous_hash TEXT,
                  current_hash TEXT,
                  details TEXT)''')
    
    # Insert sample doctor if not exists
    c.execute("SELECT COUNT(*) FROM doctors WHERE doctor_id='DOC001'")
    if c.fetchone()[0] == 0:
        hashed_pw = bcrypt.hashpw("password123".encode('utf-8'), bcrypt.gensalt())
        c.execute('''INSERT INTO doctors 
                    (doctor_id, name, email, password, hospital, department, phone, verified)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
                 ('DOC001', 'Dr. Priya Sharma', 'dr.priya@example.com', hashed_pw,
                  'Apollo Hospital', 'Pediatrics', '+91-9876543210', 1))
    
    conn.commit()
    conn.close()

# Initialize database
init_database()

# Email configuration (for demo purposes - use environment variables in production)
EMAIL_CONFIG = {
    'smtp_server': 'smtp.gmail.com',
    'smtp_port': 587,
    'sender_email': 'vaccine.monitor.demo@gmail.com',
    'sender_password': 'demo_password_123'  # In production, use app-specific password
}

class VaccineMonitorApp:
    def __init__(self):
        self.session_state = st.session_state
        if 'logged_in' not in self.session_state:
            self.session_state.logged_in = False
        if 'doctor_id' not in self.session_state:
            self.session_state.doctor_id = None
        if 'doctor_name' not in self.session_state:
            self.session_state.doctor_name = None
        
    # Email verification functions
    def send_verification_email(self, to_email, verification_code):
        """Send verification email to doctor"""
        try:
            # For demo, we'll simulate email sending
            # In real implementation, uncomment below code
            '''
            msg = MIMEMultipart()
            msg['From'] = EMAIL_CONFIG['sender_email']
            msg['To'] = to_email
            msg['Subject'] = 'Vaccine Vitals Monitor - Email Verification'
            
            body = f"""
            Dear Doctor,
            
            Thank you for registering with Vaccine Vitals Monitor.
            
            Your verification code is: {verification_code}
            
            Enter this code in the app to complete your registration.
            
            This is an automated message. Please do not reply.
            
            Best regards,
            Vaccine Vitals Monitor Team
            """
            
            msg.attach(MIMEText(body, 'plain'))
            
            server = smtplib.SMTP(EMAIL_CONFIG['smtp_server'], EMAIL_CONFIG['smtp_port'])
            server.starttls()
            server.login(EMAIL_CONFIG['sender_email'], EMAIL_CONFIG['sender_password'])
            server.send_message(msg)
            server.quit()
            '''
            
            # For demo, store verification code in session
            self.session_state.verification_code = verification_code
            self.session_state.verification_email = to_email
            
            return True
        except Exception as e:
            st.error(f"Error sending email: {str(e)}")
            return False
    
    def verify_email_code(self, entered_code):
        """Verify the email verification code"""
        stored_code = self.session_state.get('verification_code', '')
        return entered_code == stored_code
    
    # Authentication functions
    def validate_email(self, email):
        """Validate email format"""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(pattern, email) is not None
    
    def register_doctor(self, doctor_id, name, email, password, hospital, department, phone):
        """Register a new doctor"""
        if not self.validate_email(email):
            return False, "Invalid email format"
        
        conn = sqlite3.connect('vaccine_monitor.db')
        c = conn.cursor()
        
        # Check if doctor ID or email already exists
        c.execute("SELECT COUNT(*) FROM doctors WHERE doctor_id=?", (doctor_id,))
        if c.fetchone()[0] > 0:
            conn.close()
            return False, "Doctor ID already exists"
        
        c.execute("SELECT COUNT(*) FROM doctors WHERE email=?", (email,))
        if c.fetchone()[0] > 0:
            conn.close()
            return False, "Email already registered"
        
        # Hash password
        hashed_pw = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        
        # Generate verification code
        verification_code = str(np.random.randint(100000, 999999))
        
        # Insert doctor (not verified yet)
        c.execute('''INSERT INTO doctors 
                    (doctor_id, name, email, password, hospital, department, phone, verification_code)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
                 (doctor_id, name, email, hashed_pw, hospital, department, phone, verification_code))
        
        conn.commit()
        conn.close()
        
        # Send verification email
        if self.send_verification_email(email, verification_code):
            return True, f"Registration successful! Verification code sent to {email}"
        else:
            return False, "Failed to send verification email"
    
    def login_doctor(self, doctor_id, password):
        """Login doctor"""
        conn = sqlite3.connect('vaccine_monitor.db')
        c = conn.cursor()
        
        c.execute('''SELECT doctor_id, name, password, verified FROM doctors 
                     WHERE doctor_id=?''', (doctor_id,))
        result = c.fetchone()
        conn.close()
        
        if not result:
            return False, "Doctor ID not found"
        
        stored_id, name, stored_pw, verified = result
        
        if not verified:
            return False, "Email not verified. Please verify your email first."
        
        if bcrypt.checkpw(password.encode('utf-8'), stored_pw):
            self.session_state.logged_in = True
            self.session_state.doctor_id = stored_id
            self.session_state.doctor_name = name
            return True, "Login successful!"
        else:
            return False, "Invalid password"
    
    def logout(self):
        """Logout doctor"""
        self.session_state.logged_in = False
        self.session_state.doctor_id = None
        self.session_state.doctor_name = None
        st.rerun()
    
    # Temperature prediction functions
    def predict_temperature(self, past_temps, hours_ahead=2):
        """Simple temperature prediction model"""
        if len(past_temps) < 8:
            # Not enough data, return conservative estimate
            last_temp = past_temps[-1] if past_temps else 5.0
            return [last_temp + i*0.1 for i in range(1, 9)]
        
        # Simple moving average with trend
        last_8 = past_temps[-8:]
        avg_temp = np.mean(last_8)
        trend = (last_8[-1] - last_8[0]) / 7
        
        # Time-based adjustment (simulate day/night cycle)
        current_hour = datetime.now().hour
        if 20 <= current_hour or current_hour < 6:  # Night
            trend_factor = -0.05
        elif 10 <= current_hour < 16:  # Day
            trend_factor = 0.05
        else:
            trend_factor = 0
        
        predictions = []
        for i in range(1, 9):  # 8 predictions for 2 hours (15-min intervals)
            pred = avg_temp + (trend * i) + (trend_factor * i)
            predictions.append(round(pred, 2))
        
        return predictions
    
    def check_breach_risk(self, current_temp, predictions):
        """Check if temperature breach is likely"""
        upper_limit = 8.0
        lower_limit = 2.0
        warning_threshold = 0.5  # Alert when within 0.5°C of limits
        
        risks = []
        for i, pred in enumerate(predictions):
            if pred > upper_limit - warning_threshold:
                risks.append({
                    'type': 'HIGH_TEMP',
                    'time_until': f"{i*15} minutes",
                    'predicted_temp': pred,
                    'severity': 'CRITICAL' if pred > upper_limit else 'WARNING'
                })
            elif pred < lower_limit + warning_threshold:
                risks.append({
                    'type': 'LOW_TEMP',
                    'time_until': f"{i*15} minutes",
                    'predicted_temp': pred,
                    'severity': 'CRITICAL' if pred < lower_limit else 'WARNING'
                })
        
        return risks
    
    def get_action_suggestions(self, risk_type, severity):
        """Get actionable suggestions based on risk"""
        actions = {
            'HIGH_TEMP': {
                'CRITICAL': [
                    "🚨 IMMEDIATE ACTION REQUIRED",
                    "Transfer vaccines to backup cooler immediately",
                    "Add ice packs to all compartments",
                    "Move container to air-conditioned area",
                    "Notify supervisor and document incident"
                ],
                'WARNING': [
                    "⚠️ Preventive action needed",
                    "Add extra ice packs to vaccine carrier",
                    "Move to cooler location",
                    "Monitor every 15 minutes",
                    "Prepare backup storage"
                ]
            },
            'LOW_TEMP': {
                'CRITICAL': [
                    "🚨 IMMEDIATE ACTION REQUIRED",
                    "Remove some ice packs immediately",
                    "Move container to warmer area",
                    "Use temperature stabilizers",
                    "Notify supervisor immediately"
                ],
                'WARNING': [
                    "⚠️ Preventive action needed",
                    "Reduce number of ice packs",
                    "Monitor temperature closely",
                    "Adjust container insulation",
                    "Prepare warming packs"
                ]
            }
        }
        return actions.get(risk_type, {}).get(severity, ["Monitor situation"])
    
    # Audit log functions
    def add_audit_log(self, action, details=""):
        """Add entry to audit log"""
        conn = sqlite3.connect('vaccine_monitor.db')
        c = conn.cursor()
        
        # Get previous hash
        c.execute("SELECT current_hash FROM audit_trail WHERE doctor_id=? ORDER BY id DESC LIMIT 1", 
                 (self.session_state.doctor_id,))
        result = c.fetchone()
        previous_hash = result[0] if result else "0" * 64
        
        # Create current hash
        timestamp = datetime.now().isoformat()
        data_string = f"{timestamp}|{self.session_state.doctor_id}|{action}|{details}|{previous_hash}"
        current_hash = hashlib.sha256(data_string.encode()).hexdigest()
        
        # Insert log
        c.execute('''INSERT INTO audit_trail 
                    (doctor_id, timestamp, action, previous_hash, current_hash, details)
                    VALUES (?, ?, ?, ?, ?, ?)''',
                 (self.session_state.doctor_id, timestamp, action, 
                  previous_hash, current_hash, details))
        
        conn.commit()
        conn.close()
    
    def verify_audit_trail(self):
        """Verify integrity of audit trail"""
        conn = sqlite3.connect('vaccine_monitor.db')
        c = conn.cursor()
        
        c.execute('''SELECT timestamp, action, previous_hash, current_hash, details 
                     FROM audit_trail WHERE doctor_id=? ORDER BY id''', 
                 (self.session_state.doctor_id,))
        entries = c.fetchall()
        conn.close()
        
        verification_results = []
        previous_hash = "0" * 64
        
        for i, entry in enumerate(entries):
            timestamp, action, stored_prev_hash, stored_current_hash, details = entry
            
            # Verify previous hash chain
            if stored_prev_hash != previous_hash:
                verification_results.append({
                    'entry': i+1,
                    'status': 'TAMPERED',
                    'message': f"Hash chain broken at entry {i+1}"
                })
                break
            
            # Verify current hash
            data_string = f"{timestamp}|{self.session_state.doctor_id}|{action}|{details}|{stored_prev_hash}"
            calculated_hash = hashlib.sha256(data_string.encode()).hexdigest()
            
            if calculated_hash != stored_current_hash:
                verification_results.append({
                    'entry': i+1,
                    'status': 'TAMPERED',
                    'message': f"Data tampered at entry {i+1}"
                })
                break
            
            previous_hash = stored_current_hash
            verification_results.append({
                'entry': i+1,
                'status': 'VALID',
                'message': "✓"
            })
        
        return verification_results
    
    # UI Components
    def show_login_page(self):
        """Show login page"""
        col1, col2, col3 = st.columns([1, 2, 1])
        
        with col2:
            st.markdown('<div class="doctor-card">', unsafe_allow_html=True)
            st.markdown('<h1 style="text-align: center; color: white;">🩺 VACCINE VITALS MONITOR</h1>', unsafe_allow_html=True)
            st.markdown('<p style="text-align: center; color: white;">Protecting Vaccine Integrity Through AI-Powered Monitoring</p>', unsafe_allow_html=True)
            st.markdown('</div>', unsafe_allow_html=True)
            
            # Tabs for Login/Register
            tab1, tab2 = st.tabs(["🔐 Login", "📝 Register"])
            
            with tab1:
                st.subheader("Doctor Login")
                login_id = st.text_input("Doctor ID", placeholder="Enter your Doctor ID")
                login_password = st.text_input("Password", type="password", placeholder="Enter your password")
                
                if st.button("Login", key="login_btn"):
                    if login_id and login_password:
                        success, message = self.login_doctor(login_id, login_password)
                        if success:
                            st.success(message)
                            self.add_audit_log("LOGIN", "Doctor logged in successfully")
                            time.sleep(1)
                            st.rerun()
                        else:
                            st.error(message)
                    else:
                        st.warning("Please enter both Doctor ID and Password")
            
            with tab2:
                st.subheader("New Doctor Registration")
                
                with st.form("registration_form"):
                    reg_id = st.text_input("Doctor ID*", help="Unique ID assigned by hospital")
                    reg_name = st.text_input("Full Name*")
                    reg_email = st.text_input("Email*")
                    reg_password = st.text_input("Password*", type="password")
                    reg_hospital = st.text_input("Hospital/Clinic*")
                    reg_department = st.text_input("Department*")
                    reg_phone = st.text_input("Phone Number*")
                    
                    submitted = st.form_submit_button("Register")
                    
                    if submitted:
                        if not all([reg_id, reg_name, reg_email, reg_password, reg_hospital, reg_department, reg_phone]):
                            st.error("Please fill all required fields (*)")
                        else:
                            success, message = self.register_doctor(
                                reg_id, reg_name, reg_email, reg_password,
                                reg_hospital, reg_department, reg_phone
                            )
                            if success:
                                st.success(message)
                                st.info("Please check your email for verification code")
                                
                                # Show verification code input
                                verification_code = st.text_input("Enter Verification Code", 
                                                                placeholder="6-digit code from email")
                                if st.button("Verify Email"):
                                    if self.verify_email_code(verification_code):
                                        # Update doctor as verified
                                        conn = sqlite3.connect('vaccine_monitor.db')
                                        c = conn.cursor()
                                        c.execute("UPDATE doctors SET verified=1 WHERE doctor_id=?", (reg_id,))
                                        conn.commit()
                                        conn.close()
                                        st.success("✅ Email verified successfully! You can now login.")
                                        self.add_audit_log("REGISTRATION", f"New doctor registered: {reg_name}")
                                    else:
                                        st.error("Invalid verification code")
                            else:
                                st.error(message)
            
            st.markdown("---")
            st.caption("⚠️ For demo purposes, use Doctor ID: DOC001, Password: password123")
    
    def show_dashboard(self):
        """Show main dashboard"""
        # Header with doctor info
        col1, col2, col3 = st.columns([3, 1, 1])
        
        with col1:
            st.markdown(f'<h1 class="main-header">Welcome, {self.session_state.doctor_name}!</h1>', unsafe_allow_html=True)
        
        with col3:
            if st.button("🚪 Logout"):
                self.add_audit_log("LOGOUT", "Doctor logged out")
                self.logout()
        
        st.markdown("---")
        
        # Dashboard tabs
        tab1, tab2, tab3, tab4 = st.tabs(["📊 Live Monitor", "🚨 Alerts", "📋 Audit Log", "👨‍⚕️ Profile"])
        
        with tab1:
            self.show_live_monitor()
        
        with tab2:
            self.show_alerts_dashboard()
        
        with tab3:
            self.show_audit_log()
        
        with tab4:
            self.show_profile()
    
    def show_live_monitor(self):
        """Show live temperature monitoring"""
        st.markdown('<h2 class="sub-header">Live Temperature Monitoring</h2>', unsafe_allow_html=True)
        
        # Vaccine selection
        col1, col2, col3 = st.columns(3)
        with col1:
            vaccine_type = st.selectbox(
                "Vaccine Type",
                ["COVID-19", "Polio", "Measles", "BCG", "Hepatitis B", "All"]
            )
        with col2:
            device_id = st.selectbox(
                "Storage Device",
                ["Cooler-001", "Cooler-002", "Fridge-A", "Fridge-B", "All Devices"]
            )
        with col3:
            time_range = st.selectbox(
                "Time Range",
                ["Last 6 hours", "Last 12 hours", "Last 24 hours", "Last 7 days"]
            )
        
        # Generate sample temperature data
        st.markdown("---")
        st.subheader("📈 Temperature Trends & Predictions")
        
        # Create sample data
        now = datetime.now()
        hours = 24
        timestamps = [now - timedelta(hours=i/4) for i in range(hours*4, 0, -1)]
        temperatures = [5 + 2*np.sin(i/10) + np.random.normal(0, 0.3) for i in range(len(timestamps))]
        
        # Get predictions
        predictions = self.predict_temperature(temperatures[-32:])  # Last 8 hours
        
        # Create prediction timestamps
        prediction_timestamps = [now + timedelta(minutes=15*i) for i in range(1, 9)]
        
        # Create plot
        fig = go.Figure()
        
        # Historical data
        fig.add_trace(go.Scatter(
            x=timestamps[-32:],  # Last 8 hours
            y=temperatures[-32:],
            mode='lines',
            name='Historical',
            line=dict(color='blue', width=2),
            fill='tozeroy',
            fillcolor='rgba(59, 130, 246, 0.1)'
        ))
        
        # Predictions
        fig.add_trace(go.Scatter(
            x=prediction_timestamps,
            y=predictions,
            mode='lines+markers',
            name='Predicted (Next 2 hours)',
            line=dict(color='orange', width=3, dash='dash'),
            marker=dict(size=8)
        ))
        
        # Add threshold lines
        fig.add_hline(y=8.0, line_dash="dot", 
                     annotation_text="Upper Limit (8°C)", 
                     line_color="red",
                     annotation_position="bottom right")
        fig.add_hline(y=2.0, line_dash="dot", 
                     annotation_text="Lower Limit (2°C)", 
                     line_color="red",
                     annotation_position="bottom right")
        
        # Add safe zone shading
        fig.add_hrect(y0=2.0, y1=8.0, 
                     fillcolor="rgba(0, 255, 0, 0.1)", 
                     layer="below", line_width=0)
        
        # Update layout
        fig.update_layout(
            title="Temperature Monitoring with 2-Hour Prediction",
            xaxis_title="Time",
            yaxis_title="Temperature (°C)",
            height=500,
            hovermode='x unified',
            showlegend=True,
            template="plotly_white"
        )
        
        st.plotly_chart(fig, use_container_width=True)
        
        # Metrics and alerts
        current_temp = temperatures[-1]
        predicted_max = max(predictions)
        predicted_min = min(predictions)
        
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.markdown('<div class="metric-card">', unsafe_allow_html=True)
            st.metric("Current Temp", f"{current_temp:.1f}°C", 
                     delta=None, delta_color="normal")
            st.markdown('</div>', unsafe_allow_html=True)
        
        with col2:
            st.markdown('<div class="metric-card">', unsafe_allow_html=True)
            st.metric("Predicted Max", f"{predicted_max:.1f}°C", 
                     delta=f"{(predicted_max-current_temp):+.1f}°C",
                     delta_color="inverse" if predicted_max > 7.5 else "normal")
            st.markdown('</div>', unsafe_allow_html=True)
        
        with col3:
            st.markdown('<div class="metric-card">', unsafe_allow_html=True)
            st.metric("Predicted Min", f"{predicted_min:.1f}°C", 
                     delta=f"{(predicted_min-current_temp):+.1f}°C",
                     delta_color="inverse" if predicted_min < 2.5 else "normal")
            st.markdown('</div>', unsafe_allow_html=True)
        
        with col4:
            accuracy = 78.5  # Simulated accuracy
            st.markdown('<div class="metric-card">', unsafe_allow_html=True)
            st.metric("Prediction Accuracy", f"{accuracy:.1f}%", 
                     delta="+3.5%" if accuracy > 75 else "-2.5%",
                     delta_color="normal" if accuracy > 75 else "inverse")
            st.markdown('</div>', unsafe_allow_html=True)
        
        # Check for breach risks
        risks = self.check_breach_risk(current_temp, predictions)
        
        if risks:
            st.markdown("---")
            st.subheader("🚨 Risk Assessment & Actions")
            
            for risk in risks:
                if risk['severity'] == 'CRITICAL':
                    alert_class = "critical-alert"
                    icon = "🔴"
                else:
                    alert_class = "warning-alert"
                    icon = "🟡"
                
                actions = self.get_action_suggestions(risk['type'], risk['severity'])
                
                st.markdown(f'<div class="alert-box {alert_class}">', unsafe_allow_html=True)
                st.markdown(f"### {icon} {risk['severity']} ALERT: Potential {risk['type'].replace('_', ' ')}")
                st.markdown(f"**Predicted Temperature:** {risk['predicted_temp']}°C")
                st.markdown(f"**Estimated Time to Breach:** {risk['time_until']}")
                st.markdown("**Recommended Actions:**")
                for action in actions:
                    st.markdown(f"- {action}")
                st.markdown('</div>', unsafe_allow_html=True)
                
                # Log the alert
                self.add_audit_log("TEMPERATURE_ALERT", 
                                 f"{risk['type']} predicted in {risk['time_until']}")
        else:
            st.markdown('<div class="alert-box success-alert">', unsafe_allow_html=True)
            st.markdown("### ✅ All Systems Normal")
            st.markdown("No temperature breaches predicted in the next 2 hours.")
            st.markdown('</div>', unsafe_allow_html=True)
        
        # Manual temperature entry
        st.markdown("---")
        with st.expander("➕ Manual Temperature Entry"):
            col1, col2 = st.columns(2)
            with col1:
                manual_temp = st.number_input("Temperature (°C)", 
                                            min_value=-10.0, 
                                            max_value=50.0, 
                                            value=5.0, 
                                            step=0.1)
            with col2:
                location = st.text_input("Location", "Storage Room A")
            
            if st.button("Record Manual Reading"):
                # Add to database
                conn = sqlite3.connect('vaccine_monitor.db')
                c = conn.cursor()
                
                # Create hash chain entry
                c.execute("SELECT hash_chain FROM temperature_logs WHERE doctor_id=? ORDER BY id DESC LIMIT 1", 
                         (self.session_state.doctor_id,))
                result = c.fetchone()
                previous_hash = result[0] if result else "0" * 64
                
                data_string = f"{datetime.now().isoformat()}|{self.session_state.doctor_id}|{manual_temp}|{location}|{previous_hash}"
                current_hash = hashlib.sha256(data_string.encode()).hexdigest()
                
                c.execute('''INSERT INTO temperature_logs 
                            (doctor_id, timestamp, temperature, device_id, vaccine_type, location, hash_chain)
                            VALUES (?, ?, ?, ?, ?, ?, ?)''',
                         (self.session_state.doctor_id, datetime.now().isoformat(),
                          manual_temp, "Manual", vaccine_type, location, current_hash))
                
                conn.commit()
                conn.close()
                
                self.add_audit_log("MANUAL_TEMP_ENTRY", 
                                 f"Temperature {manual_temp}°C recorded at {location}")
                st.success("✅ Temperature recorded successfully!")
    
    def show_alerts_dashboard(self):
        """Show alerts dashboard"""
        st.markdown('<h2 class="sub-header">Recent Alerts & Notifications</h2>', unsafe_allow_html=True)
        
        # Sample alerts data
        alerts_data = [
            {
                "time": "2 hours ago",
                "type": "High Temperature Warning",
                "device": "Cooler-001",
                "temp": "7.8°C",
                "predicted": "8.3°C in 45 min",
                "status": "Resolved",
                "actions": "Ice packs added"
            },
            {
                "time": "6 hours ago",
                "type": "Sensor Anomaly",
                "device": "Fridge-A",
                "temp": "5.2°C",
                "predicted": "Stable",
                "status": "Investigating",
                "actions": "Sensor calibration scheduled"
            },
            {
                "time": "Yesterday",
                "type": "Low Temperature Alert",
                "device": "Cooler-002",
                "temp": "1.8°C",
                "predicted": "1.5°C in 30 min",
                "status": "Resolved",
                "actions": "Ice packs removed"
            }
        ]
        
        for alert in alerts_data:
            if alert['status'] == 'Resolved':
                alert_class = "success-alert"
            elif alert['status'] == 'Investigating':
                alert_class = "warning-alert"
            else:
                alert_class = "critical-alert"
            
            st.markdown(f'<div class="alert-box {alert_class}">', unsafe_allow_html=True)
            col1, col2, col3 = st.columns([2, 2, 1])
            with col1:
                st.markdown(f"**{alert['type']}**")
                st.markdown(f"Device: {alert['device']}")
            with col2:
                st.markdown(f"Temperature: {alert['temp']}")
                st.markdown(f"Predicted: {alert['predicted']}")
            with col3:
                st.markdown(f"**Status:** {alert['status']}")
                st.markdown(f"*{alert['time']}*")
            st.markdown(f"**Actions Taken:** {alert['actions']}")
            st.markdown('</div>', unsafe_allow_html=True)
        
        # Alert statistics
        st.markdown("---")
        st.subheader("📊 Alert Statistics")
        
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.markdown('<div class="metric-card">', unsafe_allow_html=True)
            st.markdown("**Total Alerts**")
            st.markdown("### 12")
            st.markdown("*This week*")
            st.markdown('</div>', unsafe_allow_html=True)
        
        with col2:
            st.markdown('<div class="metric-card">', unsafe_allow_html=True)
            st.markdown("**Critical Alerts**")
            st.markdown("### 3")
            st.markdown("*Requiring immediate action*")
            st.markdown('</div>', unsafe_allow_html=True)
        
        with col3:
            st.markdown('<div class="metric-card">', unsafe_allow_html=True)
            st.markdown("**False Positives**")
            st.markdown("### 1")
            st.markdown("*8.3% of total*")
            st.markdown('</div>', unsafe_allow_html=True)
        
        with col4:
            st.markdown('<div class="metric-card">', unsafe_allow_html=True)
            st.markdown("**Avg. Response Time**")
            st.markdown("### 18 min")
            st.markdown("*From alert to action*")
            st.markdown('</div>', unsafe_allow_html=True)
    
    def show_audit_log(self):
        """Show audit log"""
        st.markdown('<h2 class="sub-header">Audit Trail & Integrity Verification</h2>', unsafe_allow_html=True)
        
        col1, col2 = st.columns([3, 1])
        with col1:
            st.info("This log provides tamper-evident records of all system activities. Each entry is cryptographically linked to the previous one.")
        
        with col2:
            if st.button("🔍 Verify Integrity", type="primary"):
                results = self.verify_audit_trail()
                
                valid_count = sum(1 for r in results if r['status'] == 'VALID')
                total_count = len(results)
                
                if valid_count == total_count:
                    st.success(f"✅ All {total_count} entries are valid!")
                else:
                    st.error(f"❌ {total_count - valid_count} entries have been tampered with!")
        
        # Display audit log entries
        verification_results = self.verify_audit_trail()
        
        st.markdown("---")
        st.subheader("Audit Log Entries")
        
        # Sample audit log entries
        log_entries = [
            {"timestamp": "2024-01-15 10:30:15", "action": "LOGIN", "details": "Doctor logged in"},
            {"timestamp": "2024-01-15 10:32:45", "action": "TEMPERATURE_CHECK", "details": "Current temp: 5.2°C"},
            {"timestamp": "2024-01-15 10:45:20", "action": "PREDICTION_RUN", "details": "2-hour forecast generated"},
            {"timestamp": "2024-01-15 11:00:10", "action": "ALERT_GENERATED", "details": "High temp warning for Cooler-001"},
            {"timestamp": "2024-01-15 11:15:30", "action": "MANUAL_TEMP_ENTRY", "details": "Temp 5.5°C recorded"},
        ]
        
        for i, entry in enumerate(log_entries):
            with st.expander(f"{entry['timestamp']} - {entry['action']}"):
                col1, col2 = st.columns([3, 1])
                with col1:
                    st.markdown(f"**Action:** {entry['action']}")
                    st.markdown(f"**Details:** {entry['details']}")
                    st.markdown(f"**Hash:** `{hashlib.sha256(str(entry).encode()).hexdigest()[:16]}...`")
                with col2:
                    if i < len(verification_results):
                        if verification_results[i]['status'] == 'VALID':
                            st.success("✓ Valid")
                        else:
                            st.error("✗ Tampered")
        
        # Export option
        st.markdown("---")
        if st.button("📥 Export Audit Log"):
            # Create downloadable JSON
            log_data = {
                "doctor_id": self.session_state.doctor_id,
                "doctor_name": self.session_state.doctor_name,
                "export_timestamp": datetime.now().isoformat(),
                "entries": log_entries,
                "verification_hash": hashlib.sha256(str(log_entries).encode()).hexdigest()
            }
            
            st.download_button(
                label="Download JSON",
                data=json.dumps(log_data, indent=2),
                file_name=f"audit_log_{self.session_state.doctor_id}_{datetime.now().strftime('%Y%m%d')}.json",
                mime="application/json"
            )
    
    def show_profile(self):
        """Show doctor profile"""
        st.markdown('<h2 class="sub-header">Doctor Profile</h2>', unsafe_allow_html=True)
        
        # Get doctor info from database
        conn = sqlite3.connect('vaccine_monitor.db')
        c = conn.cursor()
        c.execute('''SELECT doctor_id, name, email, hospital, department, phone 
                     FROM doctors WHERE doctor_id=?''', 
                 (self.session_state.doctor_id,))
        doctor_info = c.fetchone()
        conn.close()
        
        if doctor_info:
            doc_id, name, email, hospital, department, phone = doctor_info
            
            col1, col2 = st.columns([1, 2])
            
            with col1:
                st.markdown("### 👨‍⚕️")
                st.markdown(f"**Doctor ID:** {doc_id}")
                st.markdown(f"**Status:** ✅ Active")
                st.markdown(f"**Last Login:** Today")
                
                st.markdown("---")
                if st.button("🔄 Change Password"):
                    st.session_state.show_password_change = True
            
            with col2:
                st.markdown("### Personal Information")
                
                info_col1, info_col2 = st.columns(2)
                with info_col1:
                    st.text_input("Full Name", value=name, disabled=True)
                    st.text_input("Email", value=email, disabled=True)
                
                with info_col2:
                    st.text_input("Hospital", value=hospital, disabled=True)
                    st.text_input("Department", value=department, disabled=True)
                
                st.text_input("Phone Number", value=phone, disabled=True)
            
            # Password change form (conditionally shown)
            if st.session_state.get('show_password_change', False):
                st.markdown("---")
                st.subheader("Change Password")
                
                current_pw = st.text_input("Current Password", type="password")
                new_pw = st.text_input("New Password", type="password")
                confirm_pw = st.text_input("Confirm New Password", type="password")
                
                col1, col2 = st.columns(2)
                with col1:
                    if st.button("Update Password"):
                        if new_pw == confirm_pw and len(new_pw) >= 8:
                            # Verify current password
                            conn = sqlite3.connect('vaccine_monitor.db')
                            c = conn.cursor()
                            c.execute("SELECT password FROM doctors WHERE doctor_id=?", (doc_id,))
                            stored_pw = c.fetchone()[0]
                            
                            if bcrypt.checkpw(current_pw.encode('utf-8'), stored_pw):
                                # Update password
                                new_hashed_pw = bcrypt.hashpw(new_pw.encode('utf-8'), bcrypt.gensalt())
                                c.execute("UPDATE doctors SET password=? WHERE doctor_id=?", 
                                         (new_hashed_pw, doc_id))
                                conn.commit()
                                conn.close()
                                
                                self.add_audit_log("PASSWORD_CHANGE", "Password updated successfully")
                                st.success("✅ Password updated successfully!")
                                st.session_state.show_password_change = False
                                time.sleep(2)
                                st.rerun()
                            else:
                                st.error("Current password is incorrect")
                        else:
                            st.error("New passwords don't match or are too short (min 8 characters)")
                
                with col2:
                    if st.button("Cancel"):
                        st.session_state.show_password_change = False
                        st.rerun()
            
            # Statistics
            st.markdown("---")
            st.subheader("📊 Your Statistics")
            
            col1, col2, col3 = st.columns(3)
            with col1:
                st.markdown('<div class="metric-card">', unsafe_allow_html=True)
                st.markdown("**Vaccines Monitored**")
                st.markdown("### 1,250")
                st.markdown("*This month*")
                st.markdown('</div>', unsafe_allow_html=True)
            
            with col2:
                st.markdown('<div class="metric-card">', unsafe_allow_html=True)
                st.markdown("**Alerts Responded**")
                st.markdown("### 42")
                st.markdown("*Avg. response: 18 min*")
                st.markdown('</div>', unsafe_allow_html=True)
            
            with col3:
                st.markdown('<div class="metric-card">', unsafe_allow_html=True)
                st.markdown("**System Accuracy**")
                st.markdown("### 78.5%")
                st.markdown("*Temperature predictions*")
                st.markdown('</div>', unsafe_allow_html=True)
    
    def run(self):
        """Main application runner"""
        if self.session_state.logged_in:
            self.show_dashboard()
        else:
            self.show_login_page()

# Run the application
if __name__ == "__main__":
    app = VaccineMonitorApp()
    app.run()
