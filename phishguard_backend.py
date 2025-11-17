# phishguard_backend.py
# Complete backend for sending phishing tests and tracking clicks

from fastapi import FastAPI, Request, BackgroundTasks
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from typing import List, Optional
import os
from datetime import datetime
import uuid
import json
from dotenv import load_dotenv
import os
load_dotenv()

# Force reload environment variables
os.environ.setdefault('SMTP_HOST', 'smtp.sendgrid.net')
os.environ.setdefault('SMTP_PORT', '587')

# Email sending
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

app = FastAPI(title="BaitBlock Backend")

# CORS for your React dashboard
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ============================================
# SIMPLE FILE-BASED "DATABASE" (upgrade to Supabase later)
# ============================================

def load_data():
    """Load data from JSON file"""
    try:
        with open('phishguard_data.json', 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return {
            "campaigns": [],
            "clicks": [],
            "companies": {}
        }

def save_data(data):
    """Save data to JSON file"""
    with open('phishguard_data.json', 'w') as f:
        json.dump(data, f, indent=2)

# ============================================
# PHISHING EMAIL TEMPLATES
# ============================================

TEMPLATES = {
    "hr_benefits": {
        "subject": "URGENT: Update Your Benefits Selection by EOD",
        "body": """
        <html>
        <body style="font-family: Arial, sans-serif;">
        <p>Dear Employee,</p>
        
        <p>Our HR system shows you have not yet updated your benefits selection for 2026.</p>
        
        <p><strong>Action Required:</strong> You must review and confirm your benefits by end of day today to avoid losing coverage.</p>
        
        <p style="text-align: center; margin: 30px 0;">
            <a href="{tracking_url}" style="background-color: #0066cc; color: white; padding: 15px 30px; text-decoration: none; border-radius: 5px; font-weight: bold;">
                UPDATE BENEFITS NOW
            </a>
        </p>
        
        <p>If you do not complete this by 5 PM today, you will be automatically enrolled in the minimum coverage plan.</p>
        
        <p>Questions? Contact HR at hr@company.com</p>
        
        <p>Best regards,<br>Human Resources Department</p>
        </body>
        </html>
        """,
        "difficulty": "medium"
    },
    
    "it_password": {
        "subject": "Your password will expire in 24 hours",
        "body": """
        <html>
        <body style="font-family: Arial, sans-serif;">
        <p>Hello,</p>
        
        <p>This is an automated reminder from IT Security.</p>
        
        <p><strong style="color: red;">Your network password will expire in 24 hours.</strong></p>
        
        <p>To prevent account lockout, please update your password immediately:</p>
        
        <p style="text-align: center; margin: 30px 0;">
            <a href="{tracking_url}" style="background-color: #dc3545; color: white; padding: 15px 30px; text-decoration: none; border-radius: 5px; font-weight: bold;">
                RESET PASSWORD
            </a>
        </p>
        
        <p>Failure to update will result in loss of access to:</p>
        <ul>
            <li>Email</li>
            <li>Shared drives</li>
            <li>All company systems</li>
        </ul>
        
        <p>IT Support Team<br>support@company.com</p>
        </body>
        </html>
        """,
        "difficulty": "hard"
    },
    
    "ceo_urgent": {
        "subject": "URGENT - Need you to handle this",
        "body": """
        <html>
        <body style="font-family: Arial, sans-serif;">
        <p>Hi,</p>
        
        <p>I'm in meetings all day but need you to take care of something urgent.</p>
        
        <p>Can you review this document and let me know your thoughts ASAP? It's time sensitive.</p>
        
        <p style="text-align: center; margin: 30px 0;">
            <a href="{tracking_url}" style="background-color: #28a745; color: white; padding: 15px 30px; text-decoration: none; border-radius: 5px; font-weight: bold;">
                VIEW DOCUMENT
            </a>
        </p>
        
        <p>Let me know once you've reviewed it.</p>
        
        <p>Thanks,<br>John CEO</p>
        
        <p style="font-size: 10px; color: #666;">Sent from my iPhone</p>
        </body>
        </html>
        """,
        "difficulty": "easy"
    },
    
    "payroll_update": {
        "subject": "Action Required: Verify Your Direct Deposit Information",
        "body": """
        <html>
        <body style="font-family: Arial, sans-serif;">
        <p>Dear Team Member,</p>
        
        <p>Due to a recent system migration, we need all employees to verify their direct deposit information.</p>
        
        <p><strong>Important:</strong> If you do not verify by Friday, your next paycheck may be delayed.</p>
        
        <p style="text-align: center; margin: 30px 0;">
            <a href="{tracking_url}" style="background-color: #0066cc; color: white; padding: 15px 30px; text-decoration: none; border-radius: 5px; font-weight: bold;">
                VERIFY BANKING INFO
            </a>
        </p>
        
        <p>This only takes 2 minutes and ensures uninterrupted payment.</p>
        
        <p>Thank you,<br>Payroll Department</p>
        </body>
        </html>
        """,
        "difficulty": "medium"
    }
}

# ============================================
# API MODELS
# ============================================

class Employee(BaseModel):
    name: str
    email: EmailStr

class CampaignRequest(BaseModel):
    company_id: str
    campaign_name: str
    template_id: str
    employees: List[Employee]
    from_name: Optional[str] = "Security Team"
    from_email: Optional[str] = "security@phishguard-test.com"

class CompanySetup(BaseModel):
    company_name: str
    admin_email: EmailStr
    employee_count: int

# ============================================
# EMAIL SENDING (using SMTP - works with Gmail, SendGrid, etc.)
# ============================================

def send_phishing_email(to_email: str, to_name: str, template: dict, tracking_url: str, from_name: str, from_email: str):
    """
    Send a phishing test email
    
    SETUP REQUIRED:
    1. For Gmail: Enable "App Passwords" in your Google account
    2. For SendGrid: Get API key from sendgrid.com
    3. Set environment variables:
       - SMTP_HOST (e.g., smtp.gmail.com or smtp.sendgrid.net)
       - SMTP_PORT (587)
       - SMTP_USER (your email or 'apikey' for SendGrid)
       - SMTP_PASS (app password or SendGrid API key)
    """
    
    # Email configuration from environment
    SMTP_HOST = os.getenv('SMTP_HOST', 'smtp.gmail.com')
    SMTP_PORT = int(os.getenv('SMTP_PORT', '587'))
    SMTP_USER = os.getenv('SMTP_USER', 'your-email@gmail.com')
    SMTP_PASS = os.getenv('SMTP_PASS', 'your-app-password')
    
    # Create message
    msg = MIMEMultipart('alternative')
    msg['Subject'] = template['subject']
    msg['From'] = f"{from_name} <{from_email}>"
    msg['To'] = to_email
    
    # Insert tracking URL into template
    html_body = template['body'].replace('{tracking_url}', tracking_url)
    
    # Attach HTML body
    html_part = MIMEText(html_body, 'html')
    msg.attach(html_part)
    
    try:
        # Send via SMTP
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASS)
            server.send_message(msg)
        
        print(f"✅ Sent phishing test to {to_email}")
        return True
    except Exception as e:
        print(f"❌ Failed to send to {to_email}: {str(e)}")
        return False

# ============================================
# API ENDPOINTS
# ============================================

@app.get("/")
def root():
    return {
        "service": "PhishGuard Backend",
        "status": "running",
        "endpoints": {
            "setup_company": "POST /api/setup",
            "launch_campaign": "POST /api/campaign/launch",
            "get_results": "GET /api/campaign/{campaign_id}/results",
            "track_click": "GET /track/{click_id}"
        }
    }

@app.post("/api/setup")
def setup_company(company: CompanySetup):
    """Setup a new company account"""
    data = load_data()
    
    company_id = str(uuid.uuid4())[:8]
    
    data["companies"][company_id] = {
        "id": company_id,
        "name": company.company_name,
        "admin_email": company.admin_email,
        "employee_count": company.employee_count,
        "created_at": datetime.now().isoformat(),
        "campaigns": []
    }
    
    save_data(data)
    
    return {
        "success": True,
        "company_id": company_id,
        "message": f"Company '{company.company_name}' setup complete",
        "dashboard_url": f"https://your-dashboard.com/company/{company_id}"
    }

@app.post("/api/campaign/launch")
async def launch_campaign(campaign: CampaignRequest, background_tasks: BackgroundTasks):
    """Launch a phishing test campaign"""
    
    data = load_data()
    
    # Check if company exists
    if campaign.company_id not in data["companies"]:
        return {"success": False, "error": "Company not found"}
    
    # Check if template exists
    if campaign.template_id not in TEMPLATES:
        return {"success": False, "error": "Template not found"}
    
    template = TEMPLATES[campaign.template_id]
    campaign_id = str(uuid.uuid4())
    
    # Create campaign record
    campaign_record = {
        "id": campaign_id,
        "company_id": campaign.company_id,
        "name": campaign.campaign_name,
        "template_id": campaign.template_id,
        "launched_at": datetime.now().isoformat(),
        "total_sent": len(campaign.employees),
        "total_clicked": 0,
        "employees": []
    }
    
    # Send emails to each employee
    base_url = os.getenv('BASE_URL', 'http://localhost:8000')
    
    for emp in campaign.employees:
        # Generate unique tracking ID for this employee
        click_id = str(uuid.uuid4())
        tracking_url = f"{base_url}/track/{click_id}"
        
        # Store employee in campaign
        campaign_record["employees"].append({
            "name": emp.name,
            "email": emp.email,
            "click_id": click_id,
            "clicked": False,
            "click_time": None
        })
        
        # Store click tracking record
        data["clicks"].append({
            "click_id": click_id,
            "campaign_id": campaign_id,
            "company_id": campaign.company_id,
            "employee_email": emp.email,
            "employee_name": emp.name,
            "clicked": False,
            "click_time": None
        })
        
        # Send email in background
        background_tasks.add_task(
            send_phishing_email,
            emp.email,
            emp.name,
            template,
            tracking_url,
            campaign.from_name,
            campaign.from_email
        )
    
    # Save campaign
    data["campaigns"].append(campaign_record)
    data["companies"][campaign.company_id]["campaigns"].append(campaign_id)
    save_data(data)
    
    return {
        "success": True,
        "campaign_id": campaign_id,
        "message": f"Campaign launched! Sending {len(campaign.employees)} phishing test emails.",
        "employees_targeted": len(campaign.employees),
        "template": campaign.template_id
    }

@app.get("/track/{click_id}")
async def track_click(click_id: str, request: Request):
    """
    Track when someone clicks a phishing link
    This is the URL that appears in the phishing email
    """
    
    data = load_data()
    
    # Find the click record
    click_record = None
    for click in data["clicks"]:
        if click["click_id"] == click_id:
            click_record = click
            break
    
    if not click_record:
        return HTMLResponse("<h1>Invalid link</h1>")
    
    # Only count first click
    if not click_record["clicked"]:
        click_record["clicked"] = True
        click_record["click_time"] = datetime.now().isoformat()
        click_record["ip_address"] = request.client.host
        click_record["user_agent"] = request.headers.get("user-agent", "Unknown")
        
        # Update campaign stats
        for campaign in data["campaigns"]:
            if campaign["id"] == click_record["campaign_id"]:
                campaign["total_clicked"] += 1
                
                # Update employee record in campaign
                for emp in campaign["employees"]:
                    if emp["click_id"] == click_id:
                        emp["clicked"] = True
                        emp["click_time"] = click_record["click_time"]
                        break
                break
        
        save_data(data)
        print(f"🎯 CLICK TRACKED: {click_record['employee_name']} ({click_record['employee_email']})")
    
    # Show "caught" page
    return HTMLResponse("""
    <html>
    <head>
        <title>PhishGuard Training</title>
        <style>
            body {
                font-family: Arial, sans-serif;
                max-width: 600px;
                margin: 100px auto;
                padding: 20px;
                text-align: center;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: white;
            }
            .box {
                background: rgba(255,255,255,0.1);
                backdrop-filter: blur(10px);
                padding: 40px;
                border-radius: 20px;
                box-shadow: 0 8px 32px rgba(0,0,0,0.3);
            }
            h1 { font-size: 48px; margin: 0 0 20px 0; }
            p { font-size: 18px; line-height: 1.6; }
            .emoji { font-size: 72px; margin: 20px 0; }
            .tips {
                text-align: left;
                margin-top: 30px;
                background: rgba(255,255,255,0.1);
                padding: 20px;
                border-radius: 10px;
            }
            .tips li { margin: 10px 0; }
        </style>
    </head>
    <body>
        <div class="box">
            <div class="emoji">🎣</div>
            <h1>You've Been Phished!</h1>
            <p><strong>Don't worry - this was a training exercise.</strong></p>
            <p>This was a simulated phishing attack designed to help you recognize threats.</p>
            
            <div class="tips">
                <h3>🛡️ How to Spot Phishing:</h3>
                <ul>
                    <li>✓ Check sender's email carefully</li>
                    <li>✓ Look for urgent language and threats</li>
                    <li>✓ Hover over links before clicking</li>
                    <li>✓ Be suspicious of unexpected requests</li>
                    <li>✓ When in doubt, contact IT directly</li>
                </ul>
            </div>
            
            <p style="margin-top: 30px; font-size: 14px; opacity: 0.8;">
                This test was conducted by PhishGuard Security Training
            </p>
        </div>
    </body>
    </html>
    """)

@app.get("/api/campaign/{campaign_id}/results")
def get_campaign_results(campaign_id: str):
    """Get results for a specific campaign"""
    
    data = load_data()
    
    # Find campaign
    campaign = None
    for c in data["campaigns"]:
        if c["id"] == campaign_id:
            campaign = c
            break
    
    if not campaign:
        return {"success": False, "error": "Campaign not found"}
    
    # Calculate stats
    total_sent = campaign["total_sent"]
    total_clicked = campaign["total_clicked"]
    click_rate = (total_clicked / total_sent * 100) if total_sent > 0 else 0
    
    return {
        "success": True,
        "campaign": {
            "id": campaign_id,
            "name": campaign["name"],
            "launched_at": campaign["launched_at"],
            "template": campaign["template_id"]
        },
        "stats": {
            "total_sent": total_sent,
            "total_clicked": total_clicked,
            "click_rate": round(click_rate, 1),
            "safe_count": total_sent - total_clicked
        },
        "employees": campaign["employees"]
    }

@app.get("/api/templates")
def get_templates():
    """List all available phishing templates"""
    return {
        "templates": [
            {
                "id": key,
                "subject": val["subject"],
                "difficulty": val["difficulty"]
            }
            for key, val in TEMPLATES.items()
        ]
    }

@app.get("/api/company/{company_id}/dashboard")
def get_company_dashboard(company_id: str):
    """Get dashboard data for a company"""
    
    data = load_data()
    
    if company_id not in data["companies"]:
        return {"success": False, "error": "Company not found"}
    
    company = data["companies"][company_id]
    
    # Get all campaigns for this company
    company_campaigns = [
        c for c in data["campaigns"] 
        if c["company_id"] == company_id
    ]
    
    # Calculate overall stats
    total_sent = sum(c["total_sent"] for c in company_campaigns)
    total_clicked = sum(c["total_clicked"] for c in company_campaigns)
    
    return {
        "success": True,
        "company": {
            "id": company_id,
            "name": company["name"],
            "employee_count": company["employee_count"]
        },
        "overall_stats": {
            "campaigns_run": len(company_campaigns),
            "total_emails_sent": total_sent,
            "total_clicks": total_clicked,
            "overall_click_rate": round((total_clicked / total_sent * 100) if total_sent > 0 else 0, 1)
        },
        "recent_campaigns": company_campaigns[-5:]  # Last 5 campaigns
    }

if __name__ == "__main__":
    print("""
    ╔══════════════════════════════════════════════╗
    ║      PhishGuard Backend Server               ║
    ╚══════════════════════════════════════════════╝
    
    Backend is ready!
    Open http://localhost:8000/docs to test the API
    """)
    
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)