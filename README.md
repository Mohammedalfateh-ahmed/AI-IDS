# AI-Powered Intrusion Detection System (AI-IDS)

> Enterprise-grade Network Intrusion Detection System with Dual-Layer Detection Architecture (XGBoost ML + Behavioral Anomaly Analysis)

**Author:** Mohammed Alfateh  
**Institution:** Final International University  
**Project:** Graduation Project 2026  
**Detection Rate:** 90% (77.3% ML + Behavioral Analysis)

---

## 📋 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [System Architecture](#system-architecture)
- [Technology Stack](#technology-stack)
- [Detection Methodology](#detection-methodology)
- [Installation](#installation)
  - [Prerequisites](#prerequisites)
  - [Local Development Setup](#local-development-setup)
  - [Environment Variables](#environment-variables)
- [Deployment](#deployment)
  - [Deploy to Render](#deploy-to-render)
  - [Deploy to Heroku](#deploy-to-heroku)
  - [Deploy with Docker](#deploy-with-docker)
- [Usage](#usage)
- [API Documentation](#api-documentation)
- [Project Structure](#project-structure)
- [Performance Metrics](#performance-metrics)
- [Future Enhancements](#future-enhancements)
- [Contributing](#contributing)
- [License](#license)
- [Acknowledgments](#acknowledgments)

---

## 🎯 Overview

AI-IDS is an advanced network intrusion detection system that combines **machine learning classification** with **behavioral anomaly detection** to achieve high detection rates for both known and zero-day attacks. The system uses a dual-layer architecture:

1. **Layer 1 - XGBoost ML Model:** Detects known attack patterns from NSL-KDD dataset (77.3% accuracy)
2. **Layer 2 - Behavioral Anomaly Analysis:** Detects zero-day threats using 3-sigma statistical deviation (catches attacks ML misses)

**Result:** ~90% combined detection rate with <5% false positives

### Key Differentiators

- ✅ **Dual-layer detection** - Multiple complementary methods
- ✅ **Zero-day protection** - Statistical anomaly detection catches novel attacks
- ✅ **Enterprise features** - JWT auth, RBAC, email alerts, auto-blocking
- ✅ **Real-time analysis** - <100ms detection latency
- ✅ **Professional dashboard** - Wazuh-inspired React interface
- ✅ **Open source** - $0 cost vs $50K-200K commercial alternatives

---

## 🚀 Features

### Detection & Analysis

- **XGBoost ML Classification**
  - Trained on 148,517 NSL-KDD records
  - 41 network features per packet
  - 4 attack categories: DoS, Probe, R2L, U2R
  - 77.3% accuracy on separate test set

- **Behavioral Anomaly Detection**
  - Per-IP baseline learning (1 min + 10 packets)
  - 3-sigma statistical deviation analysis
  - 5 anomaly types: packet size, rate, port usage, protocol, temporal
  - Risk scoring: 0-100 scale with severity levels

- **Real-time Packet Capture**
  - Scapy-based network monitoring
  - Feature extraction engine
  - Live packet statistics

### Security & Response

- **JWT Authentication** - Secure token-based auth
- **Role-Based Access Control** - Admin, Analyst, Viewer roles
- **Auto-Blocking (IPS Mode)** - Automatic IP blocking for threats >80% confidence
- **Email Alerts** - SMTP notifications for critical alerts
- **IP Whitelist/Blacklist** - Manual control over blocking
- **MITRE ATT&CK Mapping** - Attack technique classification

### Dashboard & Visualization

- **Overview Tab** - Real-time statistics and charts
- **Alerts Tab** - Recent attacks with filtering
- **Behavioral Analysis Tab** - Anomaly trends and top IPs
- **Statistics Tab** - Attack distribution and analytics
- **Responsive Design** - Desktop and mobile support

### Data Management

- **MongoDB Storage** - Scalable document database
- **JSON Profile Storage** - Fast behavioral baseline read/write
- **System Audit Logs** - Complete event tracking
- **Export Capabilities** - CSV export for reports

---

## 🏗️ System Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Network Layer                            │
│              (Scapy Real-time Capture)                      │
└────────────────────┬────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────┐
│                Feature Extraction                           │
│         (41 NSL-KDD Network Attributes)                     │
└────────────────────┬────────────────────────────────────────┘
                     │
         ┌───────────┴───────────┐
         │                       │
         ▼                       ▼
┌──────────────────┐    ┌──────────────────┐
│   Layer 1:       │    │   Layer 2:       │
│   XGBoost ML     │    │   Behavioral     │
│   (77.3%)        │    │   Analysis       │
│                  │    │   (3-sigma)      │
└────────┬─────────┘    └────────┬─────────┘
         │                       │
         └───────────┬───────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────┐
│              Decision Engine                                │
│         (Combined Risk Scoring)                             │
└────────────────────┬────────────────────────────────────────┘
                     │
         ┌───────────┴───────────┐
         │                       │
         ▼                       ▼
┌──────────────────┐    ┌──────────────────┐
│   Response       │    │   Storage        │
│   - Block IP     │    │   - MongoDB      │
│   - Send Alert   │    │   - JSON Files   │
│   - Email Notify │    │   - System Logs  │
└──────────────────┘    └──────────────────┘
         │
         ▼
┌─────────────────────────────────────────────────────────────┐
│              React Dashboard                                │
│    (Real-time Visualization & Analytics)                    │
└─────────────────────────────────────────────────────────────┘
```

### Three-Tier Architecture

**Frontend (Presentation Layer)**
- React 18 with TypeScript
- TailwindCSS styling
- Recharts visualization
- REST API communication

**Backend (Business Logic Layer)**
- Python 3.11 with FastAPI
- Scapy packet capture
- XGBoost classification
- Behavioral analysis engine

**Database (Data Layer)**
- MongoDB for structured data
- JSON for behavioral profiles
- Indexed queries for performance

---

## 💻 Technology Stack

### Backend
- **Python 3.11** - Core language
- **FastAPI** - Modern async web framework
- **XGBoost 2.0** - Gradient boosting ML
- **Scapy** - Packet manipulation
- **NumPy/Pandas** - Data processing
- **PyMongo** - MongoDB driver
- **Bcrypt** - Password hashing
- **JWT** - Authentication tokens
- **SMTP** - Email notifications

### Frontend
- **React 18** - UI library
- **TailwindCSS** - Utility-first CSS
- **Recharts** - Chart library
- **Lucide React** - Icon library
- **Axios** - HTTP client

### Database
- **MongoDB 7.0** - NoSQL database
- Collections: users, alerts, blocked_ips, system_logs

### ML & Data
- **NSL-KDD Dataset** - Training/testing data
- **Scikit-learn** - Preprocessing
- **Joblib** - Model persistence

---

## 🧠 Detection Methodology

### XGBoost ML Model

**Training Process:**
1. Load NSL-KDD training set (125,973 samples)
2. Encode categorical features (protocol, service, flag)
3. Normalize numeric features (0-1 range)
4. Train XGBoost with parameters:
   - max_depth=6
   - n_estimators=100
   - learning_rate=0.1
5. Evaluate on separate test set (22,544 samples)

**Performance:**
- Accuracy: 77.3%
- Precision: 75.8%
- Recall: 76.5%
- F1-Score: 76.1%

### Behavioral Anomaly Detection

**Learning Phase (per IP):**
- Minimum: 10 packets + 1 minute observation
- Calculate statistical baselines:
  - Mean (μ) and standard deviation (σ) of packet sizes
  - Mean (μ) and standard deviation (σ) of packet intervals
  - Port usage frequency distribution
  - Protocol distribution (TCP/UDP/ICMP)
  - Hourly activity patterns

**Detection Phase:**
- Calculate z-score: `z = (current_value - μ) / σ`
- Threshold: z > 2.5 (adjusted 3-sigma rule)
- Anomaly types detected:
  1. Packet size deviation
  2. Packet rate anomaly
  3. Unusual port access
  4. Protocol deviation
  5. Temporal pattern anomaly

**Risk Scoring:**
- Each anomaly contributes up to 25 points
- Total score: 0-100
- Severity levels:
  - CRITICAL (80-100)
  - HIGH (60-79)
  - MEDIUM (40-59)
  - LOW (20-39)
  - NORMAL (<20)

---

## 📦 Installation

### Prerequisites

- **Python 3.11+**
- **Node.js 18+** and npm
- **MongoDB 7.0+** (local or cloud)
- **Git**

### Local Development Setup

#### 1. Clone Repository

```bash
git clone https://github.com/YOUR_USERNAME/AI-IDS.git
cd AI-IDS
```

#### 2. Backend Setup

```bash
cd backend

# Create virtual environment
python -m venv venv

# Activate virtual environment
# Windows:
venv\Scripts\activate
# Linux/Mac:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Create necessary directories
mkdir -p data
mkdir -p models

# Download NSL-KDD dataset (if not included)
# Place KDDTrain+.txt and KDDTest+.txt in data/

# Train ML model (if model not included)
python train_model.py
```

#### 3. Frontend Setup

```bash
cd ../frontend

# Install dependencies
npm install

# Build for production (optional)
npm run build
```

#### 4. Configure Environment Variables

Create `.env` file in `backend/` directory:

```env
# MongoDB
MONGODB_URI=mongodb://localhost:27017/
DATABASE_NAME=ai_ids

# JWT
SECRET_KEY=your-super-secret-jwt-key-change-this-in-production
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=1440

# Email Configuration (Gmail example)
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your-email@gmail.com
SMTP_PASSWORD=your-app-password
ALERT_EMAIL_RECIPIENT=admin@example.com

# Application
DEBUG=True
ALLOWED_ORIGINS=http://localhost:3000,http://localhost:5173
```

Create `.env` file in `frontend/` directory:

```env
VITE_API_URL=http://localhost:8000
```

#### 5. Start MongoDB

```bash
# Windows:
cd C:\Program Files\MongoDB\Server\8.2\bin
mongod --dbpath C:\data\db


# Linux/Mac:
mongod --dbpath /data/db
```

#### 6. Run Application

**Backend:**
```bash
cd backend
python app/main.py
# Server runs on http://localhost:8000
```

**Frontend:**
```bash
cd frontend
npm run dev
# Server runs on http://localhost:3000
```

#### 7. Access Application

- **Frontend:** http://localhost:3000
- **API Docs:** http://localhost:8000/docs
- **API ReDoc:** http://localhost:8000/redoc

**Default Login:**
- Username: `admin`
- Password: `admin123` (change immediately!)

---

## 🌐 Deployment

### Deploy to Render

#### Prerequisites
1. Create account at [render.com](https://render.com)
2. Connect your GitHub repository

#### Backend Deployment

1. **Create New Web Service**
   - Go to Render Dashboard → New → Web Service
   - Connect your GitHub repo
   - Configure:
     - **Name:** ai-ids-backend
     - **Environment:** Python 3
     - **Build Command:** `pip install -r requirements.txt`
     - **Start Command:** `uvicorn app.main:app --host 0.0.0.0 --port $PORT`
     - **Instance Type:** Free (or paid for production)

2. **Add Environment Variables**
   ```
   MONGODB_URI=mongodb+srv://username:password@cluster.mongodb.net/
   DATABASE_NAME=ai_ids
   SECRET_KEY=your-production-secret-key-min-32-chars
   ALGORITHM=HS256
   ACCESS_TOKEN_EXPIRE_MINUTES=1440
   SMTP_SERVER=smtp.gmail.com
   SMTP_PORT=587
   SMTP_USERNAME=your-email@gmail.com
   SMTP_PASSWORD=your-app-password
   ALERT_EMAIL_RECIPIENT=admin@example.com
   DEBUG=False
   ALLOWED_ORIGINS=https://your-frontend.onrender.com
   ```

3. **Deploy**
   - Click "Create Web Service"
   - Wait for deployment (5-10 minutes)
   - Copy service URL: `https://ai-ids-backend.onrender.com`

#### Frontend Deployment

1. **Update API URL**
   - Edit `frontend/.env.production`:
     ```
     VITE_API_URL=https://ai-ids-backend.onrender.com
     ```

2. **Create Static Site**
   - Render Dashboard → New → Static Site
   - Connect GitHub repo
   - Configure:
     - **Name:** ai-ids-frontend
     - **Build Command:** `cd frontend && npm install && npm run build`
     - **Publish Directory:** `frontend/dist`

3. **Deploy**
   - Click "Create Static Site"
   - Wait for deployment
   - Access: `https://ai-ids-frontend.onrender.com`

#### MongoDB Atlas Setup

1. **Create Cluster**
   - Go to [mongodb.com/cloud/atlas](https://www.mongodb.com/cloud/atlas)
   - Create free cluster

2. **Configure Access**
   - Database Access → Add user
   - Network Access → Add IP Address → Allow from Anywhere (0.0.0.0/0)

3. **Get Connection String**
   - Clusters → Connect → Connect your application
   - Copy connection string
   - Replace `<password>` with your password
   - Use in `MONGODB_URI` environment variable

---

### Deploy to Heroku

#### Prerequisites
```bash
# Install Heroku CLI
# Windows: Download from heroku.com/cli
# Mac: brew install heroku/brew/heroku
# Linux: curl https://cli-assets.heroku.com/install.sh | sh

# Login
heroku login
```

#### Backend Deployment

```bash
cd backend

# Create Heroku app
heroku create ai-ids-backend

# Add buildpack
heroku buildpacks:set heroku/python

# Set environment variables
heroku config:set MONGODB_URI="your-mongodb-uri"
heroku config:set SECRET_KEY="your-secret-key"
heroku config:set DATABASE_NAME="ai_ids"
heroku config:set DEBUG="False"
heroku config:set ALLOWED_ORIGINS="https://ai-ids-frontend.herokuapp.com"

# Create Procfile
echo "web: uvicorn app.main:app --host 0.0.0.0 --port \$PORT" > Procfile

# Deploy
git add .
git commit -m "Deploy to Heroku"
git push heroku main

# Open app
heroku open
```

#### Frontend Deployment

```bash
cd frontend

# Update API URL in .env.production
echo "VITE_API_URL=https://ai-ids-backend.herokuapp.com" > .env.production

# Install Heroku buildpack
heroku create ai-ids-frontend
heroku buildpacks:set mars/create-react-app

# Create static.json for routing
cat > static.json << EOF
{
  "root": "dist/",
  "routes": {
    "/**": "index.html"
  }
}
EOF

# Deploy
git add .
git commit -m "Deploy frontend"
git push heroku main
```

---

### Deploy with Docker

#### Prerequisites
- Docker installed
- Docker Compose installed

#### Docker Files

**backend/Dockerfile:**
```dockerfile
FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY . .

# Expose port
EXPOSE 8000

# Run application
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
```

**frontend/Dockerfile:**
```dockerfile
FROM node:18-alpine as build

WORKDIR /app

# Copy package files
COPY package*.json ./
RUN npm install

# Copy source
COPY . .

# Build
RUN npm run build

# Production stage
FROM nginx:alpine
COPY --from=build /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
```

**docker-compose.yml:**
```yaml
version: '3.8'

services:
  mongodb:
    image: mongo:7.0
    container_name: ai-ids-mongodb
    ports:
      - "27017:27017"
    volumes:
      - mongodb_data:/data/db
    environment:
      MONGO_INITDB_ROOT_USERNAME: admin
      MONGO_INITDB_ROOT_PASSWORD: admin123

  backend:
    build: ./backend
    container_name: ai-ids-backend
    ports:
      - "8000:8000"
    environment:
      MONGODB_URI: mongodb://admin:admin123@mongodb:27017/
      DATABASE_NAME: ai_ids
      SECRET_KEY: your-secret-key-change-this
      DEBUG: "True"
      ALLOWED_ORIGINS: http://localhost:3000
    depends_on:
      - mongodb
    volumes:
      - ./backend:/app

  frontend:
    build: ./frontend
    container_name: ai-ids-frontend
    ports:
      - "3000:80"
    environment:
      VITE_API_URL: http://localhost:8000
    depends_on:
      - backend

volumes:
  mongodb_data:
```

#### Deploy with Docker Compose

```bash
# Build and start all services
docker-compose up -d

# View logs
docker-compose logs -f

# Stop services
docker-compose down

# Rebuild after changes
docker-compose up -d --build
```

---

## 🎮 Usage

### Initial Setup

1. **Access Application**
   - Open browser: http://localhost:3000
   - Login with default credentials (admin/admin123)

2. **Change Admin Password**
   - Click profile icon → Settings
   - Change password immediately

3. **Configure Email Alerts**
   - Settings → Alerts
   - Enter email configuration
   - Test email delivery

### Basic Operations

#### View Dashboard
- **Overview Tab:** Real-time statistics
- **Alerts Tab:** Recent attack detections
- **Behavioral Analysis:** Anomaly trends
- **Statistics:** Attack distribution

#### Simulate Attacks (Testing)
```bash
# From Dashboard
1. Click "Simulate Attack" button
2. Select attack type (DoS, Probe, R2L, U2R)
3. Watch detection in real-time
4. Check Alerts tab for details
```

#### Manual IP Blocking
```bash
# From Dashboard → Blocked IPs
1. Enter IP address
2. Set duration (hours)
3. Add reason/notes
4. Click "Block IP"
```

#### Export Reports
```bash
# From Alerts Tab
1. Filter alerts (date range, severity, type)
2. Click "Export to CSV"
3. Save file for analysis
```

### API Usage

#### Authentication
```bash
# Get JWT token
curl -X POST "http://localhost:8000/auth/login" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "password": "admin123"
  }'

# Response
{
  "access_token": "eyJhbGc...",
  "token_type": "bearer",
  "user": {
    "username": "admin",
    "role": "admin"
  }
}
```

#### Get Alerts
```bash
curl -X GET "http://localhost:8000/alerts?limit=10" \
  -H "Authorization: Bearer YOUR_TOKEN"
```

#### Get Behavioral Statistics
```bash
curl -X GET "http://localhost:8000/behavior/statistics" \
  -H "Authorization: Bearer YOUR_TOKEN"
```

---

## 📚 API Documentation

### Endpoints Overview

**Authentication**
- `POST /auth/register` - Register new user
- `POST /auth/login` - Login and get JWT token
- `GET /auth/me` - Get current user info

**Alerts**
- `GET /alerts` - Get all alerts (with pagination)
- `GET /alerts/{alert_id}` - Get specific alert
- `DELETE /alerts/{alert_id}` - Delete alert (admin only)

**Behavioral Analysis**
- `GET /behavior/statistics` - Get system-wide stats
- `GET /behavior/ip/{ip_address}` - Get per-IP profile
- `GET /behavior/anomalies` - Get recent anomalies
- `GET /behavior/top-anomalous-ips` - Get ranked IPs
- `POST /behavior/save-profiles` - Manual save

**Detection**
- `POST /simulate` - Simulate attack (testing)
- `POST /detect` - Real-time packet detection

**IP Management**
- `GET /blocked-ips` - Get blocked IPs
- `POST /blocked-ips` - Block IP manually
- `DELETE /blocked-ips/{ip}` - Unblock IP

**Statistics**
- `GET /statistics/overview` - Dashboard overview
- `GET /statistics/attacks-by-type` - Attack distribution
- `GET /statistics/hourly-activity` - Time-based analysis

**Full API documentation available at:**
- Swagger UI: http://localhost:8000/docs
- ReDoc: http://localhost:8000/redoc

---

## 📁 Project Structure

```
AI-IDS/
├── backend/
│   ├── app/
│   │   ├── main.py                      # FastAPI application entry
│   │   ├── auth.py                      # JWT authentication
│   │   ├── database.py                  # MongoDB connection
│   │   ├── models.py                    # Pydantic models
│   │   ├── behavior_analyzer.py         # Behavioral detection
│   │   └── utils.py                     # Utility functions
│   ├── data/
│   │   ├── KDDTrain+.txt               # NSL-KDD training data
│   │   ├── KDDTest+.txt                # NSL-KDD test data
│   │   └── behavior_profiles.json      # IP baselines
│   ├── models/
│   │   ├── ids_model.pkl               # Trained XGBoost model
│   │   ├── label_encoder.pkl           # Label encoder
│   │   └── scaler.pkl                  # Feature scaler
│   ├── requirements.txt                 # Python dependencies
│   ├── train_model.py                   # Model training script
│   └── Dockerfile                       # Backend Docker config
├── frontend/
│   ├── src/
│   │   ├── components/
│   │   │   ├── Dashboard.jsx           # Main dashboard
│   │   │   ├── AlertsTable.jsx         # Alerts display
│   │   │   ├── BehavioralAnomalyWidget.jsx  # Behavioral tab
│   │   │   └── ...                     # Other components
│   │   ├── App.jsx                     # Root component
│   │   ├── main.jsx                    # Entry point
│   │   └── index.css                   # Global styles
│   ├── public/                          # Static assets
│   ├── package.json                     # npm dependencies
│   ├── vite.config.js                  # Vite configuration
│   └── Dockerfile                       # Frontend Docker config
├── docker-compose.yml                   # Docker orchestration
├── .gitignore                          # Git ignore rules
├── LICENSE                             # MIT License
└── README.md                           # This file
```

---

## 📊 Performance Metrics

### Detection Performance

| Metric | XGBoost Alone | With Behavioral | Improvement |
|--------|---------------|-----------------|-------------|
| Accuracy | 77.3% | ~90% | +13% |
| Precision | 75.8% | ~88% | +12% |
| Recall | 76.5% | ~91% | +15% |
| False Positives | ~8% | <5% | -3% |

### System Capacity

- **Training Data:** 148,517 NSL-KDD records
- **Features:** 41 network attributes per packet
- **Baselines:** 9 pre-seeded + unlimited learnable
- **Detection Latency:** <100ms average
- **Learning Time:** 1 minute + 10 packets per IP
- **Concurrent Users:** 100+ (tested)

### Comparison with Commercial Solutions

| Feature | AI-IDS | Darktrace | Vectra AI | Cisco | Palo Alto |
|---------|--------|-----------|-----------|-------|-----------|
| Detection Rate | ~90% | 85-95%* | 85-95%* | 80-90%* | 85-92%* |
| Zero-Day Detection | ✅ Yes | ✅ Yes | ✅ Yes | ✅ Yes | ✅ Yes |
| ML Algorithm | XGBoost | Proprietary | Proprietary | Custom | Custom |
| Behavioral Analysis | ✅ 3-sigma | ✅ Advanced | ✅ Advanced | ✅ Yes | ✅ Yes |
| Annual Cost | **$0** | $50K-100K | $75K-150K | $100K-200K | $80K-180K |
| Source Code | ✅ Open | ❌ Closed | ❌ Closed | ❌ Closed | ❌ Closed |

*Claimed by vendor

---

## 🔮 Future Enhancements

### Planned Features

1. **LSTM Time-Series Prediction** (Q2 2026)
   - Predict next attack type from packet sequences
   - Proactive threat forecasting
   - Attack chain detection

2. **Deep Learning Enhancement** (Q3 2026)
   - CNN for packet byte analysis
   - Bidirectional LSTM for flows
   - Attention mechanisms

3. **Threat Intelligence Integration** (Q2 2026)
   - AbuseIPDB, AlienVault OTX feeds
   - IP reputation scoring
   - Geo-location enrichment

4. **Distributed Architecture** (Q4 2026)
   - Multi-node deployment
   - Load balancing
   - Centralized management

5. **Advanced Visualization** (Q3 2026)
   - 3D network topology
   - Attack flow maps
   - Interactive heat maps

6. **Mobile Application** (Q4 2026)
   - iOS and Android apps
   - Push notifications
   - Remote management

---

## 🤝 Contributing

Contributions are welcome! Please follow these guidelines:

### How to Contribute

1. **Fork the Repository**
   ```bash
   git clone https://github.com/YOUR_USERNAME/AI-IDS.git
   ```

2. **Create Feature Branch**
   ```bash
   git checkout -b feature/AmazingFeature
   ```

3. **Commit Changes**
   ```bash
   git commit -m 'Add AmazingFeature'
   ```

4. **Push to Branch**
   ```bash
   git push origin feature/AmazingFeature
   ```

5. **Open Pull Request**
   - Describe your changes
   - Reference any related issues
   - Wait for review

### Code Standards

- **Python:** Follow PEP 8 style guide
- **JavaScript:** Use ESLint with Airbnb config
- **Comments:** Write clear, concise comments
- **Tests:** Include unit tests for new features
- **Documentation:** Update README for major changes

### Reporting Issues

- Use GitHub Issues
- Provide detailed description
- Include steps to reproduce
- Attach screenshots if applicable

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

```
MIT License

Copyright (c) 2026 Mohammed Alfateh

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

## 🙏 Acknowledgments

### Datasets & Resources

- **NSL-KDD Dataset** - University of New Brunswick
  - Used for ML model training and evaluation
  - Industry-standard IDS benchmark

- **MITRE ATT&CK Framework** - MITRE Corporation
  - Attack technique classification
  - Threat intelligence mapping

### Inspiration & References

- **Wazuh** - Open-source SIEM/IDS design inspiration
- **Darktrace** - Behavioral anomaly detection concepts
- **Snort/Suricata** - Rule-based IDS comparison
- **Research Papers:**
  - "Intrusion Detection using Machine Learning" (Various authors)
  - "Statistical Anomaly Detection in Network Traffic" (IEEE)
  - "Deep Learning for Cybersecurity" (ACM)

### Technologies Used

- **FastAPI** - Modern Python web framework
- **React** - UI library by Meta
- **XGBoost** - Gradient boosting by DMLC
- **MongoDB** - NoSQL database
- **TailwindCSS** - Utility-first CSS framework
- **Scapy** - Packet manipulation library

### Special Thanks

- **Final International University** - Academic support and resources
- **Thesis Advisors** - Guidance and feedback
- **Open Source Community** - Tools and libraries
- **Beta Testers** - Feedback and bug reports

---

## 📞 Contact & Support

**Author:** Mohammed Alfateh  
**Email:** mohammedalfateh@example.com  
**University:** Final International University  
**GitHub:** [@YOUR_USERNAME](https://github.com/YOUR_USERNAME)  
**LinkedIn:** [Mohammed Alfateh](https://linkedin.com/in/YOUR_PROFILE)

### Support Channels

- **GitHub Issues:** Bug reports and feature requests
- **Documentation:** Check README and API docs first
- **Email:** For private inquiries
- **Discussions:** GitHub Discussions for questions

---

## 🎓 Academic Usage

This project was developed as a graduation project for Final International University (2026).

**Citing This Work:**

```bibtex
@mastersthesis{alfateh2026aiids,
  title={AI-Powered Intrusion Detection System with Dual-Layer Detection Architecture},
  author={Alfateh, Mohammed},
  year={2026},
  school={Final International University},
  type={Bachelor's Thesis},
  note={Detection Rate: ~90\% (XGBoost 77.3\% + Behavioral Anomaly Analysis)}
}
```

---

## 📈 Project Status

- ✅ **Core Features:** Complete and tested
- ✅ **ML Model:** Trained and deployed (77.3% accuracy)
- ✅ **Behavioral Detection:** Implemented and working (~90% combined)
- ✅ **Dashboard:** Fully functional with real-time updates
- ✅ **Authentication:** JWT + RBAC implemented
- ✅ **Deployment:** Ready for Render/Heroku/Docker
- 🚧 **Future Enhancements:** See roadmap above

**Last Updated:** March 2026  
**Version:** 1.0.0  
**Status:** Production Ready

---

## 🌟 Star History

[![Star History Chart](https://api.star-history.com/svg?repos=YOUR_USERNAME/AI-IDS&type=Date)](https://star-history.com/#YOUR_USERNAME/AI-IDS&Date)

---

<div align="center">

**[⬆ Back to Top](#ai-powered-intrusion-detection-system-ai-ids)**

Made with ❤️ by [Mohammed Alfateh](https://github.com/YOUR_USERNAME)

</div>