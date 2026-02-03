# Agentic Honey-Pot for Scam Detection & Intelligence Extraction

An AI-powered honeypot system that detects scam messages, engages scammers autonomously with human-like responses, and extracts actionable intelligence.

## Features

- **Scam Detection**: Pattern-based detection of bank fraud, UPI fraud, phishing, and fake offers
- **AI-Powered Engagement**: Believable human-like responses using GPT-4 or Llama 3.3
- **Intelligence Extraction**: Automatic extraction of bank accounts, UPI IDs, phone numbers, and phishing links
- **Multi-turn Conversations**: Maintains context across conversation sessions
- **GUVI Integration**: Automatic callback to GUVI evaluation endpoint

## Quick Start

### 1. Install Dependencies

```bash
# Using uv (recommended)
uv sync

# Or using pip
pip install -e .
```

### 2. Configure Environment

```bash
# Copy the example environment file
cp .env.example .env

# Edit .env and add your API keys
```

**Required Configuration:**
- `API_KEY`: Your secret key for API authentication
- `OPENAI_API_KEY` or `GROQ_API_KEY`: For AI-powered responses

### 3. Run the Server

```bash
# Using uv
uv run python main.py

# Or directly
python main.py

# Or with uvicorn
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

The API will be available at `http://localhost:8000`

## API Endpoints

### Main Honeypot Endpoint

```
POST /api/honeypot
```

**Headers:**
```
x-api-key: YOUR_SECRET_API_KEY
Content-Type: application/json
```

**Request Body (First Message):**
```json
{
  "sessionId": "unique-session-id",
  "message": {
    "sender": "scammer",
    "text": "Your bank account will be blocked today. Verify immediately.",
    "timestamp": "2026-01-21T10:15:30Z"
  },
  "conversationHistory": [],
  "metadata": {
    "channel": "SMS",
    "language": "English",
    "locale": "IN"
  }
}
```

**Request Body (Follow-up Message):**
```json
{
  "sessionId": "unique-session-id",
  "message": {
    "sender": "scammer",
    "text": "Share your UPI ID to avoid suspension.",
    "timestamp": "2026-01-21T10:17:10Z"
  },
  "conversationHistory": [
    {
      "sender": "scammer",
      "text": "Your bank account will be blocked today. Verify immediately.",
      "timestamp": "2026-01-21T10:15:30Z"
    },
    {
      "sender": "user",
      "text": "Oh no! Why is my account being blocked?",
      "timestamp": "2026-01-21T10:16:10Z"
    }
  ],
  "metadata": {
    "channel": "SMS",
    "language": "English",
    "locale": "IN"
  }
}
```

**Response:**
```json
{
  "status": "success",
  "reply": "Why is my account being suspended?"
}
```

### Health Check

```
GET /health
```

### Session Info (Debug)

```
GET /api/session/{session_id}
```

### Force Callback (Testing)

```
POST /api/force-callback/{session_id}
```

## Deployment

### Option 1: Deploy to Render (Recommended - Free Tier)

#### Step 1: Create Render Account
1. Go to [render.com](https://render.com) and sign up
2. Connect your GitHub account

#### Step 2: Create New Web Service
1. Click **"New +"** → **"Web Service"**
2. Connect your GitHub repository
3. Configure the service:

| Setting | Value |
|---------|-------|
| **Name** | `honeypot-api` |
| **Region** | Singapore (or nearest) |
| **Branch** | `main` |
| **Runtime** | `Docker` |
| **Instance Type** | `Free` |

#### Step 3: Set Environment Variables
Go to **Environment** tab and add:

| Variable | Value |
|----------|-------|
| `API_KEY` | `your-secret-api-key` |
| `GROQ_API_KEY` | `your-groq-api-key` |
| `USE_GROQ` | `true` |
| `HOST` | `0.0.0.0` |
| `PORT` | `8000` |

#### Step 4: Deploy
1. Click **"Create Web Service"**
2. Wait for build & deployment (3-5 minutes)
3. Your public URL: `https://honeypot-api.onrender.com`

#### Step 5: Verify
```bash
curl https://honeypot-api.onrender.com/health
```

> **Note**: Free tier sleeps after 15 mins of inactivity. First request after sleep takes ~30s.

---

### Option 2: Deploy to Google Cloud Platform (GCP Cloud Run)

#### Prerequisites
- Google Cloud account with billing enabled
- `gcloud` CLI installed

#### Step 1: Install gcloud CLI

```bash
# macOS
brew install google-cloud-sdk

# Linux
curl https://sdk.cloud.google.com | bash

# Verify installation
gcloud version
```

#### Step 2: Login and Set Project

```bash
# Login to GCP
gcloud auth login

# Create a new project (or use existing)
gcloud projects create honeypot-api-project --name="Honeypot API"

# Set the project
gcloud config set project honeypot-api-project

# Enable billing (required for Cloud Run)
# Do this in GCP Console: https://console.cloud.google.com/billing
```

#### Step 3: Enable Required APIs

```bash
gcloud services enable cloudbuild.googleapis.com
gcloud services enable run.googleapis.com
gcloud services enable artifactregistry.googleapis.com
```

#### Step 4: Create Artifact Registry Repository

```bash
gcloud artifacts repositories create honeypot-repo \
  --repository-format=docker \
  --location=asia-south1 \
  --description="Honeypot API Docker images"
```

#### Step 5: Build and Push Docker Image

```bash
# Navigate to project directory
cd /path/to/GUVI

# Configure Docker authentication
gcloud auth configure-docker asia-south1-docker.pkg.dev

# Build the image
docker build -t asia-south1-docker.pkg.dev/honeypot-api-project/honeypot-repo/honeypot-api:latest .

# Push to Artifact Registry
docker push asia-south1-docker.pkg.dev/honeypot-api-project/honeypot-repo/honeypot-api:latest
```

#### Step 6: Deploy to Cloud Run

```bash
gcloud run deploy honeypot-api \
  --image asia-south1-docker.pkg.dev/honeypot-api-project/honeypot-repo/honeypot-api:latest \
  --platform managed \
  --region asia-south1 \
  --allow-unauthenticated \
  --port 8000 \
  --memory 512Mi \
  --cpu 1 \
  --min-instances 0 \
  --max-instances 10 \
  --set-env-vars "API_KEY=your-secret-api-key,GROQ_API_KEY=your-groq-api-key,USE_GROQ=true,HOST=0.0.0.0,PORT=8000"
```

#### Step 7: Get Your Public URL

After deployment completes, you'll see:
```
Service URL: https://honeypot-api-xxxxxx-xx.a.run.app
```

This is your public URL!

#### Step 8: Verify Deployment

```bash
curl https://honeypot-api-xxxxxx-xx.a.run.app/health
```

#### Alternative: One-Command Deploy with Cloud Build

Create `cloudbuild.yaml` in project root:

```yaml
steps:
  # Build Docker image
  - name: 'gcr.io/cloud-builders/docker'
    args: ['build', '-t', 'asia-south1-docker.pkg.dev/$PROJECT_ID/honeypot-repo/honeypot-api:$COMMIT_SHA', '.']
  
  # Push to Artifact Registry
  - name: 'gcr.io/cloud-builders/docker'
    args: ['push', 'asia-south1-docker.pkg.dev/$PROJECT_ID/honeypot-repo/honeypot-api:$COMMIT_SHA']
  
  # Deploy to Cloud Run
  - name: 'gcr.io/google.com/cloudsdktool/cloud-sdk'
    entrypoint: gcloud
    args:
      - 'run'
      - 'deploy'
      - 'honeypot-api'
      - '--image'
      - 'asia-south1-docker.pkg.dev/$PROJECT_ID/honeypot-repo/honeypot-api:$COMMIT_SHA'
      - '--region'
      - 'asia-south1'
      - '--platform'
      - 'managed'
      - '--allow-unauthenticated'
      - '--port'
      - '8000'

images:
  - 'asia-south1-docker.pkg.dev/$PROJECT_ID/honeypot-repo/honeypot-api:$COMMIT_SHA'
```

Deploy with:
```bash
gcloud builds submit --config cloudbuild.yaml
```

#### Using Secrets (Recommended for Production)

```bash
# Create secrets
echo -n "your-secret-api-key" | gcloud secrets create api-key --data-file=-
echo -n "your-groq-api-key" | gcloud secrets create groq-api-key --data-file=-

# Get project number
PROJECT_NUMBER=$(gcloud projects describe honeypot-api-project --format='value(projectNumber)')

# Grant Cloud Run access to secrets
gcloud secrets add-iam-policy-binding api-key \
  --member="serviceAccount:${PROJECT_NUMBER}-compute@developer.gserviceaccount.com" \
  --role="roles/secretmanager.secretAccessor"

gcloud secrets add-iam-policy-binding groq-api-key \
  --member="serviceAccount:${PROJECT_NUMBER}-compute@developer.gserviceaccount.com" \
  --role="roles/secretmanager.secretAccessor"

# Update Cloud Run with secrets
gcloud run services update honeypot-api \
  --region asia-south1 \
  --set-secrets "API_KEY=api-key:latest,GROQ_API_KEY=groq-api-key:latest" \
  --set-env-vars "USE_GROQ=true,HOST=0.0.0.0,PORT=8000"
```

#### GCP Pricing
| Service | Free Tier |
|---------|-----------|
| Cloud Run | 2 million requests/month |
| Artifact Registry | 0.5 GB storage |
| Cloud Build | 120 build-minutes/day |

---

### Quick Comparison

| Feature | Render | GCP Cloud Run |
|---------|--------|---------------|
| **Setup Time** | 5 mins | 15-20 mins |
| **Free Tier** | Yes (sleeps) | Yes (generous) |
| **Custom Domain** | Yes | Yes |
| **Auto-scaling** | Limited | Yes (0-1000) |
| **Cold Start** | ~30s on free | ~2-5s |
| **Best For** | Quick demos | Production |

## Testing

### Test with curl

```bash
# First message
curl -X POST http://localhost:8000/api/honeypot \
  -H "Content-Type: application/json" \
  -H "x-api-key: your-secret-api-key" \
  -d '{
    "sessionId": "test-123",
    "message": {
      "sender": "scammer",
      "text": "Your bank account will be blocked. Share OTP immediately.",
      "timestamp": "2026-01-21T10:15:30Z"
    },
    "conversationHistory": [],
    "metadata": {"channel": "SMS", "language": "English", "locale": "IN"}
  }'

# Check session intelligence
curl http://localhost:8000/api/session/test-123 \
  -H "x-api-key: your-secret-api-key"
```

### Test with Python

```python
import requests

url = "http://localhost:8000/api/honeypot"
headers = {
    "x-api-key": "your-secret-api-key",
    "Content-Type": "application/json"
}

# First message
response = requests.post(url, headers=headers, json={
    "sessionId": "test-session",
    "message": {
        "sender": "scammer",
        "text": "Urgent! Your SBI account is blocked. Call +919876543210 now!",
        "timestamp": "2026-01-21T10:15:30Z"
    },
    "conversationHistory": [],
    "metadata": {"channel": "SMS", "language": "English", "locale": "IN"}
})

print(response.json())
```

## AI Backend Options

### OpenAI (Recommended)
- Best quality responses
- Set `OPENAI_API_KEY` in `.env`
- Default model: `gpt-4o-mini`

### Groq (Free Tier Available)
- Faster response times
- Free tier with 30 requests/minute
- Set `USE_GROQ=true` and `GROQ_API_KEY` in `.env`
- Default model: `llama-3.3-70b-versatile`

### Fallback (No API Key)
- Rule-based responses if no AI configured
- Still functional for basic scam engagement

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Incoming Message                         │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                    API Authentication                        │
│                    (x-api-key header)                        │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                    Session Manager                           │
│              (Create/Retrieve session state)                 │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                    Scam Detector                             │
│            (Pattern matching, confidence scoring)            │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                    Intelligence Extractor                    │
│        (Extract bank accounts, UPI IDs, phone numbers)       │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                    Honeypot Agent                            │
│              (Generate human-like response)                  │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                    GUVI Callback                             │
│           (Send final intelligence when ready)               │
└─────────────────────────────────────────────────────────────┘
```

## License

MIT
