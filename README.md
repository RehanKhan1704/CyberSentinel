# 🛡️ CyberSentinel

> **A full-stack phishing detection and web threat analysis tool** that classifies websites as **Phishing**, **Suspicious**, or **Benign** using a combination of a trained Machine Learning model, VirusTotal API threat intelligence, and live DOM analysis — all surfaced through a Chrome browser extension and a React web dashboard.

🔗 **Live Demo:** [cyber-sentinel-opal.vercel.app](https://cyber-sentinel-opal.vercel.app)

---

## 🚀 Features

- 🔍 **Automatic Page Scanning** — Chrome extension scans the active tab on load and instantly classifies the site
- 🖱️ **Manual URL Check** — Enter any URL manually for on-demand threat analysis
- 🤖 **ML-Powered Detection** — Random Forest classifier trained on 640,000 URL records
- 🌐 **VirusTotal Integration** — Cross-references URLs against VirusTotal's threat intelligence database
- 🧬 **DOM Analysis** — Python backend scans page structure for suspicious patterns
- 📊 **Averaged Risk Score** — Combines ML, VirusTotal, and DOM signals into a unified confidence score
- ⚡ **Real-time Results** — Instant classification with threat level indicators

---

## 🧱 Tech Stack

| Layer | Technology |
|-------|-----------|
| Frontend | React.js, Vite, CSS |
| Backend | Python, Flask |
| ML Model | scikit-learn (Random Forest) |
| Browser Extension | JavaScript, Chrome Extension API |
| Threat Intelligence | VirusTotal API |
| Deployment | Vercel (Frontend) |

---

## 📁 Project Structure

```
CyberSentinel/
├── backend/              # Python Flask backend
│   ├── app.py            # Main Flask server
│   ├── ml_model/         # Model training & inference
│   │   ├── train_model_simple.py
│   │   └── download_dataset.py
│   └── requirements.txt
├── extension/            # Chrome browser extension
├── public/               # Static assets
├── src/                  # React frontend source
├── index.html
├── package.json
└── vite.config.js
```

---

## ⚙️ How It Works

```
URL Input (Extension / Manual)
        │
        ▼
┌──────────────────────────────┐
│        Python Backend        │
│  ┌─────────┐ ┌────────────┐  │
│  │  ML     │ │ VirusTotal │  │
│  │ Model   │ │    API     │  │
│  └────┬────┘ └─────┬──────┘  │
│       │            │         │
│  ┌────▼────────────▼──────┐  │
│  │     DOM Scanner        │  │
│  └────────────┬───────────┘  │
│               │              │
│   Averaged Confidence Score  │
└──────────────────────────────┘
        │
        ▼
  ✅ Benign / ⚠️ Suspicious / 🚨 Phishing
```

---

## 🛠️ Setup & Installation

### Prerequisites
- Python 3.8+
- Node.js 18+
- A VirusTotal API key (free at [virustotal.com](https://www.virustotal.com/gui/join-us))

---

### 1. Clone the Repository

```bash
git clone https://github.com/RehanKhan1704/CyberSentinel.git
cd CyberSentinel
```

---

### 2. Backend Setup

```bash
cd backend

# Create and activate virtual environment (recommended)
python -m venv venv

# Windows
venv\Scripts\activate

# macOS / Linux
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Download dataset and train the ML model
python ml_model/download_dataset.py
python ml_model/train_model_simple.py
```

---

### 3. Configure Environment Variables

Create a `.env` file inside the `backend/` folder:

```env
VIRUSTOTAL_API_KEY=your_actual_api_key_here
```

---

### 4. Frontend Setup

```bash
# From the project root
cd ..
npm install
```

---

### 5. Run the Application

Open two terminals:

**Terminal 1 — Start Backend**
```bash
cd backend
python app.py
```

**Terminal 2 — Start Frontend**
```bash
npm run dev
```

The app will be available at `http://localhost:5173`

---

### 6. Load the Chrome Extension

1. Open Chrome and go to `chrome://extensions/`
2. Enable **Developer Mode** (top right toggle)
3. Click **Load unpacked**
4. Select the `extension/` folder from the project
5. The CyberSentinel icon will appear in your toolbar

---

## 👥 Contributors

| Name | Role |
|------|------|
| Khan Rehan Majibullah | Developer |
| Khan Mohtaseem Ashfaque | Developer |
| Ansari Hussain | Developer |
| Shaikh Saad Ayaz | Developer |


---

## 📜 References

- [VirusTotal API Documentation](https://developers.virustotal.com/reference/overview)
- [scikit-learn Random Forest](https://scikit-learn.org/stable/modules/ensemble.html#forest)
- [Chrome Extension Developer Guide](https://developer.chrome.com/docs/extensions/)
- [Phishing URL Dataset — Kaggle](https://www.kaggle.com/datasets/shashwatwork/web-page-phishing-detection-dataset)
