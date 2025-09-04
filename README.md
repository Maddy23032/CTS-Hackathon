# VulnPy GUI - Complete Setup Instructions

## 🏗️ **Architecture Overview**

The VulnPy GUI consists of two main components:
- **Frontend**: React/TypeScript application built with Vite
- **Backend**: FastAPI server that wraps the VulnPy scanner

## 📋 **Prerequisites**

1. **Python 3.8+** with pip
2. **Node.js 16+** with npm
3. **Git** (for cloning)

## 🚀 **Quick Start**

### **Option 1: Automated Startup (Recommended)**

1. **Start Backend** (Terminal 1):
   ```bash
   cd "D:\My projects\Vuln-cli\vulnp-ai-gui"
   .\start_backend.bat
   ```

2. **Start Frontend** (Terminal 2):
   ```bash
   cd "D:\My projects\Vuln-cli\vulnp-ai-gui"
   .\start_frontend.bat
   ```

### **Option 2: Manual Setup**

#### **Backend Setup**

1. **Navigate to backend directory**:
   ```bash
   cd "D:\My projects\Vuln-cli\vulnp-ai-gui\backend"
   ```

2. **Install Python dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Start the API server**:
   ```bash
   python api_server.py
   ```
   
   ✅ Backend will be available at: http://localhost:8000
   📖 API documentation: http://localhost:8000/docs

#### **Frontend Setup**

1. **Navigate to frontend directory**:
   ```bash
   cd "D:\My projects\Vuln-cli\vulnp-ai-gui"
   ```

2. **Install Node.js dependencies**:
   ```bash
   npm install
   ```

3. **Start the development server**:
   ```bash
   npm run dev
   ```
   
   ✅ Frontend will be available at: http://localhost:5173

## 🎯 **Usage Guide**

1. **Start both servers** using the startup scripts
2. **Open browser** to http://localhost:5173
3. **Navigate to Scanner** page
4. **Configure scan settings**:
   - Target URL
   - Scan types (XSS, SQLi, CSRF)
   - Scan mode (Fast/Full)
   - AI enrichment settings
5. **Start scan** and monitor progress in real-time
6. **View results** in the Vulnerabilities page
7. **Generate reports** from the Reports page

## 🔍 **Features**

### **Real-time Scanning**
- Live progress updates via WebSocket
- Phase-by-phase scan monitoring
- Real-time vulnerability discovery

### **AI Integration**
- Groq AI-powered vulnerability analysis
- Intelligent prioritization
- Smart rate limiting and caching

### **Professional UI**
- Modern React interface
- Responsive design
- Dark/light mode support
- Professional vulnerability table

## 🐛 **Troubleshooting**

### **Backend Issues**

1. **Port 8000 already in use**:
   ```bash
   # Kill existing process
   taskkill /f /im python.exe
   # Or change port in api_server.py
   ```

2. **Module import errors**:
   ```bash
   # Ensure you're in the backend directory
   cd backend
   pip install -r requirements.txt
   ```

### **Frontend Issues**

1. **Port 5173 already in use**:
   ```bash
   # Kill existing process or use different port
   npm run dev -- --port 3000
   ```

2. **API connection errors**:
   - Ensure backend is running on port 8000
   - Check API_BASE_URL in `src/lib/api.ts`

---

**🎉 Your VulnPy GUI is now ready to use!**

Navigate to http://localhost:5173 to start scanning for vulnerabilities with a professional web interface.
- Edit files directly within the Codespace and commit and push your changes once you're done.

## What technologies are used for this project?

This project is built with:

- Vite
- TypeScript
- React
- shadcn-ui
- Tailwind CSS

## How can I deploy this project?

Simply open your deployment dashboard and click on Share -> Publish.

## Can I connect a custom domain to my project?

Yes, you can!

To connect a domain, navigate to Project > Settings > Domains and click Connect Domain.

Read more here: [Setting up a custom domain](https://yourdocs.example.com/tips-tricks/custom-domain#step-by-step-guide)
