<div align="center">
<img width="1200" height="475" alt="GHBanner" src="https://github.com/user-attachments/assets/0aa67016-6eaf-458a-adb2-6e31a0763ed6" />
</div>

# Run and deploy your AI Studio app

This contains everything you need to run your app locally.

View your app in AI Studio: https://ai.studio/apps/drive/151Om7r6edfc5wB2GTKBNZs2uPmR5UDoZ

## Run Locally

**Prerequisites:**  Node.js


1. Install dependencies:
   `npm install`
2. Backend (optional AI remediation): create a `.env` file in `vulnpy/` (or project root) with:

```
GROQ_API_KEY=your_groq_key_here
```

If omitted, the remediation endpoint falls back to static guidance.

3. Set the `GEMINI_API_KEY` in [.env.local](.env.local) if the legacy Gemini frontend flow is needed (currently replaced by backend remediation).
4. Run the app:
   `npm run dev`

Backend FastAPI server (from `vulnpy` directory):

```
python api_server.py
```

Optional environment overrides (in `.env`):

```
GROQ_API_KEY=your_key
REMEDIATION_MAX_TOKENS=640  # increase for longer step-by-step plans
```

Then open the frontend at the printed Vite dev URL (default http://localhost:5173).
