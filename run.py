import uvicorn
import os

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000)) # Render uses 10000 by default
    uvicorn.run("backend.main:app", host="0.0.0.0", port=port)