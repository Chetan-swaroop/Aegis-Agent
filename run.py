import uvicorn
from backend.main import app
import os

if __name__ == "__main__":
    # Render provides the PORT as an environment variable
    port = int(os.environ.get("PORT", 10000))
    uvicorn.run(app, host="0.0.0.0", port=port)