"""
Archivo wrapper para ayudar a Oryx a detectar la aplicación.
La aplicación real se encuentra en app/main.py
"""
from app.main import app

# Si ejecutas este archivo directamente
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)