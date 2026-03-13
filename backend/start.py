import uvicorn
import webbrowser
import threading
import time

def open_browser():
    time.sleep(2)  # Wait for startup
    webbrowser.open('http://localhost:8000/dashboard')

if __name__ == "__main__":
    # Open browser in background thread
    browser_thread = threading.Thread(target=open_browser)
    browser_thread.daemon = True
    browser_thread.start()

    # Start server
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)
