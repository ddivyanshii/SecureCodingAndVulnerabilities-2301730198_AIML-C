import os

from dotenv import load_dotenv

load_dotenv()

from library_app import create_app

app = create_app()

if __name__ == "__main__":
    port = int(os.environ.get("LIBRARY_PORT", "5000"))
    app.run(host="127.0.0.1", port=port, debug=False)
