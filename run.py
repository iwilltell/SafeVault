from app import create_app

app = create_app()

if __name__ == "__main__":
    # Debug mode is for local development only. Do not deploy this as-is.
    app.run(host="127.0.0.1", port=5000, debug=True)
