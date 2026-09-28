# PhishIv2

PhishIv2 is a URL-only phishing classifier. The trained character TF-IDF model returns a calibrated phishing probability; the operating threshold is selected on validation data with a configurable false-positive cap. URLs are normalized and scored as text. They are never opened or fetched.

## Reproduce

Run `data-cleaning.ipynb`, then run `training.ipynb` from top to bottom. The notebook writes `artifacts/phishing_detector_www_no_erasure_candidate.joblib`. It removes leading `www.` from character-model input during training and inference. It does not erase phishing subdomains to make synthetic URLs because that can mislabel a legitimate parent domain. The older baseline and first `www` candidate remain available for comparison.

## Run the website

```powershell
.\venv\Scripts\python.exe web\server.py
```

Open `http://127.0.0.1:8090`. See [web/README.md](web/README.md) for API details.

## Docker

The website and model server can run in a self-contained image:

```powershell
docker compose up --build
```

The image packages the selected Joblib artifact and ranked whitelist. It does not include the raw datasets, notebooks, or virtual environment.

The compose service targets `linux/arm64` for Raspberry Pi 5. Run the build on the Pi (or use an ARM64 Buildx builder).
