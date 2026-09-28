# PhishIv2

Run the local three-layer model server from the project root:

```powershell
.\venv\Scripts\python.exe web\server.py
```

Open http://127.0.0.1:8090. The server loads `artifacts/phishing_detector_www_no_erasure_candidate.joblib` once at startup and uses the saved URL model, whitelist, typosquat reference, and calibrated combiner. `/api/health` reports whether all required components loaded, the artifact name, and its model-input policy. `/api/predict` accepts `{"url":"example.com"}` and adds `https://` to bare hostnames. `/api/analytics` returns held-out test metrics from the artifact. The page has small phishing and legitimate example buttons that fill the URL field, plus a performance snapshot with evaluation size, threshold, precision, recall, F1, AUC scores, Brier score, and confusion matrix. URLs are analyzed as text and are never opened or fetched.

## Docker

From the repository root:

```powershell
docker compose up --build
```

The compose service targets `linux/arm64`, which matches the Raspberry Pi 5. Build it on the Pi, or use Docker Buildx from another machine with an ARM64 builder. The first build downloads ARM64 wheels and can take several minutes.

Open `http://127.0.0.1:8090`. The image contains the selected model artifact and `whitelist/top-1m.csv`; datasets, notebooks, and the virtual environment are excluded. Check readiness with:

```powershell
Invoke-RestMethod http://127.0.0.1:8090/api/health
```

Stop it with `docker compose down`. To use another host or port, set `PHISHIV2_HOST` and `PHISHIV2_PORT` in the compose environment and update the port mapping.

Only a leading `www.` is removed for the character model. The normalized URL shown to users and the domain checks retain the original hostname. The model may still make mistakes: the dataset contains phishing pages hosted on otherwise legitimate services, and its legitimate examples all have `www.` hosts. The displayed probability reflects URL patterns; it does not verify the destination's content.

A domain closely resembling one of the configured top-ranked legitimate domains appears as **SUSPICIOUS** when its calibrated probability is below the phishing threshold. The API returns `typosquat_warning: true`, the matched domain, and its similarity. This is a separate spelling warning: it does not alter the probability or imply the matched domain is unsafe. The saved confusion matrix measures the probability-threshold decision and does not count these additional warnings as phishing predictions.
