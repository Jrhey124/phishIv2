const form = document.querySelector('#scanForm');
const input = document.querySelector('#urlInput');
const result = document.querySelector('#result');
const health = document.querySelector('#health');
const healthLabel = health.querySelector('.health-label');
const analyzeButton = form.querySelector('button');
const examplePhishingButton = document.querySelector('#examplePhishing');
const exampleLegitimateButton = document.querySelector('#exampleLegitimate');
const analyticsStatus = document.querySelector('#analyticsStatus');
const analyticsContent = document.querySelector('#analyticsContent');
const examples = {
  phishing: 'http://rajkotpackaging.com/',
  legitimate: 'https://www.blokker.nl'
};
let modelReady = false;

function setReady(ready) {
  modelReady = Boolean(ready);
  input.disabled = analyzeButton.disabled = examplePhishingButton.disabled = exampleLegitimateButton.disabled = !ready;
}

function setOffline(message) {
  setReady(false);
  healthLabel.textContent = 'Model offline';
  health.className = 'health offline';
  result.innerHTML = `<div class="offline-note"><strong>Scanning disabled</strong><br>${message}</div>`;
}

async function checkHealth() {
  try {
    const response = await fetch('/api/health');
    const data = await response.json();
    const ready = Boolean(response.ok && data.ok && data.three_layer);
    healthLabel.textContent = ready ? 'Model online' : 'Model offline';
    health.title = ready ? `${data.model_version} is ready` : (data.error || 'Model unavailable');
    health.className = ready ? 'health online' : 'health offline';
    setReady(ready);
    if (ready) loadAnalytics();
    else {
      result.innerHTML = '<div class="offline-note"><strong>Scanning disabled</strong><br>PhishIv2 needs the three-layer model to be available.</div>';
      analyticsStatus.textContent = 'Evaluation unavailable';
      analyticsContent.hidden = true;
    }
  } catch (_) {
    setOffline('PhishIv2 cannot be used while the API is unavailable.');
    analyticsStatus.textContent = 'Evaluation unavailable';
    analyticsContent.hidden = true;
  }
}

async function loadAnalytics() {
  try {
    const response = await fetch('/api/analytics');
    const data = await response.json();
    if (!response.ok || !data.ok) throw new Error(data.error || 'Evaluation metrics unavailable');
    const percent = value => `${(value * 100).toFixed(2)}%`;
    const number = value => Number(value).toLocaleString();
    document.querySelector('#evaluationName').textContent = `${data.model_type} · ${data.evaluation}`;
    document.querySelector('#evaluationSize').textContent = `${number(data.test_urls)} URLs across ${number(data.test_domains)} domains`;
    document.querySelector('#metricAccuracy').textContent = percent(data.accuracy);
    document.querySelector('#metricPrecision').textContent = percent(data.precision);
    document.querySelector('#metricRecall').textContent = percent(data.recall);
    document.querySelector('#metricF1').textContent = percent(data.f1);
    document.querySelector('#metricRoc').textContent = percent(data.roc_auc);
    document.querySelector('#metricPr').textContent = percent(data.pr_auc);
    document.querySelector('#metricBrier').textContent = Number(data.brier).toFixed(4);
    document.querySelector('#metricThreshold').textContent = percent(data.threshold);
    const matrix = data.confusion_matrix;
    document.querySelector('#metricTn').textContent = number(matrix.true_legitimate.predicted_legitimate);
    document.querySelector('#metricFp').textContent = number(matrix.true_legitimate.predicted_phishing);
    document.querySelector('#metricFn').textContent = number(matrix.true_phishing.predicted_legitimate);
    document.querySelector('#metricTp').textContent = number(matrix.true_phishing.predicted_phishing);
    analyticsContent.hidden = false;
    analyticsStatus.textContent = 'Threshold metrics; lookalike warnings shown separately';
  } catch (error) {
    analyticsContent.hidden = true;
    analyticsStatus.textContent = error.message;
  }
}

async function predict(url) {
  // Do not submit a URL unless the backend confirms the model is currently loaded.
  const healthResponse = await fetch('/api/health', {cache: 'no-store'});
  const healthData = await healthResponse.json();
  if (!healthResponse.ok || !healthData.ok || !healthData.three_layer) {
    setOffline('The PhishIv2 model is not ready. Your URL was not sent for analysis.');
    throw new Error('Model unavailable; URL was not submitted.');
  }

  const response = await fetch('/api/predict', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({url})
  });
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || 'Model unavailable');
  return data;
}

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, char => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[char]));
}

function renderPrediction(data) {
  const match = data.layer_signals?.matched_domain;
  const typoNote = match ? `<div class="typo-warning"><strong>Lookalike domain detected</strong><br>
    This domain is ${(data.layer_signals.typosquat_similarity * 100).toFixed(1)}% similar to ${escapeHtml(match)}.
    Check the spelling before visiting. This warning is separate from the calibrated probability.</div>` : '';
  result.innerHTML = `<div class="verdict ${data.prediction.toLowerCase()}">${escapeHtml(data.prediction)}</div>
    <div class="score">${(data.phishing_probability * 100).toFixed(2)}%</div>
    <div class="label">CALIBRATED PHISHING PROBABILITY</div>
    ${typoNote}
    <dl><dt>Model probability</dt><dd>${(data.phishing_probability * 100).toFixed(2)}%</dd>
    <dt>Layer</dt><dd>${escapeHtml(data.layer)}</dd>
    <dt>Decision threshold</dt><dd>${(data.phishing_threshold * 100).toFixed(2)}%</dd>
    <dt>Analyzed URL</dt><dd>${escapeHtml(data.normalized_url)}</dd>
    <dt>Reason</dt><dd>${escapeHtml(data.decision_reason)}</dd></dl>`;
}

form.addEventListener('submit', async event => {
  event.preventDefault();
  if (!modelReady || analyzeButton.disabled) {
    result.innerHTML = '<div class="offline-note"><strong>Scanning disabled</strong><br>The model is not ready, so your URL was not sent.</div>';
    return;
  }
  result.textContent = 'Analyzing...';
  try {
    renderPrediction(await predict(input.value.trim()));
  } catch (error) {
    setOffline(`The model request failed. ${error.message}`);
  }
});

examplePhishingButton.addEventListener('click', () => { if (!examplePhishingButton.disabled) input.value = examples.phishing; });
exampleLegitimateButton.addEventListener('click', () => { if (!exampleLegitimateButton.disabled) input.value = examples.legitimate; });

if (window.location.protocol === 'file:') {
  setOffline('Open the PhishIv2 server at http://127.0.0.1:8090 to run the model.');
} else {
  checkHealth();
}
