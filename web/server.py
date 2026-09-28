from collections import defaultdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit
import json
import os
import csv

try:
    import joblib
    import tldextract
    from rapidfuzz import process
    from rapidfuzz.distance import DamerauLevenshtein
except ImportError as exc:
    joblib = tldextract = process = DamerauLevenshtein = None
    IMPORT_ERROR = str(exc)
else:
    IMPORT_ERROR = None

ROOT = Path(__file__).resolve().parents[1]
ARTIFACT = ROOT / 'artifacts' / 'phishing_detector_www_no_erasure_candidate.joblib'
WHITELIST_PATH = ROOT / 'whitelist' / 'top-1m.csv'
model = None
metadata = {}
config = {}
bundle = {}
load_error = IMPORT_ERROR
analytics = None
try:
    if IMPORT_ERROR:
        raise RuntimeError(IMPORT_ERROR)
    bundle = joblib.load(ARTIFACT)
    model = bundle.get('model')
    metadata = bundle.get('metadata', {})
    config = bundle.get('config', {})
    required = ('layer_model', 'layer_calibrator', 'ranked_domains')
    if model is None or any(bundle.get(key) is None for key in required):
        raise RuntimeError('Artifact is missing URL model or calibrated domain-layer components')
    extractor = tldextract.TLDExtract(cache_dir=None, suffix_list_urls=(), include_psl_private_domains=True)
    ranked_domains = bundle['ranked_domains']
    if WHITELIST_PATH.exists():
        external_domains = []
        seen = set()
        with WHITELIST_PATH.open('r', encoding='utf-8-sig', newline='') as handle:
            for row in csv.reader(handle):
                if len(row) < 2:
                    continue
                domain = row[1].strip().rstrip('.').lower()
                if domain and domain not in seen:
                    external_domains.append(domain)
                    seen.add(domain)
        if external_domains:
            ranked_domains = external_domains
    whitelist = set(ranked_domains)
    typo_top_n = max(int(config.get('typo_top_n', 9000)), 9000)
    typo_threshold = float(config.get('typo_similarity_threshold', 0.90))
    typo_secondary_threshold = float(config.get('typo_secondary_similarity_threshold', 0.80))
    min_protected_name_length = int(config.get('min_protected_name_length', 5))
    typo_by_length = defaultdict(list)
    for protected_domain in ranked_domains[:typo_top_n]:
        protected_name = extractor(protected_domain).domain
        if len(protected_name) >= min_protected_name_length:
            typo_by_length[len(protected_domain)].append(protected_domain)
    typo_by_length = dict(typo_by_length)
    threshold = float(metadata.get('pipeline_decision_threshold', config.get('pipeline_decision_threshold',
                     metadata.get('default_decision_threshold', 0.5))))
    pipeline_metrics = metadata.get('pipeline_metrics') or metadata.get('model_metrics')
    if pipeline_metrics:
        tn, fp, fn, tp = pipeline_metrics['confusion_matrix'][0][0], pipeline_metrics['confusion_matrix'][0][1], pipeline_metrics['confusion_matrix'][1][0], pipeline_metrics['confusion_matrix'][1][1]
        split_rows = metadata.get('split_report', [])
        test_split = next((row for row in split_rows if row.get('split') == 'test'), {})
        analytics = {
            'ok': True,
            'model_version': 'PhishIv2',
            'model_type': 'Three-layer pipeline',
            'evaluation': 'Domain-disjoint held-out test set',
            'test_urls': int(metadata.get('test_rows', tn + fp + fn + tp)),
            'test_domains': int(test_split.get('registrable_domains', 0)),
            'threshold': threshold,
            'accuracy': float((tn + tp) / max(tn + fp + fn + tp, 1)),
            'precision': float(pipeline_metrics['precision']),
            'recall': float(pipeline_metrics['recall']),
            'f1': float(pipeline_metrics['f1']),
            'roc_auc': float(pipeline_metrics['roc_auc']),
            'pr_auc': float(pipeline_metrics['pr_auc']),
            'brier': float(pipeline_metrics['brier']),
            'confusion_matrix': {'true_legitimate': {'predicted_legitimate': int(tn), 'predicted_phishing': int(fp)},
                                 'true_phishing': {'predicted_legitimate': int(fn), 'predicted_phishing': int(tp)}},
        }
    load_error = None
except Exception as exc:
    model = None
    load_error = str(exc)
    extractor = None
    ranked_domains = []
    whitelist = set()
    typo_by_length = {}
    typo_secondary_threshold = 0.80
    threshold = 0.5
    analytics = None


def normalize(value):
    if not isinstance(value, str) or not value.strip():
        raise ValueError('URL must be non-empty')
    raw = value.strip()
    if any(ord(char) < 33 or ord(char) == 127 for char in raw):
        raise ValueError('URL contains whitespace or control characters')
    if '://' not in raw:
        raw = 'https://' + raw
    try:
        parts = urlsplit(raw)
        if parts.scheme.lower() not in ('http', 'https') or not parts.hostname:
            raise ValueError('Only HTTP(S) URLs with a hostname are supported')
        host = parts.hostname.rstrip('.').encode('idna').decode('ascii').lower()
        if not host or any(not label or len(label) > 63 for label in host.split('.')):
            raise ValueError('Invalid hostname')
        port = parts.port
        if '.' not in host and not (host.startswith('[') and host.endswith(']')):
            raise ValueError('Hostname must have a public suffix')
        authority = f'[{host}]' if ':' in host else host
        if port is not None:
            authority += f':{port}'
        normalized = urlunsplit((parts.scheme.lower(), authority, parts.path or '/', parts.query, parts.fragment))
        if not normalized:
            raise ValueError('Invalid URL')
        return normalized, host
    except (UnicodeError, ValueError) as exc:
        raise ValueError(f'Invalid URL: {exc}') from exc


def registrable_domain(host):
    extracted = extractor(host)
    if extracted.suffix and extracted.domain:
        return f'{extracted.domain}.{extracted.suffix}'
    return '.'.join(host.split('.')[-2:]) if '.' in host else host


def matching_whitelist(host):
    labels = host.split('.')
    for index in range(len(labels)):
        candidate = '.'.join(labels[index:])
        if candidate in whitelist:
            return candidate
    return None


def closest_typosquat(domain):
    best = None
    domain_length = len(domain)
    low = int(typo_threshold * domain_length + 0.999999)
    high = int(domain_length / typo_threshold)
    for length in range(low, high + 1):
        choices = typo_by_length.get(length, ())
        if not choices:
            continue
        match = process.extractOne(domain, choices,
            scorer=DamerauLevenshtein.normalized_similarity, score_cutoff=typo_threshold)
        if match and (best is None or match[1] > best[1]):
            best = match
    if best is None and domain.count('.') == 1:
        # A second tier catches two-character substitutions such as g0ogl3.com
        # while limiting broader matches to ordinary registrable domains.
        for length in range(max(1, int(typo_secondary_threshold * domain_length)),
                            int(domain_length / typo_secondary_threshold) + 1):
            choices = typo_by_length.get(length, ())
            if not choices:
                continue
            match = process.extractOne(domain, choices,
                scorer=DamerauLevenshtein.normalized_similarity,
                score_cutoff=typo_secondary_threshold - 1e-6)
            if match and (best is None or match[1] > best[1]):
                best = match
    if best and best[0] == domain:
        return None
    return (best[0], float(best[1])) if best else None


def analyze(url):
    normalized, host = normalize(url)
    domain = registrable_domain(host)
    whitelist_domain = matching_whitelist(host)
    # Check spelling even when the queried domain appears in the broad external
    # list: a low-quality whitelist can contain a lookalike entry itself.
    match = closest_typosquat(domain)
    model_url = normalized
    policy = metadata.get('model_input_policy', '')
    if 'Remove only leading www.' in policy and host.startswith('www.'):
        parts = urlsplit(normalized)
        authority = host[4:]
        if parts.port is not None:
            authority += f':{parts.port}'
        model_url = urlunsplit((parts.scheme, authority, parts.path, parts.query, parts.fragment))
    model_score = float(model.predict_proba([model_url])[0, 1])
    is_typosquat = match is not None
    similarity = match[1] if match else 0.0
    features = [[model_score, float(whitelist_domain is not None), float(is_typosquat), similarity]]
    if whitelist_domain is None and not is_typosquat:
        final_score = model_score
        comparison = 'above' if final_score >= threshold else 'below'
        reason = (f'No whitelist or typosquat match was found. The URL model scored this address '
                  f'{final_score:.2%}, {comparison} the {threshold:.2%} decision threshold. '
                  'The model analyzes URL text, not the destination content.')
    else:
        calibrated = float(bundle['layer_calibrator'].predict_proba(features)[0, 1])
        final_score = max(model_score, calibrated)
        reason = 'Combined probability was calibrated from the URL model score and domain signals.'
        if whitelist_domain:
            reason += ' Whitelist match is evidence and does not force a legitimate result.'
        if is_typosquat:
            reason += (f' This domain is {similarity:.1%} similar to {match[0]}; '
                       'treat it as suspicious even when the probability is below the decision threshold.')
    typo_warning = is_typosquat and final_score < threshold
    prediction = 'SUSPICIOUS' if typo_warning else ('PHISHING' if final_score >= threshold else 'LEGITIMATE')
    return {
        'normalized_url': normalized,
        'phishing_probability': final_score,
        'legitimate_probability': 1.0 - final_score,
        'phishing_threshold': threshold,
        'prediction': prediction,
        'typosquat_warning': typo_warning,
        'decision_basis': 'typosquat_warning' if typo_warning else 'probability_threshold',
        'layer': 'three-layer',
        'layer_signals': {
            'whitelist_match': whitelist_domain is not None,
            'whitelist_domain': whitelist_domain,
            'typosquat_match': is_typosquat,
            'matched_domain': match[0] if match else None,
            'typosquat_similarity': similarity,
            'model_probability': model_score,
        },
        'model_score': model_score,
        'decision_reason': reason,
        'source': 'PhishIv2 three-layer model',
        'model_version': 'PhishIv2',
    }


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def send_json(self, code, data):
        body = json.dumps(data, ensure_ascii=False).encode('utf-8')
        self.send_response(code)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        request_path = urlsplit(self.path).path
        if request_path == '/api/health':
            return self.send_json(200, {'ok': model is not None, 'three_layer': model is not None,
                'model_version': 'PhishIv2', 'threshold': threshold,
                'artifact': ARTIFACT.name, 'model_input_policy': metadata.get('model_input_policy'),
                'error': load_error})
        if request_path == '/api/analytics':
            if analytics is None:
                return self.send_json(503, {'ok': False, 'error': load_error or 'Artifact does not include evaluation metrics'})
            return self.send_json(200, analytics)
        files = {'/': 'index.html', '/index.html': 'index.html', '/app.js': 'app.js', '/styles.css': 'styles.css'}
        if request_path in files:
            body = (ROOT / 'web' / files[request_path]).read_bytes()
            self.send_response(200)
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_json(404, {'error': 'Not found'})

    def do_POST(self):
        if urlsplit(self.path).path != '/api/predict':
            return self.send_json(404, {'error': 'Not found'})
        try:
            payload = json.loads(self.rfile.read(int(self.headers.get('Content-Length', '0'))))
        except (ValueError, TypeError, json.JSONDecodeError) as exc:
            return self.send_json(400, {'error': str(exc)})
        if model is None:
            return self.send_json(503, {'error': 'PhishIv2 model is unavailable; URL was not analyzed', 'detail': load_error})
        try:
            result = analyze(payload.get('url'))
        except Exception as exc:
            return self.send_json(500, {'error': 'Inference failed', 'detail': str(exc)})
        self.send_json(200, result)


if __name__ == '__main__':
    address = (os.environ.get('PHISHIV2_HOST', '127.0.0.1'), int(os.environ.get('PHISHIV2_PORT', '8090')))
    server = ThreadingHTTPServer(address, Handler)
    if model is not None:
        print(f'PhishIv2 is ready at http://{address[0]}:{address[1]} (three-layer model loaded).', flush=True)
    else:
        print(f'PhishIv2 web server started at http://{address[0]}:{address[1]}, but the model is unavailable: {load_error}', flush=True)
    print('Press Ctrl+C to stop the server.', flush=True)
    server.serve_forever()
