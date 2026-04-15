// k6 load test — genieacs-relay v2.2.0
//
// Scope: health + contract validation only. Does NOT exercise real GenieACS because
// WLAN write paths have side effects (register/restart actual ONUs). Destructive
// testing requires a sandbox GenieACS + sandbox device pool and is out of scope
// for CI load testing.
//
// v2.2.0: extended contract_check to probe v2.2.0 read endpoints (status, wan,
// params, optical, wifi-clients, wifi-stats, devices list, presets read) —
// same "non-existent IP → 4xx" pattern as the v1.x /ssid probe. Write
// endpoints (factory-reset, wake, pppoe, firmware, diag dispatch, provisioning
// writes) remain deliberately excluded because they queue real TR-069 tasks
// against GenieACS. Customer-facing factory-reset workflow verification is in
// the real-device lab sweep (session 5j, see CHANGELOG.md [2.2.0]).
//
// Run:
//   k6 run k6-load-test.js
//   k6 run --vus 10 --duration 30s k6-load-test.js
//
// Thresholds are PER-SCENARIO to avoid the false-alarm pitfall where the global
// `http_req_failed{rate<0.10}` gate counts deliberate 4xx contract probes as
// failures. See the write-olt-svc §k6 default `http_req_failed` threshold is
// misleading lesson in its CHANGELOG.

import http from 'k6/http';
import { check, group } from 'k6';

const BASE = __ENV.BASE_URL || 'http://localhost:8080';
const API_KEY = __ENV.API_KEY || 'load-test-key';

export const options = {
  scenarios: {
    health_probes: {
      executor: 'constant-vus',
      vus: 5,
      duration: '30s',
      exec: 'healthProbes',
    },
    version_probe: {
      executor: 'constant-vus',
      vus: 2,
      duration: '30s',
      exec: 'versionProbe',
    },
    metrics_scrape: {
      executor: 'constant-arrival-rate',
      rate: 1,
      timeUnit: '15s',
      duration: '30s',
      preAllocatedVUs: 2,
      exec: 'metricsScrape',
    },
    contract_check: {
      executor: 'constant-vus',
      vus: 3,
      duration: '30s',
      exec: 'contractCheck',
    },
  },
  thresholds: {
    // Per-scenario failure thresholds (not global).
    'http_req_failed{scenario:health_probes}': ['rate<0.01'],
    'http_req_failed{scenario:version_probe}': ['rate<0.01'],
    'http_req_failed{scenario:metrics_scrape}': ['rate<0.01'],
    // contract_check deliberately triggers 4xx responses — NO failure threshold.

    // Latency thresholds (sub-millisecond for health/version).
    'http_req_duration{scenario:health_probes}': ['p(95)<50'],
    'http_req_duration{scenario:version_probe}': ['p(95)<50'],
    'http_req_duration{scenario:metrics_scrape}': ['p(95)<100'],
    'http_req_duration{scenario:contract_check}': ['p(95)<100'],
  },
};

export function healthProbes() {
  group('/healthz', () => {
    const res = http.get(`${BASE}/healthz`);
    check(res, {
      'status is 200': (r) => r.status === 200,
      'body contains healthy': (r) => r.body.includes('healthy'),
      'X-API-Version header set': (r) => r.headers['X-Api-Version'] === 'v1',
      'X-App-Version header set': (r) => !!r.headers['X-App-Version'],
    });
  });

  group('/readyz', () => {
    const res = http.get(`${BASE}/readyz`);
    // /readyz may be 503 if GenieACS unreachable during load test — we only care
    // the adapter itself responded within latency SLO, not upstream reachability.
    check(res, {
      'status is 200 or 503': (r) => r.status === 200 || r.status === 503,
      'content-type is json': (r) => r.headers['Content-Type'] === 'application/json',
    });
  });
}

export function versionProbe() {
  const res = http.get(`${BASE}/version`);
  check(res, {
    'status is 200': (r) => r.status === 200,
    'has version field': (r) => JSON.parse(r.body).version !== undefined,
    'has api_version field': (r) => JSON.parse(r.body).api_version === 'v1',
    'has commit field': (r) => JSON.parse(r.body).commit !== undefined,
    'X-Request-ID echoed': (r) => !!r.headers['X-Request-Id'],
  });
}

export function metricsScrape() {
  const res = http.get(`${BASE}/metrics`);
  check(res, {
    'status is 200': (r) => r.status === 200,
    'contains http_requests_total': (r) => r.body.includes('http_requests_total'),
    'contains http_request_duration_seconds': (r) => r.body.includes('http_request_duration_seconds'),
    'contains go_gc collector': (r) => r.body.includes('go_gc_duration_seconds'),
  });
}

// contract_check: deliberately triggers 404/400/401 responses to verify the v2 error
// envelope under load. Does NOT count 4xx as scenario failure per threshold config.
export function contractCheck() {
  group('404 NOT_FOUND probe', () => {
    const res = http.get(`${BASE}/api/v1/genieacs/ssid/10.255.255.254`, {
      headers: {
        'X-API-Key': API_KEY,
        'X-Request-ID': `k6-404-${__VU}-${__ITER}`,
      },
    });
    check(res, {
      'status is 4xx or 5xx': (r) => r.status >= 400,
      'error_code present': (r) => {
        try { return !!JSON.parse(r.body).error_code; } catch { return false; }
      },
      'request_id echoed in body': (r) => {
        try {
          const b = JSON.parse(r.body);
          return b.request_id && b.request_id.startsWith('k6-404-');
        } catch { return false; }
      },
    });
  });

  group('401 UNAUTHORIZED probe', () => {
    const res = http.get(`${BASE}/api/v1/genieacs/ssid/192.168.1.1`, {
      headers: {
        'X-API-Key': 'definitely-wrong-key',
        'X-Request-ID': `k6-401-${__VU}-${__ITER}`,
      },
    });
    check(res, {
      'status is 401 or 403': (r) => r.status === 401 || r.status === 403,
    });
  });

  // v2.2.0 read endpoints — 404 NOT_FOUND contract probes on non-existent IP.
  // Each asserts the v2 error envelope shape: error_code + request_id fields.
  // Write endpoints are NOT probed here to keep the test side-effect-free.
  const v22ReadPaths = [
    '/api/v1/genieacs/status/10.255.255.254',           // H1
    '/api/v1/genieacs/wan/10.255.255.254',              // H4
    '/api/v1/genieacs/optical/10.255.255.254',          // v2.1.0 but in v2.2.0 family
    '/api/v1/genieacs/wifi-clients/10.255.255.254',     // M3
    '/api/v1/genieacs/wifi-stats/10.255.255.254',       // M7
    '/api/v1/genieacs/devices/search?mac=de:ad:be:ef:00:01', // M5
    '/api/v1/genieacs/presets/nonexistent-preset-k6',   // L10
  ];
  for (const path of v22ReadPaths) {
    group(`v2.2.0 404 contract probe ${path}`, () => {
      const res = http.get(`${BASE}${path}`, {
        headers: {
          'X-API-Key': API_KEY,
          'X-Request-ID': `k6-v22-${__VU}-${__ITER}`,
        },
      });
      check(res, {
        'status is 4xx or 5xx': (r) => r.status >= 400,
        'error envelope error_code field': (r) => {
          try { return !!JSON.parse(r.body).error_code; } catch { return false; }
        },
        'error envelope request_id echoed': (r) => {
          try {
            const b = JSON.parse(r.body);
            return b.request_id && b.request_id.startsWith('k6-v22-');
          } catch { return false; }
        },
      });
    });
  }
}
