/**
 * MAD-PS Public Landing Page & Onboarding Controller
 */

// 1. Ambient Scrolling Sanitized Logs Texture
function initAmbientLogs() {
  const container = document.getElementById('scrolling-logs');
  if (!container) return;

  const sampleLogLines = [
    "[INGEST] POST /api/v1/auth/login status=200 latency=11.2ms ip=198.51.100.42 | MESH_EVAL: 8/8 models OK",
    "[DETECTION_MESH] XGBOOST_TABULAR score=0.012 | IFOREST_ANOMALY score=0.041 | AE_RECON_LOSS=0.008 | VERDICT=BENIGN",
    "[INGEST] GET /api/v1/user/1042/profile status=200 latency=14.8ms | AUTH_SUB=8892 TARGET_ID=1042 | BOLA_PROBE DETECTED",
    "[META_CLASSIFIER] Category=IDOR Confidence=0.942 Severity=HIGH Contributing=[LSTM:0.82, XGB:0.96, RF:0.91]",
    "[COUNCIL_DISPATCH] Incident INC-2026-9041-BOLA -> Reconstruction Agent (Claude-3.5-Sonnet) debating causality...",
    "[COUNCIL_CONSENSUS] Status=CONSENSUS_REACHED Score=0.96 | Recommended Action: BLOCK_TOKEN session_8892",
    "[INGEST] POST /api/v1/search payload=' UNION SELECT username, password_hash FROM users -- | 1D_CNN_SCORE=0.984",
    "[DETECTION_MESH] 1D_CNN_CONV3_5_7 MultiScale detected SQLi payload | Severity=HIGH Confidence=0.984",
    "[INGEST] POST /api/v1/webhooks/test target_url=http://169.254.169.254/latest/meta-data/ | SSRF_METADATA_PROBE",
    "[CIRCUIT_BREAKER] State=CLOSED Health=100% Active_Tenants=12 Ingest_Rate=420.4 req/sec P95=16.8ms",
    "[INGEST] POST /api/v1/system/ping payload='127.0.0.1; cat /etc/passwd' | COMMAND_INJECTION_DETECTED",
    "[META_CLASSIFIER] Category=OS_COMMAND_INJECTION Confidence=0.978 Severity=CRITICAL -> Auto-isolation ready",
  ];

  let logBuffer = "";
  for (let i = 0; i < 40; i++) {
    const line = sampleLogLines[i % sampleLogLines.length];
    const ts = new Date(Date.now() - (40 - i) * 8000).toISOString();
    logBuffer += `${ts} ${line}\n`;
  }
  container.textContent = logBuffer;
}

// 2. Scroll Progress Navigation Dots Observer (Matching Reference Image)
function initScrollObserver() {
  const dots = document.querySelectorAll('.nav-dot');
  const sections = Array.from(document.querySelectorAll('section[id]'));
  if (!dots.length || !sections.length) return;

  function updateActiveDot() {
    const scrollPos = window.scrollY;
    const windowHeight = window.innerHeight;
    const docHeight = document.documentElement.scrollHeight;
    
    // If at bottom of page, activate last item (contact)
    if (scrollPos + windowHeight >= docHeight - 60) {
      dots.forEach(d => d.classList.remove('active'));
      const lastDot = dots[dots.length - 1];
      if (lastDot) lastDot.classList.add('active');
      return;
    }

    let currentSectionId = sections[0].id;
    const triggerPoint = scrollPos + windowHeight * 0.35;

    for (let i = 0; i < sections.length; i++) {
      const sec = sections[i];
      const top = sec.offsetTop;
      const bottom = top + sec.offsetHeight;
      if (triggerPoint >= top && triggerPoint < bottom) {
        currentSectionId = sec.id;
        break;
      }
    }

    dots.forEach(dot => {
      if (dot.getAttribute('data-section') === currentSectionId) {
        dot.classList.add('active');
      } else {
        dot.classList.remove('active');
      }
    });
  }

  // Handle click on navigation dot
  dots.forEach(dot => {
    dot.addEventListener('click', (e) => {
      const targetId = dot.getAttribute('data-section');
      const targetEl = document.getElementById(targetId);
      if (targetEl) {
        e.preventDefault();
        targetEl.scrollIntoView({ behavior: 'smooth', block: 'start' });
        dots.forEach(d => d.classList.remove('active'));
        dot.classList.add('active');
        history.replaceState(null, null, `#${targetId}`);
      }
    });
  });

  window.addEventListener('scroll', updateActiveDot, { passive: true });
  updateActiveDot();
  initAuthNav();
}

// 3. Dynamic Auth State & Modal Controller (Sign In & Sign Up Only)
let currentOrg = null;
let currentApiKey = null;

function initAuthNav() {
  const token = localStorage.getItem('madps_token');
  const unauthDiv = document.getElementById('unauthNavActions');
  const authDiv = document.getElementById('authNavActions');

  if (token && token.length > 10) {
    if (unauthDiv) unauthDiv.style.display = 'none';
    if (authDiv) authDiv.style.display = 'flex';
  } else {
    if (unauthDiv) unauthDiv.style.display = 'flex';
    if (authDiv) authDiv.style.display = 'none';
  }

  // Check URL params for login/signup prompts
  const urlParams = new URLSearchParams(window.location.search);
  if (urlParams.get('login') === 'true') {
    openAuthModal('login');
  } else if (urlParams.get('signup') === 'true') {
    openAuthModal('signup');
  }
}

function logoutPlatform() {
  localStorage.removeItem('madps_token');
  localStorage.removeItem('madps_org');
  localStorage.removeItem('madps_api_key');
  localStorage.removeItem('madps_org_id');
  window.location.href = '/';
}

function openAuthModal(mode = 'login', planTier = 'free') {
  const modal = document.getElementById('auth-modal');
  if (!modal) return;
  modal.style.display = 'flex';
  switchAuthTab(mode === 'signup' ? 'signup' : 'login');
  if (mode === 'signup') {
    const tierInput = document.getElementById('signup-plan-tier');
    if (tierInput) tierInput.value = planTier;
  }
}

function closeAuthModal() {
  const modal = document.getElementById('auth-modal');
  if (modal) modal.style.display = 'none';
}

function switchAuthTab(tab) {
  const tabSignup = document.getElementById('tab-signup');
  const tabLogin = document.getElementById('tab-login');
  const signupForm = document.getElementById('signup-form');
  const loginForm = document.getElementById('login-form');

  if (tab === 'signup') {
    if (tabSignup) {
      tabSignup.classList.add('active');
      tabSignup.style.background = 'rgba(0,242,254,0.15)';
      tabSignup.style.color = 'var(--accent-cyan)';
    }
    if (tabLogin) {
      tabLogin.classList.remove('active');
      tabLogin.style.background = 'transparent';
      tabLogin.style.color = 'var(--text-muted)';
    }
    if (signupForm) signupForm.style.display = 'block';
    if (loginForm) loginForm.style.display = 'none';
  } else {
    if (tabLogin) {
      tabLogin.classList.add('active');
      tabLogin.style.background = 'rgba(0,242,254,0.15)';
      tabLogin.style.color = 'var(--accent-cyan)';
    }
    if (tabSignup) {
      tabSignup.classList.remove('active');
      tabSignup.style.background = 'transparent';
      tabSignup.style.color = 'var(--text-muted)';
    }
    if (loginForm) loginForm.style.display = 'block';
    if (signupForm) signupForm.style.display = 'none';
  }
}

function useDemoLogin(email = 'admin@madps.ai', password = 'admin123') {
  switchAuthTab('login');
  const emailEl = document.getElementById('login-email');
  const passEl = document.getElementById('login-password');
  if (emailEl) emailEl.value = email;
  if (passEl) passEl.value = password;
}

async function handleLogin(event) {
  if (event) event.preventDefault();
  const feedback = document.getElementById('login-feedback');
  const email = (document.getElementById('login-email')?.value || '').trim();
  const password = (document.getElementById('login-password')?.value || '').trim();

  if (feedback) {
    feedback.className = 'form-feedback';
    feedback.style.color = 'var(--accent-cyan)';
    feedback.textContent = 'Authenticating credentials...';
  }

  try {
    const res = await fetch('/api/v1/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password })
    });

    const data = await res.json();
    if (!res.ok) {
      if (feedback) {
        feedback.className = 'form-feedback feedback-error';
        feedback.textContent = data.detail || 'Invalid email or password.';
      }
      return;
    }

    localStorage.setItem('madps_token', data.access_token);
    if (data.org) {
      localStorage.setItem('madps_org', JSON.stringify(data.org));
      localStorage.setItem('madps_org_id', data.org.org_id);
    }

    // Fetch primary API key for this authenticated session
    try {
      const meRes = await fetch('/api/v1/auth/me', {
        headers: { 'Authorization': `Bearer ${data.access_token}` }
      });
      if (meRes.ok) {
        const meData = await meRes.json();
        if (meData.api_keys && meData.api_keys.length > 0) {
          localStorage.setItem('madps_api_key', meData.api_keys[0].api_key);
        }
      }
    } catch (e) {
      console.debug('Failed to prefetch API keys:', e);
    }

    if (feedback) {
      feedback.className = 'form-feedback feedback-success';
      feedback.textContent = '✓ Login successful! Redirecting to dashboard...';
    }

    setTimeout(() => {
      window.location.href = '/dashboard';
    }, 500);

  } catch (err) {
    if (feedback) {
      feedback.className = 'form-feedback feedback-error';
      feedback.textContent = 'Login error: ' + err.message;
    }
  }
}

async function handleSignup(event) {
  if (event) event.preventDefault();
  const feedback = document.getElementById('signup-feedback');
  if (feedback) {
    feedback.className = 'form-feedback';
    feedback.style.color = 'var(--accent-cyan)';
    feedback.textContent = 'Provisioning new organization and auto-generating API key...';
  }

  const name = document.getElementById('signup-name')?.value || 'Admin Analyst';
  const orgName = document.getElementById('signup-org')?.value || 'New Security Org';
  const email = document.getElementById('signup-email')?.value;
  const password = document.getElementById('signup-password')?.value;
  const planTier = document.getElementById('signup-plan-tier')?.value || 'free';

  try {
    const res = await fetch('/api/v1/auth/signup', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name, org_name: orgName, email, password, plan_tier: planTier })
    });

    const data = await res.json();
    if (!res.ok) {
      if (feedback) {
        feedback.className = 'form-feedback feedback-error';
        feedback.textContent = data.detail || 'Signup failed. Please try again.';
      }
      return;
    }

    // Store JWT token, org metadata, and API key
    localStorage.setItem('madps_token', data.access_token);
    if (data.org) {
      localStorage.setItem('madps_org', JSON.stringify(data.org));
      localStorage.setItem('madps_org_id', data.org.org_id);
    }
    if (data.api_key) {
      localStorage.setItem('madps_api_key', data.api_key);
    }

    if (feedback) {
      feedback.className = 'form-feedback feedback-success';
      feedback.textContent = `✓ Account & API Key created! Redirecting to Developer Setup...`;
    }

    setTimeout(() => {
      window.location.href = '/apps';
    }, 600);

  } catch (err) {
    if (feedback) {
      feedback.className = 'form-feedback feedback-error';
      feedback.textContent = 'Connection error: ' + err.message;
    }
  }
}

// 4. Unified Client Integration & Agent SDK Controller (Phase S-Correction)
async function fetchIntegrationStatus() {
  const statEvents = document.getElementById('surfacesStatEvents');
  const statIncidents = document.getElementById('surfacesStatIncidents');
  const statStatus = document.getElementById('integrationStatStatus');
  const liveBadge = document.getElementById('integrationLiveStatusBadge');
  const keyDisplay = document.getElementById('appsApiKeyDisplay');

  // Load active API key for org
  const orgKey = localStorage.getItem('madps_api_key') || 'mk_live_demo1234567890abcdef1234567890abcdef';
  if (keyDisplay) keyDisplay.value = orgKey;
  document.querySelectorAll('.org-key-placeholder').forEach(el => el.textContent = orgKey);

  try {
    const res = await fetch('/api/v1/metrics/summary');
    if (res.ok) {
      const summary = await res.json();
      const eventsCount = summary.total_inspections || summary.ingest_events || 0;
      const threatsCount = summary.threat_inspections || summary.total_reports || 0;

      if (statEvents) statEvents.textContent = eventsCount;
      if (statIncidents) statIncidents.textContent = threatsCount;

      if (eventsCount > 0) {
        if (statStatus) {
          statStatus.textContent = 'CONNECTED';
          statStatus.style.color = '#10b981';
        }
        if (liveBadge) {
          liveBadge.textContent = '● CONNECTED • STREAMING';
          liveBadge.className = 'status-pill green';
        }
      } else {
        if (statStatus) {
          statStatus.textContent = 'WAITING';
          statStatus.style.color = 'var(--accent-cyan)';
        }
        if (liveBadge) {
          liveBadge.textContent = '○ WAITING FOR FIRST EVENT...';
          liveBadge.className = 'status-pill cyan';
        }
      }
    }
  } catch (err) {
    console.debug('Failed to fetch integration summary:', err);
  }
}

// 5. Contact Form Handler (Task N6)
async function handleContactSubmit(event) {
  event.preventDefault();
  const feedback = document.getElementById('contact-feedback');
  const btn = document.getElementById('btn-submit-contact');
  
  feedback.className = 'form-feedback';
  feedback.textContent = 'Recording contact request...';
  btn.disabled = true;

  const form = document.getElementById('contact-form');
  const formData = new FormData(form);
  const payload = {
    name: formData.get('name'),
    email: formData.get('email'),
    company: formData.get('company') || '',
    message: formData.get('message')
  };

  try {
    const res = await fetch('/api/v1/contact', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });

    const data = await res.json();
    if (!res.ok) {
      feedback.className = 'form-feedback feedback-error';
      feedback.textContent = data.detail || 'Submission failed. Please try again.';
      btn.disabled = false;
      return;
    }

    feedback.className = 'form-feedback feedback-success';
    feedback.textContent = '✓ ' + (data.message || 'Thank you! We have received your inquiry and will contact you shortly.');
    form.reset();
  } catch (err) {
    feedback.className = 'form-feedback feedback-error';
    feedback.textContent = 'Error: ' + err.message;
    btn.disabled = false;
  }
}

async function loadDynamicLandingMetrics() {
  try {
    const res = await fetch('/api/v1/metrics/summary');
    if (!res.ok) return;
    const m = await res.json();
    
    // Update Macro F1
    const macroEl = document.querySelector('.metric-card .metric-value');
    if (macroEl && m.macro_f1) {
      macroEl.innerHTML = `${m.macro_f1}<span class="metric-unit">%</span>`;
    }
    
    // Update Obfuscated F1
    const obfEl = document.querySelectorAll('.metric-card .metric-value')[1];
    if (obfEl && m.obfuscated_f1) {
      obfEl.innerHTML = `${m.obfuscated_f1}<span class="metric-unit">%</span>`;
    }

    // Update P95 Latency
    const p95El = document.querySelectorAll('.metric-card .metric-value')[2];
    if (p95El && m.p95_latency_ms) {
      p95El.innerHTML = `${m.p95_latency_ms}<span class="metric-unit">ms</span>`;
    }
  } catch (err) {
    console.debug('Dynamic metrics sync skipped:', err);
  }
}

// Initialize on load
document.addEventListener('DOMContentLoaded', () => {
  initAmbientLogs();
  initScrollObserver();
  loadDynamicLandingMetrics();

  const cForm = document.getElementById('contactForm') || document.getElementById('contact-form');
  if (cForm) {
    cForm.addEventListener('submit', handleContactSubmit);
  }

  if (document.getElementById('appsApiKeyDisplay') || document.getElementById('integrationStatStatus')) {
    fetchIntegrationStatus();
  }
});
