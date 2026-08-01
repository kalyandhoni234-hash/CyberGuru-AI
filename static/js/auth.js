
(async function initAuth() {
  try {
    const res = await fetch('/auth/me', { credentials: 'include' });
    if (res.status === 401) {
      showLoginOverlay();
      return;
    }
    const data = await res.json();
    if (!data.user) { showLoginOverlay(); return; }
    // Defer to next tick so all JS is fully initialised
    await fetchCsrfToken();
    setTimeout(() => showUserProfile(data.user), 0);
  } catch (e) {
    console.error('initAuth error:', e);
    showLoginOverlay();
  }
})();

function showLoginOverlay() {
  const el = document.getElementById('login-overlay');
  if (el) el.style.display = 'flex';
}

function hideLoginOverlay() {
  const el = document.getElementById('login-overlay');
  if (el) el.style.display = 'none';
}

async function showUserProfile(user) {
  try {
    hideLoginOverlay();
    await fetchCsrfToken();

    const row = document.getElementById('user-profile-row');
    if (row) {
      document.getElementById('user-avatar').src = user.avatar || '';
      document.getElementById('user-avatar').style.display = user.avatar ? '' : 'none';
      document.getElementById('user-name').textContent = user.name || user.email;
      document.getElementById('user-email').textContent = user.email;
      row.style.display = 'flex';
    }

  } catch(err) {
    console.error('showUserProfile error:', err);
    // Still hide the overlay even if something minor fails
    hideLoginOverlay();
  }
}

async function logout() {
  await fetch('/auth/logout', { method: 'POST', credentials: 'include' });
  showLoginOverlay();
  const row = document.getElementById('user-profile-row');
  if (row) row.style.display = 'none';
}

// Intercept 401 from any fetch in the app (chat/analyze/etc.)
// ── CSRF token store ──────────────────────────────────────────
let _csrfToken = null;

async function fetchCsrfToken() {
  try {
    const res = await _origFetch('/auth/csrf-token', { credentials: 'include' });
    if (res.ok) {
      const data = await res.json();
      _csrfToken = data.csrf_token || null;
    }
  } catch (e) {
    console.warn('Could not fetch CSRF token:', e);
  }
}

// ── Fetch interceptor: attach CSRF header + handle 401/403 ────
const _origFetch = window.fetch;
window.fetch = async function(...args) {
  // Normalise args so we can inspect and mutate headers
  let [input, init = {}] = args;
  const method = (init.method || (typeof input === 'object' ? input.method : 'GET') || 'GET').toUpperCase();

  // Attach CSRF token to all state-changing requests
  if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(method) && _csrfToken) {
    init = {
      ...init,
      headers: {
        ...(init.headers || {}),
        'X-CSRF-Token': _csrfToken,
      }
    };
  }

  const res = await _origFetch(input, init);

  if (res.status === 401) {
    const clone = res.clone();
    clone.json().then(d => {
      if (d.auth_required) showLoginOverlay();
    }).catch(() => {});
  }

  if (res.status === 403) {
    const clone = res.clone();
    clone.json().then(async d => {
      if (d.csrf_error) {
        // Token is stale — re-fetch and retry once
        await fetchCsrfToken();
      }
    }).catch(() => {});
  }

  return res;
};
