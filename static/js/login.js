    // Initialize Lucide icons
    lucide.createIcons({ attrs: { 'stroke-width': 1.9 } });

    async function handleLogin(e) {
      e.preventDefault();
      
      const btn = document.getElementById('login-btn');
      const errBox = document.getElementById('login-error');
      const errText = document.getElementById('login-error-text');
      
      const username = document.getElementById('username').value.trim();
      const password = document.getElementById('password').value;

      // Reset state
      errBox.style.display = 'none';
      btn.disabled = true;
      btn.innerHTML = '<span class="spin" style="border-top-color:#fff;width:16px;height:16px;margin-right:8px;"></span> Signing in...';

      try {
        const res = await fetch('/api/v1/auth/login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ username, password })
        });

        const data = await res.json();

        if (!res.ok || data.status !== 'success') {
          throw new Error(data.error || 'Invalid credentials');
        }

        // Success - redirect to dashboard
        window.location.href = '/';
        
      } catch (err) {
        errText.textContent = err.message;
        errBox.style.display = 'flex';
        
        // Reset button
        btn.disabled = false;
        btn.innerHTML = '<span>Sign In</span><i data-lucide="arrow-right" class="ui-icon" style="margin:0"></i>';
        lucide.createIcons({ attrs: { 'stroke-width': 1.9 } });
      }
    }