import re
with open('c:/Users/Pranav/Desktop/HackHellix/index.html', 'r', encoding='utf-8') as f:
    text = f.read()

# Replace rgba(255,255,255, with rgba(var(--inv-rgb),
text = text.replace('rgba(255,255,255,', 'rgba(var(--inv-rgb),')

# Replace rgba(6,7,10, with rgba(var(--bg-rgb),
text = text.replace('rgba(6,7,10,', 'rgba(var(--bg-rgb),')
text = text.replace('rgba(10,12,18,', 'rgba(var(--bg-rgb),')

# Add the new variables to :root
root_match = re.search(r':root\{[^}]+\}', text)
if root_match:
    dark_root = """
    :root {
      --void: #0f1115;
      --bg-rgb: 15,17,21;
      --text: #f8fafc;
      --text2: #cbd5e1;
      --muted: #64748b;
      --ghost: #94a3b8;
      --glass: rgba(255,255,255,0.03);
      --glassborder: rgba(255,255,255,0.08);
      --primary: #3b82f6;
      --primary-rgb: 59,130,246;
      --inv-rgb: 255,255,255;
      --danger: #ef4444;
      --warn: #f59e0b;
      --safe: #10b981;
      --blue: #6366f1;
      --intel: #0ea5e9;
      --money: #ec4899;
    }
    :root[data-theme="light"] {
      --void: #f8fafc;
      --bg-rgb: 248,250,252;
      --text: #0f172a;
      --text2: #334155;
      --muted: #64748b;
      --ghost: #94a3b8;
      --glass: rgba(0,0,0,0.02);
      --glassborder: rgba(0,0,0,0.06);
      --primary: #2563eb;
      --primary-rgb: 37,99,235;
      --inv-rgb: 0,0,0;
      --danger: #dc2626;
      --warn: #ea580c;
      --safe: #16a34a;
      --blue: #4f46e5;
      --intel: #0284c7;
      --money: #db2777;
    }
    """
    text = text.replace(root_match.group(0), dark_root.strip())

# Add the theme toggle button HTML right after status chip
theme_btn_html = """
      <button class="lang-btn" onclick="toggleTheme()" id="themeBtn" title="Toggle Theme" style="padding:7px 9px;">
        <svg id="theme-icon-dark" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"></path></svg>
        <svg id="theme-icon-light" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="display:none"><circle cx="12" cy="12" r="5"></circle><line x1="12" y1="1" x2="12" y2="3"></line><line x1="12" y1="21" x2="12" y2="23"></line><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"></line><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"></line><line x1="1" y1="12" x2="3" y2="12"></line><line x1="21" y1="12" x2="23" y2="12"></line><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"></line><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"></line></svg>
      </button>
"""

# Replace in nav-right
text = text.replace('<div class="lang-wrap">', theme_btn_html + '      <div class="lang-wrap">')

# Append toggleTheme js
theme_js = """
    function toggleTheme() {
      const isLight = document.documentElement.getAttribute('data-theme') === 'light';
      document.documentElement.setAttribute('data-theme', isLight ? 'dark' : 'light');
      document.getElementById('theme-icon-dark').style.display = isLight ? 'block' : 'none';
      document.getElementById('theme-icon-light').style.display = isLight ? 'none' : 'block';
    }
"""
text = text.replace('/* ── LANGUAGE SYSTEM ── */', theme_js + '\n    /* ── LANGUAGE SYSTEM ── */')

with open('c:/Users/Pranav/Desktop/HackHellix/index.html', 'w', encoding='utf-8') as f:
    f.write(text)
print("Updated index.html")
