import re

with open('index.html', 'r', encoding='utf-8') as f:
    content = f.read()

# 1. Update Fonts
content = content.replace(
    'family=Syne:wght@400;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap',
    'family=Outfit:wght@300;400;500;600;700&family=Inter:wght@300;400;500;600&family=JetBrains+Mono:wght@400;500&display=swap'
)
content = content.replace(
    "fontFamily: { display: ['Syne','sans-serif'], mono: ['JetBrains Mono','monospace'] }",
    "fontFamily: { display: ['Outfit','sans-serif'], sans: ['Inter','sans-serif'], mono: ['JetBrains Mono','monospace'] }"
)
content = content.replace("font-family:'Syne',sans-serif;", "font-family:'Inter',sans-serif;")

# 2. Update Tailwind Config Colors
old_colors = """          colors: {
            void:'#08090a', surface:'#111214', card:'#18191d', border:'#26282e',
            muted:'#4a4d57', ghost:'#8b8fa8', text:'#e8e9ef', accent:'#c8ff00',
            danger:'#ff3b3b', warn:'#ffaa00', safe:'#22c55e', intel:'#38bdf8', money:'#ec4899',
          },"""
new_colors = """          colors: {
            void:'#030712', surface:'rgba(17, 24, 39, 0.4)', card:'rgba(31, 41, 55, 0.4)', border:'rgba(255, 255, 255, 0.08)',
            muted:'#6b7280', ghost:'#9ca3af', text:'#f9fafb', accent:'#3b82f6',
            danger:'#ef4444', warn:'#f59e0b', safe:'#10b981', intel:'#0ea5e9', money:'#8b5cf6',
          },"""
content = content.replace(old_colors, new_colors)

# 3. Update Global CSS
old_css_start = "    body{background:#08090a;color:#e8e9ef;font-family:'Syne',sans-serif;min-height:100vh;}"
new_css_start = """    body{background:#030712;color:#f9fafb;font-family:'Inter',sans-serif;min-height:100vh;}
    body::before{content:'';position:fixed;inset:0;background:radial-gradient(circle at 50% 0%, rgba(59,130,246,0.15) 0%, transparent 60%), radial-gradient(circle at 0% 100%, rgba(139,92,246,0.1) 0%, transparent 50%);pointer-events:none;z-index:0;}
    ::-webkit-scrollbar{width:6px;} ::-webkit-scrollbar-track{background:transparent;} ::-webkit-scrollbar-thumb{background:rgba(255,255,255,0.1);border-radius:3px;}
    ::-webkit-scrollbar-thumb:hover{background:rgba(255,255,255,0.2);}

    .glass { background: rgba(17, 24, 39, 0.4); backdrop-filter: blur(16px); -webkit-backdrop-filter: blur(16px); border: 1px solid rgba(255, 255, 255, 0.08); box-shadow: 0 4px 30px rgba(0, 0, 0, 0.1); }
    .glass-card { background: rgba(31, 41, 55, 0.4); backdrop-filter: blur(16px); -webkit-backdrop-filter: blur(16px); border: 1px solid rgba(255, 255, 255, 0.08); box-shadow: 0 8px 32px rgba(0, 0, 0, 0.1); transition: transform 0.3s ease, box-shadow 0.3s ease; }
    .glass-card:hover { transform: translateY(-2px); box-shadow: 0 12px 40px rgba(0, 0, 0, 0.15); }
    .glass-input { background: rgba(0, 0, 0, 0.2); backdrop-filter: blur(8px); border: 1px solid rgba(255, 255, 255, 0.08); color: #f9fafb; }
    .glass-input:focus { border-color: #3b82f6; outline: none; box-shadow: 0 0 0 2px rgba(59,130,246,0.2); }"""

content = content.replace(old_css_start, new_css_start)

# Replace noise background if it exists later in CSS
content = re.sub(r"body::before{content:'';position:fixed;inset:0;background-image:url[^}]+}", "", content)

# Smooth animations & rounded corners updates
content = content.replace("animation:fadeIn .45s ease forwards", "animation:fadeIn .6s cubic-bezier(0.16,1,0.3,1) forwards")
content = content.replace("animation:slideUp .45s ease forwards", "animation:slideUp .6s cubic-bezier(0.16,1,0.3,1) forwards")
content = content.replace("animation:slideUp .4s ease forwards", "animation:slideUp .5s cubic-bezier(0.16,1,0.3,1) forwards")
content = content.replace("animation:fadeIn .3s ease forwards", "animation:fadeIn .4s cubic-bezier(0.16,1,0.3,1) forwards")

# Update rounded-xl to rounded-2xl for better modern look
content = content.replace("rounded-xl", "rounded-2xl")

# Fix hardcoded colors (accent -> blue, void -> gray, surface -> glass)
content = content.replace("#c8ff00", "#3b82f6")
content = content.replace("rgba(200,255,0", "rgba(59,130,246")
content = content.replace("#08090a", "#030712")
content = content.replace("#111214", "rgba(17,24,39,0.4)")
content = content.replace("#18191d", "rgba(31,41,55,0.4)")
content = content.replace("#26282e", "rgba(255,255,255,0.08)")
content = content.replace("#4a4d57", "#6b7280")
content = content.replace("#8b8fa8", "#9ca3af")
content = content.replace("#e8e9ef", "#f9fafb")

# Replace bg-card and bg-surface with glass-card and glass
content = content.replace("bg-card", "glass-card")
content = content.replace("bg-surface", "glass")
content = content.replace("bg-void/90", "glass")

# 4. Inject Language Converter Button into header
old_header_right = """  <div class="flex items-center gap-3">
    <span class="pill hidden md:inline-flex" style="background:rgba(59,130,246,.09);color:#3b82f6;border:1px solid rgba(59,130,246,.2);">✦ AI-powered</span>"""

new_header_right = """  <div class="flex items-center gap-4">
    <!-- Language Selector -->
    <div class="relative group">
      <button class="flex items-center gap-1.5 font-sans text-xs text-text border border-border glass px-3 py-1.5 rounded-lg hover:border-muted transition-all">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/><path d="M2 12h20"/></svg>
        EN
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="m6 9 6 6 6-6"/></svg>
      </button>
      <div class="absolute right-0 mt-2 w-28 glass-card rounded-xl opacity-0 invisible group-hover:opacity-100 group-hover:visible transition-all duration-300 transform origin-top-right scale-95 group-hover:scale-100 overflow-hidden flex flex-col shadow-xl border border-border z-50">
        <button class="text-xs text-left px-4 py-2.5 hover:bg-white/10 text-text transition-colors">English</button>
        <button class="text-xs text-left px-4 py-2.5 hover:bg-white/10 text-ghost transition-colors">Español</button>
        <button class="text-xs text-left px-4 py-2.5 hover:bg-white/10 text-ghost transition-colors">Français</button>
      </div>
    </div>
    <span class="pill hidden md:inline-flex" style="background:rgba(59,130,246,.09);color:#3b82f6;border:1px solid rgba(59,130,246,.2);">✦ AI-powered</span>"""

content = content.replace(old_header_right, new_header_right)

# 5. Fix Chat Input Background
content = content.replace('id="chat-input" type="text" placeholder="Ask about any clause..." class="flex-1 glass border border-border rounded-lg px-4 py-2.5 text-sm text-text outline-none transition-colors font-display"',
                          'id="chat-input" type="text" placeholder="Ask about any clause..." class="flex-1 glass-input rounded-lg px-4 py-2.5 text-sm outline-none transition-all duration-300 font-sans"')

# Fix general buttons
content = content.replace('hover:bg-accent/90 active:scale-[0.99] transition-all duration-150', 'hover:bg-accentHover active:scale-[0.98] transition-all duration-300 shadow-lg shadow-accent/20')

# 6. Smooth hover effects on buttons/cards
content = content.replace("transition-colors", "transition-all duration-300")
content = content.replace("transition:all .18s", "transition:all .3s cubic-bezier(0.16,1,0.3,1)")

# Replace the specific hardcoded linear-gradient for scanline since we replaced colors blindly
content = content.replace("linear-gradient(90deg,transparent,#c8ff00,transparent)", "linear-gradient(90deg,transparent,#3b82f6,transparent)")

with open('index.html', 'w', encoding='utf-8') as f:
    f.write(content)

print("Done updating index.html")
