# SteadyState Documentation Site

A minimalist, man-page style documentation site with sidebar navigation. No JavaScript.

## Structure

```
.github/
└── workflows/
    └── docs.yml          # GitHub Action for deployment

docs/
├── _nav.txt              # Navigation config ← EDIT THIS TO ADD PAGES
├── _style.css            # Man-page style CSS
├── _template.html        # HTML template with sidebar
├── build.sh              # Build script (pandoc)
├── index.md              # Main page
├── getting_started.md    
├── quickstart.md         
├── commands.md           
├── configuration.md      
├── architecture.md       
└── troubleshooting.md    
```

---

## Adding New Pages

### Step 1: Create the markdown file

```bash
touch docs/mypage.md
```

Write content using man-page style:

```markdown
# NAME

**mypage** - short description

# DESCRIPTION

Your content here...

# EXAMPLES

Code examples...

# SEE ALSO

**otherpage**(1)
```

### Step 2: Add to navigation

Edit `docs/_nav.txt`:

```
SECTION: User Guide
getting_started|Getting Started
quickstart|Quick Start
mypage|My New Page          ← ADD HERE

SECTION: Reference
commands|Commands
...
```

Format: `filename|Display Name`

### Step 3: Build and preview

```bash
cd docs
./build.sh
cd _site && python3 -m http.server 8000
```

### Step 4: Push to deploy

```bash
git add docs/
git commit -m "Add mypage documentation"
git push
```

GitHub Action builds and deploys automatically.

---

## Navigation Configuration

The `_nav.txt` file controls the sidebar:

```
# Comments start with #

SECTION: User Guide
getting_started|Getting Started
quickstart|Quick Start

SECTION: Reference  
commands|Commands
configuration|Configuration

SECTION: Internals
architecture|Architecture
troubleshooting|Troubleshooting
```

- `SECTION: Name` - Creates a section header
- `filename|Display Name` - Links to `filename.md`
- Pages not in `_nav.txt` won't appear in sidebar
- Order in file = order in sidebar

---

## Local Development

### Prerequisites

```bash
# Ubuntu/Debian
sudo apt install pandoc

# macOS
brew install pandoc

# NixOS
nix-shell -p pandoc
```

### Build

```bash
cd docs
./build.sh
```

### Preview

```bash
cd docs/_site
python3 -m http.server 8000
# Open http://localhost:8000
```

---

## Themes

Edit `_style.css` to change theme. Uncomment one of:

### Light (default)
Black on white, classic man page.

### Dark
```css
:root {
    --bg: #1a1a1a;
    --bg-sidebar: #141414;
    --fg: #c0c0c0;
    ...
}
```

### Amber (retro terminal)
```css
:root {
    --bg: #1a1200;
    --bg-sidebar: #120c00;
    --fg: #ffb000;
    ...
}
```

---

## GitHub Pages Setup

1. Copy `docs/` and `.github/` to your repo
2. Push to `main`
3. Go to **Settings → Pages**
4. Source: **Deploy from a branch**
5. Branch: **website** / **/ (root)**
6. Save

Site URL: `https://<user>.github.io/<repo>/`

---

## Design

- **No JavaScript** - Pure HTML/CSS
- **Sidebar navigation** - Always visible
- **Man page aesthetic** - Unix style
- **Mobile responsive** - Collapses on small screens
- **Print friendly** - Clean print output
