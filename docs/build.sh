#!/bin/bash
set -e

# SteadyState Documentation Builder
# Converts markdown files to a minimal, man-page style static site

DOCS_DIR="$(cd "$(dirname "$0")" && pwd)"
OUTPUT_DIR="$DOCS_DIR/_site"
TEMPLATE="$DOCS_DIR/_template.html"
CSS="$DOCS_DIR/_style.css"

# Clean and create output directory
rm -rf "$OUTPUT_DIR"
mkdir -p "$OUTPUT_DIR"

# Copy CSS
cp "$CSS" "$OUTPUT_DIR/style.css"

# Get current date for footer
BUILD_DATE=$(date -u +"%Y-%m-%d")

# Function to convert a single markdown file
convert_md() {
    local input="$1"
    local output="$2"
    local title="$3"
    local nav="$4"
    
    # Convert markdown to HTML body using pandoc
    pandoc --from=markdown --to=html "$input" > /tmp/body.html
    
    # Read template, substitute simple variables, then insert body
    sed -e "s|{{TITLE}}|$title|g" \
        -e "s|{{NAV}}|$nav|g" \
        -e "s|{{DATE}}|$BUILD_DATE|g" \
        "$TEMPLATE" | \
    sed -e '/{{BODY}}/{r /tmp/body.html' -e 'd}' > "$output"
}

# Build navigation from docs structure
build_nav() {
    local current="$1"
    local nav="<a href=\"index.html\""
    [[ "$current" == "index" ]] && nav="$nav class=\"current\""
    [[ "$basename" == "README" ]] && continue
    nav="$nav>STEADYSTATE(1)</a>"

    # Add each doc file
    for f in "$DOCS_DIR"/*.md; do
        [[ ! -f "$f" ]] && continue
        local basename=$(basename "$f" .md)
        [[ "$basename" == "index" ]] && continue

        # Convert filename to title: getting_started -> GETTING_STARTED
        local title=$(echo "$basename" | tr '[:lower:]' '[:upper:]' | tr '-' '_')
        local section="7"  # Default section for guides

        # Assign sections based on content type
        case "$basename" in
            getting_started|quickstart) section="1" ;;
            configuration|config) section="5" ;;
            api|protocol) section="3" ;;
            troubleshooting|faq) section="7" ;;
            architecture|internals) section="8" ;;
            *) section="7" ;;
        esac
        
        nav="$nav <a href=\"${basename}.html\""
        [[ "$current" == "$basename" ]] && nav="$nav class=\"current\""
        nav="$nav>${title}($section)</a>"
    done
    
    echo "$nav"
}

echo "Building SteadyState documentation..."
echo "Output directory: $OUTPUT_DIR"

# Convert each markdown file
for f in "$DOCS_DIR"/*.md; do
    [[ ! -f "$f" ]] && continue
    
    basename=$(basename "$f" .md)
    title=$(echo "$basename" | tr '[:lower:]' '[:upper:]' | tr '-' '_')
    
    # Special case for index
    [[ "$basename" == "index" ]] && title="STEADYSTATE"
    
    nav=$(build_nav "$basename")
    
    echo "  Converting: $basename.md -> $basename.html"
    convert_md "$f" "$OUTPUT_DIR/${basename}.html" "$title" "$nav"
done

# Count files
count=$(find "$OUTPUT_DIR" -name "*.html" | wc -l)
echo "Done. Generated $count pages."
