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

# Build navigation from _nav.txt
build_nav() {
    local current="$1"
    local nav_file="$DOCS_DIR/_nav.txt"
    local nav_html=""
    
    # Add Home link
    local class=""
    [[ "$current" == "index" ]] && class="class=\"current\""
    
    nav_html+="<div class=\"sidebar-header\">"
    nav_html+="<a href=\"index.html\" $class>STEADYSTATE</a>"
    nav_html+="</div>"

    if [[ ! -f "$nav_file" ]]; then
        echo "Error: _nav.txt not found" >&2
        return 1
    fi

    local in_list=false
    
    while IFS= read -r line || [[ -n "$line" ]]; do
        # Skip comments and empty lines
        [[ "$line" =~ ^#.*$ ]] && continue
        [[ -z "${line// }" ]] && continue
        
        if [[ "$line" =~ ^SECTION:(.*)$ ]]; then
            # Close previous list if open
            if [[ "$in_list" == "true" ]]; then
                nav_html+="</ul></div>"
            fi
            
            local title="${BASH_REMATCH[1]}"
            # Trim whitespace
            title="$(echo -e "${title}" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
            
            nav_html+="<div class=\"sidebar-section\">"
            nav_html+="<div class=\"sidebar-title\">$title</div>"
            nav_html+="<ul>"
            in_list=true
            
        elif [[ "$line" =~ ^([^|]+)\|(.*)$ ]]; then
            local file="${BASH_REMATCH[1]}"
            local label="${BASH_REMATCH[2]}"
            # Trim whitespace
            file="$(echo -e "${file}" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
            label="$(echo -e "${label}" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
            
            local class=""
            [[ "$current" == "$file" ]] && class="class=\"current\""
            
            nav_html+="<li><a href=\"${file}.html\" $class>$label</a></li>"
        fi
    done < "$nav_file"
    
    if [[ "$in_list" == "true" ]]; then
        nav_html+="</ul></div>"
    fi
    
    echo "$nav_html"
}

echo "Building SteadyState documentation..."
echo "Output directory: $OUTPUT_DIR"

# Convert each markdown file
for f in "$DOCS_DIR"/*.md; do
    [[ ! -f "$f" ]] && continue
    
    basename=$(basename "$f" .md)
    
    # Special case: Copy README.md raw, don't convert
    if [[ "$basename" == "README" ]]; then
        echo "  Copying raw: $basename.md"
        cp "$f" "$OUTPUT_DIR/"
        continue
    fi

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
