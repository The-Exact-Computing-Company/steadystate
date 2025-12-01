use anyhow::Result;
use std::path::Path;

/// Supported Python versions in nixpkgs
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PythonVersion {
    Python39,
    Python310,
    Python311,
    Python312,
    Python313,
}

impl PythonVersion {
    /// Returns the nixpkgs attribute name
    pub fn nix_attr(&self) -> &'static str {
        match self {
            Self::Python39 => "python39",
            Self::Python310 => "python310",
            Self::Python311 => "python311",
            Self::Python312 => "python312",
            Self::Python313 => "python313",
        }
    }
    
    /// Parse from a version string like "3.11" or "3.11.4"
    pub fn from_version_str(s: &str) -> Option<Self> {
        let parts: Vec<&str> = s.trim().split('.').collect();
        if parts.len() < 2 {
            return None;
        }
        
        let major: u8 = parts[0].parse().ok()?;
        let minor: u8 = parts[1].parse().ok()?;
        
        if major != 3 {
            return None;
        }
        
        match minor {
            9 => Some(Self::Python39),
            10 => Some(Self::Python310),
            11 => Some(Self::Python311),
            12 => Some(Self::Python312),
            13 => Some(Self::Python313),
            _ => None,
        }
    }
    
    /// Parse from a version specifier like ">=3.11", ">=3.10,<3.13", "~=3.11"
    /// Returns the minimum compatible version
    pub fn from_specifier(spec: &str) -> Option<Self> {
        let spec = spec.trim();
        
        // Handle common patterns:
        // ">=3.11" → 3.11
        // ">=3.10,<3.13" → 3.10 (take first/minimum)
        // "==3.11.*" → 3.11
        // "~=3.11" → 3.11
        // "^3.11" → 3.11 (poetry style)
        
        for pattern in [">=", "~=", "^", "=="] {
            if let Some(rest) = spec.strip_prefix(pattern) {
                let version_part = rest.split(',').next()?;
                let version_part = version_part
                    .trim_end_matches(".*")
                    .trim_end_matches('*');
                return Self::from_version_str(version_part);
            }
        }
        
        // Try parsing as bare version
        Self::from_version_str(spec)
    }
}

impl Default for PythonVersion {
    fn default() -> Self {
        Self::Python312
    }
}

/// Detect Python version from repository files
pub async fn detect_python_version<E: crate::compute::traits::RemoteExecutor + ?Sized>(
    executor: &E,
    repo_path: &Path,
) -> Result<PythonVersion> {
    // Priority 1: .python-version file
    let python_version_file = repo_path.join(".python-version");
    if executor.exists(&python_version_file).await? {
        let content = executor.read_file(&python_version_file).await?;
        let content = String::from_utf8_lossy(&content);
        if let Some(version) = PythonVersion::from_version_str(content.trim()) {
            tracing::info!("Detected Python {} from .python-version", content.trim());
            return Ok(version);
        }
    }
    
    // Priority 2: uv.lock
    let uv_lock = repo_path.join("uv.lock");
    if executor.exists(&uv_lock).await? {
        let content = executor.read_file(&uv_lock).await?;
        let content = String::from_utf8_lossy(&content);
        if let Some(version) = parse_requires_python(&content) {
            tracing::info!("Detected Python {} from uv.lock", version.nix_attr());
            return Ok(version);
        }
    }
    
    // Priority 3: pyproject.toml
    let pyproject = repo_path.join("pyproject.toml");
    if executor.exists(&pyproject).await? {
        let content = executor.read_file(&pyproject).await?;
        let content = String::from_utf8_lossy(&content);
        if let Some(version) = parse_requires_python(&content) {
            tracing::info!("Detected Python {} from pyproject.toml", version.nix_attr());
            return Ok(version);
        }
    }
    
    // Fallback
    tracing::info!(
        "No Python version detected, using default {}",
        PythonVersion::default().nix_attr()
    );
    Ok(PythonVersion::default())
}

/// Parse requires-python from TOML content
fn parse_requires_python(content: &str) -> Option<PythonVersion> {
    for line in content.lines() {
        let line = line.trim();
        
        if line.starts_with('#') {
            continue;
        }
        
        // Look for: requires-python = ">=3.11"
        // Look for: requires-python = ">=3.11"
        // Look for: requires-python = ">=3.11"
        if line.starts_with("requires-python") {
            if let Some((_, value_part)) = line.split_once('=') {
                let value = value_part.trim().trim_matches(|c| c == '"' || c == '\'');
                return PythonVersion::from_specifier(value);
            }
        }
    }
    
    None
}

/// Generate a flake.nix for Python environment
pub fn generate_python_flake(python_version: PythonVersion) -> String {
    let python_attr = python_version.nix_attr();
    
    format!(r#"{{
  description = "SteadyState Python environment";

  inputs = {{
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  }};

  outputs = {{ self, nixpkgs, flake-utils }}:
    flake-utils.lib.eachDefaultSystem (system:
    let
      pkgs = import nixpkgs {{ inherit system; }};
      python = pkgs.{python_attr};
    in {{
      devShells.default = pkgs.mkShell {{
        name = "steadystate-python";
        
        buildInputs = [
          python
          pkgs.uv
          pkgs.git
          pkgs.neovim
          pkgs.ne
        ];

        shellHook = ''
          export UV_CACHE_DIR="$HOME/.cache/uv"
          export UV_PYTHON_PREFERENCE="only-system"
          
          setup_python_env() {{
            if [ -f uv.lock ]; then
              echo "📦 Found uv.lock, syncing dependencies..."
              uv sync --frozen 2>/dev/null || uv sync
            elif [ -f pyproject.toml ]; then
              echo "📦 Found pyproject.toml, installing..."
              uv sync 2>/dev/null || uv pip install -e .
            elif [ -f requirements.txt ]; then
              echo "📦 Found requirements.txt, installing..."
              [ -d .venv ] || uv venv
              source .venv/bin/activate
              uv pip install -r requirements.txt
            elif [ -f setup.py ]; then
              echo "📦 Found setup.py, installing..."
              [ -d .venv ] || uv venv
              source .venv/bin/activate
              uv pip install -e .
            else
              echo "📦 No Python project files found, creating venv..."
              [ -d .venv ] || uv venv
            fi
            
            # Activate venv if exists and not already active
            if [ -d .venv ] && [ -z "$VIRTUAL_ENV" ]; then
              source .venv/bin/activate
            fi
          }}
          
          setup_python_env
          echo ""
          echo "✓ Python environment ready ($(python --version))"
        '';
      }};
    }});
}}
"#)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_from_version_str() {
        assert_eq!(
            PythonVersion::from_version_str("3.11"),
            Some(PythonVersion::Python311)
        );
        assert_eq!(
            PythonVersion::from_version_str("3.11.4"),
            Some(PythonVersion::Python311)
        );
        assert_eq!(
            PythonVersion::from_version_str("3.12"),
            Some(PythonVersion::Python312)
        );
        assert_eq!(
            PythonVersion::from_version_str("2.7"),
            None
        );
        assert_eq!(
            PythonVersion::from_version_str("3.8"),
            None  // Too old
        );
    }
    
    #[test]
    fn test_from_specifier() {
        assert_eq!(
            PythonVersion::from_specifier(">=3.11"),
            Some(PythonVersion::Python311)
        );
        assert_eq!(
            PythonVersion::from_specifier(">=3.10,<3.13"),
            Some(PythonVersion::Python310)
        );
        assert_eq!(
            PythonVersion::from_specifier("~=3.11"),
            Some(PythonVersion::Python311)
        );
        assert_eq!(
            PythonVersion::from_specifier("==3.11.*"),
            Some(PythonVersion::Python311)
        );
    }
    
    #[test]
    fn test_parse_requires_python() {
        let uv_lock = r#"
version = 1
requires-python = ">=3.11"

[[package]]
name = "requests"
"#;
        assert_eq!(
            parse_requires_python(uv_lock),
            Some(PythonVersion::Python311)
        );
        
        let pyproject = r#"
[project]
name = "myproject"
requires-python = ">=3.10,<3.13"
"#;
        assert_eq!(
            parse_requires_python(pyproject),
            Some(PythonVersion::Python310)
        );
    }
}
