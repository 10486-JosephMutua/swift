import os
import tempfile
import logging
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger("swiftaudit.config")


class Config:
    # LLM / Groq
    GROQ_API_KEY: str      = os.getenv("GROQ_API_KEY", "")
    GROQ_MODEL: str        = os.getenv("GROQ_MODEL", "llama-3.1-70b-versatile")
    LLM_TEMPERATURE: float = float(os.getenv("LLM_TEMPERATURE", "0.1"))
    MAX_LLM_RETRIES: int   = int(os.getenv("MAX_LLM_RETRIES", "3"))

    # Snyk
    SNYK_TOKEN: str   = os.getenv("SNYK_TOKEN", "")
    SNYK_TIMEOUT: int = int(os.getenv("SNYK_TIMEOUT", "120"))

    # Trivy — allow enough time for DB init on first run
    TRIVY_TIMEOUT: int     = int(os.getenv("TRIVY_TIMEOUT", "300"))
    TOOL_SCAN_TIMEOUT: int = int(os.getenv("TOOL_SCAN_TIMEOUT", "360"))

    # GitHub
    GITHUB_TOKEN: str = os.getenv("GITHUB_TOKEN", "")

    # Flask — debug must stay False to preserve in-memory scan store
    FLASK_ENV: str        = os.getenv("FLASK_ENV", "development")
    FLASK_DEBUG: bool     = False
    FLASK_SECRET_KEY: str = os.getenv("FLASK_SECRET_KEY", "dev-secret-change-me")
    FLASK_HOST: str       = os.getenv("FLASK_HOST", "0.0.0.0")
    FLASK_PORT: int       = int(os.getenv("FLASK_PORT", "5000"))

    # Concurrency
    CONCURRENT_FILE_FETCH: int = int(os.getenv("CONCURRENT_FILE_FETCH", "6"))
    CONCURRENT_LLM_SCANS: int  = int(os.getenv("CONCURRENT_LLM_SCANS", "4"))
    CONCURRENT_SCANNERS: bool  = os.getenv("CONCURRENT_SCANNERS", "true").lower() == "true"

    # Context / chunking
    MAX_TOKENS_PER_FILE: int = int(os.getenv("MAX_TOKENS_PER_FILE", "6000"))
    MAX_FILES_TO_ANALYZE: int = int(os.getenv("MAX_FILES_TO_ANALYZE", "15"))
    MAX_FILE_SIZE_BYTES: int  = int(os.getenv("MAX_FILE_SIZE_BYTES", "1048576"))

    # Scan store
    SCAN_STORE_MAX_SIZE: int  = int(os.getenv("SCAN_STORE_MAX_SIZE", "500"))
    SCAN_STORE_TTL_HOURS: int = int(os.getenv("SCAN_STORE_TTL_HOURS", "24"))

    # Repo / clone
    GIT_CLONE_TIMEOUT: int = int(os.getenv("GIT_CLONE_TIMEOUT", "90"))
    TEMP_CLONE_DIR: str    = os.getenv(
        "TEMP_CLONE_DIR",
        os.path.join(tempfile.gettempdir(), "swiftaudit_clones"),
    )
    MAX_REPO_SIZE_MB: int = int(os.getenv("MAX_REPO_SIZE_MB", "200"))

    # Reports
    REPORTS_OUTPUT_DIR: str   = os.getenv("REPORTS_OUTPUT_DIR", "reports/output")
    REPORT_TEMPLATES_DIR: str = os.getenv("REPORT_TEMPLATES_DIR", "templates")

    # All dependency / lock filenames Trivy + Snyk recognise
    DEPENDENCY_FILENAMES: frozenset = frozenset({
        "requirements.txt", "requirements-dev.txt", "requirements-prod.txt",
        "requirements-test.txt", "requirements-base.txt", "requirements-lock.txt",
        "requirements_dev.txt", "requirements_prod.txt", "requirements_test.txt",
        "pipfile", "pipfile.lock",
        "setup.py", "setup.cfg", "pyproject.toml",
        "poetry.lock", "pdm.lock", "uv.lock",
        "conda-lock.yml", "environment.yml", "environment.yaml",
        "package.json", "package-lock.json",
        "yarn.lock", "pnpm-lock.yaml",
        "npm-shrinkwrap.json", "bun.lock", "bun.lockb",
        "pom.xml",
        "build.gradle", "build.gradle.kts",
        "settings.gradle", "settings.gradle.kts",
        "gradle.lockfile",
        "build.sbt",
        "go.mod", "go.sum",
        "cargo.toml", "cargo.lock",
        "gemfile", "gemfile.lock",
        "podfile", "podfile.lock",
        "composer.json", "composer.lock",
        "packages.config", "nuget.config",
        "packages.lock.json",
        "directory.packages.props",
        "package.resolved",
        "pubspec.yaml", "pubspec.lock",
        "mix.exs", "mix.lock",
        "project.clj", "deps.edn",
        "cabal.project", "stack.yaml", "stack.yaml.lock",
        "flake.lock",
        "conanfile.txt", "conanfile.py", "conan.lock",
        "vcpkg.json", "vcpkg-configuration.json",
        ".terraform.lock.hcl",
        "paket.dependencies", "paket.lock",
    })

    DEP_EXTENSIONS: frozenset = frozenset({".lock", ".mod", ".sum"})

    IGNORED_EXTENSIONS: frozenset = frozenset({
        ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".svg", ".webp",
        ".mp4", ".mp3", ".wav", ".avi", ".mov", ".mkv",
        ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
        ".zip", ".tar", ".gz", ".rar", ".7z", ".bz2",
        ".exe", ".dll", ".so", ".dylib", ".pyd", ".pyc",
        ".ttf", ".otf", ".woff", ".woff2", ".eot",
        ".bin", ".obj", ".o", ".a", ".lib",
        ".min.js", ".min.css",
    })

    SOURCE_EXTENSIONS: frozenset = frozenset({
        ".py", ".js", ".ts", ".jsx", ".tsx",
        ".java", ".kt", ".kts", ".scala",
        ".go", ".rs",
        ".c", ".cpp", ".cc", ".cxx", ".h", ".hpp",
        ".cs", ".vb", ".fs",
        ".rb", ".php", ".swift",
        ".sh", ".bash", ".zsh", ".ps1", ".psm1", ".bat", ".cmd",
        ".yaml", ".yml", ".json", ".xml", ".toml",
        ".tf", ".hcl", ".dockerfile",
        ".env", ".ini", ".cfg", ".conf", ".properties", ".config",
        ".sql", ".graphql", ".gql", ".proto",
        ".r", ".m", ".pl", ".ex", ".exs", ".erl",
        ".dart", ".lua", ".groovy",
    })

    IGNORED_DIRS: frozenset = frozenset({
        "node_modules", ".git", "vendor", "dist", "build", ".next",
        "__pycache__", ".pytest_cache", ".mypy_cache",
        "venv", ".venv", "env", ".env_folder",
        "target", "out", ".gradle", ".idea", ".vscode",
        "coverage", ".nyc_output", "htmlcov",
        ".terraform",
    })

    HIGH_VALUE_PATTERNS: frozenset = frozenset({
        "dockerfile", "makefile", "jenkinsfile", "vagrantfile",
        ".env", ".env.example", ".env.sample", ".env.local",
        "config", "settings", "secrets", "credentials",
        "auth", "login", "token", "password",
    })

    def validate(self) -> None:
        errors = []
        if not self.GROQ_API_KEY:
            errors.append("GROQ_API_KEY is required")
        if errors:
            raise ValueError(f"Config validation failed: {'; '.join(errors)}")

        logger.info(f"[CONFIG] Model              : {self.GROQ_MODEL}")
        logger.info(f"[CONFIG] Max tokens/file    : {self.MAX_TOKENS_PER_FILE}")
        logger.info(f"[CONFIG] Max files          : {self.MAX_FILES_TO_ANALYZE}")
        logger.info(f"[CONFIG] Dependency files   : {len(self.DEPENDENCY_FILENAMES)}")
        logger.info(f"[CONFIG] Scan store TTL     : {self.SCAN_STORE_TTL_HOURS}h")
        logger.info(f"[CONFIG] Snyk token         : {'SET' if self.SNYK_TOKEN else 'NOT SET'}")
        logger.info(f"[CONFIG] Concurrent fetches : {self.CONCURRENT_FILE_FETCH}")
        logger.info(f"[CONFIG] Concurrent LLM     : {self.CONCURRENT_LLM_SCANS}")
        logger.info(f"[CONFIG] Concurrent scanners: {self.CONCURRENT_SCANNERS}")
        logger.info("[CONFIG] Configuration valid.")


config = Config()
