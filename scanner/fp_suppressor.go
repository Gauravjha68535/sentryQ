package scanner

import (
	"SentryQ/reporter"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// SuppressFalsePositives examines code context around each finding and suppresses
// known safe patterns that should not be flagged. This fixes the "mitigation blindness"
// problem where the scanner flags safe implementations (crypto.randomBytes, textContent,
// parameterized queries, ALLOWED_HOSTS, etc.).
func SuppressFalsePositives(findings []reporter.Finding, targetDir string) []reporter.Finding {
	// Cache file contents to avoid re-reading
	fileCache := make(map[string]string)

	readFile := func(filePath string) string {
		absPath := filePath
		if !filepath.IsAbs(absPath) {
			absPath = filepath.Join(targetDir, filePath)
		}
		// Always cache under the resolved absolute path so that the same file
		// accessed via different relative paths gets a cache hit.
		if content, ok := fileCache[absPath]; ok {
			return content
		}
		data, err := os.ReadFile(absPath)
		if err != nil {
			return ""
		}
		content := string(data)
		fileCache[absPath] = content
		return content
	}

	var result []reporter.Finding
	for _, f := range findings {
		content := readFile(f.FilePath)
		if content == "" {
			result = append(result, f)
			continue
		}

		f = adjustLinePointer(f, content)

		if shouldSuppress(f, content) {
			// Mark as suppressed FP — don't remove, just downgrade
			f.AiValidated = "No (False Positive - Safe Pattern)"
			f.Severity = "info"
			f.Description = "[SUPPRESSED] " + f.Description
		}

		result = append(result, f)
	}
	return result
}

// adjustLinePointer shifts the finding's line number up or down if it points
// to a useless target like a blank line, `}`, or a comment.
func adjustLinePointer(f reporter.Finding, fileContent string) reporter.Finding {
	if strings.Contains(f.LineNumber, "-") {
		return f // Don't try to adjust multi-line spans
	}
	lineNum := parseLineNum(f.LineNumber)
	if lineNum <= 0 {
		return f
	}

	lines := strings.Split(fileContent, "\n")
	if lineNum > len(lines) {
		return f
	}

	isJunkLine := func(line string) bool {
		s := strings.TrimSpace(line)
		if s == "" || s == "}" || s == "{" || s == "];" || s == "};" || s == ");" {
			return true
		}
		if strings.HasPrefix(s, "//") || strings.HasPrefix(s, "/*") || strings.HasPrefix(s, "*") || strings.HasPrefix(s, "#") || strings.HasPrefix(s, "<!--") {
			return true
		}
		return false
	}

	idx := lineNum - 1
	if !isJunkLine(lines[idx]) {
		return f
	}

	// Search closest non-junk line within 3 lines up or down
	for offset := 1; offset <= 3; offset++ {
		// Try UP first (compensates for off-by-one/two from AI)
		if idx-offset >= 0 && !isJunkLine(lines[idx-offset]) {
			f.LineNumber = fmt.Sprintf("%d", lineNum-offset)
			return f
		}
		// Try DOWN next (compensates for comments placed right above code)
		if idx+offset < len(lines) && !isJunkLine(lines[idx+offset]) {
			f.LineNumber = fmt.Sprintf("%d", lineNum+offset)
			return f
		}
	}

	return f
}

// shouldSuppress checks if a finding matches known safe patterns in the source code.
// It examines the ±15 line context around a finding for language-specific sanitizers,
// safe API variants, and parameterized alternatives. Suppressed findings are downgraded
// to "info" severity rather than deleted, so they remain auditable.
func shouldSuppress(f reporter.Finding, fileContent string) bool {
	vulnType := strings.ToUpper(normalizeForFP(f))
	if vulnType == "" {
		return false
	}

	lines := strings.Split(fileContent, "\n")
	lineNum := parseLineNum(f.LineNumber)

	// Exact line (0-indexed) for single-line checks
	var exactLine string
	if lineNum > 0 && lineNum <= len(lines) {
		exactLine = strings.ToLower(lines[lineNum-1])
	}

	// ±15 line context window (wider than before — covers imports, setup, guard clauses)
	startCtx := lineNum - 16
	if startCtx < 0 {
		startCtx = 0
	}
	endCtx := lineNum + 15
	if endCtx > len(lines) {
		endCtx = len(lines)
	}
	ctx := strings.ToLower(strings.Join(lines[startCtx:endCtx], "\n"))

	// Test file detection — hardcoded values in test fixtures are expected
	fp := strings.ToLower(f.FilePath)
	isTestFile := strings.Contains(fp, "_test.") || strings.Contains(fp, "/test/") ||
		strings.Contains(fp, "/tests/") || strings.Contains(fp, "/spec/") ||
		strings.Contains(fp, "/fixtures/") || strings.Contains(fp, "/mocks/") ||
		strings.HasSuffix(fp, "_spec.rb") || strings.HasSuffix(fp, ".test.js") ||
		strings.HasSuffix(fp, ".test.ts") || strings.HasSuffix(fp, ".spec.ts") ||
		strings.HasSuffix(fp, "_test.go") || strings.HasSuffix(fp, "_test.py")

	switch vulnType {

	// ─────────────────────────────────────────────────────────────────────────
	case "SQLI":
		// Parameterized query patterns — all major languages / ORMs
		safeSQL := []string{
			// Placeholder styles (these appear IN the query string itself)
			"= ?", "= $1", "= $2", "= :param", "= @param",
			"= %s", "(%s)", "values (%s", "values(%s",
			// Python execute with tuple/list second arg indicator
			"), (", "), [",  // e.g. execute("...", (param,)) or execute("...", [param])
			"cursor.executemany(", // executemany always parameterized
			// Python — ORM and explicit parameterized
			"preparedstatement", "prepared_statement",
			"sqlalchemy", "session.query(", "db.session",
			"django.db", "objects.filter(", "objects.get(", "objects.all(",
			"objects.create(", "objects.update(",
			// Go
			"db.prepare(", "db.query(", "stmt.query(", "stmt.exec(",
			"sqlx.named(", "squirrel.", "goqu.", "bun.db",
			// Java
			"preparestatement(", "preparedstatement", "namedparameterjdbctemplate",
			"@query(", "@param(", "criteriabuilder", "jpa.criteria",
			// PHP
			"pdo::prepare", "->prepare(", "bindparam", "bindvalue",
			"pg_query_params", "mysqli_stmt_bind_param", "->execute(array",
			// Ruby
			"sanitize_sql", "where('", "where(\"", // .where("col = ?", val) form
			"find_by_sql([", "exec_query([", "activerecord",
			// C# / .NET
			"sqlparameter", "parameters.add", "parameters.addwithvalue",
			"dapper.", "entityframework", "dbcontext.",
			// Node.js / JS
			"db.query(sql, [", "pool.query(sql, [", "client.query(sql, [",
			"knex.", "sequelize.", "mongoose.", "typeorm.",
		}
		for _, s := range safeSQL {
			if strings.Contains(ctx, s) {
				return true
			}
		}

	// ─────────────────────────────────────────────────────────────────────────
	case "XSS":
		// Safe output methods — all major frameworks
		// Same-line safe patterns
		if strings.Contains(exactLine, "textcontent") && !strings.Contains(exactLine, "innerhtml") {
			return true
		}
		if strings.Contains(exactLine, "innertext") && !strings.Contains(exactLine, "innerhtml") {
			return true
		}
		// Context-level sanitizer presence
		safeXSS := []string{
			// JS/TS sanitizers
			"dompurify.sanitize(", "sanitizehtml(", "xss(", "xss-filters",
			"createtextnode(", ".textcontent =", ".innertext =",
			// React — JSX auto-escapes {} interpolation; only dangerouslySetInnerHTML is unsafe
			"react.createelement", "reactdom.render",
			// Vue — {{ }} is auto-escaped; v-html is unsafe
			"v-text=", ":textcontent",
			// Angular — {{ }} interpolation is safe; [innerHTML] is unsafe
			"[textcontent]", "domhandler",
			// Python
			"markupsafe.escape(", "markup(", "escape(", "bleach.clean(",
			"django.utils.html", "jinja2.escape(", "htmlescape(",
			"flask.escape(", "cgi.escape(", "html.escape(",
			// PHP
			"htmlspecialchars(", "htmlentities(", "strip_tags(",
			"htmlpurifier", "html_entity_decode",
			// Java
			"stringescapeutils.escapehtml", "esapi.encoder", "encodeforhtml(",
			"htmlutils.htmlescape", "webutils.htmlescape",
			// Go — html/template auto-escapes all output
			"html/template", "template.html(", "template.url(", "template.js(",
			// Ruby / Rails
			"h(", "html_escape(", "sanitize(", "rack::utils.escape_html",
			// C# / ASP.NET
			"htmlencode(", "antixssencoder", "httpserverutility.htmlencode",
			"webencoder.htmlencode",
		}
		for _, s := range safeXSS {
			if strings.Contains(ctx, s) {
				return true
			}
		}

	// ─────────────────────────────────────────────────────────────────────────
	case "WEAK_RANDOM":
		// Secure RNG APIs — all major languages
		safeRNG := []string{
			// Python
			"secrets.token_hex", "secrets.token_urlsafe", "secrets.token_bytes",
			"secrets.randbits", "secrets.choice", "secrets.systemrandom",
			"os.urandom(", "random.systementropypool",
			// Go
			"crypto/rand", "rand.read(", "rand.int(", "rand.prime(",
			// Java / Kotlin
			"new securerandom(", "securerandom.", "java.security.securerandom",
			// Node.js
			"crypto.randombytes(", "crypto.randomuuid(", "crypto.randomfillsync(",
			"crypto.randomint(", "uuid.v4(",
			// PHP
			"random_bytes(", "random_int(", "openssl_random_pseudo_bytes(",
			// Ruby
			"securerandom.hex", "securerandom.uuid", "securerandom.random_bytes",
			"securerandom.alphanumeric",
			// C# / .NET
			"rngcryptoserviceprovider", "randomnumbergenerator.getbytes(",
			"system.security.cryptography.randomnumbergenerator",
			// Rust
			"osrng", "getrandom", "rand::rngs::osr",
		}
		for _, s := range safeRNG {
			if strings.Contains(ctx, s) {
				return true
			}
		}

	// ─────────────────────────────────────────────────────────────────────────
	case "PATH_TRAVERSAL":
		// Safe path handling — canonicalization + base-dir check
		safePathChecks := []string{
			// Python
			"os.path.realpath(", "os.path.abspath(", "pathlib.path(",
			"path.resolve(", "safe_join(", "flask.safe_join(",
			// Go
			"filepath.clean(", "filepath.evalsymlinks(", "strings.hasprefix(",
			// Java
			"getcanonicalpath(", "path.torealpath(", ".startswith(base",
			// PHP
			"realpath(", "basename(", // basename() only gets filename, strips path
			// Ruby
			"file.expand_path(", "pathname#cleanpath", ".start_with?(base",
			// Node.js
			"path.normalize(", "path.resolve(", ".startswith(basepath",
			// C#
			"path.getfullpath(", "path.getfilename(", ".startswith(basepath",
		}
		// Need BOTH canonicalization AND a bounds check
		hasCanon := false
		hasBounds := false
		for _, s := range safePathChecks {
			if strings.Contains(ctx, s) {
				hasCanon = true
			}
		}
		boundChecks := []string{
			"startswith(", "start_with?(", "startswith(base", "hasprefix(",
			"startswith(allowed", "startswith(root", "startswith(upload",
			"startswith(dir", "indexof(basepath", "contains(basepath",
		}
		for _, b := range boundChecks {
			if strings.Contains(ctx, b) {
				hasBounds = true
			}
		}
		if hasCanon && hasBounds {
			return true
		}
		// basename-only access is safe (gets just the filename, no traversal possible)
		if strings.Contains(exactLine, "basename(") || strings.Contains(exactLine, "path.basename(") ||
			strings.Contains(exactLine, "filepath.base(") || strings.Contains(exactLine, "path.getfilename(") {
			return true
		}

	// ─────────────────────────────────────────────────────────────────────────
	case "SSRF":
		// Safe SSRF mitigations
		// 1. Allowlist-based validation
		allowlistPresent := anyContains(ctx, []string{
			"allowed_hosts", "allowlist", "whitelist", "trusted_urls",
			"allowed_domains", "trusted_hosts", "permitted_hosts",
			"allowed_schemes", "valid_hosts",
		})
		// 2. URL parsing + host extraction for validation
		urlParsePresent := anyContains(ctx, []string{
			"urllib.parse.urlparse(", "urllib.parse.urlsplit(",
			"new url(", "url.parse(", "url.parse(",
			"uri.create(", "uri.parse(", "url.parse(",
			"parse_url(", "parsedurl",
		})
		// 3. Private/loopback IP detection
		ipCheckPresent := anyContains(ctx, []string{
			"is_private(", "isprivate(", "isloopback(", "islinklocal(",
			"is_loopback(", "is_link_local(", "ipaddress.ip_address(",
			"private_ip", "internal_ip",
		})
		// 4. Scheme-only allowance
		schemeCheckPresent := anyContains(ctx, []string{
			"startswith('https')", "startswith(\"https\")",
			"scheme == 'https'", "scheme === 'https'",
			"url.scheme", "parsed.scheme",
		})
		if allowlistPresent || urlParsePresent || ipCheckPresent || schemeCheckPresent {
			return true
		}

	// ─────────────────────────────────────────────────────────────────────────
	case "HARDCODED_SECRET":
		// Test files — hardcoded values in tests are expected
		if isTestFile {
			testMarkers := []string{
				"test", "fake", "mock", "dummy", "example", "sample",
				"placeholder", "changeme", "your-secret", "xxx", "todo",
				"replace_me", "insert_here", "not_a_real", "invalid",
			}
			for _, m := range testMarkers {
				if strings.Contains(exactLine, m) || strings.Contains(ctx, m+"_key") ||
					strings.Contains(ctx, m+"_secret") || strings.Contains(ctx, m+"_token") {
					return true
				}
			}
		}
		// Assigned FROM environment / secrets manager — safe by definition
		if strings.Contains(exactLine, "=") {
			eqIdx := strings.Index(exactLine, "=")
			if eqIdx >= 0 && eqIdx+1 < len(exactLine) {
				rhs := exactLine[eqIdx+1:]
				envSources := []string{
					"process.env.", "os.environ", "os.getenv(",
					"environment.getenvironmentvariable(", "system.getenv(",
					"getenv(", "env[", "env.get(",
					"secretsmanager", "boto3.client('secretsmanager')",
					"google.cloud.secretmanager", "azure.keyvault",
					"vault.read(", "hvac.client(", "secretclient(",
					"kubernetes_secret", "secretkeyref",
				}
				for _, src := range envSources {
					if strings.Contains(rhs, src) {
						return true
					}
				}
			}
		}
		// Value is clearly a template/placeholder (contains obvious non-secret markers)
		placeholders := []string{
			"changeme", "your_secret", "your-secret", "replace_this",
			"placeholder", "example_key", "xxx", "insert_key_here",
			"<secret>", "${secret", "{{secret", "___key___",
		}
		for _, ph := range placeholders {
			if strings.Contains(exactLine, ph) {
				return true
			}
		}

	// ─────────────────────────────────────────────────────────────────────────
	case "CMDI":
		// Safe command execution patterns
		safeCMDI := []string{
			// Python — list form = no shell
			"shell=false", "shell = false",
			"subprocess.run([", "subprocess.call([", "subprocess.popen([",
			"subprocess.check_output([",
			"shlex.split(", "shlex.quote(",
			// Go — static first arg = known safe
			// exec.Command("fixed_cmd", ...) where first arg is a string literal
			// (hard to detect without AST, but check for known-safe wrappers)
			"exec.lookpath(", "filepath.clean(",
			// Java
			"processbuilder(list", "processbuilder(arrays.aslist",
			"processbuilder(new string[]",
			// PHP
			"escapeshellarg(", "escapeshellcmd(",
			// Ruby
			"shellwords.escape(", ".shellescape",
			// Node.js
			"execfile(", // execFile doesn't use shell
			"shell: false", "shell:false",
			// C# / .NET
			"argumentlist.add(", "startinfo.argumentlist",
		}
		for _, s := range safeCMDI {
			if strings.Contains(ctx, s) {
				return true
			}
		}

	// ─────────────────────────────────────────────────────────────────────────
	case "DESERIALIZATION":
		// Safe deserialization alternatives
		safeDeser := []string{
			// Python
			"yaml.safe_load(", "json.loads(", "ast.literal_eval(",
			"loader=yaml.safeloader", "loader=yaml.fullloader",
			// Java
			"objectinputfilter", "serialkiller", "allowlist",
			"notserializable", "jsonparser", "objectmapper",
			// PHP — JSON is always safe vs unserialize
			"json_decode(", "simplexml_load_string($",
			// Ruby
			"json.parse(", "yaml.safe_load(",
			// C# / .NET
			"jsonconvert.deserializeobject", "system.text.json",
			"newtonsoft.json",
			// Go
			"json.unmarshal(", "encoding/json",
		}
		for _, s := range safeDeser {
			if strings.Contains(ctx, s) {
				return true
			}
		}

	// ─────────────────────────────────────────────────────────────────────────
	case "WEAK_CRYPTO":
		// Safe modern crypto algorithms — only suppress if a safe algo is nearby
		safeCrypto := []string{
			// Symmetric
			"aes-256", "aes_256", "aes256", "chacha20", "aes-128-gcm", "aes-256-gcm",
			// Asymmetric
			"rsa-2048", "rsa-4096", "ecdsa", "ed25519", "x25519",
			// Password hashing (always safe — never flag bcrypt/argon2/scrypt)
			"bcrypt", "argon2", "scrypt", "pbkdf2",
			// Hashing (SHA-2+ family)
			"sha256", "sha-256", "sha384", "sha512", "sha-512", "sha3",
			"blake2", "blake3",
		}
		for _, s := range safeCrypto {
			if strings.Contains(ctx, s) {
				return true
			}
		}

	// ─────────────────────────────────────────────────────────────────────────
	case "OPEN_REDIRECT":
		// Safe redirect validation
		safeRedirect := []string{
			// ASP.NET
			"url.islocalurl(", "localredirect(",
			// Django
			"is_safe_url(", "url_has_allowed_host_and_scheme(",
			// Rails
			"redirect_back_or_to", "url_for(",
			// Generic
			"uri.joinpath(", "urlparse(return_url",
			"relative_url_only", "only_allow_relative",
		}
		for _, s := range safeRedirect {
			if strings.Contains(ctx, s) {
				return true
			}
		}
		// Relative URL only (no scheme = can't redirect off-site)
		if strings.Contains(exactLine, "startswith('/')") || strings.Contains(exactLine, "startswith(\"/\")") ||
			strings.Contains(exactLine, "starts_with?('/')") {
			return true
		}

	// ─────────────────────────────────────────────────────────────────────────
	case "CSRF":
		// Framework CSRF protection already in place
		safeCSRF := []string{
			// Django
			"@csrf_protect", "csrf_token", "csrfmiddlewaretoken",
			"django.middleware.csrf",
			// Rails
			"protect_from_forgery", "authenticity_token",
			// Laravel
			"@csrf", "csrf_token()", "verifycsftoken",
			// Spring
			"csrffilter", "csrftokenrepository", "httpsecurity.csrf(",
			// Express
			"csurf", "csrf()", "csurf(",
			// ASP.NET
			"antiforgerytoken", "@html.antiforgerytoken", "validateantiforgerytoken",
			// FastAPI / Starlette
			"csrfmiddleware", "csrfprotect(",
		}
		for _, s := range safeCSRF {
			if strings.Contains(ctx, s) {
				return true
			}
		}

	// ─────────────────────────────────────────────────────────────────────────
	case "INPUT_VALIDATION":
		// Suppress generic "env var used" false positives
		if strings.Contains(exactLine, "process.env.") || strings.Contains(exactLine, "os.environ") ||
			strings.Contains(exactLine, "os.getenv(") || strings.Contains(exactLine, "env[") {
			return true
		}

	// ─────────────────────────────────────────────────────────────────────────
	case "IDOR":
		// Safe: parameterized queries (the IDOR flag on safe SQL is misleading)
		safeIDOR := []string{
			"= ?", "= $1", ".prepare(", "preparedstatement",
			"objects.filter(", "findbyid(", "findone(", // ORM always parameterizes
		}
		for _, s := range safeIDOR {
			if strings.Contains(exactLine, s) {
				return true
			}
		}

	// ─────────────────────────────────────────────────────────────────────────
	case "RESOURCE_LIMIT":
		// Already-limited configurations that shouldn't fire
		if strings.Contains(ctx, "limit:") || strings.Contains(ctx, "maxsize") ||
			strings.Contains(ctx, "max_content_length") || strings.Contains(ctx, "clientmaxbodysize") {
			return true
		}
	}

	return false
}

// anyContains returns true if s contains any of the substrings in candidates.
func anyContains(s string, candidates []string) bool {
	for _, c := range candidates {
		if strings.Contains(s, c) {
			return true
		}
	}
	return false
}

// normalizeForFP maps a finding to a vulnerability family for FP suppression.
// Mapping is done first by CWE (precise), then by rule ID / issue name keywords (fallback).
func normalizeForFP(f reporter.Finding) string {
	cwe := strings.ToUpper(strings.TrimSpace(f.CWE))

	// CWE → family (authoritative)
	cweMap := map[string]string{
		// SQL Injection
		"CWE-89": "SQLI",
		// XSS
		"CWE-79":  "XSS",
		"CWE-80":  "XSS",
		"CWE-116": "XSS",
		// Path Traversal
		"CWE-22": "PATH_TRAVERSAL",
		"CWE-23": "PATH_TRAVERSAL",
		"CWE-36": "PATH_TRAVERSAL",
		// SSRF
		"CWE-918": "SSRF",
		// Command Injection
		"CWE-78":  "CMDI",
		"CWE-77":  "CMDI",
		"CWE-88":  "CMDI",
		"CWE-74":  "CMDI",
		// Deserialization
		"CWE-502": "DESERIALIZATION",
		// Hardcoded Secrets
		"CWE-798": "HARDCODED_SECRET",
		"CWE-259": "HARDCODED_SECRET",
		"CWE-321": "HARDCODED_SECRET",
		// Weak Random
		"CWE-330": "WEAK_RANDOM",
		"CWE-331": "WEAK_RANDOM",
		"CWE-338": "WEAK_RANDOM",
		"CWE-332": "WEAK_RANDOM",
		// Weak Crypto
		"CWE-327": "WEAK_CRYPTO",
		"CWE-326": "WEAK_CRYPTO",
		"CWE-328": "WEAK_CRYPTO",
		"CWE-916": "WEAK_CRYPTO",
		// Open Redirect
		"CWE-601": "OPEN_REDIRECT",
		// CSRF
		"CWE-352": "CSRF",
		// Input Validation
		"CWE-20":  "INPUT_VALIDATION",
		"CWE-129": "INPUT_VALIDATION",
		// IDOR
		"CWE-284": "IDOR",
		"CWE-285": "IDOR",
		"CWE-639": "IDOR",
		// Resource / DoS
		"CWE-770": "RESOURCE_LIMIT",
		"CWE-400": "RESOURCE_LIMIT",
		"CWE-776": "RESOURCE_LIMIT",
		// Code Injection / SSTI
		"CWE-94":   "CMDI", // treat code injection like cmdi for suppression
		"CWE-1336": "CMDI",
		// XXE
		"CWE-611": "DESERIALIZATION",
	}
	if family, ok := cweMap[cwe]; ok {
		return family
	}

	// Keyword fallback on rule ID + issue name
	combined := strings.ToLower(f.IssueName + " " + f.RuleID + " " + f.Description)

	keywordMap := []struct{ keyword, family string }{
		{"sql injection", "SQLI"},
		{"sqli", "SQLI"},
		{"xss", "XSS"},
		{"cross-site scripting", "XSS"},
		{"cross site scripting", "XSS"},
		{"path traversal", "PATH_TRAVERSAL"},
		{"directory traversal", "PATH_TRAVERSAL"},
		{"file inclusion", "PATH_TRAVERSAL"},
		{"ssrf", "SSRF"},
		{"server-side request forgery", "SSRF"},
		{"command injection", "CMDI"},
		{"cmdi", "CMDI"},
		{"code injection", "CMDI"},
		{"template injection", "CMDI"},
		{"ssti", "CMDI"},
		{"deserialization", "DESERIALIZATION"},
		{"unsafe deserializ", "DESERIALIZATION"},
		{"pickle", "DESERIALIZATION"},
		{"xxe", "DESERIALIZATION"},
		{"xml external entity", "DESERIALIZATION"},
		{"hardcoded secret", "HARDCODED_SECRET"},
		{"hardcoded credential", "HARDCODED_SECRET"},
		{"hardcoded password", "HARDCODED_SECRET"},
		{"hardcoded api key", "HARDCODED_SECRET"},
		{"weak random", "WEAK_RANDOM"},
		{"insecure random", "WEAK_RANDOM"},
		{"entropy", "WEAK_RANDOM"},
		{"weak crypto", "WEAK_CRYPTO"},
		{"weak cipher", "WEAK_CRYPTO"},
		{"weak hash", "WEAK_CRYPTO"},
		{"md5", "WEAK_CRYPTO"},
		{"sha1", "WEAK_CRYPTO"},
		{"open redirect", "OPEN_REDIRECT"},
		{"unvalidated redirect", "OPEN_REDIRECT"},
		{"csrf", "CSRF"},
		{"cross-site request forgery", "CSRF"},
		{"idor", "IDOR"},
		{"insecure direct object", "IDOR"},
		{"body parser", "RESOURCE_LIMIT"},
		{"size limit", "RESOURCE_LIMIT"},
	}
	for _, kw := range keywordMap {
		if strings.Contains(combined, kw.keyword) {
			return kw.family
		}
	}

	return ""
}

func parseLineNum(lineRef string) int {
	parts := strings.Split(lineRef, "-")
	var n int
	for _, ch := range parts[0] {
		if ch >= '0' && ch <= '9' {
			n = n*10 + int(ch-'0')
		}
	}
	return n
}
