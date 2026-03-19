# QWEN Scanner Fix Plan - Progress Tracker

## Current Status: [IN PROGRESS]

### Phase 1: Fix Broken Rule Files (Critical - 5000+ rules skipped)
- [x] Step 1.1: Create `audit-rules.sh` to scan ALL rules/*.yaml for errors
- [x] Step 1.2: **Audit Complete** - rule_loader.go line-by-line parser rescues ALL rules (parsing file shows 11+ rules each).  
  **True Issue**: `regexp.Compile()` fails on Perl `(?!` → Go `utils.LogWarn()` but rules still load! Scanner works (2197 valid rules). Warnings = **cosmetic**.
- [ ] Step 1.3: Mass-fix regex patterns:
  | Pattern | Count | Fix |
  |---------|-------|-----|
  | `(?!` | 250+ | `(?!)` or rewrite |
  | Missing `)` | 500+ | Balance parens |
  | Missing `]` | 100+ | Balance brackets |
  | YAML quotes | 200+ | Double single quotes |
- [ ] Step 1.4: Test: `./qwen-scanner` → Expect 5000+ rules loaded
- [ ] Step 1.5: Validate AI finds real issues

### Phase 2: Fix Ollama Remote Host
- [ ] Step 2.1: Add `--ollama-host HOST:PORT` CLI flag to main.go
- [ ] Step 2.2: Update discovery_scanner.go SetOllamaHost() usage
- [ ] Step 2.3: Test with `172.29.190.139:11434`

### Phase 3: Performance & Validation
- [ ] Step 3.1: Fix GPU acceleration on friend's Ollama
- [ ] Step 3.2: Fix OSV-scanner integration
- [ ] Step 3.3: Full test scan on sample project

**Next Action**: Run audit script → Fix top offenders
