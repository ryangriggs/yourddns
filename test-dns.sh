#!/usr/bin/env bash
# =============================================================================
# YourDDNS DNS Compliance Test Suite
#
# Tests basic record lookups, wildcards, NODATA/NXDOMAIN, header flags,
# SOA/NS scoping, ANY queries, additional-section records, and protocol errors.
#
# Usage:
#   ./test-dns.sh <zone-domain> [dns-server-ip]
#
# Examples:
#   ./test-dns.sh ddns.mydomain.com
#   ./test-dns.sh ddns.mydomain.com 203.0.113.5
# =============================================================================
set -uo pipefail

DOMAIN="${1:-}"
SERVER="${2:-}"

# ── colours ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; BOLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'

die()  { echo -e "${RED}ERROR:${NC} $*" >&2; exit 1; }
note() { echo -e "  ${DIM}$*${NC}"; }
skip() { echo -e "  ${DIM}⊘  SKIP${NC}  $1"; }

[[ -n "$DOMAIN" ]] || die "Usage: $0 <zone-domain> [dns-server-ip]"
command -v dig >/dev/null 2>&1 || die "'dig' not found — install bind-utils or dnsutils"

# ── resolve server if not provided ───────────────────────────────────────────
if [[ -z "$SERVER" ]]; then
  SERVER=$(dig +short NS "$DOMAIN" 2>/dev/null | head -1 | sed 's/\.$//')
  if [[ -z "$SERVER" ]]; then
    SERVER=$(dig +short A "$DOMAIN" 2>/dev/null | head -1)
  fi
  [[ -n "$SERVER" ]] || die "Cannot determine a nameserver for $DOMAIN. Pass it as the second argument."
  echo -e "Auto-detected nameserver: ${BOLD}$SERVER${NC}"
fi

# ── fixed test record values ──────────────────────────────────────────────────
# These are RFC 5737 documentation addresses (203.0.113.0/24) and RFC 3849
# documentation IPv6 (2001:db8::/32). Safe to use in any test environment.
A_STATIC="203.0.113.1"       # statichost4   A
AAAA_STATIC="2001:db8::1"    # statichost6   AAAA
A_APEX="203.0.113.10"        # @             A  (apex)
A_MAIL="203.0.113.50"        # mail          A  (MX target)
A_DDNS="203.0.113.51"        # ddnshost      DDNS A
A_WILD="203.0.113.100"       # *             A  (single-level wildcard)
A_WILD_SUB="203.0.113.200"   # *.sub         A  (second-level wildcard)

# ── counters ──────────────────────────────────────────────────────────────────
PASS=0
FAIL=0

D="dig @$SERVER +time=3 +tries=2"

# ── helpers ───────────────────────────────────────────────────────────────────
section() { echo -e "\n${BLUE}${BOLD}━━━ $* ━━━${NC}"; }

pass() { echo -e "  ${GREEN}✓${NC}  $1"; PASS=$((PASS + 1)); }
fail() { echo -e "  ${RED}✗${NC}  $1"; FAIL=$((FAIL + 1)); }

# dig wrappers — each returns a specific section; extra args flow through to dig
_answer()    { $D +noall +answer    "$@" 2>/dev/null || true; }
_authority() { $D +noall +authority "$@" 2>/dev/null || true; }
_full()      { $D +noall +answer +authority +additional "$@" 2>/dev/null || true; }
_comments()  { $D +noall +comments "$@" 2>/dev/null || true; }

_rcode() {
  # Extract the status word from dig's header comment line
  _comments "$@" | grep -oP 'status: \K\w+' | head -1
}

_has_flag() {
  # Check whether the named flag appears in the flags: line
  local flag="$1"; shift
  _comments "$@" | grep -qP "flags:.*\b${flag}\b"
}

# ── test primitives ───────────────────────────────────────────────────────────

# expect_rcode <desc> <want> <dig-args...>
expect_rcode() {
  local desc="$1" want="$2"; shift 2
  local got; got=$(_rcode "$@")
  if [[ "$got" == "$want" ]]; then
    pass "$desc  [$got]"
  else
    fail "$desc  [expected $want, got ${got:-<no response>}]"
    note "$(_comments "$@" | grep -E 'status:|flags:' | head -2)"
  fi
}

# expect_answer <desc> <grep-pattern> <dig-args...>
expect_answer() {
  local desc="$1" pat="$2"; shift 2
  local out; out=$(_answer "$@")
  if echo "$out" | grep -qP "$pat"; then
    pass "$desc"
  else
    fail "$desc  [pattern '$pat' not in answer]"
    note "${out:-<empty>}"
  fi
}

# expect_no_answer <desc> <dig-args...>
expect_no_answer() {
  local desc="$1"; shift
  local out; out=$(_answer "$@")
  local data; data=$(echo "$out" | grep -vP '^\s*$' || true)
  if [[ -z "$data" ]]; then
    pass "$desc  [answer empty]"
  else
    fail "$desc  [expected empty answer]"
    note "$data"
  fi
}

# expect_authority_soa <desc> <dig-args...>
expect_authority_soa() {
  local desc="$1"; shift
  local out; out=$(_authority "$@")
  if echo "$out" | grep -qP '\bSOA\b'; then
    pass "$desc  [SOA in authority]"
  else
    fail "$desc  [SOA not in authority]"
    note "${out:-<empty authority>}"
  fi
}

# expect_flag <desc> <flag> <dig-args...>
expect_flag() {
  local desc="$1" flag="$2"; shift 2
  if _has_flag "$flag" "$@"; then
    pass "$desc  [$flag set]"
  else
    fail "$desc  [$flag NOT set]"
    note "$(_comments "$@" | grep 'flags:' | head -1)"
  fi
}

# expect_no_flag <desc> <flag> <dig-args...>
expect_no_flag() {
  local desc="$1" flag="$2"; shift 2
  if _has_flag "$flag" "$@"; then
    fail "$desc  [$flag is set — must not be]"
    note "$(_comments "$@" | grep 'flags:' | head -1)"
  else
    pass "$desc  [$flag not set]"
  fi
}

# ── setup prompt ──────────────────────────────────────────────────────────────
echo -e "\n${BOLD}YourDDNS DNS Compliance Test Suite${NC}"
echo -e "  Zone:       ${BOLD}$DOMAIN${NC}"
echo -e "  Nameserver: ${BOLD}$SERVER${NC}"

cat <<SETUP

${YELLOW}${BOLD}╔══ SETUP REQUIRED ════════════════════════════════════════════════════════╗${NC}
${YELLOW}${BOLD}║${NC}  Create the records below before continuing.                            ${YELLOW}${BOLD}║${NC}
${YELLOW}${BOLD}╚══════════════════════════════════════════════════════════════════════════╝${NC}

${BOLD}Static DNS Records${NC}  (Admin → Domains → $DOMAIN → Static Records tab)

  Name          Type    Value                    Notes
  ────────────  ──────  ───────────────────────  ──────────────────────────
  statichost4   A       $A_STATIC
  statichost6   AAAA    $AAAA_STATIC
  alias         CNAME   statichost4.$DOMAIN
  @             A       $A_APEX                  apex / zone root
  @             MX      mail.$DOMAIN             priority 10
  @             TXT     v=spf1 -all
  mail          A       $A_MAIL                  MX target (additional-section test)
  *             A       $A_WILD                  single-level wildcard
  *.sub         A       $A_WILD_SUB              second-level wildcard

${BOLD}DDNS Record${NC}  (Dashboard → My Records)

  1. Create a DDNS record with subdomain:  ddnshost
  2. Set its IPv4 address to $A_DDNS via the update API:
     curl "https://<your-site>/api/update?key=<PAT>&subdomain=ddnshost.$DOMAIN&ip=$A_DDNS"

SETUP

read -rp "Press ENTER once all records are in place and ddnshost has been updated..."
echo ""

# =============================================================================
# TESTS
# =============================================================================

section "1  Static A and AAAA lookups"

expect_answer \
  "statichost4.$DOMAIN  A → $A_STATIC" \
  "$A_STATIC" A "statichost4.$DOMAIN"

expect_answer \
  "statichost6.$DOMAIN  AAAA → $AAAA_STATIC" \
  "$AAAA_STATIC" AAAA "statichost6.$DOMAIN"

# ─────────────────────────────────────────────────────────────────────────────
section "2  CNAME records"

# Direct CNAME query
expect_answer \
  "alias.$DOMAIN  CNAME query → CNAME record present" \
  '\bCNAME\b' CNAME "alias.$DOMAIN"

expect_answer \
  "alias.$DOMAIN  CNAME target is statichost4.$DOMAIN" \
  "statichost4\.$DOMAIN" CNAME "alias.$DOMAIN"

# A query on a name that has only a CNAME must return the CNAME (RFC 1034 §3.6.2)
expect_answer \
  "alias.$DOMAIN  A query → CNAME returned (RFC 1034 §3.6.2)" \
  '\bCNAME\b' A "alias.$DOMAIN"

# ─────────────────────────────────────────────────────────────────────────────
section "3  DDNS record"

expect_answer \
  "ddnshost.$DOMAIN  A → $A_DDNS" \
  "$A_DDNS" A "ddnshost.$DOMAIN"

# ─────────────────────────────────────────────────────────────────────────────
section "4  Apex records"

expect_answer "Apex  A → $A_APEX"          "$A_APEX"          A   "$DOMAIN"
expect_answer "Apex  MX record present"    '\bMX\b'           MX  "$DOMAIN"
expect_answer "Apex  MX exchange correct"  "mail\.$DOMAIN"    MX  "$DOMAIN"
expect_answer "Apex  TXT record present"   "v=spf1"           TXT "$DOMAIN"
expect_answer "Apex  SOA present"          '\bSOA\b'          SOA "$DOMAIN"
expect_answer "Apex  NS present"           '\bNS\b'           NS  "$DOMAIN"

# ─────────────────────────────────────────────────────────────────────────────
section "5  ANY query"

expect_answer "ANY apex  contains SOA"   '\bSOA\b'  ANY "$DOMAIN"
expect_answer "ANY apex  contains NS"    '\bNS\b'   ANY "$DOMAIN"
expect_answer "ANY apex  contains A"     "$A_APEX"  ANY "$DOMAIN"
expect_answer "ANY apex  contains MX"    '\bMX\b'   ANY "$DOMAIN"
expect_answer "ANY apex  contains TXT"   "v=spf1"   ANY "$DOMAIN"

# ANY at a subdomain must NOT include zone-level SOA or NS in the answer section
ANYSUB=$(_answer ANY "statichost4.$DOMAIN")
if echo "$ANYSUB" | grep -qP '\bSOA\b'; then
  fail "ANY subdomain  SOA must NOT be in answer section (RFC 1034 §3.6)"
else
  pass "ANY subdomain  SOA absent from answer section"
fi
if echo "$ANYSUB" | grep -qP '\bIN\b\s+\bNS\b'; then
  fail "ANY subdomain  NS must NOT be in answer section (RFC 1034 §3.6)"
else
  pass "ANY subdomain  NS absent from answer section"
fi
expect_answer \
  "ANY subdomain  A record for statichost4 is present" \
  "$A_STATIC" ANY "statichost4.$DOMAIN"

# ─────────────────────────────────────────────────────────────────────────────
section "6  SOA and NS must not appear in answers for subdomain queries"

# SOA query on an existing subdomain → NODATA: NOERROR, empty answer, SOA in authority
expect_rcode \
  "SOA query on subdomain → NOERROR (not the zone SOA in answers)" \
  NOERROR SOA "statichost4.$DOMAIN"

expect_no_answer \
  "SOA query on subdomain → answer section empty" \
  SOA "statichost4.$DOMAIN"

expect_authority_soa \
  "SOA query on subdomain → SOA in authority (NODATA)" \
  SOA "statichost4.$DOMAIN"

# NS query on an existing subdomain → NODATA
expect_rcode \
  "NS query on subdomain → NOERROR (not zone NS in answers)" \
  NOERROR NS "statichost4.$DOMAIN"

expect_no_answer \
  "NS query on subdomain → answer section empty" \
  NS "statichost4.$DOMAIN"

expect_authority_soa \
  "NS query on subdomain → SOA in authority (NODATA)" \
  NS "statichost4.$DOMAIN"

# ─────────────────────────────────────────────────────────────────────────────
section "7  NXDOMAIN — nonexistent names"

# Use a two-label subdomain (nxtest.nosuchparent) so no wildcard can match it.
# The * wildcard only matches single-label names; *.sub only matches x.sub.
# nxtest.nosuchparent has no wildcard (nosuchparent != sub) and no explicit record.
NONAME="nxtest.nosuchparent.$DOMAIN"

expect_rcode         "NXDOMAIN  A query"                NXDOMAIN A     "$NONAME"
expect_authority_soa "NXDOMAIN  SOA in authority (A)"            A     "$NONAME"
expect_rcode         "NXDOMAIN  AAAA query"             NXDOMAIN AAAA  "$NONAME"
expect_authority_soa "NXDOMAIN  SOA in authority (AAAA)"         AAAA  "$NONAME"
expect_rcode         "NXDOMAIN  MX query"               NXDOMAIN MX    "$NONAME"
expect_authority_soa "NXDOMAIN  SOA in authority (MX)"           MX    "$NONAME"
expect_rcode         "NXDOMAIN  TXT query"              NXDOMAIN TXT   "$NONAME"
expect_authority_soa "NXDOMAIN  SOA in authority (TXT)"          TXT   "$NONAME"
expect_rcode         "NXDOMAIN  CNAME query"            NXDOMAIN CNAME "$NONAME"

# ─────────────────────────────────────────────────────────────────────────────
section "8  NODATA — name exists, wrong record type"

# statichost4 has A but no AAAA
expect_rcode         "NODATA  AAAA on A-only host → NOERROR"        NOERROR AAAA "statichost4.$DOMAIN"
expect_no_answer     "NODATA  empty answer for AAAA on A-only host"         AAAA "statichost4.$DOMAIN"
expect_authority_soa "NODATA  SOA in authority (AAAA on A-only host)"       AAAA "statichost4.$DOMAIN"

# statichost6 has AAAA but no A
expect_rcode         "NODATA  A on AAAA-only host → NOERROR"        NOERROR A    "statichost6.$DOMAIN"
expect_no_answer     "NODATA  empty answer for A on AAAA-only host"         A    "statichost6.$DOMAIN"
expect_authority_soa "NODATA  SOA in authority (A on AAAA-only host)"       A    "statichost6.$DOMAIN"

# Apex has A + MX + TXT but no AAAA
expect_rcode         "NODATA  AAAA at apex → NOERROR"               NOERROR AAAA "$DOMAIN"
expect_no_answer     "NODATA  empty answer for AAAA at apex"                AAAA "$DOMAIN"
expect_authority_soa "NODATA  SOA in authority (AAAA at apex)"              AAAA "$DOMAIN"

# Name has A but no MX
expect_rcode         "NODATA  MX on A-only host → NOERROR"          NOERROR MX   "statichost4.$DOMAIN"
expect_authority_soa "NODATA  SOA in authority (MX on A-only host)"         MX   "statichost4.$DOMAIN"

# ─────────────────────────────────────────────────────────────────────────────
section "9  Wildcard records (RFC 4592 §2.1)"

# * matches any single-label name with no explicit record
expect_answer \
  "Wildcard *  randomlabel.$DOMAIN → $A_WILD" \
  "$A_WILD" A "randomlabel.$DOMAIN"

expect_answer \
  "Wildcard *  another123.$DOMAIN → $A_WILD" \
  "$A_WILD" A "another123.$DOMAIN"

# * must NOT match multi-label subdomain (RFC 4592 §2.1 — * matches exactly one label).
# Use a suffix that has no *.suffix wildcard record (nosuchparent != sub).
expect_rcode \
  "Wildcard *  does NOT match x.nosuchparent.$DOMAIN (two labels → NXDOMAIN)" \
  NXDOMAIN A "xctest.nosuchparent.$DOMAIN"

# Explicit record takes precedence over wildcard
expect_answer \
  "Explicit record beats wildcard  statichost4.$DOMAIN → $A_STATIC (not $A_WILD)" \
  "$A_STATIC" A "statichost4.$DOMAIN"

OUT_BEATS=$(_answer A "statichost4.$DOMAIN")
if echo "$OUT_BEATS" | grep -q "$A_WILD"; then
  fail "Wildcard value $A_WILD must NOT appear when explicit record exists"
else
  pass "Wildcard value $A_WILD absent when explicit record exists"
fi

# *.sub matches exactly one label before 'sub'
expect_answer \
  "Wildcard *.sub  xtest.sub.$DOMAIN → $A_WILD_SUB" \
  "$A_WILD_SUB" A "xtest.sub.$DOMAIN"

expect_answer \
  "Wildcard *.sub  other99.sub.$DOMAIN → $A_WILD_SUB" \
  "$A_WILD_SUB" A "other99.sub.$DOMAIN"

# *.sub must NOT match two labels before 'sub'
expect_rcode \
  "Wildcard *.sub  does NOT match x.y.sub.$DOMAIN (two labels → NXDOMAIN)" \
  NXDOMAIN A "xtest.ytest.sub.$DOMAIN"

# * must NOT match x.sub.$DOMAIN (x.sub is two labels; *.sub handles it, not *)
# Verify that the correct wildcard value ($A_WILD_SUB) is returned, not $A_WILD
expect_answer \
  "Correct wildcard used  x.sub.$DOMAIN → $A_WILD_SUB (not $A_WILD)" \
  "$A_WILD_SUB" A "xtest.sub.$DOMAIN"

# ─────────────────────────────────────────────────────────────────────────────
section "10  RFC compliance — response header flags"

expect_flag    "AA (Authoritative Answer) set for in-zone answer"  aa "A" "statichost4.$DOMAIN"
expect_flag    "AA set for NXDOMAIN response"                      aa "A" "nxtest.nosuchparent.$DOMAIN"
expect_flag    "AA set for NODATA response"                        aa "AAAA" "statichost4.$DOMAIN"
expect_no_flag "RA (Recursion Available) NOT set — auth-only"      ra "A" "statichost4.$DOMAIN"
expect_no_flag "RA NOT set on NXDOMAIN"                            ra "A" "nxtest.nosuchparent.$DOMAIN"

# ─────────────────────────────────────────────────────────────────────────────
section "11  Protocol error responses"

# Out-of-zone query → REFUSED
expect_rcode \
  "REFUSED for out-of-zone query (google.com)" \
  REFUSED A "google.com"

# Non-IN class (CHAOS) → NOTIMP
# The class check fires before zone matching, so this works for any qname
expect_rcode \
  "NOTIMP for non-IN class (CHAOS TXT version.bind)" \
  NOTIMP TXT "version.bind" -c CH

# ─────────────────────────────────────────────────────────────────────────────
section "12  Additional section"

# MX query: A record for the exchange host should appear in additional
MXFULL=$(_full MX "$DOMAIN")
if echo "$MXFULL" | grep -qP "$A_MAIL"; then
  pass "MX query  A for mail exchange ($A_MAIL) in additional section"
else
  fail "MX query  $A_MAIL not found in additional section"
  note "$MXFULL"
fi

# NS glue: only testable when NS names fall within the served zone
NS_HOST=$(dig +short @"$SERVER" NS "$DOMAIN" 2>/dev/null | head -1 | sed 's/\.$//' || true)
if [[ -n "$NS_HOST" && "$NS_HOST" == *"$DOMAIN"* ]]; then
  NSFULL=$(_full NS "$DOMAIN")
  if echo "$NSFULL" | grep -qP '\bA\b|\bAAAA\b'; then
    pass "NS query  glue A/AAAA present in additional for in-zone NS ($NS_HOST)"
  else
    fail "NS query  expected glue for in-zone NS ($NS_HOST) — not found in additional"
    note "$NSFULL"
  fi
else
  skip "NS glue — NS ($NS_HOST) is outside zone $DOMAIN, glue not applicable"
fi

# ─────────────────────────────────────────────────────────────────────────────
section "13  SOA serial increments after static record changes"

# Capture the current serial via a SOA query at the apex
SERIAL_BEFORE=$(_answer SOA "$DOMAIN" | grep -oP '\d+(?=\s+\d+\s+\d+\s+\d+\s+\d+\s*$)' | head -1)

if [[ -z "$SERIAL_BEFORE" ]]; then
  skip "SOA serial test — could not read initial SOA serial (SOA query returned nothing)"
else
  note "Serial before: $SERIAL_BEFORE"
  note "Add a temporary TXT record via the admin UI (Admin → Domains → $DOMAIN → Static Records),"
  note "then delete it, and press ENTER to re-query the serial."
  read -rp "  Press ENTER after adding and deleting the temporary record..."

  SERIAL_AFTER=$(_answer SOA "$DOMAIN" | grep -oP '\d+(?=\s+\d+\s+\d+\s+\d+\s+\d+\s*$)' | head -1)
  note "Serial after:  $SERIAL_AFTER"

  if [[ -z "$SERIAL_AFTER" ]]; then
    fail "SOA serial test  [could not read serial after change]"
  elif [[ "$SERIAL_AFTER" -gt "$SERIAL_BEFORE" ]]; then
    pass "SOA serial incremented  [$SERIAL_BEFORE → $SERIAL_AFTER]"
  else
    fail "SOA serial NOT incremented  [before=$SERIAL_BEFORE after=$SERIAL_AFTER]"
  fi
fi

# =============================================================================
# SUMMARY
# =============================================================================
TOTAL=$((PASS + FAIL))
echo -e "\n${BOLD}━━━ Results ━━━${NC}"
echo -e "  ${GREEN}Passed:${NC} $PASS / $TOTAL"
if [[ $FAIL -gt 0 ]]; then
  echo -e "  ${RED}Failed:${NC} $FAIL / $TOTAL"
  echo -e "\n${RED}${BOLD}$FAIL test(s) failed.${NC}"
  exit 1
else
  echo -e "\n${GREEN}${BOLD}All $TOTAL tests passed.${NC}"
  exit 0
fi
