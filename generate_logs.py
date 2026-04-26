import random
import datetime
import ipaddress
 
# Seed for reproducibility
random.seed(42)
 
# --- Configuration ---
TOTAL_LINES = 5000
OUTPUT_FILE = "/mnt/user-data/outputs/access.log"
 
# --- Data Pools ---
NORMAL_IPS = [f"192.168.{random.randint(1,254)}.{random.randint(1,254)}" for _ in range(80)]
CDN_IPS    = [f"151.101.{random.randint(0,255)}.{random.randint(0,255)}" for _ in range(20)]
 
# Brute-force attacker IPs (few IPs, high volume)
BRUTE_IPS  = ["45.33.32.156", "198.20.69.74", "104.236.179.97", "23.94.3.173", "185.220.101.45"]
 
# SQL injection attacker IPs
SQLI_IPS   = ["91.108.4.200", "176.9.28.202", "5.188.210.100", "77.247.181.163"]
 
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4_1 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Android 14; Mobile; rv:125.0) Gecko/125.0 Firefox/125.0",
    "python-requests/2.31.0",
    "curl/8.4.0",
]
 
MALICIOUS_UA = [
    "sqlmap/1.7.11#stable (https://sqlmap.org)",
    "Hydra v9.5 (www.thc.org/thc-hydra)",
    "Medusa v2.3",
    "python-requests/2.28.0",
    "-",
]
 
NORMAL_PATHS = [
    "/", "/index.html", "/about", "/contact", "/products", "/services",
    "/blog", "/blog/post-1", "/blog/post-2", "/faq", "/pricing",
    "/static/main.css", "/static/app.js", "/favicon.ico", "/robots.txt",
    "/images/logo.png", "/api/v1/products", "/api/v1/categories",
    "/search?q=laptop", "/search?q=phone", "/cart", "/checkout",
    "/profile", "/settings", "/notifications",
]
 
LOGIN_PATH = "/login"
ADMIN_PATHS = ["/admin", "/admin/login", "/wp-admin", "/wp-login.php",
               "/administrator", "/admin/dashboard", "/user/login"]
 
# SQL injection payloads
SQLI_PAYLOADS = [
    "/search?q=' OR '1'='1",
    "/login?user=admin'--",
    "/api/v1/users?id=1 UNION SELECT username,password FROM users--",
    "/products?id=1; DROP TABLE users--",
    "/search?q=1' AND SLEEP(5)--",
    "/api/data?filter='; INSERT INTO logs VALUES('pwned')--",
    "/user?id=1 OR 1=1",
    "/search?q=admin' OR 'x'='x",
    "/api/v1/items?sort=name); DELETE FROM items--",
    "/profile?id=1' UNION SELECT NULL,NULL,NULL--",
    "/login?username=' OR 1=1--&password=anything",
    "/api/search?term=test' AND (SELECT * FROM (SELECT(SLEEP(5)))bAKL)--",
    "/items?cat=1 AND extractvalue(1,concat(0x7e,(SELECT version())))--",
    "/page?id=1; EXEC xp_cmdshell('whoami')--",
    "/api/v1/data?id=1' AND (SELECT 2*(IF((SELECT * FROM (SELECT CONCAT(0x71,0x70,0x71,0x70,0x71,(SELECT (ELT(1=1,1))),0x71,0x71,0x70,0x70,0x71) FROM DUAL),8446744073709551610,8446744073709551610)))-- -",
]
 
METHODS = ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS"]
HTTP_VERSIONS = ["HTTP/1.1", "HTTP/2.0"]
 
STATUS_WEIGHTS = {
    200: 55, 304: 10, 301: 5, 302: 3,
    400: 3, 401: 5, 403: 4, 404: 8,
    500: 3, 503: 2, 429: 2,
}
STATUS_CODES = list(STATUS_WEIGHTS.keys())
STATUS_PROBS  = [v / sum(STATUS_WEIGHTS.values()) for v in STATUS_WEIGHTS.values()]
 
def random_status(weights=None):
    if weights:
        codes = list(weights.keys())
        probs = [v/sum(weights.values()) for v in weights.values()]
        return random.choices(codes, probs)[0]
    return random.choices(STATUS_CODES, STATUS_PROBS)[0]
 
def random_bytes(status):
    if status in (301, 302, 304):
        return random.randint(0, 512)
    if status == 200:
        return random.randint(512, 65536)
    return random.randint(100, 4096)
 
def format_log(ip, ts, method, path, proto, status, size, referer, ua):
    ts_str = ts.strftime("%d/%b/%Y:%H:%M:%S +0000")
    return f'{ip} - - [{ts_str}] "{method} {path} {proto}" {status} {size} "{referer}" "{ua}"'
 
def random_ts(base, offset_seconds_range=(0, 60)):
    delta = datetime.timedelta(seconds=random.randint(*offset_seconds_range))
    return base + delta
 
# --- Base timestamp ---
base_time = datetime.datetime(2024, 6, 1, 0, 0, 0)
 
lines = []
line_index = 0
 
# ── 1. Normal Traffic: 3500 lines ─────────────────────────────────────────────
normal_count = 3500
for i in range(normal_count):
    ip = random.choice(NORMAL_IPS + CDN_IPS)
    ts = base_time + datetime.timedelta(seconds=i * 8 + random.randint(-3, 3))
    method = random.choices(METHODS, [60, 20, 5, 3, 7, 5])[0]
    path   = random.choice(NORMAL_PATHS)
    proto  = random.choice(HTTP_VERSIONS)
    status = random_status()
    size   = random_bytes(status)
    ref    = random.choice(["-", "https://google.com", "https://bing.com", "https://example.com"])
    ua     = random.choice(USER_AGENTS)
    lines.append((ts, format_log(ip, ts, method, path, proto, status, size, ref, ua)))
 
# ── 2. Brute Force Attacks: ~800 lines ────────────────────────────────────────
# Each attacker hammers /login or admin paths rapidly
brute_force_count = 800
attack_start = base_time + datetime.timedelta(hours=2)
 
for i in range(brute_force_count):
    ip     = random.choice(BRUTE_IPS)
    # Very tight timestamps — many requests per second
    ts     = attack_start + datetime.timedelta(seconds=i * 0.3 + random.uniform(0, 0.1))
    method = "POST"
    path   = random.choice([LOGIN_PATH] + ADMIN_PATHS)
    proto  = "HTTP/1.1"
    # Mostly 401/403, occasional 200 (successful crack simulation)
    status = random_status({401: 60, 403: 25, 200: 3, 429: 10, 500: 2})
    size   = random_bytes(status)
    ref    = "-"
    ua     = random.choice(MALICIOUS_UA)
    lines.append((ts, format_log(ip, ts, method, path, proto, status, size, ref, ua)))
 
# ── 3. SQL Injection Attacks: ~400 lines ──────────────────────────────────────
sqli_count = 400
sqli_start = base_time + datetime.timedelta(hours=5)
 
for i in range(sqli_count):
    ip     = random.choice(SQLI_IPS)
    ts     = sqli_start + datetime.timedelta(seconds=i * 1.2 + random.uniform(0, 0.5))
    method = random.choice(["GET", "POST"])
    path   = random.choice(SQLI_PAYLOADS)
    proto  = "HTTP/1.1"
    status = random_status({200: 10, 400: 30, 403: 20, 500: 35, 503: 5})
    size   = random_bytes(status)
    ref    = "-"
    ua     = random.choice(MALICIOUS_UA)
    lines.append((ts, format_log(ip, ts, method, path, proto, status, size, ref, ua)))
 
# ── 4. Mixed anomalous traffic (scan, enumeration): ~300 lines ────────────────
scan_count = 300
scan_start = base_time + datetime.timedelta(hours=8)
scan_paths = [f"/{p}" for p in [
    "wp-config.php", ".env", ".git/config", "config.php", "backup.zip",
    "admin.php", "phpinfo.php", "shell.php", "upload.php", "test.php",
    "server-status", ".htaccess", "web.config", "database.yml",
    "etc/passwd", "proc/self/environ", "api/v1/admin/users",
]]
 
scan_ip = "185.220.102.8"
for i in range(scan_count):
    ts     = scan_start + datetime.timedelta(seconds=i * 0.8)
    method = "GET"
    path   = random.choice(scan_paths)
    proto  = "HTTP/1.1"
    status = random_status({404: 70, 403: 20, 200: 5, 500: 5})
    size   = random_bytes(status)
    ref    = "-"
    ua     = random.choice(MALICIOUS_UA)
    lines.append((ts, format_log(scan_ip, ts, method, path, proto, status, size, ref, ua)))
 
# ── Sort all lines by timestamp ────────────────────────────────────────────────
lines.sort(key=lambda x: x[0])
 
# Trim or pad to exactly 5000
log_lines = [l for _, l in lines]
if len(log_lines) > 5000:
    log_lines = log_lines[:5000]
 
print(f"Total log lines generated: {len(log_lines)}")
 
with open(OUTPUT_FILE, "w") as f:
    f.write("\n".join(log_lines) + "\n")
 
print(f"Written to {OUTPUT_FILE}")
 
# Print a summary
brute_lines = [l for l in log_lines if any(ip in l for ip in BRUTE_IPS)]
sqli_lines  = [l for l in log_lines if any(ip in l for ip in SQLI_IPS)]
scan_lines  = [l for l in log_lines if scan_ip in l]
normal_lines = len(log_lines) - len(brute_lines) - len(sqli_lines) - len(scan_lines)
 
print("\n=== Log Composition ===")
print(f"  Normal traffic:         {normal_lines}")
print(f"  Brute force (POST /login): {len(brute_lines)}")
print(f"  SQL injection:          {len(sqli_lines)}")
print(f"  Recon/path scan:        {len(scan_lines)}")
print(f"  TOTAL:                  {len(log_lines)}")