import argparse, asyncio, json, subprocess, pyfiglet
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, urljoin
import tldextract
from playwright.async_api import async_playwright
from bs4 import BeautifulSoup
from rich.console import Console
from rich.table import Table
from rich.text import Text

def print_banner():
    console = Console()
    ascii_art = pyfiglet.figlet_format("SHASTRA", font="slant")
    console.print(f"[bold cyan]{ascii_art}[/bold cyan]")
    console.print("[italic green]Playwright-powered SQLi & Static Analyzer[/italic green]")
    console.print("[bold yellow]by mrgreyhat07[/bold yellow]\n")



SQL_PAYLOADS = ["'", "''", "--", "-- OR 1=1", "--1=1"]
ERROR_SIGNS = ["sql syntax", "mysql", "ora-", "syntax error", "unclosed quotation"]

console = Console()

def domain_key(url):
    e = tldextract.extract(url)
    return f"{e.subdomain}.{e.domain}.{e.suffix}"

def detect_diff(base, test):
    diffs = []
    if abs(test["length"] - base["length"]) > 50:
        diffs.append("length change")
    if any(sig in test["body"].lower() for sig in ERROR_SIGNS):
        diffs.append("error signature")
    if test["headers"] != base["headers"]:
        diffs.append("header change")
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
    try:
        if method == "POST":
            resp = await ctx.post(url, data=payload)
        else:
            resp = await ctx.get(url, params=payload)
        text = await resp.text()
        if debug:
            body_data = urlencode(payload or {})
            req = format_request(method, url, headers or {}, body_data)
            res = format_response(resp.status, resp.headers, text)
            print_http_block("request", req)
            print_http_block("response", res)
        return {"status": resp.status, "headers": resp.headers, "body": text, "length": len(text)}
    except Exception as e:
        if debug:
            console.print(f"[red][ERROR] {method} {url}: {e}[/red]")
        return None

async def test_forms(page, url, base, out, headers, debug=False):
    # Reuse the existing request context; no new_context() call
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
                diffs = detect_diff(base, test)
                if diffs or debug:
                    out.append((action, f"form ({method})", payload, diffs))

async def analyze_url(pw, url, seen, headers_list, delay, debug):
    results = []
    # launch a fresh browser context for each URL
    browser = await pw.chromium.launch(headless=True)
    ctx = await browser.new_context()
    page = await ctx.new_page()

    # baseline GET
    base = await fetch_raw(ctx.request, "GET", url, headers={}, debug=debug)
    if base:
        await page.goto(url)
        await test_forms(page, url, base, results, {}, debug)
    await page.close()
    await ctx.close()
    await browser.close()

    # header fuzzing per domain
    dom = domain_key(url)
    if base and dom not in seen:
        seen.add(dom)
        for hdr in headers_list:
            for payload in SQL_PAYLOADS:
                browser = await pw.chromium.launch(headless=True)
                ctx = await browser.new_context(extra_http_headers={hdr: payload})
                test = await fetch_raw(ctx.request, "GET", url, headers={hdr: payload}, debug=debug)
                if test:
                    diffs = detect_diff(base, test)
                    if diffs or debug:
                        results.append((url, f"header {hdr}", payload, diffs))
                        page = await ctx.new_page()
                        await page.goto(url)
                        await test_forms(page, url, base, results, {hdr: payload}, debug)
                        await page.close()
                await ctx.close()
                await browser.close()

    # parameter fuzzing
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)
    if base:
        if qs:
            for param in qs:
                for payload in SQL_PAYLOADS:
                    newqs = qs.copy()
                    newqs[param] = [payload]
                    test_url = urlunparse(parsed._replace(query=urlencode(newqs, doseq=True)))
                    browser = await pw.chromium.launch(headless=True)
                    ctx = await browser.new_context()
                    test = await fetch_raw(ctx.request, "GET", test_url, headers={}, debug=debug)
                    if test:
                        diffs = detect_diff(base, test)
                        if diffs or debug:
                            results.append((test_url, f"param {param}", payload, diffs))
                    await ctx.close()
                    await browser.close()
        else:
            # path fuzzing
            for payload in SQL_PAYLOADS:
                test_url = urlunparse(parsed._replace(path=parsed.path + payload))
                browser = await pw.chromium.launch(headless=True)
                ctx = await browser.new_context()
                test = await fetch_raw(ctx.request, "GET", test_url, headers={}, debug=debug)
                if test:
                    diffs = detect_diff(base, test)
                    if diffs or debug:
                        results.append((test_url, "path injection", payload, diffs))
                await ctx.close()
                await browser.close()

    await asyncio.sleep(delay)
    return url, results

async def run_dynamic(urls, threads, delay, headers_list, debug):
    semaphore = asyncio.Semaphore(threads)
    seen = set()

    async with async_playwright() as pw:
        async def worker(url):
            async with semaphore:
                u, res = await analyze_url(pw, url, seen, headers_list, delay, debug)
                display_results(u, res)
                return u, res

        tasks = [asyncio.create_task(worker(u)) for u in urls]
        try:
            return await asyncio.gather(*tasks)
        except KeyboardInterrupt:
            for t in tasks: t.cancel()
            console.print("[bold red]Cancelled by user.[/bold red]")
            await asyncio.gather(*tasks, return_exceptions=True)
            return []

def display_results(url, results):
    if not results:
        return
    console.rule(f"[bold green]Results for {url}")
    tbl = Table("Location", "Payload Type", "Payload", "Indicators")
    for loc, typ, payload, diffs in results:
        tbl.add_row(loc, typ, payload, "; ".join(diffs) or "?")
    console.print(tbl)

def run_bandit():
    proc = subprocess.run(
        ["bandit", "-r", ".", "-c", "bandit.yaml", "-f", "json"],
        capture_output=True, text=True
    )
    if proc.returncode == 0 and proc.stdout:
        return json.loads(proc.stdout).get("results", [])
    return []

def cli():
    p = argparse.ArgumentParser()
    grp = p.add_mutually_exclusive_group(required=True)
    grp.add_argument("-u", "--url")
    grp.add_argument("-l", "--list", help="file containing URLs")
    p.add_argument("-H", "--header", action="append", help="additional header to fuzz")
    p.add_argument("--threads", type=int, default=2, help="concurrent threads (default: 2)")
    p.add_argument("--delay", type=float, default=1.0, help="delay between requests (default: 1.0s)")
    p.add_argument("--debug", action="store_true", help="show raw HTTP request/response")
    p.add_argument("-o", "--output", help="output file")
    return p.parse_args()

def main():
    args = cli()
    print_banner()

    headers = args.header or ["User-Agent"]
    urls = [args.url] if args.url else [line.strip() for line in open(args.list)]
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        results = loop.run_until_complete(
            run_dynamic(urls, args.threads, args.delay, headers, args.debug)
        )
    except KeyboardInterrupt:
        console.print("[bold red]Interrupted. Exiting cleanly.[/bold red]")
        return

    band = run_bandit()
    if band:
        console.rule("[bold yellow]Static Analysis Results")
        tbl = Table("File", "Line", "Issue", "Code")
        for issue in band:
            if issue.get("test_id") == "B608":
                loc = f"{issue['filename']}:{issue['line_number']}"
                tbl.add_row(loc, str(issue["line_number"]), issue["issue_text"], issue.get("code", "").strip())
        console.print(tbl)

    if args.output:
        with open(args.output, "w") as f:
            json.dump({"dynamic": [{u: r} for u, r in results], "static": band}, f, indent=2)

if __name__ == "__main__":
    main()
