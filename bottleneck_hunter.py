#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Bottleneck Hunter
=================
Proxy (forward / web proxy) performans ve gecikme analiz araci.

Tek dosyalik tasarim. Ag fazlarini ayri ayri olcer (DNS / TCP / TLS / sunucu
isleme / transfer) ve ayrica gercek tarayici ile render dahil sayfa acilis
sureleri (TTFB / FCP / LCP / DOMContentLoaded / load) toplar.

Testler:
  1. latency   - Tek hedef icin tam faz kirilimi + direct vs proxy farki
  2. ssl       - SSL inspection maliyeti (inspekte vs bypass domain)
  3. load      - Artan eszamanliliik altinda p50/p95/p99 ve kirilma noktasi
  4. throughput- Buyuk dosya indirme, efektif Mbps
  5. cache     - Cache miss vs hit kiyasi
  6. soak      - Uzun sureli sabit yuk altinda degradasyon izleme
  7. browser   - GERCEK tarayici (Playwright) ile render dahil sayfa acilisi
  8. full      - Hepsini sirayla calistir

Renk: Onemli/farkli degerler renklendirilir (yesil=iyi, sari=orta, kirmizi=kotu,
      cyan=baslik/etiket). Kapatmak icin --no-color.

Gereksinim:
  pip install pycurl
  pip install playwright   ;  playwright install chromium   (yalniz 'browser' icin)
"""

import argparse
import csv
import json
import os
import statistics
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from datetime import datetime
from io import BytesIO
from typing import Optional

from config_loader import expand_config_args, load_config, test_parameters
from reporting import render_comparison_html, report_envelope
from safety import MAX_CONCURRENCY, MAX_REQUESTS_PER_LEVEL, validate_active_test

try:
    import pycurl
except ImportError:
    pycurl = None

APP_NAME = "Bottleneck Hunter"
APP_VERSION = "1.2.0"


# --------------------------------------------------------------------------- #
# Renk katmani
# --------------------------------------------------------------------------- #
class Ansi:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    GREY = "\033[90m"


COLOR_ENABLED = True


def _enable_windows_ansi():
    """Windows konsolunda ANSI/VT islemeyi acmaya calis (cmd/PowerShell)."""
    if os.name != "nt":
        return
    try:
        import colorama  # varsa en saglamı
        colorama.just_fix_windows_console()
        return
    except Exception:
        pass
    try:
        import ctypes
        k = ctypes.windll.kernel32
        # ENABLE_PROCESSED_OUTPUT | ENABLE_WRAP_AT_EOL | ENABLE_VIRTUAL_TERMINAL_PROCESSING
        k.SetConsoleMode(k.GetStdHandle(-11), 7)
    except Exception:
        pass


def setup_color(force_off=False):
    global COLOR_ENABLED
    if force_off or not sys.stdout.isatty() or os.environ.get("NO_COLOR"):
        COLOR_ENABLED = False
        return
    COLOR_ENABLED = True
    _enable_windows_ansi()


def c(text, color, bold=False):
    """Metni renklendir (renk kapaliysa oldugu gibi dondur)."""
    if not COLOR_ENABLED:
        return str(text)
    pre = (Ansi.BOLD if bold else "") + color
    return f"{pre}{text}{Ansi.RESET}"


# Faz/metric esik degerleri (ms): (iyi_ust, orta_ust). Ustu = kirmizi.
THRESHOLDS = {
    "dns": (20, 80),
    "tcp": (30, 100),
    "tls": (80, 250),
    "server": (200, 600),
    "transfer": (100, 400),
    "total": (300, 1000),
    # tarayici metrikleri
    "ttfb": (200, 600),
    "fcp": (1000, 2500),
    "lcp": (2500, 4000),
    "dcl": (1500, 3500),
    "load": (2000, 4500),
}


def grade_color(value, key):
    good, warn = THRESHOLDS.get(key, (0, 0))
    if good == 0 and warn == 0:
        return Ansi.RESET
    if value <= good:
        return Ansi.GREEN
    if value <= warn:
        return Ansi.YELLOW
    return Ansi.RED


def cval(value, key, width=8):
    """ms degerini esige gore renkli ve hizalanmis dondur."""
    s = f"{value:>{width}}"
    return c(s, grade_color(value, key))


def banner():
    art = r"""
  ____        _   _   _                      _      _   _             _
 | __ )  ___ | |_| |_| | ___ _ __   ___  ___| | __ | | | |_   _ _ __ | |_ ___ _ __
 |  _ \ / _ \| __| __| |/ _ \ '_ \ / _ \/ __| |/ / | |_| | | | | '_ \| __/ _ \ '__|
 | |_) | (_) | |_| |_| |  __/ | | |  __/ (__|   <  |  _  | |_| | | | | ||  __/ |
 |____/ \___/ \__|\__|_|\___|_| |_|\___|\___|_|\_\ |_| |_|\__,_|_| |_|\__\___|_|"""
    sub = f"            Proxy Performans & Gecikme Analiz Araci  v{APP_VERSION}"
    return c(art, Ansi.CYAN, bold=True) + "\n" + c(sub, Ansi.CYAN)


# --------------------------------------------------------------------------- #
# Veri yapilari
# --------------------------------------------------------------------------- #
@dataclass
class ProxyConfig:
    proxy: Optional[str] = None
    proxy_user: Optional[str] = None     # kullanici:parola
    insecure: bool = False               # SSL dogrulamayi atla
    ssl_no_revoke: bool = False          # CRL/OCSP revocation kontrolunu kapat (Schannel/izole ag)
    timeout: int = 30
    connect_timeout: int = 10
    user_agent: str = f"{APP_NAME}/{APP_VERSION}"
    extra_headers: list = field(default_factory=list)


@dataclass
class Sample:
    """Tek bir curl istegi (saniye cinsinden zamanlar)."""
    ok: bool
    http_code: int = 0
    err: str = ""
    dns: float = 0.0
    tcp: float = 0.0
    tls: float = 0.0
    server: float = 0.0
    transfer: float = 0.0
    total: float = 0.0
    size_bytes: int = 0
    speed_bps: float = 0.0
    via_proxy: bool = False
    label: str = ""


@dataclass
class BrowserSample:
    """Gercek tarayici ile tek sayfa acilisi (ms cinsinden)."""
    ok: bool
    err: str = ""
    ttfb: float = 0.0          # ilk byte
    fcp: float = 0.0           # First Contentful Paint
    lcp: float = 0.0           # Largest Contentful Paint
    dcl: float = 0.0           # DOMContentLoaded
    load: float = 0.0          # load event (toplam acilis)
    total: float = 0.0         # = load (rapor ortakligi icin)
    req_count: int = 0
    transfer_kb: float = 0.0
    via_proxy: bool = False
    label: str = "browser"


# --------------------------------------------------------------------------- #
# Yardimcilar
# --------------------------------------------------------------------------- #
def percentile(data, p):
    if not data:
        return 0.0
    s = sorted(data)
    if len(s) == 1:
        return s[0]
    k = (len(s) - 1) * (p / 100.0)
    f = int(k)
    cc = min(f + 1, len(s) - 1)
    if f == cc:
        return s[f]
    return s[f] + (s[cc] - s[f]) * (k - f)


def ms(x):
    return round(x * 1000, 2)


def summarize(samples, key, already_ms=False):
    """Bir liste ornek uzerinden bir metrigin istatistigi. already_ms=True ise
    deger zaten ms cinsindendir (tarayici ornekleri)."""
    vals = [getattr(s, key) for s in samples if s.ok]
    if not vals:
        return {"n": 0}
    conv = (lambda v: round(v, 2)) if already_ms else ms
    return {
        "n": len(vals),
        "min_ms": conv(min(vals)),
        "p50_ms": conv(percentile(vals, 50)),
        "p95_ms": conv(percentile(vals, 95)),
        "p99_ms": conv(percentile(vals, 99)),
        "max_ms": conv(max(vals)),
        "mean_ms": conv(statistics.fmean(vals)),
        "stdev_ms": conv(statistics.pstdev(vals)) if len(vals) > 1 else 0.0,
    }


def now_iso():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def ensure_scheme(url, default="https"):
    """Sema yoksa basa ekle. Tarayici (Playwright) ciplak host kabul etmez;
    curl tahmin etse de tutarlilik icin burada normalize ediyoruz."""
    if not url:
        return url
    u = url.strip()
    if "://" not in u:
        u = f"{default}://{u}"
    return u


def hl(text):
    """Ozet satiri vurgusu."""
    return c(text, Ansi.MAGENTA, bold=True)


def good_bad(value, good_is_low=True, good=0, warn=0, suffix=""):
    """Bir ozet sayisini iyi/orta/kotu olarak renklendir."""
    if good_is_low:
        color = Ansi.GREEN if value <= good else (Ansi.YELLOW if value <= warn else Ansi.RED)
    else:
        color = Ansi.GREEN if value >= good else (Ansi.YELLOW if value >= warn else Ansi.RED)
    return c(f"{value}{suffix}", color, bold=True)


# --------------------------------------------------------------------------- #
# Cekirdek: tek curl istegi + faz kirilimi
# --------------------------------------------------------------------------- #
def do_request(url, cfg: ProxyConfig, via_proxy: bool, label: str = "",
               count_body: bool = False) -> Sample:
    if pycurl is None:
        return Sample(ok=False, err="pycurl yuklu degil (pip install pycurl)",
                      via_proxy=via_proxy, label=label)

    url = ensure_scheme(url)
    cur = pycurl.Curl()
    counter = {"n": 0}
    if count_body:
        def write_cb(data):
            counter["n"] += len(data)
            return len(data)
        cur.setopt(cur.WRITEFUNCTION, write_cb)
    else:
        cur.setopt(cur.WRITEDATA, BytesIO())

    try:
        cur.setopt(cur.URL, url)
        cur.setopt(cur.FOLLOWLOCATION, True)
        cur.setopt(cur.NOSIGNAL, 1)
        cur.setopt(cur.TIMEOUT, cfg.timeout)
        cur.setopt(cur.CONNECTTIMEOUT, cfg.connect_timeout)
        cur.setopt(cur.USERAGENT, cfg.user_agent)
        if cfg.extra_headers:
            cur.setopt(cur.HTTPHEADER, cfg.extra_headers)

        cur.setopt(cur.FRESH_CONNECT, True)
        cur.setopt(cur.FORBID_REUSE, True)

        if cfg.insecure:
            cur.setopt(cur.SSL_VERIFYPEER, 0)
            cur.setopt(cur.SSL_VERIFYHOST, 0)

        if cfg.ssl_no_revoke and hasattr(cur, "SSL_OPTIONS") and hasattr(pycurl, "SSLOPT_NO_REVOKE"):
            cur.setopt(cur.SSL_OPTIONS, pycurl.SSLOPT_NO_REVOKE)

        if via_proxy and cfg.proxy:
            cur.setopt(cur.PROXY, cfg.proxy)
            if cfg.proxy_user:
                cur.setopt(cur.PROXYUSERPWD, cfg.proxy_user)

        cur.perform()

        namelookup = cur.getinfo(cur.NAMELOOKUP_TIME)
        connect = cur.getinfo(cur.CONNECT_TIME)
        appconnect = cur.getinfo(cur.APPCONNECT_TIME)
        pretransfer = cur.getinfo(cur.PRETRANSFER_TIME)
        starttransfer = cur.getinfo(cur.STARTTRANSFER_TIME)
        total = cur.getinfo(cur.TOTAL_TIME)
        code = cur.getinfo(cur.RESPONSE_CODE)
        speed = cur.getinfo(getattr(cur, "SPEED_DOWNLOAD_T", cur.SPEED_DOWNLOAD))
        dl_size = cur.getinfo(getattr(cur, "SIZE_DOWNLOAD_T", cur.SIZE_DOWNLOAD))

        dns = namelookup
        tcp = max(connect - namelookup, 0.0)
        tls = max(appconnect - connect, 0.0) if appconnect > 0 else 0.0
        server = max(starttransfer - pretransfer, 0.0)
        transfer = max(total - starttransfer, 0.0)
        size = counter["n"] if count_body else int(dl_size)

        return Sample(ok=True, http_code=int(code), dns=dns, tcp=tcp, tls=tls,
                      server=server, transfer=transfer, total=total,
                      size_bytes=size, speed_bps=speed,
                      via_proxy=via_proxy, label=label)
    except pycurl.error as e:
        return Sample(ok=False, err=str(e), via_proxy=via_proxy, label=label)
    finally:
        cur.close()


# --------------------------------------------------------------------------- #
# Test 1: Latency breakdown
# --------------------------------------------------------------------------- #
def _phase_report(samples):
    return {
        "ok_count": sum(1 for s in samples if s.ok),
        "fail_count": sum(1 for s in samples if not s.ok),
        "dns": summarize(samples, "dns"),
        "tcp": summarize(samples, "tcp"),
        "tls": summarize(samples, "tls"),
        "server": summarize(samples, "server"),
        "transfer": summarize(samples, "transfer"),
        "total": summarize(samples, "total"),
    }


def _fmt_breakdown(s: Sample):
    """Tek istegin renkli faz kirilimi; en buyuk faz vurgulanir."""
    phases = [("dns", s.dns), ("tcp", s.tcp), ("tls", s.tls),
              ("server", s.server), ("transfer", s.transfer)]
    max_key = max(phases, key=lambda kv: kv[1])[0] if any(v for _, v in phases) else None
    labels = {"dns": "dns", "tcp": "tcp", "tls": "tls", "server": "srv", "transfer": "xfer"}
    parts = []
    for key, val in phases:
        valms = ms(val)
        txt = c(f"{valms}", grade_color(valms, key))
        if key == max_key:
            txt = c(f"{valms}", Ansi.MAGENTA, bold=True)  # zaman nerede gitti
        parts.append(f"{labels[key]}={txt}")
    return "  ".join(parts)


def test_latency(url, cfg: ProxyConfig, repeat=20, compare_direct=True):
    print(f"\n{c('[latency]', Ansi.CYAN, bold=True)} {url}  | tekrar={repeat}")
    result = {"test": "latency", "url": url, "repeat": repeat,
              "started": now_iso(), "modes": {}}

    if cfg.proxy:
        modes = [("proxy", True)]
        if compare_direct:
            modes.insert(0, ("direct", False))
    else:
        modes = [("direct", False)]

    for name, via in modes:
        if via and not cfg.proxy:
            continue
        samples = []
        for i in range(repeat):
            s = do_request(url, cfg, via_proxy=via, label=name)
            samples.append(s)
            if s.ok:
                mark = c("ok", Ansi.GREEN)
                totc = cval(ms(s.total), "total")
                print(f"  {c(name,Ansi.BLUE):>6} #{i+1:>3}  total={totc} ms  "
                      f"{_fmt_breakdown(s)}  {mark}")
            else:
                print(f"  {c(name,Ansi.BLUE):>6} #{i+1:>3}  "
                      f"{c('HATA', Ansi.RED, bold=True)}({c(s.err, Ansi.RED)})")
        result["modes"][name] = _phase_report(samples)
        result["modes"][name]["raw"] = [asdict(s) for s in samples]

    if compare_direct and "direct" in result["modes"] and "proxy" in result["modes"]:
        d = result["modes"]["direct"]["total"].get("p50_ms")
        p = result["modes"]["proxy"]["total"].get("p50_ms")
        if d is not None and p is not None:
            ov = round(p - d, 2)
            result["proxy_overhead_p50_ms"] = ov
            print("\n  " + hl(">> Proxy overhead (p50 total): ")
                  + good_bad(ov, good=20, warn=80, suffix=" ms"))
    return result


# --------------------------------------------------------------------------- #
# Test 2: SSL inspection maliyeti
# --------------------------------------------------------------------------- #
def test_ssl(inspected_url, bypass_url, cfg: ProxyConfig, repeat=20):
    proxy_mode = "explicit" if cfg.proxy else "transparent"
    print(f"\n{c('[ssl]', Ansi.CYAN, bold=True)} inspected={inspected_url}  "
          f"bypass={bypass_url}  tekrar={repeat}  proxy={proxy_mode}")
    result = {"test": "ssl_inspection", "inspected_url": inspected_url,
              "bypass_url": bypass_url, "repeat": repeat,
              "proxy_mode": proxy_mode,
              "started": now_iso(), "groups": {}}

    for name, url in (("inspected", inspected_url), ("bypass", bypass_url)):
        if not url:
            continue
        samples = [do_request(url, cfg, via_proxy=True, label=name) for _ in range(repeat)]
        rep = _phase_report(samples)
        rep["raw"] = [asdict(s) for s in samples]
        result["groups"][name] = rep
        tls = rep["tls"].get("p50_ms")
        tot = rep["total"].get("p50_ms")
        if tls is None or tot is None:
            print(f"  {c(name,Ansi.BLUE):>10}  {c('olculemedi (tum istekler basarisiz)', Ansi.RED)}")
        else:
            print(f"  {c(name,Ansi.BLUE):>10}  p50 total={cval(tot,'total')} ms  "
                  f"p50 tls={cval(tls,'tls')} ms")

    g = result["groups"]
    if ("inspected" in g and "bypass" in g
            and g["inspected"]["tls"].get("p50_ms") is not None
            and g["bypass"]["tls"].get("p50_ms") is not None):
        if g["inspected"]["tls"]["p50_ms"] == 0 and g["bypass"]["tls"]["p50_ms"] == 0:
            result["inspection_warning"] = "Her iki hedefte TLS zamanlamasi 0 ms; inspection maliyeti hesaplanmadi"
            print("\n  " + c(">> Her iki hedefte TLS zamanlamasi 0 ms; inspection/bypass politikasini ve HTTPS erisimini dogrula.", Ansi.YELLOW))
            return result
        d_tls = g["inspected"]["tls"]["p50_ms"] - g["bypass"]["tls"]["p50_ms"]
        d_tot = g["inspected"]["total"]["p50_ms"] - g["bypass"]["total"]["p50_ms"]
        result["inspection_tls_overhead_p50_ms"] = round(d_tls, 2)
        result["inspection_total_overhead_p50_ms"] = round(d_tot, 2)
        print("\n  " + hl(">> SSL inspection ek TLS maliyeti (p50): ")
              + good_bad(round(d_tls, 2), good=50, warn=150, suffix=" ms"))
        print("  " + hl(">> SSL inspection ek toplam maliyet (p50): ")
              + good_bad(round(d_tot, 2), good=50, warn=200, suffix=" ms"))
    return result


# --------------------------------------------------------------------------- #
# Test 3: Eszamanliliik / yuk
# --------------------------------------------------------------------------- #
def test_load(url, cfg: ProxyConfig, levels=(10, 25, 50, 100),
              requests_per_level=200, via_proxy=True):
    print(f"\n{c('[load]', Ansi.CYAN, bold=True)} {url}  "
          f"seviyeler={levels}  istek/seviye={requests_per_level}")
    result = {"test": "load", "url": url, "levels": list(levels),
              "requests_per_level": requests_per_level,
              "started": now_iso(), "results": []}

    for conc in levels:
        samples = []
        t0 = time.time()
        with ThreadPoolExecutor(max_workers=conc) as ex:
            futures = [ex.submit(do_request, url, cfg, via_proxy, f"c{conc}")
                       for _ in range(requests_per_level)]
            for f in as_completed(futures):
                samples.append(f.result())
        elapsed = time.time() - t0
        ok = sum(1 for s in samples if s.ok)
        fail = len(samples) - ok
        rps = round(len(samples) / elapsed, 1) if elapsed > 0 else 0
        tot = summarize(samples, "total")
        err_rate = round(100 * fail / len(samples), 2) if samples else 0
        entry = {"concurrency": conc, "elapsed_s": round(elapsed, 2), "rps": rps,
                 "ok": ok, "fail": fail, "error_rate_pct": err_rate, "total": tot}
        result["results"].append(entry)
        err_c = good_bad(err_rate, good=0.5, warn=5, suffix="%")
        print(f"  conc={c(str(conc),Ansi.BLUE):>4}  rps={c(str(rps),Ansi.CYAN):>7}  "
              f"err={err_c:>5}  "
              f"p50={cval(tot.get('p50_ms',0),'total')} "
              f"p95={cval(tot.get('p95_ms',0),'total')} "
              f"p99={cval(tot.get('p99_ms',0),'total')} ms")

    breaking = None
    base_p95 = result["results"][0]["total"].get("p95_ms") if result["results"] else None
    for e in result["results"]:
        if e["error_rate_pct"] > 5 or (base_p95 and e["total"].get("p95_ms", 0) > base_p95 * 3):
            breaking = e["concurrency"]
            break
    result["breaking_point"] = breaking
    if breaking:
        print("\n  " + hl(">> Olasi kirilma noktasi: ")
              + c(f"~{breaking} eszamanli baglanti", Ansi.RED, bold=True))
    else:
        print("\n  " + hl(">> ") + c("Test edilen seviyelerde belirgin kirilma gozlenmedi", Ansi.GREEN))
    return result


# --------------------------------------------------------------------------- #
# Test 4: Throughput
# --------------------------------------------------------------------------- #
def test_throughput(url, cfg: ProxyConfig, repeat=5, via_proxy=True):
    print(f"\n{c('[throughput]', Ansi.CYAN, bold=True)} {url}  tekrar={repeat}")
    result = {"test": "throughput", "url": url, "repeat": repeat,
              "started": now_iso(), "samples": []}
    speeds = []
    for i in range(repeat):
        s = do_request(url, cfg, via_proxy=via_proxy, label="throughput", count_body=True)
        if s.ok and s.total > 0:
            mbps = (s.size_bytes * 8) / s.total / 1_000_000
            speeds.append(mbps)
            print(f"  #{i+1}  {s.size_bytes/1_048_576:.2f} MiB  {s.total:.2f} s  "
                  f"{c(f'{mbps:.2f} Mbps', Ansi.CYAN, bold=True)}")
        else:
            print(f"  #{i+1}  {c('HATA', Ansi.RED, bold=True)}: {c(s.err, Ansi.RED)}")
        result["samples"].append(asdict(s))
    if speeds:
        result["mbps_mean"] = round(statistics.fmean(speeds), 2)
        result["mbps_max"] = round(max(speeds), 2)
        print("\n  " + hl(">> Ortalama: ") + c(f"{result['mbps_mean']} Mbps", Ansi.GREEN, bold=True)
              + "  |  " + hl("En iyi: ") + c(f"{result['mbps_max']} Mbps", Ansi.GREEN, bold=True))
    return result


# --------------------------------------------------------------------------- #
# Test 5: Cache (miss vs hit)
# --------------------------------------------------------------------------- #
def test_cache(url, cfg: ProxyConfig, rounds=5, via_proxy=True):
    print(f"\n{c('[cache]', Ansi.CYAN, bold=True)} {url}  tur={rounds}")
    result = {"test": "cache", "url": url, "rounds": rounds,
              "started": now_iso(), "rounds_data": []}
    miss, hit = [], []
    for i in range(rounds):
        s1 = do_request(url, cfg, via_proxy=via_proxy, label="miss")
        s2 = do_request(url, cfg, via_proxy=via_proxy, label="hit")
        if s1.ok:
            miss.append(s1.total)
        if s2.ok:
            hit.append(s2.total)
        print(f"  tur {i+1}  1.istek={cval(ms(s1.total),'total')} ms  "
              f"2.istek={cval(ms(s2.total),'total')} ms")
        result["rounds_data"].append({"first": asdict(s1), "second": asdict(s2)})
    if miss and hit:
        m = statistics.fmean(miss)
        h = statistics.fmean(hit)
        result["first_mean_ms"] = ms(m)
        result["second_mean_ms"] = ms(h)
        imp = round(100 * (m - h) / m, 2) if m else 0
        result["improvement_pct"] = imp
        print("\n  " + hl(f">> 1.istek ort={ms(m)} ms  2.istek ort={ms(h)} ms  iyilesme=")
              + good_bad(imp, good_is_low=False, good=20, warn=5, suffix="%"))
        print("     " + c("(Buyuk fark cache hit'e isaret eder; X-Cache header ile dogrulayin.)", Ansi.GREY))
    return result


# --------------------------------------------------------------------------- #
# Test 6: Soak
# --------------------------------------------------------------------------- #
def test_soak(url, cfg: ProxyConfig, duration_s=300, interval_s=5,
              concurrency=5, via_proxy=True):
    print(f"\n{c('[soak]', Ansi.CYAN, bold=True)} {url}  sure={duration_s}s  "
          f"aralik={interval_s}s  conc={concurrency}")
    result = {"test": "soak", "url": url, "duration_s": duration_s,
              "interval_s": interval_s, "concurrency": concurrency,
              "started": now_iso(), "timeline": []}
    t_end = time.time() + duration_s
    tick = 0
    try:
        while time.time() < t_end:
            tick += 1
            samples = []
            with ThreadPoolExecutor(max_workers=concurrency) as ex:
                futures = [ex.submit(do_request, url, cfg, via_proxy, "soak")
                           for _ in range(concurrency)]
                for f in as_completed(futures):
                    samples.append(f.result())
            tot = summarize(samples, "total")
            fail = sum(1 for s in samples if not s.ok)
            entry = {"t": now_iso(), "tick": tick,
                     "p50_ms": tot.get("p50_ms"), "p95_ms": tot.get("p95_ms"), "fail": fail}
            result["timeline"].append(entry)
            failc = c(str(fail), Ansi.RED if fail else Ansi.GREEN)
            print(f"  t={tick:>4}  p50={cval(entry['p50_ms'] or 0,'total')} "
                  f"p95={cval(entry['p95_ms'] or 0,'total')} ms  fail={failc}")
            time.sleep(interval_s)
    except KeyboardInterrupt:
        print("\n  " + c("(Kullanici tarafindan durduruldu)", Ansi.YELLOW))

    tl = [e for e in result["timeline"] if e["p95_ms"] is not None]
    if len(tl) >= 5:
        k = max(1, len(tl) // 5)
        early = statistics.fmean([e["p95_ms"] for e in tl[:k]])
        late = statistics.fmean([e["p95_ms"] for e in tl[-k:]])
        drift = round(100 * (late - early) / early, 2) if early else 0
        result["p95_drift_pct"] = drift
        print("\n  " + hl(">> p95 surukleme (ilk vs son): ")
              + good_bad(drift, good=5, warn=25, suffix="%")
              + c("  (pozitif = zamanla yavaslama / olasi birikme)", Ansi.GREY))
    return result


# --------------------------------------------------------------------------- #
# Stress: kademeli rampalama -> kirilma noktasi (ve --spike toparlanma)
# --------------------------------------------------------------------------- #
def _stage_worker(url, cfg, via_proxy, deadline):
    """Stage suresi bitene kadar surekli istek atan tek isci."""
    out = []
    while time.time() < deadline:
        out.append(do_request(url, cfg, via_proxy, "stress"))
    return out


def _run_stage(url, cfg, via_proxy, conc, duration):
    """conc isci ile 'duration' sn boyunca surekli yuk; tum ornekleri dondur."""
    deadline = time.time() + duration
    samples = []
    with ThreadPoolExecutor(max_workers=conc) as ex:
        futs = [ex.submit(_stage_worker, url, cfg, via_proxy, deadline)
                for _ in range(conc)]
        for f in as_completed(futs):
            samples.extend(f.result())
    return samples


def _stage_stats(samples, conc, duration):
    ok = sum(1 for s in samples if s.ok)
    fail = len(samples) - ok
    tot = summarize(samples, "total")
    return {
        "concurrency": conc,
        "requests": len(samples),
        "rps": round(len(samples) / duration, 1) if duration > 0 else 0,
        "ok": ok, "fail": fail,
        "error_rate_pct": round(100 * fail / len(samples), 2) if samples else 100.0,
        "total": tot,
    }


def _print_stage(e):
    err_c = good_bad(e["error_rate_pct"], good=1, warn=5, suffix="%")
    print(f"  conc={c(str(e['concurrency']),Ansi.BLUE):>4}  "
          f"rps={c(str(e['rps']),Ansi.CYAN):>7}  istek={e['requests']:>5}  "
          f"err={err_c:>5}  "
          f"p50={cval(e['total'].get('p50_ms',0),'total')} "
          f"p95={cval(e['total'].get('p95_ms',0),'total')} "
          f"p99={cval(e['total'].get('p99_ms',0),'total')} ms")


def test_stress(url, cfg: ProxyConfig, start=10, step=10, max_conc=200,
                stage_duration=15, err_threshold=10.0, latency_factor=4.0,
                spike=False, via_proxy=True):
    print(f"\n{c('[stress]', Ansi.CYAN, bold=True)} {url}  "
          f"{'SPIKE' if spike else f'rampa {start}->{max_conc} adim {step}'}  "
          f"stage={stage_duration}s")
    print("  " + c("UYARI: gercek yuk uretir. Yalnizca yetkili test/staging "
                   "hedeflerine uygulayin; prod proxy'yi vurmayin.", Ansi.YELLOW))
    result = {"test": "stress", "url": url, "started": now_iso(),
              "params": {"start": start, "step": step, "max_conc": max_conc,
                         "stage_duration": stage_duration,
                         "err_threshold": err_threshold,
                         "latency_factor": latency_factor, "spike": spike},
              "stages": []}

    baseline_p95 = None
    breaking = None

    if spike:
        # Ani sok: dusuk -> yuksek -> tekrar dusuk (toparlanma)
        plan = [("baseline", start), ("spike", max_conc), ("recovery", start)]
        for phase, conc in plan:
            samples = _run_stage(url, cfg, via_proxy, conc, stage_duration)
            e = _stage_stats(samples, conc, stage_duration)
            e["phase"] = phase
            result["stages"].append(e)
            print(f"  {c(phase,Ansi.BLUE):>9}:", end=" ")
            _print_stage(e)
        # Toparlanma degerlendirmesi
        base = result["stages"][0]["total"].get("p95_ms")
        rec = result["stages"][2]["total"].get("p95_ms")
        if base and rec:
            ratio = round(rec / base, 2)
            result["recovery_ratio"] = ratio
            print("\n  " + hl(">> Toparlanma (recovery p95 / baseline p95): ")
                  + good_bad(ratio, good=1.3, warn=2.0, suffix="x")
                  + c("  (~1.0 = tam toparlandi)", Ansi.GREY))
        return result

    # Kademeli rampa: kirilma noktasina kadar
    conc = start
    while conc <= max_conc:
        samples = _run_stage(url, cfg, via_proxy, conc, stage_duration)
        e = _stage_stats(samples, conc, stage_duration)
        result["stages"].append(e)
        _print_stage(e)

        p95 = e["total"].get("p95_ms", 0)
        if baseline_p95 is None and e["ok"] > 0:
            baseline_p95 = p95

        knee = (e["error_rate_pct"] >= err_threshold or
                (baseline_p95 and p95 > baseline_p95 * latency_factor))
        if knee:
            breaking = conc
            print("  " + c(f">> Kirilma: conc={conc} "
                           f"(err={e['error_rate_pct']}% / p95={p95}ms, "
                           f"baseline p95={baseline_p95}ms)", Ansi.RED, bold=True))
            break
        conc += step

    result["baseline_p95_ms"] = baseline_p95
    result["breaking_point"] = breaking
    # Pik throughput hangi seviyede yakalandi
    if result["stages"]:
        peak = max(result["stages"], key=lambda x: x["rps"])
        result["peak_rps"] = peak["rps"]
        result["peak_rps_at_conc"] = peak["concurrency"]
        print("\n  " + hl(">> Pik throughput: ")
              + c(f"{peak['rps']} rps @ conc={peak['concurrency']}", Ansi.GREEN, bold=True))
    if breaking:
        print("  " + hl(">> Kirilma noktasi: ")
              + c(f"~{breaking} eszamanli baglanti", Ansi.RED, bold=True))
    else:
        print("  " + hl(">> ") + c(f"max_conc={max_conc}'a kadar kirilma gozlenmedi "
                                   f"(daha yuksek --max dene)", Ansi.YELLOW))
    return result
_LCP_INIT = """
window.__bh_lcp = 0;
try {
  new PerformanceObserver((l) => {
    for (const e of l.getEntries()) { window.__bh_lcp = e.startTime; }
  }).observe({ type: 'largest-contentful-paint', buffered: true });
} catch (e) {}
"""

_METRICS_JS = """
() => {
  const nav = performance.getEntriesByType('navigation')[0] || {};
  const paint = performance.getEntriesByType('paint') || [];
  const fcpEntry = paint.find(p => p.name === 'first-contentful-paint');
  return {
    ttfb: nav.responseStart || 0,
    dcl: nav.domContentLoadedEventEnd || 0,
    load: nav.loadEventEnd || 0,
    fcp: fcpEntry ? fcpEntry.startTime : 0,
    lcp: window.__bh_lcp || 0,
    transferSize: nav.transferSize || 0,
  };
}
"""


def _browser_proxy(cfg: ProxyConfig):
    if not cfg.proxy:
        return None
    p = {"server": cfg.proxy}
    if cfg.proxy_user and ":" in cfg.proxy_user:
        u, pw = cfg.proxy_user.split(":", 1)
        p["username"], p["password"] = u, pw
    return p


def test_browser(url, cfg: ProxyConfig, repeat=5, via_proxy=True, headless=True):
    url = ensure_scheme(url)
    print(f"\n{c('[browser]', Ansi.CYAN, bold=True)} {url}  tekrar={repeat}  "
          f"({'proxy' if (via_proxy and cfg.proxy) else 'direct'})")
    result = {"test": "browser", "url": url, "repeat": repeat,
              "via_proxy": bool(via_proxy and cfg.proxy),
              "started": now_iso(), "raw": []}

    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        msg = "playwright yuklu degil. Kurulum: pip install playwright && playwright install chromium"
        print("  " + c(msg, Ansi.RED, bold=True))
        result["error"] = msg
        return result

    proxy = _browser_proxy(cfg) if via_proxy else None
    ignore_cert = cfg.insecure or cfg.ssl_no_revoke
    args = []
    if ignore_cert:
        args.append("--ignore-certificate-errors")

    samples = []
    with sync_playwright() as pw:
        launch_kwargs = {"headless": headless, "args": args}
        if proxy:
            launch_kwargs["proxy"] = proxy
        browser = pw.chromium.launch(**launch_kwargs)
        try:
            for i in range(repeat):
                # Her tekrar icin taze context = soguk yukleme (cache yok)
                ctx = browser.new_context(ignore_https_errors=ignore_cert)
                ctx.add_init_script(_LCP_INIT)
                page = ctx.new_page()
                req = {"n": 0}
                page.on("request", lambda r: req.__setitem__("n", req["n"] + 1))
                try:
                    page.goto(url, wait_until="load", timeout=cfg.timeout * 1000)
                    page.wait_for_timeout(600)  # LCP'nin oturmasi icin
                    m = page.evaluate(_METRICS_JS)
                    s = BrowserSample(
                        ok=True,
                        ttfb=float(m.get("ttfb", 0)), fcp=float(m.get("fcp", 0)),
                        lcp=float(m.get("lcp", 0)), dcl=float(m.get("dcl", 0)),
                        load=float(m.get("load", 0)), total=float(m.get("load", 0)),
                        req_count=req["n"],
                        transfer_kb=round(float(m.get("transferSize", 0)) / 1024, 1),
                        via_proxy=bool(proxy),
                    )
                    print(f"  #{i+1:>3}  load={cval(round(s.load,2),'load')} ms  "
                          f"ttfb={cval(round(s.ttfb,2),'ttfb')}  "
                          f"fcp={cval(round(s.fcp,2),'fcp')}  "
                          f"lcp={cval(round(s.lcp,2),'lcp')}  "
                          f"dcl={cval(round(s.dcl,2),'dcl')} ms  "
                          f"istek={c(str(s.req_count),Ansi.BLUE)}  {c('ok',Ansi.GREEN)}")
                except Exception as e:
                    s = BrowserSample(ok=False, err=str(e)[:200], via_proxy=bool(proxy))
                    print(f"  #{i+1:>3}  {c('HATA',Ansi.RED,bold=True)}: {c(s.err, Ansi.RED)}")
                finally:
                    ctx.close()
                samples.append(s)
        finally:
            browser.close()

    result["raw"] = [asdict(s) for s in samples]
    result["metrics"] = {
        "ttfb": summarize(samples, "ttfb", already_ms=True),
        "fcp": summarize(samples, "fcp", already_ms=True),
        "lcp": summarize(samples, "lcp", already_ms=True),
        "dcl": summarize(samples, "dcl", already_ms=True),
        "load": summarize(samples, "load", already_ms=True),
    }
    oks = [s for s in samples if s.ok]
    if oks:
        result["avg_requests"] = round(statistics.fmean([s.req_count for s in oks]), 1)
        load50 = result["metrics"]["load"].get("p50_ms", 0)
        lcp50 = result["metrics"]["lcp"].get("p50_ms", 0)
        print("\n  " + hl(">> load p50: ") + cval(load50, "load", 1).strip()
              + hl("  ms  |  LCP p50: ") + cval(lcp50, "lcp", 1).strip() + " ms")
    return result


# --------------------------------------------------------------------------- #
# Test 8: Full
# --------------------------------------------------------------------------- #
def test_full(args, cfg: ProxyConfig, tests=None):
    print("\n" + c("========== FULL TEST ==========", Ansi.CYAN, bold=True))
    out = {"test": "full", "started": now_iso(), "components": {}}
    tests = tests or {}
    latency = tests.get("latency", {})
    ssl = tests.get("ssl", {})
    load = tests.get("load", {})
    cache = tests.get("cache", {})
    throughput = tests.get("throughput", {})
    browser = tests.get("browser", {})
    soak = tests.get("soak", {})
    stress = tests.get("stress", {})
    load_levels = load.get("levels", args.levels)
    if isinstance(load_levels, str):
        load_levels = tuple(int(x) for x in load_levels.split(","))
    out["components"]["latency"] = test_latency(
        latency.get("url", args.url), cfg, repeat=latency.get("repeat", args.repeat), compare_direct=bool(cfg.proxy))
    bypass_url = ssl.get("bypass_url", args.bypass_url)
    if bypass_url:
        out["components"]["ssl"] = test_ssl(ssl.get("url", args.url), bypass_url, cfg,
                                               repeat=ssl.get("repeat", args.repeat))
    out["components"]["load"] = test_load(
        load.get("url", args.url), cfg, levels=tuple(load_levels),
        requests_per_level=load.get("requests", args.requests))
    out["components"]["cache"] = test_cache(cache.get("url", args.url), cfg,
                                               rounds=cache.get("rounds", args.cache_rounds))
    throughput_url = throughput.get("url", args.throughput_url)
    if throughput_url:
        out["components"]["throughput"] = test_throughput(throughput_url, cfg,
                                                              repeat=throughput.get("repeat", args.repeat))
    if browser.get("enabled", getattr(args, "browser", False)):
        out["components"]["browser"] = test_browser(browser.get("url", args.url), cfg,
                                                        repeat=browser.get("repeat", args.repeat),
                                                        headless=not browser.get("headed", False))
    soak_duration = soak.get("duration", args.soak)
    if soak_duration > 0:
        out["components"]["soak"] = test_soak(soak.get("url", args.url), cfg, duration_s=soak_duration,
                                                  interval_s=soak.get("interval", args.soak_interval),
                                                  concurrency=soak.get("concurrency", 5))
    if stress.get("enabled", False):
        out["components"]["stress"] = test_stress(
            stress.get("url", args.url), cfg,
            start=stress.get("start", 10), step=stress.get("step", 10),
            max_conc=stress.get("max", 200),
            stage_duration=stress.get("stage_duration", 15),
            err_threshold=stress.get("err_threshold", 10.0),
            latency_factor=stress.get("latency_factor", 4.0),
            spike=stress.get("spike", False),
            via_proxy=not stress.get("no_proxy_mode", False),
        )
    return out


# --------------------------------------------------------------------------- #
# Rapor yazimi
# --------------------------------------------------------------------------- #
def save_report(result, prefix="bottleneck"):
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    base = f"{prefix}_{result.get('test','run')}_{stamp}"

    json_path = f"{base}.json"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(report_envelope(result), f, ensure_ascii=False, indent=2)

    html_path = f"{base}.html"
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(render_comparison_html(result))

    csv_path = f"{base}_samples.csv"
    rows = _collect_samples(result)
    if rows:
        # Farkli semalar (curl vs tarayici) karisabilir -> anahtar birlesimi
        fieldnames = []
        for r in rows:
            for k in r.keys():
                if k not in fieldnames:
                    fieldnames.append(k)
        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=fieldnames, restval="", extrasaction="ignore")
            w.writeheader()
            w.writerows(rows)
    else:
        csv_path = None

    txt_path = f"{base}_summary.txt"
    with open(txt_path, "w", encoding="utf-8") as f:
        f.write(f"{APP_NAME} v{APP_VERSION} - Rapor\n")
        f.write(f"Olusturulma: {now_iso()}\n")
        f.write("=" * 60 + "\n")
        f.write(json.dumps(_summary_view(result), ensure_ascii=False, indent=2))
        f.write("\n")

    print("\n" + c("--- Rapor kaydedildi ---", Ansi.GREEN, bold=True))
    print("  JSON   : " + c(json_path, Ansi.GREEN))
    print("  HTML   : " + c(html_path, Ansi.GREEN))
    if csv_path:
        print("  CSV    : " + c(csv_path, Ansi.GREEN))
    print("  Ozet   : " + c(txt_path, Ansi.GREEN))
    return json_path


def _collect_samples(result):
    rows = []

    def walk(node):
        if isinstance(node, dict):
            for key in ("raw", "samples"):
                if key in node and isinstance(node[key], list):
                    for s in node[key]:
                        if isinstance(s, dict) and "total" in s and "ok" in s:
                            rows.append(s)
            for v in node.values():
                walk(v)
        elif isinstance(node, list):
            for v in node:
                walk(v)

    walk(result)
    return rows


def _summary_view(result):
    import copy
    v = copy.deepcopy(result)

    def strip(node):
        if isinstance(node, dict):
            node.pop("raw", None)
            node.pop("samples", None)
            node.pop("rounds_data", None)
            for x in node.values():
                strip(x)
        elif isinstance(node, list):
            for x in node:
                strip(x)

    strip(v)
    return v


# --------------------------------------------------------------------------- #
# Etkilesimli menu
# --------------------------------------------------------------------------- #
def prompt(text, default=None):
    sfx = f" [{default}]" if default is not None else ""
    val = input(c(f"{text}{sfx}: ", Ansi.CYAN)).strip()
    return val if val else default


def _interactive_value(config, section, key, text, default=None):
    value = config.get(section, {}).get(key)
    if value is not None and value != "":
        return value
    return prompt(text, default)


def _yes(value):
    return value if isinstance(value, bool) else str(value).lower() in ("true", "e", "evet")


def _authorized(config, test_name):
    """Prefer a test-specific authorization, then fall back to common."""
    test_value = config.get("tests", {}).get(test_name, {}).get("authorized_target")
    if test_value is not None and test_value != "":
        return _yes(test_value)
    return _yes(config.get("common", {}).get("authorized_target", False))


def _validate_interactive_active_test(*args, **kwargs):
    try:
        validate_active_test(*args, **kwargs)
        return True
    except ValueError as exc:
        print(c(f"Yuk testi baslatilmadi: {exc}", Ansi.RED))
        return False


def _display_config(config):
    import copy
    visible = copy.deepcopy(config)
    common = visible.get("common", {})
    if common.get("proxy_user"):
        common["proxy_user"] = "***"
    print(json.dumps(visible, ensure_ascii=False, indent=2))


def interactive(save_prompt=True, ai_check=None, config_path="bottleneck.config.json"):
    print(banner())
    if pycurl is None:
        print(c("\nUYARI: pycurl yuklu degil. Kurun: pip install pycurl", Ansi.YELLOW))

    try:
        config = load_config(config_path, require_command=False)
        print(c(f"\nConfig yuklendi: {config_path}", Ansi.GREEN))
    except FileNotFoundError:
        config = {"common": {}, "parameters": {}}

    last_result = None
    while True:
        print("\nHangi islemi yapmak istersin?")
        print(f"  {c('1',Ansi.BLUE)}) latency    - Faz kirilimi (direct vs proxy)")
        print(f"  {c('2',Ansi.BLUE)}) ssl        - SSL inspection maliyeti")
        print(f"  {c('3',Ansi.BLUE)}) load       - Eszamanliliik / yuk")
        print(f"  {c('4',Ansi.BLUE)}) throughput - Bant genisligi")
        print(f"  {c('5',Ansi.BLUE)}) cache      - Cache miss vs hit")
        print(f"  {c('6',Ansi.BLUE)}) soak       - Uzun sureli degradasyon")
        print(f"  {c('7',Ansi.BLUE)}) stress     - Kirilma noktasi (rampa / spike)")
        print(f"  {c('8',Ansi.BLUE)}) browser    - Gercek tarayici (render dahil)")
        print(f"  {c('9',Ansi.BLUE)}) full       - Tum testler")
        print(f"  {c('10',Ansi.BLUE)}) AI baglanti kontrolu")
        print(f"  {c('11',Ansi.BLUE)}) Config goruntule")
        print(f"  {c('0',Ansi.BLUE)}) Cikis")
        command_names = ("latency", "ssl", "load", "throughput", "cache", "soak", "stress", "browser", "full")
        command_choices = {name: str(index) for index, name in enumerate(command_names, 1)}
        choice = str(prompt("Secim (0-11)", command_choices.get(config.get("command"), "1")))

        if choice == "0":
            return last_result
        if choice == "10":
            if ai_check is None:
                try:
                    from bh_agent import check_ai_connection
                    from ai_health import print_ai_check
                    print_ai_check(check_ai_connection())
                except Exception as exc:
                    print(c(f"AI baglanti kontrolu basarisiz: {exc}", Ansi.RED))
            else:
                ai_check()
            continue
        if choice == "11":
            _display_config(config)
            continue
        if choice not in set("123456789"):
            print(c("Gecersiz secim.", Ansi.RED))
            continue

        selected_command = command_names[int(choice) - 1]
        param_config = dict(config)
        param_config["parameters"] = test_parameters(config, selected_command)

        cfg = ProxyConfig()
        cfg.proxy = _interactive_value(config, "common", "proxy", "Explicit proxy (bos = direct/transparent proxy)", None)
        if cfg.proxy:
            cfg.proxy_user = _interactive_value(config, "common", "proxy_user", "Proxy auth (kullanici:parola, bos = yok)", None)
        insec = _interactive_value(config, "common", "insecure", "SSL dogrulamayi atla? (e/h)", "h")
        cfg.insecure = insec if isinstance(insec, bool) else bool(insec) and insec.lower().startswith("e")
        norev = _interactive_value(config, "common", "ssl_no_revoke", "Revocation (CRL/OCSP) kontrolunu kapat? Schannel/izole ag icin (e/h)", "h")
        cfg.ssl_no_revoke = norev if isinstance(norev, bool) else bool(norev) and norev.lower().startswith("e")
        cfg.timeout = int(_interactive_value(config, "common", "timeout", "Timeout (sn)", "30"))

        url = _interactive_value(param_config, "parameters", "url", "Hedef URL", "https://www.example.com")
        repeat = int(_interactive_value(param_config, "parameters", "repeat", "Tekrar sayisi", "20"))

        if choice == "1":
            no_direct = param_config.get("parameters", {}).get("no_direct", False)
            res = test_latency(url, cfg, repeat=repeat, compare_direct=bool(cfg.proxy) and not no_direct)
        elif choice == "2":
            bypass = _interactive_value(param_config, "parameters", "bypass_url", "Bypass (inspekte edilmeyen) URL", "https://www.example.org")
            res = test_ssl(url, bypass, cfg, repeat=repeat)
        elif choice == "3":
            lv = _interactive_value(param_config, "parameters", "levels", "Eszamanliliik seviyeleri (virgulle)", "10,25,50,100")
            if isinstance(lv, list):
                lv = ",".join(str(x) for x in lv)
            levels = tuple(int(x) for x in lv.split(","))
            rpl = int(_interactive_value(param_config, "parameters", "requests", "Istek/seviye", "200"))
            authorized = _authorized(config, "load")
            if not _validate_interactive_active_test(url, max(levels), rpl, authorized):
                continue
            res = test_load(url, cfg, levels=levels, requests_per_level=rpl)
        elif choice == "4":
            res = test_throughput(url, cfg, repeat=repeat)
        elif choice == "5":
            rounds = int(_interactive_value(param_config, "parameters", "rounds", "Tur sayisi", "5"))
            res = test_cache(url, cfg, rounds=rounds)
        elif choice == "6":
            dur = int(_interactive_value(param_config, "parameters", "duration", "Sure (sn)", "300"))
            interval = int(_interactive_value(param_config, "parameters", "interval", "Aralik (sn)", "5"))
            conc = int(_interactive_value(param_config, "parameters", "concurrency", "Eszamanliliik", "5"))
            res = test_soak(url, cfg, duration_s=dur, interval_s=interval, concurrency=conc)
        elif choice == "7":
            st = int(_interactive_value(param_config, "parameters", "start", "Baslangic eszamanliliik", "10"))
            step = int(_interactive_value(param_config, "parameters", "step", "Adim", "10"))
            mx = int(_interactive_value(param_config, "parameters", "max", "Ust sinir", "200"))
            sd = int(_interactive_value(param_config, "parameters", "stage_duration", "Stage suresi (sn)", "15"))
            spike_value = _interactive_value(param_config, "parameters", "spike", "Spike (ani sok + toparlanma) modu? (e/h)", "h")
            spike = spike_value if isinstance(spike_value, bool) else spike_value.lower().startswith("e")
            authorized = _authorized(config, "stress")
            if not _validate_interactive_active_test(url, mx, authorized=authorized):
                continue
            res = test_stress(url, cfg, start=st, step=step, max_conc=mx, stage_duration=sd, spike=spike)
        elif choice == "8":
            res = test_browser(url, cfg, repeat=repeat)
        else:
            levels = _interactive_value(param_config, "parameters", "levels", "Yuk seviyeleri", "10,25,50,100")
            if isinstance(levels, list):
                levels = ",".join(str(x) for x in levels)
            ns = argparse.Namespace(
                url=url, repeat=repeat,
                bypass_url=_interactive_value(param_config, "parameters", "bypass_url", "Bypass URL (bos = atla)", None),
                throughput_url=_interactive_value(param_config, "parameters", "throughput_url", "Throughput icin buyuk dosya URL (bos = atla)", None),
                levels=tuple(int(x) for x in levels.split(",")),
                requests=int(_interactive_value(param_config, "parameters", "requests", "Yuk istek/seviye", "200")),
                cache_rounds=int(_interactive_value(param_config, "parameters", "cache_rounds", "Cache tur", "5")),
                browser=_yes(_interactive_value(param_config, "parameters", "browser", "Tarayici testi de calissin mi? (e/h)", "h")),
                soak=int(_interactive_value(param_config, "parameters", "soak", "Soak sure sn (0 = atla)", "0")),
                soak_interval=int(_interactive_value(param_config, "parameters", "soak_interval", "Soak aralik sn", "5")),
            )
            authorized = _authorized(config, "full") or _authorized(config, "load")
            full_load = config.get("tests", {}).get("load", {})
            full_load_levels = full_load.get("levels", ns.levels)
            if isinstance(full_load_levels, str):
                full_load_levels = tuple(int(x) for x in full_load_levels.split(","))
            if not _validate_interactive_active_test(full_load.get("url", url), max(full_load_levels),
                                                     full_load.get("requests", ns.requests), authorized):
                continue
            res = test_full(ns, cfg, tests=config.get("tests"))

        if save_prompt:
            no_save = config.get("common", {}).get("no_save")
            should_save = not no_save if no_save is not None and no_save != "" else (
                str(prompt("Raporu kaydet? (e/h)", "e")).lower().startswith("e")
            )
            if should_save:
                save_report(res, prefix=config.get("common", {}).get("prefix", "bottleneck"))
        last_result = res


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def build_parser():
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--proxy", help="Proxy adresi, or. http://10.0.0.1:8080")
    common.add_argument("--proxy-user", help="Proxy auth 'kullanici:parola'")
    common.add_argument("--insecure", action="store_true", help="SSL dogrulamayi atla")
    common.add_argument("--ssl-no-revoke", action="store_true",
                        help="CRL/OCSP revocation kontrolunu kapat (Schannel/izole ag)")
    common.add_argument("--timeout", type=int, default=30, help="Istek timeout (sn)")
    common.add_argument("--connect-timeout", type=int, default=10)
    common.add_argument("--header", action="append", default=[],
                        help="Ek HTTP header (cok kez verilebilir)")
    common.add_argument("--no-color", action="store_true", help="Renkli ciktiyi kapat")
    common.add_argument("--no-save", action="store_true", help="Raporu dosyaya yazma")
    common.add_argument("--prefix", default="bottleneck", help="Cikti dosya on eki")
    common.add_argument("--authorized-target", action="store_true",
                        help="Aktif yuk testi icin hedef yetkisini onayla")

    p = argparse.ArgumentParser(
        prog="bottleneck_hunter.py",
        description=f"{APP_NAME} - Proxy performans & gecikme analiz araci",
        parents=[common])
    p.add_argument("--config", help="Tum runtime ayarlarini iceren JSON config dosyasi")
    sub = p.add_subparsers(dest="cmd")

    sp = sub.add_parser("latency", parents=[common], help="Faz kirilimi (direct vs proxy)")
    sp.add_argument("--url", required=True)
    sp.add_argument("--repeat", type=int, default=20)
    sp.add_argument("--no-direct", action="store_true", help="Direct baseline'i atla")

    sp = sub.add_parser("ssl", parents=[common], help="SSL inspection maliyeti")
    sp.add_argument("--url", required=True, help="Inspekte edilen URL")
    sp.add_argument("--bypass-url", required=True, help="Bypass listesindeki URL")
    sp.add_argument("--repeat", type=int, default=20)

    sp = sub.add_parser("load", parents=[common], help="Eszamanliliik / yuk")
    sp.add_argument("--url", required=True)
    sp.add_argument("--levels", default="10,25,50,100")
    sp.add_argument("--requests", type=int, default=200, choices=range(1, MAX_REQUESTS_PER_LEVEL + 1))
    sp.add_argument("--no-proxy-mode", action="store_true", help="Proxy yerine direct yukle")

    sp = sub.add_parser("throughput", parents=[common], help="Bant genisligi")
    sp.add_argument("--url", required=True, help="Buyuk dosya URL'si")
    sp.add_argument("--repeat", type=int, default=5)

    sp = sub.add_parser("cache", parents=[common], help="Cache miss vs hit")
    sp.add_argument("--url", required=True)
    sp.add_argument("--rounds", type=int, default=5)

    sp = sub.add_parser("soak", parents=[common], help="Uzun sureli degradasyon")
    sp.add_argument("--url", required=True)
    sp.add_argument("--duration", type=int, default=300)
    sp.add_argument("--interval", type=int, default=5)
    sp.add_argument("--concurrency", type=int, default=5)

    sp = sub.add_parser("stress", parents=[common],
                        help="Kademeli rampa ile kirilma noktasi (ve --spike toparlanma)")
    sp.add_argument("--url", required=True)
    sp.add_argument("--start", type=int, default=10, help="Baslangic eszamanliliik")
    sp.add_argument("--step", type=int, default=10, help="Her stage'de artis")
    sp.add_argument("--max", dest="max_conc", type=int, default=200, choices=range(1, MAX_CONCURRENCY + 1), help="Ust sinir eszamanliliik")
    sp.add_argument("--stage-duration", type=int, default=15, help="Her stage suresi (sn)")
    sp.add_argument("--err-threshold", type=float, default=10.0, help="Kirilma: hata orani %% esigi")
    sp.add_argument("--latency-factor", type=float, default=4.0, help="Kirilma: p95 baseline'in kac kati")
    sp.add_argument("--spike", action="store_true", help="Rampa yerine ani sok + toparlanma testi")
    sp.add_argument("--no-proxy-mode", action="store_true", help="Proxy yerine direct yukle")

    sp = sub.add_parser("browser", parents=[common],
                        help="Gercek tarayici (Playwright) ile render dahil olcum")
    sp.add_argument("--url", required=True)
    sp.add_argument("--repeat", type=int, default=5)
    sp.add_argument("--no-proxy-mode", action="store_true", help="Proxy yerine direct")
    sp.add_argument("--headed", action="store_true", help="Tarayiciyi gorunur ac (headless degil)")

    sp = sub.add_parser("full", parents=[common], help="Tum testler")
    sp.add_argument("--url", required=True)
    sp.add_argument("--repeat", type=int, default=20)
    sp.add_argument("--bypass-url", default=None)
    sp.add_argument("--throughput-url", default=None)
    sp.add_argument("--levels", default="10,25,50,100")
    sp.add_argument("--requests", type=int, default=200)
    sp.add_argument("--cache-rounds", type=int, default=5)
    sp.add_argument("--browser", action="store_true", help="Tarayici testini de dahil et")
    sp.add_argument("--soak", type=int, default=0, help="Soak sure sn (0 = atla)")
    sp.add_argument("--soak-interval", type=int, default=5)

    return p


def cfg_from_args(a) -> ProxyConfig:
    headers = list(a.header) if getattr(a, "header", None) else []
    return ProxyConfig(
        proxy=a.proxy, proxy_user=a.proxy_user, insecure=a.insecure,
        ssl_no_revoke=getattr(a, "ssl_no_revoke", False),
        timeout=a.timeout, connect_timeout=a.connect_timeout, extra_headers=headers)


def main():
    if len(sys.argv) == 1:
        setup_color(force_off=False)
        interactive()
        return

    config_data = None
    if "--config" in sys.argv:
        config_data = load_config(sys.argv[sys.argv.index("--config") + 1])
    parser = build_parser()
    a = parser.parse_args(expand_config_args(sys.argv[1:]))
    setup_color(force_off=getattr(a, "no_color", False))

    if not a.cmd:
        parser.print_help()
        return

    print(banner())
    if pycurl is None:
        print(c("\nUYARI: pycurl yuklu degil. Kurun: pip install pycurl", Ansi.YELLOW))

    cfg = cfg_from_args(a)
    res = None

    if a.cmd == "latency":
        res = test_latency(a.url, cfg, repeat=a.repeat, compare_direct=not a.no_direct)
    elif a.cmd == "ssl":
        res = test_ssl(a.url, a.bypass_url, cfg, repeat=a.repeat)
    elif a.cmd == "load":
        levels = tuple(int(x) for x in a.levels.split(","))
        validate_active_test(a.url, max(levels), a.requests, a.authorized_target)
        res = test_load(a.url, cfg, levels=levels, requests_per_level=a.requests,
                        via_proxy=not a.no_proxy_mode)
    elif a.cmd == "throughput":
        res = test_throughput(a.url, cfg, repeat=a.repeat)
    elif a.cmd == "cache":
        res = test_cache(a.url, cfg, rounds=a.rounds)
    elif a.cmd == "soak":
        res = test_soak(a.url, cfg, duration_s=a.duration, interval_s=a.interval,
                        concurrency=a.concurrency)
    elif a.cmd == "stress":
        validate_active_test(a.url, a.max_conc, authorized=a.authorized_target)
        res = test_stress(a.url, cfg, start=a.start, step=a.step, max_conc=a.max_conc,
                          stage_duration=a.stage_duration, err_threshold=a.err_threshold,
                          latency_factor=a.latency_factor, spike=a.spike,
                          via_proxy=not a.no_proxy_mode)
    elif a.cmd == "browser":
        res = test_browser(a.url, cfg, repeat=a.repeat,
                           via_proxy=not a.no_proxy_mode, headless=not a.headed)
    elif a.cmd == "full":
        a.levels = tuple(int(x) for x in a.levels.split(","))
        full_tests = config_data.get("tests", {}) if config_data else {}
        load_cfg = full_tests.get("load", {})
        load_levels = load_cfg.get("levels", a.levels)
        if isinstance(load_levels, str):
            load_levels = tuple(int(x) for x in load_levels.split(","))
        full_authorized = a.authorized_target or (_authorized(config_data, "load") if config_data else False)
        validate_active_test(load_cfg.get("url", a.url), max(load_levels),
                             load_cfg.get("requests", a.requests), full_authorized)
        stress_cfg = full_tests.get("stress", {})
        if stress_cfg.get("enabled", False):
            stress_authorized = a.authorized_target or _authorized(config_data, "stress")
            validate_active_test(stress_cfg.get("url", a.url), stress_cfg.get("max", 200),
                                 authorized=stress_authorized)
        res = test_full(a, cfg, tests=full_tests)

    if res and not a.no_save:
        save_report(res, prefix=a.prefix)
    return res


if __name__ == "__main__":
    main()
