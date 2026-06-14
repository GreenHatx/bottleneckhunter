#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Bottleneck Hunter - LangChain Agent
===================================
Bottleneck Hunter testlerini LLM'in cagirabilecegi tool'lara donusturur.
Akis: LLM soruyu alir -> uygun tool'u (proxy testi) cagirir -> tool calisir ->
sonuc (ozet JSON) LLM'e geri verilir -> LLM yorumlar.

Calistirma:  python bh_agent.py
Gereksinim:  pip install langchain-openai langchain-core httpx
             (ayrica ayni klasorde bottleneck_hunter.py)
"""

import io
import json
import contextlib
import os
from pathlib import Path

import httpx
from dotenv import load_dotenv
from langchain_openai import ChatOpenAI
from langchain_core.tools import tool
from langchain_core.messages import HumanMessage, SystemMessage, ToolMessage

import bottleneck_hunter as bh
from ai_health import check_ai_connection as run_ai_connection_check, print_ai_check

# TTY'ye gore renk; tool ciktisini konsola basarken ANSI gurultusu olmasin
bh.setup_color()


# --------------------------------------------------------------------------- #
# Yardimci: test sonucundan LLM'e verilecek SADE ozeti cikar
# --------------------------------------------------------------------------- #
def _compact(result: dict) -> str:
    """Ham ornekleri at (raw/samples), kalan ozeti JSON string olarak dondur.
    ToolMessage.content string olmali; ayrica LLM'i ham veriyle bogmamak icin."""
    summary = bh._summary_view(result)   # raw/samples/rounds_data temizler
    return json.dumps(summary, ensure_ascii=False)


def _make_cfg(proxy=None, proxy_user=None, ssl_no_revoke=False, insecure=False, timeout=30):
    return bh.ProxyConfig(proxy=proxy, proxy_user=proxy_user,
                          ssl_no_revoke=ssl_no_revoke, insecure=insecure,
                          timeout=timeout)


# --------------------------------------------------------------------------- #
# Tool tanimlari  (docstring + tip ipuclari LLM'in gordugu semadir; onemli!)
# --------------------------------------------------------------------------- #
@tool
def proxy_latency(url: str, proxy: str = "", repeat: int = 10,
                  ssl_no_revoke: bool = False) -> str:
    """Bir URL icin ag gecikmesini fazlarina ayirir (DNS/TCP/TLS/sunucu/transfer)
    ve proxy verilirse direct ile karsilastirip proxy overhead'ini hesaplar.
    Args:
        url: Test edilecek hedef (or. https://intranet.local).
        proxy: Proxy adresi (or. http://10.0.0.1:8080). Bos ise direct olcum.
        repeat: Tekrar sayisi (varsayilan 10).
        ssl_no_revoke: Schannel/izole ag icin CRL/OCSP revocation kontrolunu kapatir.
    """
    cfg = _make_cfg(proxy=proxy or None, ssl_no_revoke=ssl_no_revoke)
    res = bh.test_latency(url, cfg, repeat=repeat, compare_direct=bool(proxy))
    return _compact(res)


@tool
def proxy_ssl_cost(inspected_url: str, bypass_url: str, proxy: str,
                   repeat: int = 10, ssl_no_revoke: bool = False) -> str:
    """SSL inspection'in gecikme maliyetini olcer: inspekte edilen bir domain ile
    bypass listesindeki bir domaini proxy uzerinden kiyaslar.
    Args:
        inspected_url: SSL inspection uygulanan hedef.
        bypass_url: Inspection bypass listesindeki hedef.
        proxy: Proxy adresi (zorunlu).
        repeat: Tekrar sayisi.
        ssl_no_revoke: Revocation kontrolunu kapat.
    """
    cfg = _make_cfg(proxy=proxy, ssl_no_revoke=ssl_no_revoke)
    res = bh.test_ssl(inspected_url, bypass_url, cfg, repeat=repeat)
    return _compact(res)


@tool
def proxy_load(url: str, proxy: str = "", levels: str = "10,25,50",
               requests_per_level: int = 100, ssl_no_revoke: bool = False) -> str:
    """Artan eszamanliliik seviyelerinde p50/p95/p99 gecikme ve hata oranini olcer,
    olasi kirilma noktasini bulur. DIKKAT: gercek yuk uretir, yetkili hedeflerde calistir.
    Args:
        url: Hedef.
        proxy: Proxy adresi. Bos ise direct.
        levels: Virgulle ayrik eszamanliliik seviyeleri (or. '10,25,50,100').
        requests_per_level: Her seviyede atilacak istek sayisi.
        ssl_no_revoke: Revocation kontrolunu kapat.
    """
    cfg = _make_cfg(proxy=proxy or None, ssl_no_revoke=ssl_no_revoke)
    lv = tuple(int(x) for x in levels.split(","))
    res = bh.test_load(url, cfg, levels=lv, requests_per_level=requests_per_level,
                       via_proxy=bool(proxy))
    return _compact(res)


@tool
def proxy_stress(url: str, proxy: str = "", start: int = 10, step: int = 10,
                 max_conc: int = 100, stage_duration: int = 10,
                 ssl_no_revoke: bool = False) -> str:
    """Eszamanliliik kademeli artirilarak proxy'nin kirilma noktasi bulunur.
    Hata orani %10'u veya p95 baseline'in 4 katini gecince otomatik durur.
    DIKKAT: yogun gercek yuk uretir; yalnizca yetkili test/staging hedeflerinde.
    Args:
        url: Hedef.
        proxy: Proxy adresi. Bos ise direct.
        start: Baslangic eszamanliliik.
        step: Her stage'de artis.
        max_conc: Ust sinir.
        stage_duration: Her stage suresi (sn).
        ssl_no_revoke: Revocation kontrolunu kapat.
    """
    cfg = _make_cfg(proxy=proxy or None, ssl_no_revoke=ssl_no_revoke)
    res = bh.test_stress(url, cfg, start=start, step=step, max_conc=max_conc,
                         stage_duration=stage_duration, via_proxy=bool(proxy))
    return _compact(res)


tools = [proxy_latency, proxy_ssl_cost, proxy_load, proxy_stress]
tools_by_name = {t.name: t for t in tools}


# --------------------------------------------------------------------------- #
# LLM (AIHub / LiteLLM ic endpoint)
# --------------------------------------------------------------------------- #
# Kurumsal proxy/inspection sertifikasi yuzunden SSL dogrulama sorun cikarabilir.
# En saglami: kurumsal CA paketini ver -> verify="/path/to/corp-ca.pem"
# Hizli/gecici cozum (guvenligi dusurur): verify=False
http_client = httpx.Client(verify=False)   # PROD'da kurumsal CA paketiyle degistir

llm_base = None
llm = None


def load_ai_environment():
    """Load local AI settings without overriding explicit environment values."""
    load_dotenv(Path(__file__).with_name(".env"), override=False)


def configure_llm():
    """Validate settings and initialize the optional AI layer on first use."""
    global llm_base, llm
    if llm_base is not None:
        return llm_base
    load_ai_environment()
    base_url = os.environ.get("BOTTLENECK_LLM_BASE_URL")
    api_key = os.environ.get("BOTTLENECK_LLM_API_KEY")
    if not base_url or not api_key:
        raise RuntimeError("AI yorumu icin BOTTLENECK_LLM_BASE_URL ve BOTTLENECK_LLM_API_KEY gerekli")
    llm_base = ChatOpenAI(
        model=os.environ.get("BOTTLENECK_LLM_MODEL", "gpt-4o"),
        base_url=base_url,
        api_key=api_key,
        temperature=0,
        http_client=http_client,
    )
    llm = llm_base.bind_tools(tools)
    return llm_base


def check_ai_connection():
    """Make a minimal request to validate AI endpoint, credentials, and model access."""
    load_ai_environment()
    return run_ai_connection_check(
        lambda: configure_llm().invoke(
            [HumanMessage(content="Reply only with OK")]
        ).content,
        os.environ.get("BOTTLENECK_LLM_MODEL", "gpt-4o"),
    )


SYSTEM = SystemMessage(content=(
    "Sen bir proxy performans analiz asistanisin. Kullanici bir proxy/web sitesi "
    "performansi sordugunda uygun olcum aracini cagir. Sonuc JSON'unu Turkce, kisa "
    "ve eyleme donuk yorumla: hangi faz darbogaz, proxy overhead'i ne, kirilma "
    "noktasi nerede. Sayilari ms cinsinden ve p50/p95/p99 ayrimiyla acikla."
))

# Manuel mod icin yorumcu (tool YOK; tek isi metin uretmek)
YORUMCU = SystemMessage(content=(
    "Sen bir proxy performans analiz uzmanisin. Sana bir olcum sonucu JSON'u "
    "verilecek. Turkce, kisa ve eyleme donuk yorumla: hangi faz darbogaz "
    "(DNS/TCP/TLS/sunucu/transfer), varsa proxy overhead'i, p50/p95/p99 ayrimi "
    "ve kirilma noktasi. Sadece veriye dayan, uydurma."
))


# --------------------------------------------------------------------------- #
# MANUEL MOD: testi SEN calistir, sonucu LLM yorumlasin (tool dongusu yok)
# --------------------------------------------------------------------------- #
def yorumla(result: dict, ek_soru: str = "") -> str:
    """Senin calistirdigin bir test sonucu sozlugunu LLM'e yorumlatir."""
    ozet = bh._summary_view(result)              # ham raw/samples temizlenir
    icerik = "Olcum sonucu:\n" + json.dumps(ozet, ensure_ascii=False, indent=2)
    if ek_soru:
        icerik += f"\n\nEk soru: {ek_soru}"
    response = configure_llm().invoke([YORUMCU, HumanMessage(content=icerik)])
    print(response.content)
    return response.content


def yorumla_dosya(json_path: str, ek_soru: str = "") -> str:
    """Daha once --prefix ile kaydedilmis bir rapor JSON'unu yorumlatir."""
    with open(json_path, "r", encoding="utf-8") as f:
        return yorumla(json.load(f), ek_soru)


# --------------------------------------------------------------------------- #
# Agent dongusu (senin ask fonksiyonunun cok-turlu, saglamlastirilmis hali)
# --------------------------------------------------------------------------- #
def ask(soru: str, max_steps: int = 5):
    configure_llm()
    print(f"\nSoru: {soru}")
    messages = [SYSTEM, HumanMessage(content=soru)]

    for _ in range(max_steps):
        response = llm.invoke(messages)
        messages.append(response)

        # Tool cagrisi yoksa nihai cevap gelmistir
        if not response.tool_calls:
            print(f"\nYorum: {response.content}")
            return response.content

        # Tum tool cagrilarini calistir, sonuclari geri besle
        for tc in response.tool_calls:
            print(f"→ Arac cagrisi: {tc['name']}({tc['args']})")
            tool = tools_by_name.get(tc["name"])
            if tool is None:
                tool_result = f"Hata: bilinmeyen arac '{tc['name']}'"
            else:
                try:
                    tool_result = tool.invoke(tc["args"])   # zaten string dondurur
                except Exception as e:
                    tool_result = f"Hata: {e}"
            if not isinstance(tool_result, str):
                tool_result = json.dumps(tool_result, ensure_ascii=False)
            print("→ Sonuc alindi")
            messages.append(ToolMessage(content=tool_result, tool_call_id=tc["id"]))

        # Donguye devam: LLM sonuclari gorup ya yorumlar ya da yeni tool cagirir

    print("\n(max_steps asildi)")
    return None


def run():
    """Bottleneck Hunter'i normal CLI/menu akisiyla calistir; bittikten sonra
    sonucu LLM'e yorumlat. Test ciktisi onceki gibi komut ekraninda gorunur,
    en sonda 'AI Yorumu' bolumu eklenir."""
    import sys
    if "--check-ai" in sys.argv:
        raise SystemExit(print_ai_check(check_ai_connection()))

    original_argv = list(sys.argv)
    save_final_report = "--no-save" not in original_argv
    prefix = "bottleneck"
    if "--prefix" in original_argv:
        prefix = original_argv[original_argv.index("--prefix") + 1]

    if len(sys.argv) == 1:
        bh.setup_color()
        res = bh.interactive(
            save_prompt=False,
            ai_check=lambda: print_ai_check(check_ai_connection()),
        )  # Nihai rapor AI yorumundan sonra yazilir.
    else:
        if save_final_report:
            sys.argv.append("--no-save")
        try:
            res = bh.main()             # alt komut: python bh_agent.py latency --url ...
        finally:
            sys.argv[:] = original_argv

    if not res:
        return

    print("\n" + bh.c("=" * 28 + " AI Yorumu " + "=" * 28, bh.Ansi.MAGENTA, bold=True))
    try:
        res["ai_analysis"] = yorumla(res)
    except Exception as e:
        print(bh.c(f"AI yorumu alinamadi: {e}", bh.Ansi.RED))
        print(bh.c("(Endpoint/SSL ayarlarini ve agi kontrol et.)", bh.Ansi.GREY))
    if save_final_report:
        bh.save_report(res, prefix=prefix)


if __name__ == "__main__":
    run()
