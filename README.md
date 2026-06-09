# Bottleneck Hunter

**Proxy / web proxy performans ve gecikme analiz aracı** — v1.1.0

Bottleneck Hunter, bir forward/web proxy'nin (ör. Forcepoint WCG) bir isteğe kattığı gecikmeyi tek bir rakama indirgemek yerine **fazlarına ayırarak** ölçer: DNS çözümleme, TCP bağlantısı, TLS el sıkışması, sunucu işleme (TTFB) ve transfer. Böylece darboğazın proxy'de mi yoksa upstream'de mi olduğunu, SSL inspection'ın ne kadar maliyet getirdiğini, sistemin hangi yükte kırıldığını ve gerçek bir tarayıcının render dahil sayfayı ne kadar sürede açtığını ayrı ayrı görürsün.

İki bileşenden oluşur:

- **`bottleneck_hunter.py`** — Çekirdek ölçüm aracı. Tek dosya, CLI + etkileşimli menü. AI olmadan tek başına çalışır.
- **`bh_agent.py`** — Üstüne eklenen LLM yorum katmanı. Testi sen çalıştırırsın, sonucu bir LLM (AIHub/LiteLLM endpoint'i) Türkçe yorumlar.

---

## İçindekiler

1. [Kurulum](#kurulum)
2. [Hızlı başlangıç](#hızlı-başlangıç)
3. [Test modülleri](#test-modülleri)
4. [Ortak seçenekler](#ortak-seçenekler)
5. [Çıktı ve raporlar](#çıktı-ve-raporlar)
6. [Renkler ve metrik eşikleri](#renkler-ve-metrik-eşikleri)
7. [SSL / izole ağ notları](#ssl--izole-ağ-notları)
8. [AI yorum katmanı (bh_agent.py)](#ai-yorum-katmanı-bh_agentpy)
9. [Operasyonel uyarılar](#operasyonel-uyarılar)
10. [Sık karşılaşılan sorunlar](#sık-karşılaşılan-sorunlar)

---

## Kurulum

```bash
# Çekirdek araç (zorunlu)
pip install pycurl

# Gelistirme ve test bagimliliklari
pip install -e '.[test]'

# Tarayıcı modülü için (yalnızca 'browser' testini kullanacaksan)
pip install playwright
playwright install chromium

# AI yorum katmanı için (yalnızca bh_agent.py kullanacaksan)
pip install langchain-openai langchain-core httpx
```

İki Python dosyası (`bottleneck_hunter.py` ve `bh_agent.py`) **aynı klasörde** durmalı; agent, çekirdeği modül olarak içe aktarır.

`pycurl`, libcurl'e bağlanır. Windows'ta genelde Schannel (yerel TLS) backend'i ile gelir — bu, izole ağda revocation davranışını etkiler; bkz. [SSL / izole ağ notları](#ssl--izole-ağ-notları).

---

## Hızlı başlangıç

**Etkileşimli menü** (argümansız çalıştır, sorular sorar, sen seçersin):

```bash
python bottleneck_hunter.py
```

**Doğrudan komutla:**

```bash
# Tek hedef için faz kırılımı, proxy ile direct karşılaştırması
python bottleneck_hunter.py latency --url https://intranet.local \
    --proxy http://10.0.0.1:8080 --ssl-no-revoke --repeat 20

# Kırılma noktası testi
python bottleneck_hunter.py stress --url https://intranet.local \
    --proxy http://10.0.0.1:8080 --start 10 --step 10 --max 200 --authorized-target

# Tüm testler tek seferde
python bottleneck_hunter.py full --url https://intranet.local \
    --proxy http://10.0.0.1:8080 --bypass-url https://bypass.local --browser --authorized-target
```

Global seçenekler (`--proxy`, `--no-color` vb.) hem alt komuttan önce hem sonra verilebilir.

---

## Test modülleri

| # | Komut | Ne ölçer | Asıl sorusu |
|---|-------|----------|-------------|
| 1 | `latency` | Tek isteğin faz kırılımı + proxy overhead | "Gecikme nerede harcanıyor? Proxy kaç ms ekliyor?" |
| 2 | `ssl` | SSL inspection maliyeti (inspekte vs bypass) | "Decrypt/re-encrypt kaç ms'ye mal oluyor?" |
| 3 | `load` | Sabit eşzamanlılık seviyelerinde p50/p95/p99 | "Beklenen yükte nasıl davranıyor?" |
| 4 | `throughput` | Büyük dosya indirme, efektif Mbps | "Bant genişliği ne?" |
| 5 | `cache` | Cache miss vs hit süresi | "Cache çalışıyor mu, ne kadar kazandırıyor?" |
| 6 | `soak` | Uzun süreli sabit yük altında degradasyon | "Zamanla yavaşlıyor / birikme var mı?" |
| 7 | `stress` | Kademeli rampa ile kırılma noktası (+ spike) | "Tam olarak nerede kırılıyor, toparlanıyor mu?" |
| 8 | `browser` | Gerçek tarayıcı ile render dahil sayfa açılışı | "Kullanıcı tarayıcıda ne hissediyor?" |
| 9 | `full` | Yukarıdakilerin sırayla çalışması | Bütünsel profil |

### 1. latency

Faz kırılımı: `dns`, `tcp`, `tls`, `server` (TTFB), `transfer`. Proxy verilirse hem direct hem proxy ölçülür ve **proxy overhead** (p50 toplam farkı) hesaplanır.

```bash
python bottleneck_hunter.py latency --url https://x --repeat 20 [--no-direct]
```

| Seçenek | Varsayılan | Açıklama |
|---------|-----------|----------|
| `--url` | (zorunlu) | Hedef URL |
| `--repeat` | 20 | Tekrar sayısı |
| `--no-direct` | — | Direct baseline'ı atla (yalnız proxy) |

### 2. ssl

İnspekte edilen bir domain ile bypass listesindeki bir domaini proxy üzerinden kıyaslar; TLS fazındaki farkı SSL inspection maliyeti olarak verir.

```bash
python bottleneck_hunter.py ssl --url https://inspekte.com --bypass-url https://bypass.com --proxy http://p:8080
```

### 3. load

Artan eşzamanlılık seviyelerinde sabit sayıda istek atar; her seviyede p50/p95/p99, RPS ve hata oranını ölçer, olası kırılma noktasını işaretler. **Kapalı model** (sabit işçi havuzu).

```bash
python bottleneck_hunter.py load --url https://x --levels 10,25,50,100 --requests 200
```

| Seçenek | Varsayılan | Açıklama |
|---------|-----------|----------|
| `--levels` | 10,25,50,100 | Eşzamanlılık seviyeleri (virgülle) |
| `--requests` | 200 | Her seviyede atılacak istek |
| `--no-proxy-mode` | — | Proxy yerine direct yükle |

### 4. throughput

Büyük bir dosyayı indirip efektif Mbps hesaplar.

```bash
python bottleneck_hunter.py throughput --url https://x/bigfile.bin --repeat 5
```

### 5. cache

Aynı kaynağı arka arkaya iki kez ister (miss → hit) ve iyileşme yüzdesini verir. Büyük fark cache hit'e işaret eder; `X-Cache` benzeri header ile doğrula.

```bash
python bottleneck_hunter.py cache --url https://x --rounds 5
```

### 6. soak

Belirtilen süre boyunca sabit eşzamanlılıkta yük uygular, zaman serisi p50/p95 üretir ve **p95 sürüklenmesini** (ilk %20 vs son %20) hesaplar. Bellek sızıntısı / birikme tespiti için.

```bash
python bottleneck_hunter.py soak --url https://x --duration 600 --interval 5 --concurrency 5
```

### 7. stress

İki modu var.

**Rampa (varsayılan):** Eşzamanlılığı `--start`'tan `--max`'a `--step` ile çıkarır; her seviyeyi `--stage-duration` saniye sürekli yük altında tutar. Hata oranı `--err-threshold`'u (%10) aşınca ya da p95, baseline'in `--latency-factor` katını (4x) geçince **otomatik durur**. Pik throughput ve kırılma noktasını verir.

**Spike (`--spike`):** Düşük baseline → ani yüksek yük → tekrar düşük (recovery). Toparlanma oranını (recovery p95 / baseline p95) ölçer.

```bash
python bottleneck_hunter.py stress --url https://x --start 10 --step 10 --max 300 --stage-duration 15
python bottleneck_hunter.py stress --url https://x --spike --start 5 --max 200 --stage-duration 20
```

| Seçenek | Varsayılan | Açıklama |
|---------|-----------|----------|
| `--start` | 10 | Başlangıç eşzamanlılık |
| `--step` | 10 | Her stage'de artış |
| `--max` | 200 | Üst sınır |
| `--stage-duration` | 15 | Her stage süresi (sn) |
| `--err-threshold` | 10.0 | Kırılma: hata oranı % eşiği |
| `--latency-factor` | 4.0 | Kırılma: p95 baseline'in kaç katı |
| `--spike` | — | Rampa yerine şok + toparlanma |

### 8. browser

Gerçek Chromium başlatıp sayfayı render dahil açar; tarayıcının Performance API'lerinden **TTFB, FCP, LCP, DOMContentLoaded, load** ve istek sayısını toplar. Proxy ve SSL ayarlarını devralır. Her tekrar taze context = soğuk yükleme.

```bash
python bottleneck_hunter.py browser --url https://x --proxy http://p:8080 --repeat 5 [--headed]
```

> **Not:** `latency` modülü yalnızca tek bir HTTP isteğinin ağ fazlarını ölçer; render, JS yürütme, alt kaynaklar ve cache yoktur. Gerçek kullanıcı deneyimini ölçmek için `browser` modülünü kullan. İkisi birlikte "ağ maliyeti" ile "kullanıcının hissettiği süre"yi yan yana koyar.

### 9. full

Tek `--url` ile latency + load + cache çalıştırır; `--bypass-url`, `--throughput-url`, `--browser`, `--soak` verilirse ilgili testleri de ekler.

```bash
python bottleneck_hunter.py full --url https://x --proxy http://p:8080 \
    --bypass-url https://bypass.com --throughput-url https://x/big.bin \
    --browser --soak 300
```

---

## Ortak seçenekler

Tüm alt komutlarda geçerli:

| Seçenek | Açıklama |
|---------|----------|
| `--proxy` | Proxy adresi, ör. `http://10.0.0.1:8080` |
| `--proxy-user` | Proxy auth, `kullanici:parola` |
| `--insecure` | SSL sertifika doğrulamasını tamamen atla |
| `--ssl-no-revoke` | CRL/OCSP revocation kontrolünü kapat (Schannel/izole ağ) |
| `--timeout` | İstek timeout (sn, varsayılan 30) |
| `--connect-timeout` | Bağlantı timeout (sn, varsayılan 10) |
| `--header` | Ek HTTP header (birden çok kez verilebilir) |
| `--no-color` | Renkli çıktıyı kapat |
| `--no-save` | Raporu dosyaya yazma |
| `--prefix` | Çıktı dosyası ön eki (varsayılan `bottleneck`) |

URL'yi şemasız (`x.com`) verirsen araç otomatik `https://` ekler.

---

## Çıktı ve raporlar

Her koşu sonunda üç dosya yazılır (`--no-save` ile kapatılır):

- **`<prefix>_<test>_<zaman>.json`** — Tam sonuç (ham örnekler dahil).
- **`<prefix>_<test>_<zaman>_samples.csv`** — Tekil istek örnekleri (varsa). curl ve tarayıcı örnekleri aynı dosyada farklı sütunlarla birleşir.
- **`<prefix>_<test>_<zaman>_summary.txt`** — Ham örnekler atılmış okunabilir özet.

Tüm metrikler **p50/p95/p99** ayrımıyla raporlanır; ayrıca min, max, ortalama ve standart sapma.

---

## Renkler ve metrik eşikleri

Önemli/farklı değerler renklendirilir: **yeşil** = iyi, **sarı** = orta, **kırmızı** = kötü/yavaş, **cyan** = başlık/etiket, **magenta** = özet satırları ve faz kırılımında **zamanın en çok gittiği faz** (vurgulu). Renk, Windows cmd/PowerShell'de VT modu açılarak çalışır (`colorama` varsa onu kullanır); çıktı bir dosyaya/pipe'a yönlendirilince veya `--no-color` ile otomatik kapanır.

Renklendirme eşikleri (milisaniye; `iyi ≤ ilk değer`, `orta ≤ ikinci değer`, üstü kırmızı):

| Metrik | İyi (yeşil) | Orta (sarı) | Kötü (kırmızı) |
|--------|-------------|-------------|----------------|
| dns | ≤ 20 | ≤ 80 | > 80 |
| tcp | ≤ 30 | ≤ 100 | > 100 |
| tls | ≤ 80 | ≤ 250 | > 250 |
| server (TTFB) | ≤ 200 | ≤ 600 | > 600 |
| transfer | ≤ 100 | ≤ 400 | > 400 |
| total | ≤ 300 | ≤ 1000 | > 1000 |
| ttfb (browser) | ≤ 200 | ≤ 600 | > 600 |
| fcp | ≤ 1000 | ≤ 2500 | > 2500 |
| lcp | ≤ 2500 | ≤ 4000 | > 4000 |
| dcl | ≤ 1500 | ≤ 3500 | > 3500 |
| load | ≤ 2000 | ≤ 4500 | > 4500 |

Bu eşikler genel bir referanstır; kendi ortamına göre `bottleneck_hunter.py` içindeki `THRESHOLDS` sözlüğünden ayarlayabilirsin.

---

## SSL / izole ağ notları

İnternet-izole bir Windows ortamında en sık karşılaşılan hata:

```
(35, 'schannel: next InitializeSecurityContext failed')
```

**Sebep:** Windows'un yerel TLS katmanı (Schannel), sertifikayı doğrularken CA'nın CRL/OCSP uçlarına gidip "iptal edilmiş mi?" diye sorar. İzole ağda bu uçlara ulaşılamayınca Schannel el sıkışmayı **reddeder** — sertifikada sorun olmasa bile.

**Çözüm:** `--ssl-no-revoke` (libcurl `SSLOPT_NO_REVOKE`). Revocation kontrolünü atlar, ulaşılamayan uçlar artık bağlantıyı bozmaz.

Teşhis sırası:
1. `--ssl-no-revoke` ile düzeliyorsa → sebep revocation idi.
2. Yalnız `--insecure` ile düzeliyorsa → sertifika zinciri güveni (büyük olasılıkla kurumsal inspection CA'sı Windows mağazasında değil).
3. İkisi de düzeltmiyorsa → transport sorunu; o hedefe ağdan direct çıkılamıyor, proxy üzerinden test et.

> `--insecure` TLS doğrulamayı baypas ettiği için ölçtüğün TLS faz süresi gerçeği tam yansıtmayabilir; teşhis için iyi, nihai raporda revocation'ı kapatıp doğrulamayı açık tutmak daha sağlıklı.

---

## AI yorum katmanı (bh_agent.py)

Testi sen çalıştırırsın, sonucu bir LLM yorumlar. Tool seçtirme yok (manuel mod); istersen LLM'in tool seçtiği otomatik mod da var.

**Önce yapılandır:** `.env.example` dosyasındaki `BOTTLENECK_LLM_MODEL`, `BOTTLENECK_LLM_BASE_URL` ve `BOTTLENECK_LLM_API_KEY` değişkenlerini ortamında tanımla. Kurumsal sertifika için `http_client` satırını `httpx.Client(verify="/path/kurumsal-ca.pem")` yap.

### Manuel mod (önerilen)

CLI/menü akışını çalıştırır, normal çıktıyı ekrana basar, **sonunda "AI Yorumu" bölümü** ekler:

```bash
# Menü ile (baştaki gibi)
python bh_agent.py

# Ya da doğrudan alt komutla — aynı bayraklar, sonunda AI Yorumu çıkar
python bh_agent.py latency --url https://intranet.local --proxy http://10.0.0.1:8080 --ssl-no-revoke --repeat 20
```

Kendi kodundan da çağırabilirsin:

```python
import bottleneck_hunter as bh
from bh_agent import yorumla, yorumla_dosya

cfg = bh.ProxyConfig(proxy="http://10.0.0.1:8080", ssl_no_revoke=True)
sonuc = bh.test_latency("https://intranet.local", cfg, repeat=20)  # SEN çalıştır

yorumla(sonuc)                               # O yorumlasın
yorumla(sonuc, "bu overhead kabul edilebilir mi?")   # yönlendir
yorumla_dosya("bottleneck_latency_20260602.json")    # kayıtlı rapordan
```

LLM'e gönderilen içerik, ham örnekler atılmış özet JSON'dur (token tasarrufu + daha iyi yorum).

### Otomatik mod

LLM uygun proxy testini kendisi seçip çalıştırır, sonra yorumlar. Çok turlu (önce latency, sonra stress gibi). Tool'lar: `proxy_latency`, `proxy_ssl_cost`, `proxy_load`, `proxy_stress`.

```python
from bh_agent import ask
ask("intranet.local proxy http://10.0.0.1:8080 üzerinden ne kadar yavaşlıyor?")
```

> Otomatik modda LLM, yük üreten `proxy_load`/`proxy_stress` araçlarını kendi kararıyla tetikleyebilir. Canlı proxy'yi korumak istiyorsan bu araçları devre dışı bırak veya çağrı öncesi insan onayı ekle.

---

## Operasyonel uyarılar

- **`load` ve `stress` gerçek yük üretir.** Yalnızca yetkili test/staging hedeflerine uygula; canlı proxy'yi vurma, gerçek kullanıcıları etkilersin.
- **Tek makineli üreteç.** Bu kapalı-model üreteç, tek makinenin CPU/soket limitiyle sınırlıdır. Ölçtüğün kırılma bazen proxy'nin değil **kendi test makinenin** limiti olabilir; emin olmak için test makinesinin CPU'suna bak ve aynı testi ikinci bir makineden de koş. On binlerce RPS'lik gerçek açık-model stres için k6/vegeta/wrk dağıtık koşmak daha doğru.
- **Tutarlı baseline.** Gerçek "boştaki" gecikmeyi görmek için ilk seviyenin eşzamanlılığını düşük tut (`--start 1`).

---

## Sık karşılaşılan sorunlar

**`(35) schannel ... InitializeSecurityContext failed`** → İzole ağda revocation kontrolü; `--ssl-no-revoke` ekle. Bkz. [SSL / izole ağ notları](#ssl--izole-ağ-notları).

**`Cannot navigate to invalid URL` (browser)** → URL'yi şemayla ver (`https://...`). Araç şemasız host'a otomatik `https://` ekler ama tam URL en güvenlisi.

**Renkler ANSI kodu olarak görünüyor (`\033[...`)** → Konsol VT modunu desteklemiyor; `pip install colorama` ya da `--no-color`.

**`browser` testi çalışmıyor / Chromium bulunamadı** → `playwright install chromium`. İnternet-izole makinede bu indirme takılır; Chromium'u erişimi olan bir makinede indirip `%USERPROFILE%\AppData\Local\ms-playwright` klasörünü kopyala veya `PLAYWRIGHT_BROWSERS_PATH` ile elle yerleştir.

**AI Yorumu bölümünde hata** → Endpoint/SSL ayarı; `base_url`, `api_key` ve kurumsal CA (`verify`) kontrolü. Test çıktın bu hatadan etkilenmez, yalnızca AI bölümü atlanır.
