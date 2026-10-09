# Biçim fixture'ları: bayt dönüşüm manifesti

Bu klasördeki bazı fixture'lar Write aracıyla birebir üretilemeyen baytlar
içerir: UTF-8 BOM, CRLF/CR satır sonu, kontrol karakterleri, Unicode satır
ayırıcıları ve geçersiz UTF-8. Bu dosyalar **şablon** olarak yazıldı.
Şablonda `{AD}` biçimli belirteçler ve satır sonu kuralı kullanılır. Ana
oturum, Python golden çıktılarını üretmeden **önce** aşağıdaki betiği bir kez
çalıştırır. Betik idempotenttir, ikinci çalıştırma dosyaları değiştirmez.

> Sıra: (1) bu dönüşüm, (2) doğrulama çıktısının kontrolü, (3) golden üretimi
> (`python -m src.scanner.sandbox.parsers.scan --scan-id <id> --work-dir <vaka> --ecosystems nodejs,python`),
> (4) commit. `tests/fixtures/.gitattributes` (`* -text`) baytları korur.

## Belirteçler

| Belirteç | Bayt(lar) | Anlam |
| --- | --- | --- |
| `{BOM}` | `EF BB BF` | Dosya başı UTF-8 BOM |
| `{BOMCHAR}` | `EF BB BF` | Dosya ortasında U+FEFF (Python'da boşluk değildir) |
| `{SP}` | `20` | Boşluk (satır sonu boşluğu görünür kalsın diye) |
| `{TAB}` | `09` | Sekme |
| `{LF}` / `{CR}` / `{CRLF}` | `0A` / `0D` / `0D 0A` | Yalnız `raw` dosyalarda, karışık satır sonu |
| `{VT}` `{FF}` | `0B` `0C` | `str.splitlines` ayırıcıları |
| `{FS}` `{GS}` `{RS}` | `1C` `1D` `1E` | `str.splitlines` ayırıcıları (aynı zamanda `isspace`) |
| `{US}` | `1F` | `isspace` ama satır ayırıcı değil |
| `{NEL}` | `C2 85` | U+0085, satır ayırıcı |
| `{NBSP}` | `C2 A0` | U+00A0, boşluk |
| `{LS}` / `{PS}` | `E2 80 A8` / `E2 80 A9` | U+2028 / U+2029, satır ayırıcı |
| `{IDSP}` | `E3 80 80` | U+3000, boşluk |
| `{EMSP}` | `E2 80 83` | U+2003, boşluk |
| `{ZWSP}` | `E2 80 8B` | U+200B, boşluk **değil** |
| `{XNN}` | `NN` (tek ham bayt) | Geçersiz UTF-8 üretmek için (ör. `{XFF}`, `{XE9}`) |

## Dosya listesi

`eol`: `lf` = tüm satır sonları LF; `crlf` = tüm satır sonları CRLF; `cr` = tüm
satır sonları yalnız CR; `raw` = satır sonu dönüşümü yok, satır sonları
belirteçle verilir (dosya tek satırlık şablondur). `final`: `false` ise dosya
sonundaki satır sonu kaldırılır.

| Dosya (`formats/` altında) | eol | Belirteçler | Amaç |
| --- | --- | --- | --- |
| `npm-yarn-v1-crlf/yarn.lock` | crlf | — | AC-P10-8: `npm-yarn-v1-basic/yarn.lock` ile aynı içerik, CRLF |
| `npm-yarn-v1-quirks/yarn.lock` | lf, final=false | `{SP}` `{TAB}` | Satır sonu boşluğu, yalnız boşluk satırı, sekmeyle girintili satır, son satırda satır sonu yok |
| `npm-yarn-separators/yarn.lock` | lf | `{US}` `{NEL}` `{NBSP}` `{XE9}` `{VT}` `{LS}` `{ZWSP}` | `pySplitLines`/`pyRstrip`, geçersiz UTF-8 adı |
| `py-requirements-crlf/requirements.txt` | crlf | — | AC-P10-8: `py-requirements-basic/requirements.txt` ile aynı içerik, CRLF |
| `py-requirements-cr-only/requirements.txt` | cr | — | Yalnız CR satır sonu (Python evrensel satır sonu) |
| `py-requirements-mixed-eol/requirements.txt` | raw | `{LF}` `{CR}` `{CRLF}` | Aynı dosyada karışık satır sonu |
| `py-requirements-separators/requirements.txt` | lf | `{VT}` `{FF}` `{FS}` `{GS}` `{RS}` `{NEL}` `{LS}` `{PS}` `{US}` `{NBSP}` `{IDSP}` `{EMSP}` `{ZWSP}` `{BOMCHAR}` | `splitlines`, `strip`, `\s` kümeleri |
| `py-requirements-invalid-utf8/requirements.txt` | lf | `{XE9}` `{XFF}` `{XE2}` `{X82}` `{XC3}` `{XED}` `{XA0}` `{X80}` | `errors="replace"` (U+FFFD sayısı) |
| `npm-errors/invalid-utf8/package.json` | lf | `{XFF}` | Katı UTF-8 JSON okuma hatası |
| `py-errors/invalid-utf8-pyproject/pyproject.toml` | lf | `{XFF}` | Katı UTF-8 TOML okuma hatası |
| `py-errors/invalid-utf8-poetry-lock/poetry.lock` | lf | `{XFF}` | Katı UTF-8 TOML okuma hatası |
| `py-pyproject-crlf/pyproject.toml` | crlf | — | CRLF TOML |
| `py-pyproject-crlf/poetry.lock` | crlf | — | CRLF TOML |
| `py-pyproject-cr-only/pyproject.toml` | cr | — | Yalnız CR TOML (Python evrensel satır sonuyla geçerli okur) |
| `bom-manifests/npm-package-json/package.json` | lf | `{BOM}` | BOM'lu JSON hatası |
| `bom-manifests/npm-package-lock/package-lock.json` | lf | `{BOM}` | BOM'lu kilit hatası, kayıt `package.json` yolunda |
| `bom-manifests/npm-yarn-lock/yarn.lock` | lf | `{BOM}` | BOM ilk girdi adına yapışır |
| `bom-manifests/npm-yarn-lock-comment-first/yarn.lock` | lf | `{BOM}` | BOM yorum satırına yapışır |
| `bom-manifests/py-requirements/requirements.txt` | lf | `{BOM}` | İlk satır atlanır |
| `bom-manifests/py-requirements-dev/requirements-dev.txt` | lf | `{BOM}` | İlk satır yorum, kayıp yok |
| `bom-manifests/py-requirements-test/requirements-test.txt` | lf | `{BOM}` | Tek satır, bağımlılık üretmez |
| `bom-manifests/py-pyproject/pyproject.toml` | lf | `{BOM}` | BOM'lu TOML hatası |
| `bom-manifests/py-pyproject-comment-first/pyproject.toml` | lf | `{BOM}` | Yorumla başlasa da TOML hatası |
| `bom-manifests/py-poetry-lock/poetry.lock` | lf | `{BOM}` | BOM'lu `poetry.lock` hatası |

**Boş (0 bayt) olması gereken dosyalar.** Dönüşüm gerekmez, betik boyutu
doğrular:

- `npm-errors/empty-package-json/package.json`
- `npm-errors/empty-lock/package-lock.json`
- `npm-errors/empty-yarn/yarn.lock`
- `py-errors/empty-pyproject/pyproject.toml`
- `py-errors/empty-poetry-lock/poetry.lock`
- `py-errors/empty-requirements/requirements.txt`

Listede olmayan her vaka dosyası düz UTF-8, BOM'suz ve LF'dir. Betik bunu da
doğrular: listede olmayan dosyada `0D` baytı veya `{AD}` belirteci kalırsa
hata verir.

## Betik

Depo kökünden çalıştırılır (`node <betik-yolu>`). Betik dosyası scratchpad'e
kopyalanabilir, depoya eklenmesi gerekmez.

```js
'use strict';
// REQ-003 P-10 biçim fixture'ları: idempotent bayt dönüşümü ve doğrulama.
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const BASE = path.join(process.cwd(), 'tests', 'fixtures', 'p10-golden', 'formats');

const NAMED = {
  BOM: 'efbbbf', BOMCHAR: 'efbbbf', SP: '20', TAB: '09', LF: '0a', CR: '0d', CRLF: '0d0a',
  VT: '0b', FF: '0c', FS: '1c', GS: '1d', RS: '1e', US: '1f',
  NEL: 'c285', NBSP: 'c2a0', LS: 'e280a8', PS: 'e280a9', IDSP: 'e38080', EMSP: 'e28083', ZWSP: 'e2808b',
};

const FILES = {
  'npm-yarn-v1-crlf/yarn.lock': { eol: 'crlf' },
  'npm-yarn-v1-quirks/yarn.lock': { eol: 'lf', final: false },
  'npm-yarn-separators/yarn.lock': { eol: 'lf' },
  'py-requirements-crlf/requirements.txt': { eol: 'crlf' },
  'py-requirements-cr-only/requirements.txt': { eol: 'cr' },
  'py-requirements-mixed-eol/requirements.txt': { eol: 'raw' },
  'py-requirements-separators/requirements.txt': { eol: 'lf' },
  'py-requirements-invalid-utf8/requirements.txt': { eol: 'lf' },
  'npm-errors/invalid-utf8/package.json': { eol: 'lf' },
  'py-errors/invalid-utf8-pyproject/pyproject.toml': { eol: 'lf' },
  'py-errors/invalid-utf8-poetry-lock/poetry.lock': { eol: 'lf' },
  'py-pyproject-crlf/pyproject.toml': { eol: 'crlf' },
  'py-pyproject-crlf/poetry.lock': { eol: 'crlf' },
  'py-pyproject-cr-only/pyproject.toml': { eol: 'cr' },
  'bom-manifests/npm-package-json/package.json': { eol: 'lf' },
  'bom-manifests/npm-package-lock/package-lock.json': { eol: 'lf' },
  'bom-manifests/npm-yarn-lock/yarn.lock': { eol: 'lf' },
  'bom-manifests/npm-yarn-lock-comment-first/yarn.lock': { eol: 'lf' },
  'bom-manifests/py-requirements/requirements.txt': { eol: 'lf' },
  'bom-manifests/py-requirements-dev/requirements-dev.txt': { eol: 'lf' },
  'bom-manifests/py-requirements-test/requirements-test.txt': { eol: 'lf' },
  'bom-manifests/py-pyproject/pyproject.toml': { eol: 'lf' },
  'bom-manifests/py-pyproject-comment-first/pyproject.toml': { eol: 'lf' },
  'bom-manifests/py-poetry-lock/poetry.lock': { eol: 'lf' },
};

const EMPTY = [
  'npm-errors/empty-package-json/package.json',
  'npm-errors/empty-lock/package-lock.json',
  'npm-errors/empty-yarn/yarn.lock',
  'py-errors/empty-pyproject/pyproject.toml',
  'py-errors/empty-poetry-lock/poetry.lock',
  'py-errors/empty-requirements/requirements.txt',
];

const TOKEN = /\{([A-Z][A-Z0-9]*)\}/g;

function tokenBytes(name) {
  const hex = NAMED[name] ?? (/^X[0-9A-F]{2}$/.test(name) ? name.slice(1).toLowerCase() : null);
  if (hex === null) throw new Error(`bilinmeyen belirteç {${name}}`);
  return Buffer.from(hex, 'hex').toString('latin1');
}

function abs(rel) {
  return path.join(BASE, ...rel.split('/'));
}

// 1) Dönüşüm (latin1 = bayt bayt gidiş-dönüş).
for (const [rel, opt] of Object.entries(FILES)) {
  let s = fs.readFileSync(abs(rel)).toString('latin1');
  if (opt.eol !== 'raw') {
    s = s.replace(/\r\n?/g, '\n');
    if (opt.final === false) s = s.replace(/\n+$/, '');
    if (opt.eol === 'crlf') s = s.replace(/\n/g, '\r\n');
    if (opt.eol === 'cr') s = s.replace(/\n/g, '\r');
  }
  s = s.replace(TOKEN, (_, name) => tokenBytes(name));
  fs.writeFileSync(abs(rel), Buffer.from(s, 'latin1'));
}

// 2) Doğrulama: yalnız vaka klasörleri (formats/ altındaki README/MANIFEST hariç).
const problems = [];
function walk(dir) {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, e.name);
    if (e.isDirectory()) walk(full);
    else if (e.isFile()) check(full);
  }
}
function check(full) {
  const rel = path.relative(BASE, full).split(path.sep).join('/');
  const buf = fs.readFileSync(full);
  const latin = buf.toString('latin1');
  if (latin.match(TOKEN)) problems.push(`${rel}: belirteç kaldı`);
  if (!FILES[rel] && buf.includes(0x0d)) problems.push(`${rel}: listede değil ama CR içeriyor`);
  if (!FILES[rel] && buf.subarray(0, 3).equals(Buffer.from('efbbbf', 'hex'))) problems.push(`${rel}: listede değil ama BOM içeriyor`);
  if (EMPTY.includes(rel) && buf.length !== 0) problems.push(`${rel}: 0 bayt olmalı (${buf.length})`);
}
for (const e of fs.readdirSync(BASE, { withFileTypes: true })) {
  if (e.isDirectory()) walk(path.join(BASE, e.name));
}
const opt = (rel) => FILES[rel];
for (const rel of Object.keys(FILES)) {
  const buf = fs.readFileSync(abs(rel));
  const o = opt(rel);
  if (o.eol === 'crlf' && /(^|[^\r])\n/.test(buf.toString('latin1'))) problems.push(`${rel}: CRLF olmayan LF var`);
  if (o.eol === 'cr' && buf.includes(0x0a)) problems.push(`${rel}: LF var`);
  console.log(`${crypto.createHash('sha256').update(buf).digest('hex')}  ${String(buf.length).padStart(6)}  ${rel}`);
}
if (problems.length) {
  console.error(problems.join('\n'));
  process.exit(1);
}
console.log('OK');
```

Beklenen sonuç: 24 satırlık `sha256 boyut yol` listesi ve `OK`. Ayrıca
`bom-manifests/*` dosyalarının ilk üç baytı `EF BB BF` olmalıdır, kontrol
için `xxd -l 3 <dosya>` kullanılabilir.
