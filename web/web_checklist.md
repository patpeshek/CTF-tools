# Чек-лист по вебу

## 0. Всегда
- `view-source`, DevTools → Network, Application → Cookies.
- Открыть `robots.txt`, `sitemap.xml`, `security.txt`, `.git/HEAD`, `/.env`.
- Прогнать gobuster/dirsearch/ffuf по стандартному словарю (не долго, 1–2 минуты).
- Если дали исходники — читать их первыми, а не тыкать наугад.

## 1. Параметры и IDOR
- Все параметры: `id`, `user`, `user_id`, `page`, `file`, `path`, `role`, `price`, `q`, `debug`.
- `id=1`, перебор 1..2000 (Burp Intruder, sort by status/length). Часто прячут у `id=1337`, `1` или `0`.
- Смена `role=user` → `admin`, `is_admin=1`.

## 2. SQL-инъекция
- `'`, `"`, `' OR 1=1 --`, `admin' or 1=1 –123`.
- Если фильтры: `/**/` вместо пробелов, регистр (`oR`, `SeLeCt`), `UNION%0aSELECT`, `--` вместо `#`.
- UNION: сначала узнать число колонок `ORDER BY 1..10`, потом `UNION SELECT NULL,...`.
- Полезно: `sqlite_master`, `information_schema.tables`, `users(password)`.

## 3. LFI / path traversal
- `?file=../../../../etc/passwd`.
- Обход: `%2e%2e%2f`, `..%2f`, `....//`, двойное кодирование `%252e%252e%252f`.
- Читать: `/etc/passwd`, исходники (`/app/main.py`, `config.js`), `/proc/self/environ`.

## 4. JWT
- Декодировать: `python jwt_tool.py decode <token>`.
- Проверить `alg:none`; слабый секрет (брут hashcat 16500 или словарь).
- Секрет часто утекает: cookie `secret_key`, `/log`, `.git`, `/debug`.
- Подделка: `python jwt_tool.py forge --secret ... --sub admin --role admin`.
- Помни: `sub`, `user_id`, `role` — то, что проверяет сервер.

## 5. SSTI
- Пробы: `{{7*7}}`, `${7*7}`, `<%= 7*7 %>`, `#{7*7}`.
- Go-шаблоны: `{{.}}` → дамп структуры, `{{call .SomeMethod}}`.
- Jinja2: `{{config}}`, `{{''.__class__.__mro__}}`, RCE через `cycler`.

## 6. Бизнес-логика
- Отрицательное количество/цена (`quantity=-10`), дробные числа, переполнение баланса.
- Покупка «дорогого» товара после манипуляций с корзиной.
- Купоны, повторное применение, race condition (несколько запросов одновременно).

## 7. Загрузка файлов
- Обход расширений: `.php5`, `.phtml`, `shell.php.jpg`, `%00`, двойное расширение.
- ZIP: symlink внутри архива (LFI), zip-slip (`../../app/main.py`).
- Проверить, куда файл реально лёг и доступен ли по URL.

## 8. Прочее, что уже встречалось
- Нестандартный HTTP-метод (`CTF`, `ACTION_FLAG`) и кастомный User-Agent.
- `security.txt` / `robots.txt` как место флага.
- `logs/system.log` с утёкшими токенами.
- Cookie forging, если известен алгоритм (md5 от username и т.п.).
