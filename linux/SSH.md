# SSH — подключение и туннели (внешними средствами)

`linux/` в этом ките — **не про подключение к серверам**. Это пост-эксплуатация:
что делать, когда шелл уже есть (sudo/SUID/cron/контейнер). SSH — отдельно, системным
`ssh`/`openssl`, скрипты кита его не заменяют.

---

## 1. Обычное подключение

```bash
ssh user@host
ssh -p 2222 user@host
ssh -i id_rsa user@host
```

Ключ с паролем:

```bash
ssh-keygen -p -f id_rsa          # сменить пароль
ssh-keygen -y -f id_rsa          # вытащить публичный
```

Права на ключ:

```bash
chmod 600 id_rsa
```

---

## 2. SSH через TLS / SNI (openssl s_client)

Бывает, что SSH спрятан за TLS-обёрткой:

```bash
ssh -o ProxyCommand="openssl s_client -connect host:443 -servername host -quiet" user@host
```

Или через `socat`:

```bash
socat TCP-LISTEN:2222,fork OPENSSL:host:443,verify=0
ssh -p 2222 user@localhost
```

Проверить, что там TLS:

```bash
openssl s_client -connect host:443 -servername host
```

---

## 3. Прыжки и туннели

```bash
ssh -J jump@host target@internal     # ProxyJump
ssh -L 8080:localhost:80 user@host   # локальный порт -> удалённый
ssh -R 9001:localhost:9001 user@host # удалённый -> локальный
ssh -D 1080 user@host                # SOCKS5
```

Через несколько прыжков:

```bash
ssh -J a@h1,b@h2 c@h3
```

---

## 4. Ключи и пароли в CTF

- ключ найден в `.git`, `.ssh`, бэкапе, образе;
- ключ зашифрован паролем → `ssh2john id_rsa > hash`, `john hash --wordlist=rockyou.txt`;
- пароль в `id_rsa` может быть пустым;
- `authorized_keys` на сервере — закрепление;
- `.ssh/known_hosts` — куда ходили.

---

## 5. Если ssh не установлен

- Linux: `apt install openssh-client`.
- Windows 10/11: компонент OpenSSH Client.
- Из Python: `paramiko` (не входит в кит).

---

## 6. Связанное в ките

- `linux/privesc.sh` — что делать **после** входа.
- `linux/docker_audit.sh` — контейнер.
- `linux/gtfobins.py` — повышение прав.
- `network/pcap_creds.py` — пароли SSH в трафике (если незашифрованный/логи).
