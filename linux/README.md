# linux

`linux/` — это **пост-эксплуатация**: что делать, когда доступ к машине уже есть.
Не подключение к серверам. SSH и туннели — внешним `ssh`/`openssl`, см. `SSH.md`.

Подробный сценарий «зашёл на машину → нашёл флаг → стал root» — `LINUX.md`.

- `privesc.sh` — разведка прав: `id`, `sudo -l`, SUID/SGID, capabilities, cron,
  записываемые конфиги, группы, docker.sock, PATH, свежие изменения, процессы root.
- `flag_hunt.sh` — поиск `flag`, `flag.txt`, `flag_<random>`, `*flag*`, `user.txt`,
  `root.txt` и `CTF{...}`.
- `gtfobins.py` — оффлайн-таблица «как выйти в шелл через штатный бинарь».
  `--list`, `--check "find,base64"`, `--from-sudo sudo.txt`.
- `script_audit.py` — что скрипт `source`-ит, что читает через `cat`, какие пути
  трогает, и можно ли их подменить (`--check-writable`).
- `docker_audit.sh` — контейнер: capabilities, docker.sock, монтирования, cgroup,
  host PID, секреты.
- `k8s_audit.sh` — под Kubernetes: service account, API, secrets.
- `wsl.py` — запуск ELF с Windows в WSL-дистрибутиве Arch: `info`, `run`
  (копирует файл/`--dir` каталог в `~/run`, `+x`), `sh`, `which`, `install`.
- `DOCKER.md` — побег из контейнера и форензика образа.
- `SSH.md` — подключение, ProxyCommand/openssl s_client, туннели, ключи.
- `TRANSFER.md` — залить скрипт на сервер / забрать файл.
- `LINUX.md` — полный сценарий «зашёл → нашёл флаг → root».

Типовые цепочки:
1. `sudo -l` → GTFObins → `sudo find . -exec /bin/sh \; -quit`.
2. root-скрипт делает `source` записываемого конфига → дописать команду → запустить.
3. SUID-бинарь читает файл по пути → path traversal к `/root/flag`.
4. Группа `root` + `sudo` на `bash script.sh` → подменить скрипт/переменную.
5. `docker.sock` → `docker run -v /:/host ... chroot /host`.
