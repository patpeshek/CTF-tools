# ml-router — экспериментальная ветка локального решателя

**Статус: эксперимент. В `site`/`main` не вливается, пока не будет доказано, что
оно реально помогает.** Ветка создана 2026-11-14 от `site` (`b08414e`/`f87bba8`).

Цель — не «ещё один шаблон», а слой, который **понимает, что дали**, и решает,
**куда это кинуть**: семейство, инструмент, следующий шаг. Вдохновлено Jev
(TypeSafe AI, сентябрь 2026): decision model, который не генерирует текст, а
возвращает вероятности по заданным вариантам (`choice` / `noul` / `score`).

## Что уже работает

- `features.py` — признаки артефакта: длина, энтропия, printable, алфавит,
  IoC, zlib-ratio, base64/hex-валидность, магия, числа, UTF-16, хвостовые
  пробелы. Плюс гистограмма байт и первые 256 байт.
- `gen_tasks.py` — 13 семейств с генераторами и **композициями**:
  `raw_text, b64, b32, hex, rot13, caesar, xor1, reverse, gzip, zlib, utf16,
  rsa, random_bin`. `b32` и `utf16` — **невиданные** (OOD), их нет в train.
- `model.py` — `FeatureMLP` и `ByteTransformer` (char-level, 4 слоя, 602k
  параметров). Обе выдают логиты, т.е. вероятности, а не текст.
- `train.py` — AMP bf16 на GPU, OneCycleLR, label smoothing, метрики по эпохам,
  TensorBoard, `*.jsonl` для дашборда, примеры «что модель думает», матрица
  ошибок, OOD-отчёт.
- `dashboard.py` — живой локальный дашборд на stdlib: графики, KPI, top-3
  вероятности по примерам. `http://127.0.0.1:8773/`.
- `predict.py` — inference для файла/строки: top-5 семейств, уверенность,
  самые «влиятельные» признаки.
- `eval_dir.py` — прогон модели по **реальным** файлам из папки: top-3 на
  каждый файл, сколько раз выбрано семейство, сколько «не уверен».
- `eval_true.py` — то же, но ключ выводится из сигнатур и текстовых
  эвристик, поэтому точность считается автоматически на любом наборе файлов.
- `realdata.py` — собирает настоящие файлы в npz той же формы, что
  `gen_tasks.py` (`split="real"`), с метками из `eval_true.expected`.
- `eval_npz.py` — быстрый замер модели по npz (синтетика или реальные).
- `finetune_real.py` — эксперимент «дообучение на реальных»: делит реальные
  файлы по хешу на train/test, меряет синтетику и реальные до и после, чтобы
  видеть, не портит ли доменная подстройка основную задачу.
- `BACKLOG.md` — живой список дырок и решений.
- `train_hf.py` — дообучение готового энкодера (DeBERTa/ModernBERT) как
  decision model. `--view meta` даёт модели компактное описание артефакта
  (`size`, `printable`, начало текста или hex) — иначе бинарь превращается в
  поток символов-заменителей. Пишет `<out>/train.jsonl` для дашборда.

## Как запускать

Python с CUDA уже есть:

```
F:\ml\gdrl\python\venv\Scripts\python.exe   # torch 2.5.1+cu121, CUDA=True
```

Генерация данных и обучение:

```
set PYTHONUTF8=1
F:\ml\gdrl\python\venv\Scripts\python.exe ml\gen_tasks.py --n 100000 ^
    --out F:\AIproject\ml-runs\data_100k.npz

F:\ml\gdrl\python\venv\Scripts\python.exe ml\train.py ^
    --data F:\AIproject\ml-runs\data_100k.npz --arch transformer --epochs 40 ^
    --out F:\AIproject\ml-runs\tf_live.pt
```

Смотреть обучение:

```
F:\ml\gdrl\python\venv\Scripts\python.exe ml\dashboard.py ^
    --run F:\AIproject\ml-runs\tf_live --port 8773
F:\ml\gdrl\python\venv\Scripts\tensorboard.exe ^
    --logdir F:\AIproject\ml-runs --port 6006
```

`http://127.0.0.1:8773/` — графики, эпоха, loss/acc, примеры top-3 с
вероятностями; `http://127.0.0.1:6006/` — TensorBoard.

Проверить на файле:

```
... python.exe ml\predict.py --model F:\AIproject\ml-runs\mlp_100k.pt --file chall.bin
```

## Настоящие файлы из задач (не синтетика)

```
... python.exe ml\realdata.py --out F:\AIproject\ml-runs\real_v1.npz ^
    --roots F:\AIproject\ctf-files\таски F:\AIproject\ctf-files\BCACTF ^
            F:\AIproject\ctf-files\corpus F:\AIproject\_scratch\custom_tasks

... python.exe ml\eval_npz.py --model F:\AIproject\ml-runs\mlp_v8.pt ^
    --npz F:\AIproject\ml-runs\real_v1.npz

... python.exe ml\finetune_real.py --syn F:\AIproject\ml-runs\data_v8_100k.npz ^
    --real F:\AIproject\ml-runs\real_v1.npz --epochs 6 --repeat 12
```

Реальных файлов сотни, а не сотни тысяч: их нельзя просто подмешать в 100k —
утонут. Поэтому порядок такой: сначала синтетика задаёт правила, потом
`finetune_real` аккуратно подстраивает под реальное распределение, а
`eval_npz`/`eval_true` показывают, что при этом не сломалась основная задача.

## Первые результаты (синтетика, 100k)

- MLP: **99.7%** test, top-2 **100%**, ~1 с/эпоха.
- Transformer: **99.7%** после 4 эпох, ~16 с/эпоха.
- OOD (невиданные `b32`/`utf16`): mean max prob ~0.77 — **плохо**: модель
  слишком уверена. Нужны temperature scaling / отдельный класс `unknown` /
  энергетический скор. Это следующий шаг.

Важно: это лёгкий синтетический датасет; признаки почти прямо кодируют
семейство. Настоящая проверка — реальные задачи и выбор **инструмента**, а не
только семейства.

## Готовые модели (вариант «скачать и переобучить»)

Установлено 2026-11-14 через `uv` в тот же venv:

```
transformers 4.46.3, accelerate 1.15.0, sentencepiece 0.2.3, tokenizers 0.20.3
```

Важно: `transformers 5.x` требует свежий torch и с 2.5.1 просто отключает
torch-бэкенд («PyTorch was not found») — поэтому держим 4.46.x.
Кэш моделей: `HF_HOME=F:\AIproject\ml-runs\hf`.

На 8 ГБ 3070 влезает:

| модель | параметров | зачем |
|---|---|---|
| `microsoft/deberta-v3-small` | 44M | быстрый текстовый классификатор/reranker |
| `sentence-transformers/all-MiniLM-L6-v2` | 22M | эмбеддинги, shortlist инструментов |
| `answerdotai/ModernBERT-base` | 149M | длинный контекст (логи + условие), лучшее качество |

Установка (один раз, попросить разрешение): `transformers`, `accelerate`,
опционально `onnx`, `onnxruntime-gpu`. Модели качаются в HF-кэш.

```
F:\ml\gdrl\python\venv\Scripts\pip install transformers accelerate
F:\ml\gdrl\python\venv\Scripts\python.exe ml\train_hf.py ^
    --data F:\AIproject\ml-runs\data_100k.npz ^
    --model microsoft/deberta-v3-small --epochs 4 ^
    --out F:\AIproject\ml-runs\hf_deberta
```

## Дальше

1. **Граф преобразований + логи + loop guard** (в `solve.py`, ветка `ml-router`):
   узлы-артефакты, рёбра-инструменты, visited-set, no-progress pruning.
2. Сбор реальных трасс: `ml/collect.py` (пока не написан) — состояние → ход →
   результат.
3. OOD/калибровка: unknown-класс, temperature scaling, energy.
4. Router по **инструментам**, не только семействам; top-3 + abstain.
5. Cross-encoder reranker (DeBERTa) + bandit.
6. JEPA/self-supervised на трассах, когда их ≥10k.

## Правила

- Всё локально, без сети в рантайме; на соревнованиях с запретом AI — не
  включать, использовать `SOLVER_OFF=1` и детерминированный кит.
- Ветка живёт отдельно: `site` продолжает работать как раньше.

## Политика действий (эксперимент, выключена)

Отдельный слой поверх роутера: не «что за файл», а «какой инструмент
сработает». Обучена на реальных трассах солвера (2213 задач архива).
Лежит в `ml/policy/` вместе с трассами и документацией.

```
python ml\suggest.py ml\router_best.npz <файл>       # что это за файл
python solve.py <задача> --smart --policy ml/policy/policy_best.npz
```

По умолчанию не включена: замер показал, что при пачечном исполнении порядок
шагов не влияет на результат. Подробности — `ml/policy/README.md`.
