# Ghidra без боли (реверс-инжиниринг)

Ghidra — бесплатный декомпилятор от NSA. Читает ELF/PE/Mach-O, показывает
C-подобный код. Для CTF заменяет IDA.

## 1. Где лежит и как запустить

- Установка: `F:\dev\ghidra_12.2\ghidra_12.2_PUBLIC` (или `GHIDRA_HOME`).
- Запуск GUI: `ghidraRun.bat` в корне Ghidra.
- Нужна Java: для Ghidra 12.x — **JDK 21**, для 11.x — 17.
  Проверить: `java -version`; JDK лежит в `F:\dev\jdk-*`.
- Если Java не та: `set JAVA_HOME=F:\dev\jdk-21...` перед запуском
  (или поправить `support\launch.properties`).

## 2. Первый запуск: проект и импорт

1. `File → New Project → Non-Shared` → папка `F:\AIproject\_ghidra_projects`.
2. `File → Import File…` → выбрать бинарник (ELF/PE).
3. Галочка **Analyze** → `Yes` → оставить дефолтные анализаторы → `Analyze`.
   Ждать: от секунд (мелкий crackme) до минут (Go/Rust 2 МБ).
4. Открыть файл двойным кликом.

## 3. Что смотреть (окна)

- **Symbol Tree** — функции и импорты; ищи `main`, `check`, `verify`, `strcmp`.
- **Listing** — ассемблер; **Decompiler** (справа) — C-код функции.
- Клик по имени функции в декомпиляторе → переход; `X` — кто вызывает.
- **Search → For Strings…** — все строки; двойной клик → место использования.
- **Window → Defined Strings** — то же списком.

## 4. Хоткеи, которые реально нужны

| Клавиша | Что делает |
|---|---|
| `G` | перейти по адресу (`0x401136`) |
| `Ctrl+Shift+E` | поиск по строкам/именам |
| `F` | переименовать функцию/переменную |
| `;` | комментарий |
| `X` | cross-references (кто ссылается) |
| `L` | поставить метку |
| `P` | создать функцию из выделения |
| `C` | дизассемблировать байты |
| `D` | определить как данные |
| `Ctrl+E` | **патч байтов** (поменять код) |
| `Ctrl+Shift+G` | go to next reference |

## 5. Типовой crackme за 10 минут

1. **Строки:** `Search → For Strings` → ищи `Wrong`, `Correct`, `flag`, `{`.
2. `X` на строке «Wrong» → попадаешь в функцию проверки.
3. В декомпиляторе читаешь: обычно `if (strcmp(input, secret) == 0)` или
   цикл `buf[i] ^ key[i]`.
4. `F` переименуй `FUN_00401136` → `check_flag`, переменные → `i`, `key`.
5. Если сравнение с массивом констант — клик по массиву, видно байты.
   Перевернуть преобразование (xor/rot/сложение) и получить флаг.
6. Если проверка мешает — патч: `Ctrl+E`, замени `jz` на `jnz` или NOP
   (`90`), затем `File → Export Program` (или запуск локально).

## 6. Headless (без GUI) — из кита

Декомпилировать всё в C-текст:

```powershell
python toolbox.py ghidra bin --out dump.c --timeout 300
python toolbox.py ghidra bin --grep "main|check|flag"
```

Под капотом: `analyzeHeadless` + `reverse/ghidra_scripts/DumpDecomp.java`.
Работает на Windows без GUI, кладёт проект во временную папку и удаляет.

Ручной запуск, если нужно своё:

```powershell
$g = "F:\dev\ghidra_12.2\ghidra_12.2_PUBLIC\support\analyzeHeadless.bat"
& $g F:\AIproject\_ghidra_projects proj1 -import .\bin `
   -postScript DumpDecomp.java `
   -scriptPath C:\Users\nispa\.vscode\projectPy\toolbox\reverse\ghidra_scripts `
   -deleteProject
```

## 7. Полезные мелочи

- **Экспорт C-кода:** `File → Export Program → C/C++`.
- **Сравнение двух бинарников:** `Tools → Version Tracking` (для задач «найди
  отличие»).
- **ELF с другой архитектурой** (aarch64) — Ghidra читает и декомпилирует без
  запуска, это её сильная сторона.
- **Python-скрипты:** `Window → Script Manager` (Jython/PyGhidra).
- Не запускай чужие бинарники на хосте: сначала статика (Ghidra), запуск — в
  изолированной ВМ/контейнере.
- Если декомпилятор ругается на «lowlevel error» — попробуй `Analysis →
  One Shot → Aggressive Instruction Finder`.

## 8. Что делать, если Ghidra «не видит» код

- Это данные, а не код: выдели диапазон → `C` (дизассемблировать) → `P`
  (создать функцию).
- Архитектура определена неверно: `Language` при импорте.
- Обфускация/упаковка: сначала распакуй (`reverse/py_pack.py`, `megarev`),
  потом импортируй.
