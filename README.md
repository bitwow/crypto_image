# Crypto Image

`Crypto Image` — это приложение на Python для скрытия и расшифровки сообщений внутри изображений с использованием библиотеки `stegano`. Программа поддерживает шифрование сообщений с использованием ключа, что добавляет дополнительный уровень безопасности.

## Установка

### Требования:
- Python 3.9 или выше
- Установленные модули: `PyQt5`, `stegano`, `cryptography`

### Установка зависимостей
1. Склонируйте репозиторий:
   ```bash
   git clone https://github.com/bitwow/crypto_image.git
   cd crypto_image
   ```

2. Создайте виртуальное окружение и активируйте его:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate  # Для macOS и Linux
   .venv\Scripts\activate   # Для Windows
   ```

3. Установите зависимости:
   ```bash
   pip install -r requirements.txt
   ```

## Как воспользоваться

1. Запустите приложение:
   ```bash
   python interface.py
   ```

2. В приложении выберите одну из вкладок:
   - **Зашифровать**: Загрузите изображение, введите текст и ключ, затем сохраните новое изображение.
   - **Расшифровать**: Загрузите изображение с зашифрованным сообщением, введите ключ для расшифровки.

## Сборка приложения

### macOS
1. Установите PyInstaller, если он ещё не установлен:
   ```bash
   pip install pyinstaller
   ```

2. Соберите приложение:
   ```bash
   pyinstaller --onefile --windowed interface.py
   ```

3. Найдите готовый `.app` файл в папке `dist`.

### Linux
1. Убедитесь, что PyInstaller установлен:
   ```bash
   pip install pyinstaller
   ```

2. Соберите приложение:
   ```bash
   pyinstaller --onefile --windowed interface.py
   ```

3. Найдите готовый исполняемый файл в папке `dist`.

### Windows
1. Убедитесь, что PyInstaller установлен:
   ```bash
   pip install pyinstaller
   ```

2. Соберите приложение:
   ```bash
   pyinstaller --onefile --windowed interface.py
   ```

3. Найдите готовый `.exe` файл в папке `dist`.
