
          
Вот пошаговое руководство по установке Astracat DNS Resolver:

**Установка Astracat DNS Resolver**

Этот процесс включает сборку проекта, создание системной службы и запуск ее.

1.  **Сборка проекта:**
    *   Перейдите в корневой каталог проекта Astracat DNS Resolver.
    *   Выполните команду для сборки исполняемого файла:
        ```bash
        go build -o astracat-dns .
        ```
        Эта команда создаст исполняемый файл с именем `astracat-dns` в текущем каталоге.

2.  **Создание файла службы systemd:**
    *   Будет создан файл службы systemd по адресу `/etc/systemd/system/astracat-dns.service`. Этот файл настраивает, как служба Astracat DNS Resolver будет управляться системой.
    *   Содержимое файла службы будет следующим:
        ```
        [Unit]
        Description=Astracat DNS Resolver Service
        After=network.target

        [Service]
        ExecStart=/Users/astracat/Astracat-DNS-Resolver-1/astracat-dns
        WorkingDirectory=/Users/astracat/Astracat-DNS-Resolver-1
        Restart=always
        User=root

        [Install]
        WantedBy=multi-user.target
        ```
        *   `Description`: Описание службы.
        *   `After=network.target`: Указывает, что служба должна запускаться после инициализации сети.
        *   `ExecStart`: Определяет команду для запуска службы, указывая путь к исполняемому файлу `astracat-dns`.
        *   `WorkingDirectory`: Устанавливает рабочий каталог для службы.
        *   `Restart=always`: Гарантирует, что служба будет автоматически перезапускаться в случае сбоя.
        *   `User=root`: Запускает службу от имени пользователя root.
        *   `WantedBy=multi-user.target`: Указывает, что служба должна быть запущена в многопользовательском режиме.

3.  **Включение и запуск службы:**
    *   Перезагрузите демоны systemd, чтобы система узнала о новой службе:
        ```bash
        systemctl daemon-reload
        ```
    *   Включите службу Astracat DNS Resolver, чтобы она запускалась при загрузке системы:
        ```bash
        systemctl enable astracat-dns
        ```
    *   Запустите службу Astracat DNS Resolver:
        ```bash
        systemctl start astracat-dns
        ```

После выполнения этих шагов служба Astracat DNS Resolver будет установлена и запущена в вашей системе.
        
