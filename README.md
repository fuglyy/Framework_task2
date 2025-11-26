ControlSystem - Микросервисная архитектура

Проект представляет собой учебную микросервисную систему для управления пользователями и заказами.
Архитектура разделена на три независимых сервиса:

API Gateway — единая точка входа

Users Service — авторизация, роли, профиль

Orders Service — создание и управление заказами

Сервисы общаются по HTTP и разворачиваются через Docker Compose.

Технологии

Node.js + Express — все сервисы

JWT — авторизация

Axios — внутренняя прокси-коммуникация

Pino — структурированное логирование

Rate Limit — защита от спама и brute-force

Docker Compose — запуск всей системы

OpenAPI 3.0 — документация API

Gateway управляет безопасностью, логированием, валидацией токенов и маршрутизацией.
Users/Orders — полностью независимые микросервисы.

Структура проекта
/
├── gateway/
│   ├── index.js
│   └── ...
├── users-service/
│   ├── index.js
│   └── ...
├── orders-service/
│   ├── index.js
│   └── ...
├── docker-compose.yml
└── README.md

Запуск проекта
1) Установите Docker и Docker Compose

https://www.docker.com/products/docker-desktop/

2) Запустите все сервисы:
docker-compose up --build

Users Service
Основные функции:

регистрация

вход и генерация JWT

просмотр профиля

обновление профиля

получение списка пользователей (только admin)

Основные маршруты:

POST /auth/register

POST /auth/login

GET /users/profile

PUT /users/profile

GET /users (admin)

Orders Service
Основные функции:

создание заказов

получение списка (только свои, admin — все)

изменение статуса заказа

отмена заказа

Статусы:

created → in_progress → completed → cancelled

API Gateway
Отвечает за:

проверку и валидацию JWT

rate limiting

логирование через Pino

проксирование запросов

единый формат ошибок:

{
  "success": false,
  "error": { "code": "...", "message": "..." }
}


healthcheck всех сервисов

Единый формат response

Успех:

{
  "success": true,
  "data": { ... }
}


Ошибка:

{
  "success": false,
  "error": {
    "code": "ERROR_CODE",
    "message": "Описание ошибки"
  }
}

Healthcheck

Проверка состояния системы:

GET /health


Ответ:

{
  "success": true,
  "data": {
    "status": "healthy",
    "services": {
      "gateway": "ok",
      "users": "ok",
      "orders": "ok"
    }
  }
}

Преимущества архитектуры

независимые микросервисы

централизованная безопасность

единый формат ошибок

удобное логирование (Request ID)

простота тестирования


