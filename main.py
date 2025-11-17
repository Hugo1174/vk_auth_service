from fastapi import FastAPI, HTTPException, status, Request
from starlette.responses import RedirectResponse, JSONResponse
from starlette.middleware.sessions import SessionMiddleware
import httpx
from dotenv import load_dotenv
import os
import logging
import secrets
import hashlib
import base64

# Настройка логирования
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# --- Конфигурация ---
load_dotenv()
app = FastAPI(title="VKAuthService")

# Session Middleware
SESSION_SECRET = os.getenv('VK_CLIENT_SECRET')
app.add_middleware(SessionMiddleware, secret_key=SESSION_SECRET, max_age=3600)

# Параметры VK ID
PUBLIC_HTTPS_URL = 'https://vavilonus10.ru'
VK_CLIENT_ID = os.getenv('VK_CLIENT_ID')
VK_CLIENT_SECRET = os.getenv('VK_CLIENT_SECRET')
REDIRECT_URI = f'{PUBLIC_HTTPS_URL}/auth/vk/callback'

# ✅ Новые endpoints VK ID
VK_AUTHORIZE_URL = 'https://id.vk.ru/authorize'
VK_TOKEN_URL = 'https://id.vk.ru/oauth2/auth'
VK_USER_INFO_URL = 'https://id.vk.ru/oauth2/user_info'

# Scope для получения email и телефона
VK_SCOPE = 'email phone'  # Можно оставить пустым для базовой информации


# --- Вспомогательные функции для PKCE ---

def generate_code_verifier() -> str:
    """Генерирует code_verifier для PKCE (43-128 символов)"""
    return base64.urlsafe_b64encode(secrets.token_bytes(32)).decode('utf-8').rstrip('=')


def generate_code_challenge(verifier: str) -> str:
    """Генерирует code_challenge из code_verifier методом S256"""
    digest = hashlib.sha256(verifier.encode('utf-8')).digest()
    return base64.urlsafe_b64encode(digest).decode('utf-8').rstrip('=')


def generate_state() -> str:
    """Генерирует случайный state (минимум 32 символа)"""
    return secrets.token_urlsafe(32)


# --- Эндпоинты ---

@app.get('/')
def home():
    """Возвращает JSON-сообщение о статусе сервиса"""
    return {"message": "VKAuthService запущен. Для авторизации используйте /auth/vk/login"}


@app.get('/config')
def get_config_for_debug():
    """Возвращает критические параметры для отладки"""
    return {
        "VK_CLIENT_ID": VK_CLIENT_ID,
        "PUBLIC_HTTPS_URL": PUBLIC_HTTPS_URL,
        "REDIRECT_URI": REDIRECT_URI,
        "VK_SCOPE": VK_SCOPE,
        "VK_AUTHORIZE_URL": VK_AUTHORIZE_URL,
        "VK_TOKEN_URL": VK_TOKEN_URL
    }


@app.get('/auth/vk/login')
async def login_via_vk(request: Request):
    """
    Шаг 1: Перенаправление пользователя на страницу авторизации VK ID
    """
    # Генерируем PKCE параметры
    code_verifier = generate_code_verifier()
    code_challenge = generate_code_challenge(code_verifier)
    state = generate_state()

    # Сохраняем в сессию для последующей проверки
    request.session['code_verifier'] = code_verifier
    request.session['state'] = state

    # Формируем URL авторизации
    auth_params = {
        'response_type': 'code',
        'client_id': VK_CLIENT_ID,
        'redirect_uri': REDIRECT_URI,
        'scope': VK_SCOPE,
        'state': state,
        'code_challenge': code_challenge,
        'code_challenge_method': 'S256'
    }

    # Создаем URL с параметрами
    auth_url = f"{VK_AUTHORIZE_URL}?{'&'.join([f'{k}={v}' for k, v in auth_params.items()])}"

    logger.info(f"Redirecting to VK ID: {auth_url}")
    return RedirectResponse(url=auth_url)


@app.get('/auth/vk/callback')
async def vk_callback(request: Request):
    """
    Шаг 2: Обработка callback от VK ID, обмен кода на токен
    """
    # Получаем параметры из callback
    code = request.query_params.get('code')
    state = request.query_params.get('state')
    device_id = request.query_params.get('device_id')
    error = request.query_params.get('error')

    # Проверка на ошибки
    if error:
        error_description = request.query_params.get('error_description', 'Неизвестная ошибка')
        logger.error(f"VK ID Authorization Error: {error} - {error_description}")
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"detail": f"Ошибка авторизации: {error_description}"}
        )

    # Проверка state
    saved_state = request.session.get('state')
    if not state or state != saved_state:
        logger.error("State mismatch - possible CSRF attack")
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"detail": "Ошибка безопасности: state не совпадает"}
        )

    # Получаем code_verifier из сессии
    code_verifier = request.session.get('code_verifier')
    if not code_verifier:
        logger.error("code_verifier not found in session")
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"detail": "Ошибка: code_verifier отсутствует"}
        )

    # Обмен кода на токен
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            token_data = {
                'grant_type': 'authorization_code',
                'code': code,
                'code_verifier': code_verifier,
                'redirect_uri': REDIRECT_URI,
                'client_id': VK_CLIENT_ID,
                'device_id': device_id,
                'state': state
            }

            response = await client.post(
                VK_TOKEN_URL,
                data=token_data,
                headers={'Content-Type': 'application/x-www-form-urlencoded'}
            )
            response.raise_for_status()
            token_response = response.json()

            logger.info(f"Token received: {token_response}")

            # Получаем access_token
            access_token = token_response.get('access_token')
            user_id = token_response.get('user_id')

    except httpx.HTTPStatusError as e:
        logger.error(f"HTTP Error during token exchange: {e.response.text}")
        return JSONResponse(
            status_code=e.response.status_code,
            content={"detail": f"Ошибка обмена кода на токен: {e.response.text}"}
        )
    except Exception as e:
        logger.error(f"General error during token exchange: {e}")
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"detail": f"Внутренняя ошибка при обмене кода: {e}"}
        )

    # Шаг 3: Получение информации о пользователе
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            user_info_data = {
                'client_id': VK_CLIENT_ID,
                'access_token': access_token
            }

            response = await client.post(
                VK_USER_INFO_URL,
                data=user_info_data,
                headers={'Content-Type': 'application/x-www-form-urlencoded'}
            )
            response.raise_for_status()
            user_info_response = response.json()

            logger.info(f"User info received: {user_info_response}")

            # Извлекаем данные пользователя
            user_data = user_info_response.get('user', {})

    except httpx.HTTPStatusError as e:
        logger.error(f"HTTP Error during user info request: {e.response.text}")
        return JSONResponse(
            status_code=e.response.status_code,
            content={"detail": f"Ошибка получения информации о пользователе: {e.response.text}"}
        )
    except Exception as e:
        logger.error(f"General error during user info request: {e}")
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"detail": f"Внутренняя ошибка при запросе данных пользователя: {e}"}
        )

    # Формируем финальный ответ
    user_payload = {
        "vk_id": user_data.get('user_id'),
        "first_name": user_data.get('first_name'),
        "last_name": user_data.get('last_name'),
        "full_name": f"{user_data.get('first_name', '')} {user_data.get('last_name', '')}",
        "email": user_data.get('email'),
        "phone": user_data.get('phone'),
        "avatar": user_data.get('avatar'),
        "sex": user_data.get('sex'),
        "birthday": user_data.get('birthday'),
        "verified": user_data.get('verified'),
        "message": "Авторизация через VK ID успешна"
    }

    # Очищаем сессию
    request.session.pop('code_verifier', None)
    request.session.pop('state', None)

    return user_payload


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8080)
