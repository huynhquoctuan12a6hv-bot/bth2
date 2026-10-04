import jwt

from django.conf import settings
from django.http import JsonResponse


class JWTMiddleware:

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):

        # Không yêu cầu JWT đối với login và auth
        if request.path in ['/login/', '/auth/']:
            return self.get_response(request)

        # Lấy Authorization Header
        auth_header = request.headers.get('Authorization')

        if not auth_header:
            return JsonResponse({
                'message': 'Bạn chưa đăng nhập'
            }, status=401)

        try:

            # Authorization: Bearer <token>
            parts = auth_header.split(' ')

            if len(parts) != 2 or parts[0] != 'Bearer':
                return JsonResponse({
                    'message': 'Authorization không đúng định dạng'
                }, status=401)

            token = parts[1]

            # Giải mã JWT
            payload = jwt.decode(
                token,
                settings.SECRET_KEY,
                algorithms=['HS256']
            )

            # Lưu thông tin user vào request
            request.user_id = payload['IdUser']
            request.username = payload['UserName']

        except jwt.ExpiredSignatureError:

            return JsonResponse({
                'message': 'Token đã hết hạn'
            }, status=401)

        except jwt.InvalidTokenError:

            return JsonResponse({
                'message': 'Token không hợp lệ'
            }, status=401)

        return self.get_response(request)