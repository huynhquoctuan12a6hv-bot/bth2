import jwt
import datetime

from django.conf import settings
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt

from .models import User


# =========================
# LOGIN
# =========================
@csrf_exempt
def login(request):

    if request.method != 'POST':
        return JsonResponse({
            'message': 'Chỉ hỗ trợ POST'
        }, status=405)

    username = request.POST.get('userName')
    password = request.POST.get('password')

    if not username or not password:
        return JsonResponse({
            'message': 'Vui lòng nhập userName và password'
        }, status=400)

    try:
        user = User.objects.get(UserName=username)
    except User.DoesNotExist:
        return JsonResponse({
            'message': 'Sai username hoặc password'
        }, status=401)

    if user.Password != password:
        return JsonResponse({
            'message': 'Sai username hoặc password'
        }, status=401)

    # Tạo JWT
    payload = {
        'IdUser': user.IdUser,
        'UserName': user.UserName,
        'exp': datetime.datetime.now(datetime.timezone.utc)
              + datetime.timedelta(hours=1)
    }

    token = jwt.encode(
        payload,
        settings.SECRET_KEY,
        algorithm='HS256'
    )

    # Lưu token vào database
    user.Token = token
    user.save()

    return JsonResponse({
        'message': 'Đăng nhập thành công',
        'token': token
    })


# =========================
# AUTH
# =========================
@csrf_exempt
def auth(request):

    if request.method != 'GET':
        return JsonResponse({
            'message': 'Chỉ hỗ trợ GET'
        }, status=405)

    auth_header = request.headers.get('Authorization')

    if not auth_header:
        return JsonResponse({
            'message': 'Không có token'
        }, status=401)

    try:
        # Authorization: Bearer token
        token = auth_header.split(' ')[1]

        payload = jwt.decode(
            token,
            settings.SECRET_KEY,
            algorithms=['HS256']
        )

        return JsonResponse({
            'message': 'Token hợp lệ',
            'IdUser': payload['IdUser'],
            'UserName': payload['UserName']
        })

    except jwt.ExpiredSignatureError:
        return JsonResponse({
            'message': 'Token đã hết hạn'
        }, status=401)

    except Exception:
        return JsonResponse({
            'message': 'Token không hợp lệ'
        }, status=401)


# =========================
# HELLO WORLD
# =========================
def hello_world(request):

    return JsonResponse({
        'message': 'Hello World'
    })