import multiprocessing
import os
from pickle import TRUE


BASE_DIR = os.path.abspath(os.path.dirname(__file__))

class Config:
    SECRET_KEY = '' # 여기에 실제 생성한 강력한보안의 랜덤문자열 입력
    SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(BASE_DIR, 'app.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    R2_ACCESS_KEY = ''  # 여기에 실제 R2 Access Key 입력
    R2_SECRET_KEY = ''  # 여기에 실제 R2 Secret Key 입력
    R2_BUCKET_NAME = ''  # 여기에 실제 R2 Bucket Name 입력
    R2_ENDPOINT_URL = ''  # 여기에 실제 R2 Endpoint 입력

    PUBLIC_DOMAIN = '' # 여기에 실제 퍼블릭용 R2도메인 입력
    PREVIEW_DOMAIN = '' # 여기에 실제 프리뷰용 R2도메인 입력

    # Mailgun 설정
    MAILGUN_API_KEY = '' # 여기에 실제 Mailgun API키 입력
    MAILGUN_DOMAIN = '' # 여기에 실제 Mailgun용 도메인 입력
    MAILGUN_SENDER = '' # 여기에 실제 Mailgun 메일발신용 이메일 입력

    # HTTPS 관련 설정
    SESSION_COOKIE_SECURE = True
    REMEMBER_COOKIE_SECURE = True
    CSRF_COOKIE_SECURE = True

    # 서버 설정
    HOST = os.environ.get('SERVER_HOST', '0.0.0.0')
    PORT = int(os.environ.get('SERVER_PORT', 5000))
    
    # 워커 설정
    WORKERS = int(os.environ.get('WORKERS', multiprocessing.cpu_count() * 2 + 1))
    FLASK_ENV='production'

    # 비공개 코드 입력 필수 여부 설정
    REQUIRE_REGISTRATION_CODE = TRUE

    # 회원탈퇴용 폴더 경로지정
    SERVICES_FOLDER = 'C:/Users/admin/Documents/GitHub/web-profile-card__console/services'
    UPLOAD_FOLDER = 'C:/Users/admin/Documents/GitHub/web-profile-card__console/uploads'