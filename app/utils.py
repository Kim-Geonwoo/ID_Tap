import requests
import random
import secrets
import string
import os
import re
from datetime import datetime, timedelta
from flask import current_app, url_for, json
from app import db  # 애플리케이션 컨텍스트에서 db 가져오기
from app.models import UserModel, MyService, PasswordResetAttempt
from config import Config  # Config 클래스 import
import shutil
import boto3
from datetime import datetime
import logging


now = datetime.now() # 한국 현재시간 계산 1
kst = now + timedelta(hours=17) # 한국 현재시간 계산 2

# 최초 회원가입시 1회 이메일 인증을 위한 이메일 발송관련 코드
def send_verification_email(user):
    # 기존 코드 유지 (변경 없음)
    verification_token = ''.join([str(random.randint(0, 9)) for _ in range(6)]) # 6자리 숫자로 만들어진 토큰생성
    
    user.email_verification_token = verification_token # DB에 생성된 토큰값 입력
    user.email_verification_expires_at = kst + timedelta(hours=1) # DB에 토큰값 생성과 함께, 현재 한국표준시의 시간 + 1시간으로 토큰 유효기간 설정

    # DB에 내용저장
    db.session.commit()

    # Mailgun 서비스를 활용한, 이메일 인증을 위한 발송관련 코드
    response = requests.post(
        f"https://api.mailgun.net/v3/{Config.MAILGUN_DOMAIN}/messages",
        auth=("api", Config.MAILGUN_API_KEY), # Mailgun의 API키 가져오기 (config.py 참고)
        data={
            "from": Config.MAILGUN_SENDER, # Mailgun의 보내는주소 가져오기 (config.py 참고)
            "to": [user.email], # 현재 유저의 이메일을 가져와서, 이메일을 받는사람 지정
            "subject": "아이디탭 - 이메일 인증 코드",
            "text": f"인증 코드: {verification_token}\n\n1시간 내에 인증해주세요."
        }
    )
    
    return response.status_code == 200


# 유저의 비밀번호 초기회용 토큰생성 관련코드
def generate_password_reset_token(user):
    """
    비밀번호 재설정 토큰 생성
    """
    # 안전한 URL 토큰 생성 (32바이트)
    token = secrets.token_urlsafe(32)
    
    # 토큰과 만료 시간 저장
    user.password_reset_token = token # DB에 URL토큰 문자열 저장
    user.password_reset_expires_at = kst + timedelta(minutes=30) # DB에 비밀번호 초기화용 문자열의 유효기간을 지정 (한국표준시의 시간 + 30분)
    db.session.commit()
    
    return token

# 비밀번호 재설정을 위한 이메일 재발송 관련코드
def send_password_reset_email(user, reset_token):
    """
    비밀번호 재설정 이메일 발송
    """
    # 외부 접근 가능한 비밀번호 재설정 URL 생성
    reset_url = url_for('main.reset_password', token=reset_token, _external=True) #DB에서 유저의 비밀번호 초기화 URL문자열 가져오기
    
    # 이메일 메시지 구성 (HTML 형식)
    email_subject = "아이디탭 - 비밀번호 재설정 안내"
    email_body = f"""
안녕하세요,<br><br>

비밀번호 재설정을 요청하셨습니다.<br><br>

아래 링크를 클릭하여 30분 이내에 비밀번호를 재설정해주세요:<br>
<a href="{reset_url}">{reset_url}</a><br><br>

(클릭이 안 되는 경우 아래 주소를 브라우저에 직접 복사하여 붙여넣기 해주세요)<br><br>

만약 본인이 요청하지 않았다면, 개발자에게 제보해주세요..!!!<br>
빠르게 파악 후, 조치하겠습니다.<br><br>

개발자 이메일 : magoso@naver.com<br><br>

감사합니다.
"""

    # Mailgun API를 사용한 이메일 발송
    response = requests.post(
        f"https://api.mailgun.net/v3/{Config.MAILGUN_DOMAIN}/messages",
        auth=("api", Config.MAILGUN_API_KEY), # Mailgun의 API키 가져오기 (config.py 참고)
        data={
            "from": Config.MAILGUN_SENDER, # Mailgun의 보내는주소 가져오기 (config.py 참고)
            "to": [user.email], # 현재 유저의 이메일을 가져와서, 이메일을 받는사람 지정
            "subject": email_subject,
            "html": email_body  # HTML 형식으로 전송
        }
    )
    
    return response.status_code == 200

# 비밀번호 재설정용 토큰을 검증하기 위한 관련코드
def verify_password_reset_token(token):
    """
    비밀번호 재설정 토큰 검증
    """
    from app.models import UserModel  # 순환 참조 방지를 위해 여기서 import
    
    # 토큰으로 사용자 조회
    user = UserModel.query.filter_by(password_reset_token=token).first() # 해당 토큰값으로 동일한 토큰값을 가지고있는 유저를 조회,. (랜덤한32비트의 문자열이 겹쳐서 보안오류가 발생할 오류 0%에 수렴.)
    
    # 토큰이 존재하고 만료 시간이 지나지 않았는지 확인
    if user and user.password_reset_expires_at and user.password_reset_expires_at > kst:
        return user
    
    return None


# 비밀번호 재설정 시도를 제한하기 위한 관련코드
def check_password_reset_limit(user):
    """
    사용자의 비밀번호 재설정 요청 횟수 확인
    
    :param user: 현재 사용자
    :return: 비밀번호 재설정 가능 여부와 남은 횟수
    """
    # 현재 날짜의 시작 시간 - 한국표준시 활용
    today_start = kst.replace(hour=0, minute=0, second=0, microsecond=0)
    
    # 마지막 비밀번호 재설정 시도 시간 확인
    if not user.password_reset_attempts_at or user.password_reset_attempts_at < today_start:
        # 새로운 날짜이므로 횟수 초기화
        return True, 5
    
    # 오늘 날짜의 비밀번호 재설정 시도 횟수 확인
    reset_attempts = UserModel.query.filter(
        UserModel.id == user.id,
        UserModel.password_reset_attempts_at >= today_start
    ).count()
    
    # 남은 시도 횟수 계산
    remaining_attempts = max(0, 5 - reset_attempts)
    
    # 하루 최대 5회 제한
    return reset_attempts < 5, remaining_attempts


# 비밀번호 재설정시도를 초기화하기위한 전용 내부코드
def reset_password_reset_attempts():
    """
    만료된 비밀번호 재설정 시도 횟수 초기화
    """
    # 하루 이전 날짜
    yesterday = kst - timedelta(days=1)
    
    try:
        # 하루 이전 날짜의 재설정 시도 횟수 초기화
        users = UserModel.query.filter(
            UserModel.password_reset_attempts_at < yesterday
        ).all()
        
        for user in users:
            user.password_reset_attempts_at = None
        
        db.session.commit()
        print(f"비밀번호 재설정 시도 횟수 초기화 완료: {len(users)}명의 사용자")
    
    except Exception as e:
        db.session.rollback()
        print(f"비밀번호 재설정 시도 횟수 초기화 중 오류 발생: {str(e)}")

# 비밀번호 재설정시도를 초기화하기위한 전용 내부코드
def record_password_reset_attempt(user):
    """
    비밀번호 재설정 시도 기록
    
    :param user: 현재 사용자
    """
    try:
        # 현재 시간으로 재설정 시도 시간 업데이트
        user.password_reset_attempts_at = kst
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        print(f"비밀번호 재설정 시도 기록 중 오류 발생: {str(e)}")



# 비밀번호 생성조건을 체크하기위한 관련코드
def validate_password(password):
    """
    비밀번호 유효성 검사 함수
    
    조건:
    - 최소 8자리 이상
    - 대문자 1개 이상 포함
    - 숫자 3자리 이상 포함
    """
    if len(password) < 8: # 8자리 이상의 문자열
        return False
    
    # 대문자 최소 1개 확인
    if not re.search(r'[A-Z]', password):
        return False
    
    # 숫자 3개 이상 확인
    number_count = len(re.findall(r'\d', password))
    if number_count < 3:
        return False
    
    return True


# 비밀번호 재설정을 위한 통합 검증코드
def validate_password_reset(new_password, confirm_password):
    """
    비밀번호 재설정 통합 검증 함수
    
    :param new_password: 새 비밀번호
    :param confirm_password: 비밀번호 확인
    :return: 검증 결과 딕셔너리
    """
    # 비밀번호 일치 확인
    if new_password != confirm_password:
        return {
            'is_valid': False,
            'message': '비밀번호가 일치하지 않습니다.'
        }
    
    # 비밀번호 유효성 검사
    if not validate_password(new_password):
        return {
            'is_valid': False,
            'message': '비밀번호가 다음 조건을 충족하지 않습니다:\n'
                       '- 최소 8자리 이상\n'
                       '- 대문자 1개 이상 포함\n'
                       '- 숫자 3자리 이상 포함'
        }
    
    return {
        'is_valid': True,
        'message': ''
    }

# 재설정된 비밀번호로 업데이트하기위한 관련코드ㄴ
def update_password_and_reset_token(user, new_password):
    """
    비밀번호 및 토큰 업데이트 트랜잭션 함수
    
    :param user: 사용자 객체
    :param new_password: 새 비밀번호
    """
    try:
        # 비밀번호 업데이트 (해싱 포함)
        user.set_password(new_password)
        
        # 토큰 및 만료 시간 초기화
        user.password_reset_token = None
        user.password_reset_expires_at = None
        
        # 데이터베이스 커밋
        db.session.commit()
    except Exception as e:
        # 롤백 처리
        db.session.rollback()
        current_app.logger.error(f"비밀번호 업데이트 중 오류 발생: {str(e)}")
        raise



# 설정된 모든 보안로그를 기록하기위한 관련코드
def log_security_event(user, event_type, details=None):
    """
    보안 관련 이벤트 로깅 함수
    
    :param user: 사용자 객체
    :param event_type: 이벤트 유형 (예: 'password_reset', 'login_attempt')
    :param details: 추가 세부 정보
    """
    try:
        # 실제 로깅 시스템이나 데이터베이스 로깅 테이블에 기록
        current_app.logger.info(
            f"Security Event: user={user.email}, "
            f"type={event_type}, "
            f"details={details}"
        )
    except Exception as e:
        current_app.logger.error(f"로깅 중 오류 발생: {str(e)}")



# 비공개 테스터용 회원가입 승인 관련코드 - json파일 로드
def load_registration_codes(file_path='C:/Users/admin/Documents/GitHub/web-profile-card__console/registration_codes.json'):
    """
    JSON 파일에서 등록 코드 로드
    """
    if not os.path.exists(file_path):
        return []
    
    with open(file_path, 'r', encoding='utf-8') as f:
        return json.load(f)

# 비공개 테스터용 회원가입 승인 관련코드 - 일치하는 승인코드인지 검증하는 코드
def validate_registration_code(code):
    try:
        # UTF-8 인코딩으로 파일 읽기
        with open('registration_codes.json', 'r', encoding='utf-8') as f:
            codes = json.load(f)
        
        # 코드 검색
        for code_info in codes:
            if code_info['code'] == code and code_info['status'] == 'no_use':
                return code_info
        
        return None
    except Exception as e:
        print(f"코드 검증 중 오류 발생: {e}")
        return None

# 비공개 테스터용 회원가입 승인 관련코드 - 승인코드 사용시 코드의 상태 업데이트
def update_registration_code_status(code):
    try:
        # UTF-8 인코딩으로 파일 읽기
        with open('registration_codes.json', 'r', encoding='utf-8') as f:
            codes = json.load(f)
        
        # 코드 상태 업데이트
        for code_info in codes:
            if code_info['code'] == code:
                code_info['status'] = 'used'
                code_info['used_at'] = datetime.now().isoformat()
                break
        
        # UTF-8 인코딩으로 파일 쓰기
        with open('registration_codes.json', 'w', encoding='utf-8') as f:
            json.dump(codes, f, indent=4, ensure_ascii=False)
        
        return True
    except Exception as e:
        print(f"코드 상태 업데이트 중 오류 발생: {e}")
        return False

# 비공개 테스터용 회원가입 승인 관련코드 - (? 왜 내가 이게뭔지 모르겠지???)
def get_code_details(code):
    """
    특정 코드의 상세 정보 반환
    """
    codes = load_registration_codes()
    
    for reg_code in codes:
        if reg_code['code'] == code:
            return reg_code
    
    return None


# 회원탈퇴용 이메일 발송 관련 코드
def send_withdrawal_verification_email(user):
    """
    회원 탈퇴 인증 이메일 발송
    
    :param user: 현재 사용자
    :return: 이메일 발송 성공 여부
    """
    # 6자리 인증 코드 생성
    verification_token = ''.join([str(random.randint(0, 9)) for _ in range(6)])
    
    # 사용자 모델에 인증 코드와 만료 시간 저장
    user.withdrawal_verification_token = verification_token
    user.withdrawal_verification_expires_at = kst + timedelta(minutes=30)
    db.session.commit()

    # 이메일 메시지 구성
    email_subject = "아이디탭 - 회원 탈퇴 인증 코드"
    email_body = f"""
안녕하세요, {user.username}님,

회원 탈퇴를 위한 인증 코드입니다.

인증 코드: {verification_token}

이 코드는 30분 동안 유효합니다. 
30분 이내에 인증을 완료해주세요.

그동안 아이디탭을 사용해주셔서 감사합니다.
"""

    # Mailgun API를 사용한 이메일 발송
    response = requests.post(
        f"https://api.mailgun.net/v3/{Config.MAILGUN_DOMAIN}/messages",
        auth=("api", Config.MAILGUN_API_KEY),
        data={
            "from": Config.MAILGUN_SENDER,
            "to": [user.email],
            "subject": email_subject,
            "text": email_body
        }
    )
    
    # 이메일 발송 결과에 따른 반환값 설정
    result = {
        'success': response.status_code == 200,
        'status_code': response.status_code
    }
    
    return result

# 회원탈퇴용 인증코드 검증 관련코드
def verify_withdrawal_token(user, token):
    """
    회원 탈퇴 인증 토큰 검증
    
    :param user: 현재 사용자
    :param token: 인증 토큰
    :return: 토큰 유효성
    """
    # 토큰과 만료 시간 확인
    if (user.withdrawal_verification_token == token and 
        user.withdrawal_verification_expires_at and 
        user.withdrawal_verification_expires_at > kst):
        return True
    
    return False

# 탈퇴한 회원의 발급된 회원탈퇴용 인증코드와 만료기간을 초기화하는 코드
def reset_withdrawal_verification(user):
    """
    회원 탈퇴 인증 정보 초기화
    
    :param user: 현재 사용자
    """
    user.withdrawal_verification_token = None
    user.withdrawal_verification_expires_at = None
    db.session.commit()


# 회원탈퇴 진행시, 모든 정보를 삭제하기위한 코드 
def process_withdrawal(user, email, password, verification_code):
    # 1. 이메일 및 비밀번호 검증
    if email != user.email or not user.check_password(password):
        return {'success': False, 'message': '이메일 또는 비밀번호가 일치하지 않습니다.'}
    
    # 2. 이메일 인증 코드 검증
    if not verify_withdrawal_token(user, verification_code):  # 독립 함수 사용
        return {'success': False, 'message': '인증 코드가 유효하지 않습니다.'}
    
    try:
        # 3. 사용자의 모든 서비스 처리
        services = MyService.query.filter_by(user_id=user.id).all()
        
        for service in services:
            # R2 서비스 삭제 로직
            try:
                s3_client = boto3.client(
                    's3',
                    aws_access_key_id=Config.R2_ACCESS_KEY,
                    aws_secret_access_key=Config.R2_SECRET_KEY,
                    endpoint_url=Config.R2_ENDPOINT_URL,
                    region_name='auto'
                )
                
                # 해당 서비스의 모든 객체 삭제
                paginator = s3_client.get_paginator('list_objects_v2')
                for result in paginator.paginate(Bucket=Config.R2_BUCKET_NAME, Prefix=service.short_url):
                    if 'Contents' in result:
                        objects = [{'Key': obj['Key']} for obj in result['Contents']]
                        s3_client.delete_objects(
                            Bucket=Config.R2_BUCKET_NAME, 
                            Delete={'Objects': objects}
                        )
            except Exception as e:
                current_app.logger.error(f"R2 서비스 삭제 중 오류: {e}")
            
            # 로컬 서비스 디렉토리 삭제
            service_dir_name = f"{user.uuid}_{service.uuid[:7]}"
            service_dir = os.path.join(
                current_app.config['SERVICES_FOLDER'], 
                service_dir_name
            )
            
            if os.path.exists(service_dir):
                try:
                    shutil.rmtree(service_dir)
                except Exception as e:
                    current_app.logger.error(f"서비스 디렉토리 삭제 중 오류: {e}")
        
        # 4. 사용자 관련 파일 삭제
        user_folder = os.path.join(current_app.config['UPLOAD_FOLDER'], user.username)
        if os.path.exists(user_folder):
            try:
                shutil.rmtree(user_folder)
            except Exception as e:
                current_app.logger.error(f"사용자 폴더 삭제 중 오류: {e}")
        
        # 5. PasswordResetAttempt 처리 
        # 모든 다른 삭제 및 처리 로직이 성공적으로 완료된 후에 실행
        reset_attempts = PasswordResetAttempt.query.filter_by(user_id=user.id).all()
        
        for attempt in reset_attempts:
            # 안전한 기본값으로 변경
            attempt.user_id = 0  # 시스템에서 사용하지 않는 ID
            attempt.created_at = datetime(1970, 1, 1)  # 기준 시간
        
        # 6. 사용자 삭제
        db.session.delete(user)
        db.session.commit()
        
        return {'success': True}
    
    except Exception as e:
        db.session.rollback()
        # 로깅 방식 변경
        logging.error(f"회원 탈퇴 중 오류: {e}")
        return {'success': False, 'message': '회원 탈퇴 중 오류가 발생했습니다.'}


# 회원탈퇴를 위한 탈퇴인증토큰 생성
def generate_withdrawal_token(self):
    """
    회원탈퇴 인증 토큰 생성
    """
    # 6자리 숫자 인증 코드 생성
    token = ''.join(random.choices(string.digits, k=6))
    
    # 토큰 만료 시간 설정 (15분)
    expires_at = kst + timedelta(minutes=15)
    
    # 토큰과 만료 시간 저장
    self.withdrawal_verification_token = token
    self.withdrawal_verification_expires_at = expires_at
    
    db.session.add(self)
    db.session.commit()
    
    return token


# 회원탈퇴 진행시, 토큰을 검증하기위한 코드
def verify_withdrawal_token(user, token):
    """
    회원 탈퇴 인증 토큰 검증
    
    :param user: 현재 사용자
    :param token: 인증 토큰
    :return: 토큰 유효성
    """
    # 토큰이 없거나 만료된 경우
    if (not user.withdrawal_verification_token or 
        not user.withdrawal_verification_expires_at or 
        kst > user.withdrawal_verification_expires_at):
        return False
    
    # 토큰 일치 여부 확인
    is_valid = user.withdrawal_verification_token == token
    
    # 토큰 초기화
    if is_valid:
        user.withdrawal_verification_token = None
        user.withdrawal_verification_expires_at = None
        db.session.add(user)
        db.session.commit()
    
    return is_valid
