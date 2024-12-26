from datetime import datetime, timedelta
import os
import random
import secrets
import string
import uuid
import shutil
import requests
import re
from app import db
from flask import Blueprint, jsonify, render_template, request, redirect, url_for, flash, current_app, json
from flask_login import login_user, login_required, logout_user, current_user
from app.models import UserModel, MyService, PasswordResetAttempt
import base64

from functools import wraps
from flask import abort
from werkzeug.exceptions import HTTPException

import logging
# Set up logging
logging.basicConfig(level=logging.INFO)

from PIL import Image
import io



import boto3

from config import Config  # Config 클래스 import
from app.utils import send_verification_email, generate_password_reset_token, send_password_reset_email, verify_password_reset_token, log_security_event, validate_password_reset, update_password_and_reset_token, validate_registration_code, update_registration_code_status, send_withdrawal_verification_email, process_withdrawal   # 유틸리티 함수
from app.decorators import email_verified_required
from flask import send_from_directory


# 로그 설정
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

BASE_DIR = 'C:/Users/admin/Documents/GitHub/web-profile-card__console'  # 기본 경로 설정
DEFAULT_TEMPLATE_FOLDER = os.path.join(os.getcwd(), '../samples') # 서비스 생성시 기본템플릿 폴더 복사

now = datetime.now() # 한국 현재시간 계산 1
kst = now + timedelta(hours=17) # 한국 현재시간 계산 2

# 관리자 전용 페이지제한 코드
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            abort(403)  # Forbidden 에러 반환
        return f(*args, **kwargs)
    return decorated_function

# 기본적인 허용파일 목록코드
def allowed_file(filename):
    ALLOWED_EXTENSIONS = {
        'html', 'HTML',
        'png', 'PNG',
        'jpg', 'JPG',
        'jpeg', 'JPEG',
        'gif', 'GIF',
        'css', 'js', 'json', 'JSON',
        'md', 'MD'
    }
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS
bp = Blueprint('main', __name__)


# 에러발생시 지정한 오류 html을 표시하도록 구성
from werkzeug.exceptions import HTTPException

@bp.errorhandler(400)
def bad_request(error: HTTPException):
    return render_template('errors/400.html', error_message=str(error)), 400

# 401 오류에 대한 커스텀 핸들러
@bp.errorhandler(401)
def unauthorized(error: HTTPException):  # error의 타입을 명시적으로 지정
    # error 객체의 속성에 접근
    return render_template('errors/401.html', error_message=str(error)), 401

@bp.errorhandler(403) # 작동몰?루
def forbidden(error: HTTPException):
    return render_template('errors/403.html', error_message=str(error)), 403

@bp.errorhandler(404) # 작동안함
def page_not_found(error: HTTPException):
    return render_template('errors/404.html', error_message=str(error)), 404

@bp.errorhandler(500) # 작동몰?루
def internal_server_error(error: HTTPException):
    return render_template('errors/500.html', error_message=str(error)), 500

# 502 오류에 대한 커스텀 핸들러
@bp.errorhandler(502)
def bad_gateway(error: HTTPException):  # error의 타입을 명시적으로 지정
    # error 객체의 속성에 접근
    return render_template('errors/502.html', error_message=str(error)), 502




# 메인 index 페이지
@bp.route('/')
def index():
    users = UserModel.query.all()
    return render_template('index.html', users=users)

# 이미 로그인된것을 감지하였을경우 리다이렉트
@bp.route('/logged_in')
def logged_in():
    return render_template('errors/logged-in.html')

# 로그인 페이지
@bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        flash('이미 로그인을 하였습니다.', 'error')
        return redirect(url_for('main.logged_in'))
                        
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = UserModel.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('main.index'))
        else:
            flash('올바르지 않은 사용자 또는 비밀번호')
    
    return render_template('login.html')

    

# 회원가입 페이지
@bp.route('/register', methods=['GET', 'POST'])
def register_user():
    if current_user.is_authenticated:
        flash('이미 로그인을 하였습니다.', 'error')
        return redirect(url_for('main.logged_in'))
    
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        
        # 비공개 코드 입력 필수 여부 확인
        private_code = request.form.get('private_code', '')
        
        # 비밀번호 유효성 검사 로직
        if not validate_password(password):
            flash('비밀번호가 다음 조건을 충족하지 않습니다:\n'
                    '- 최소 8자리 이상\n'
                    '- 대문자 1개 이상 포함\n'
                    '- 숫자 3자리 이상 포함')
            return render_template('register.html')

        
        user_title = '일반사용자'  # 기본 유저타이틀(칭호)

        # 비공개 코드 검증 로직 (config.py서 on, off 가능)
        if current_app.config['REQUIRE_REGISTRATION_CODE'] and private_code:
            # 코드 유효성 검증
            code_info = validate_registration_code(private_code)
            if not code_info:
                flash('유효하지 않은 등록 코드입니다.')
                return render_template('register.html')
            
            # user_title을 비공개코드내의 타이틀로 설정
            user_title = code_info.get('user_title', '일반사용자')

        # 새 사용자 생성
        new_user = UserModel(
            id=UserModel.generate_unique_id(),  # 고유한 5글자 ID 생성
            username=username, 
            email=email,
            email_verified=False, # 회원가입시 이메일인증의 기본상태는 미인증
            user_title=user_title  # user_title 설정
        )
        new_user.set_password(password)
        
        try:
            # 데이터베이스에 사용자 추가
            db.session.add(new_user)
            db.session.commit()

            # 사용자 프로필 이미지 폴더 생성 및 기본 이미지 복사
            profile_dir = 'C:/Users/admin/Documents/GitHub/web-profile-card__console/static/userimg/'
            user_folder = os.path.join(profile_dir, new_user.id)

            # 사용자 폴더가 존재하지 않으면 생성
            if not os.path.exists(user_folder):
                os.makedirs(user_folder)

            # 기본 이미지 경로
            default_image_path = os.path.join(profile_dir, 'default.webp')
            # 새 이미지 경로
            new_image_path = os.path.join(user_folder, f"{new_user.id}_profile_img.webp")

            # 기본 이미지를 새 경로로 복사
            shutil.copyfile(default_image_path, new_image_path)

            # 비공개 코드가 있고 유효한 경우에만 상태 업데이트
            if current_app.config['REQUIRE_REGISTRATION_CODE'] and private_code:
                update_registration_code_status(private_code)

            # 이메일 발송 - utils.py 참고.
            send_verification_email(new_user)

            # 로그인 처리
            login_user(new_user)

            # 이메일 인증 페이지로 리다이렉트
            flash('회원가입이 완료되었습니다.\n 이메일 인증을 완료해주세요.')
            return redirect(url_for('main.verify_email'))

        except Exception as e:
            # 오류 발생 시 롤백 및 오류 처리
            db.session.rollback()
            flash(f'회원가입 중 오류가 발생했습니다: {str(e)}')
            return render_template('register.html')
    
    return render_template('register.html')

# 회원가입 페이지 - 비밀번호 생성조건 검증코드
def validate_password(password):
    """
    비밀번호 유효성 검사 함수
    
    조건:
    1. 최소 8자리 이상
    2. 대문자 최소 1개 포함
    3. 숫자 최소 3개 포함
    
    :param password: 검사할 비밀번호 문자열
    :return: 유효성 검사 결과 (True/False)
    """
    # 최소 길이 체크 - 8자 이상으로
    if len(password) < 8:
        return False
    
    # 대문자 최소 1개 체크
    if not re.search(r'[A-Z]', password):
        return False
    
    # 숫자 최소 3개 체크
    number_count = len(re.findall(r'\d', password))
    if number_count < 3:
        return False
    
    return True



# 회원가입시 최초1회 이메일 인증용 페이지
@bp.route('/verify_email', methods=['GET', 'POST'])
@login_required
def verify_email():
    # 이미 인증된 경우 대시보드로 리다이렉트
    if current_user.email_verified is True:
        flash('이미 이메일 인증이 완료되었습니다.', 'success')
        return redirect(url_for('main.dashboard'))
    
    if request.method == 'POST':
        token = request.form.get('token')
        
        # 이메일 인증토큰 검증
        if (current_user.email_verification_token == token and 
            current_user.email_verification_expires_at > kst): # 토큰검증 및 토큰 만료시간(1시간) 체크
            
            current_user.email_verified = True # 이메일 인증상태를 하였음, 으로 갱신
            current_user.email_verification_token = None # 발급되있는 토큰내용 삭제
            current_user.email_verification_expires_at = None # 현재 이메일 인증용 토큰의 만료기간을 초기화
            
            # DB에 커밋
            db.session.commit()
            
            flash('이메일 인증이 완료되었습니다.', 'success')
            return redirect(url_for('main.dashboard'))
        
        else:
            flash('유효하지 않은 인증 코드입니다.', 'error')
    
    return render_template('verify_email.html')


# 이메일 인증코드 재발급 및 이메일 재전송용 코드 (호출전용, 페이지없음)
@bp.route('/resend_verification')
@login_required
def resend_verification():

    # 이미 인증된 경우 처리
    if current_user.email_verified is True:
        flash('이미 이메일 인증이 완료되었습니다.', 'success')
        return redirect(url_for('main.dashboard'))

    # 새로운 인증 코드 발송 - utils.py 참고.
    if send_verification_email(current_user):
        flash('새로운 인증 코드가 발송되었습니다.', 'success')
    else:
        flash('인증 코드 발송에 실패했습니다.', 'error')
    
    return redirect(url_for('main.verify_email'))


# 이메일 인증코드 발송제한 코드 - 1시간에 10번으로 발송제한
def get_remaining_reset_attempts(user):
    """
    남은 비밀번호 재설정 시도 횟수 계산
    
    :param user: 현재 사용자
    :return: 남은 시도 횟수 (0-10)
    """
    # 현재 시간
    now = datetime.now()  # 현재 시간
    one_hour_ago = now - timedelta(hours=1)  # 1시간 전 시간

    # 지난 1시간 동안의 비밀번호 재설정 시도 횟수 확인
    reset_attempts = PasswordResetAttempt.query.filter(
        PasswordResetAttempt.user_id == user.id,
        PasswordResetAttempt.created_at >= one_hour_ago
    ).count()

    # 최대 10회에서 현재 시도 횟수 빼기
    return max(10 - reset_attempts, 0)


# 비밀번호 찾기 페이지
@bp.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    max_attempts = 5  # 최대 시도 횟수제한 - 하루에 5번

    # 비밀번호 재설정 시도 제한용 코드
    def get_remaining_attempts(user):
        """남은 비밀번호 재설정 시도 횟수 계산"""
        today_start = kst.replace(hour=0, minute=0, second=0, microsecond=0)
        reset_attempts = PasswordResetAttempt.query.filter(
            PasswordResetAttempt.user_id == user.id,
            PasswordResetAttempt.created_at >= today_start
        ).count()
        return max(0, max_attempts - reset_attempts)

    # 현재 로그인된 사용자인 경우
    if current_user.is_authenticated:
        remaining_attempts = get_remaining_attempts(current_user)
    else:
        remaining_attempts = max_attempts  # 기본값 설정

    if request.method == 'POST':
        email = request.form.get('email')
        
        # 이메일로 사용자 조회
        user = UserModel.query.filter_by(email=email).first()
        
        if user:
            remaining_attempts = get_remaining_attempts(user)
            
            # 비밀번호 재설정 제한 확인
            if remaining_attempts <= 0:
                flash(f'하루 최대 {max_attempts}회까지만 비밀번호 재설정을 요청할 수 있습니다.', 'error')
                return render_template('forgot_password.html', remaining_attempts=0)
            
            try:
                # 비밀번호 재설정 토큰 생성
                reset_token = generate_password_reset_token(user)
                
                # 비밀번호 재설정 이메일 발송
                if send_password_reset_email(user, reset_token):
                    # 비밀번호 재설정 시도 기록 (DB에 새로운 레코드 생성)
                    new_attempt = PasswordResetAttempt(
                        user_id=user.id,
                        created_at=kst
                    )
                    db.session.add(new_attempt)
                    db.session.commit()
                    
                    # 남은 시도 횟수 다시 계산
                    remaining_attempts = get_remaining_attempts(user)
                    
                    # 보안 이벤트 로깅
                    log_security_event(
                        user, 
                        'password_reset_request', 
                        {'remaining_attempts': remaining_attempts}
                    )
                    
                    # 성공 메시지에 남은 시도 횟수 포함
                    flash(f'비밀번호 재설정 링크가 이메일로 발송되었습니다. 오늘 남은 시도 횟수: {remaining_attempts}회', 'success')
                    
                    return render_template('forgot_password.html', remaining_attempts=remaining_attempts)
                else:
                    # 이메일 발송 실패 처리
                    flash('이메일 발송 중 오류가 발생했습니다. 잠시 후 다시 시도해주세요.', 'error')
            
            except Exception as e:
                # 통합 에러 로깅 및 처리
                current_app.logger.error(f"비밀번호 재설정 프로세스 오류: {str(e)}")
                flash('시스템 오류로 인해 요청을 처리할 수 없습니다.', 'error')
        else:
            flash('해당 이메일로 등록된 사용자가 없습니다.', 'error')
    
    return render_template('forgot_password.html', remaining_attempts=remaining_attempts)


# 이메일로 발송된 비밀번호 초기화시도용 임시 페이지
@bp.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    # 토큰 유효성 검증
    user = verify_password_reset_token(token)
    
    if not user:
        flash('유효하지 않거나 만료된 비밀번호 재설정 링크입니다.', 'error')
        return redirect(url_for('main.login'))
    
    if request.method == 'POST':
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        # 비밀번호 검증 (utils.py의 validate_password_reset 함수 활용)
        validation_result = validate_password_reset(new_password, confirm_password)
        
        if not validation_result['is_valid']:
            flash(validation_result['message'], 'error')
            return render_template('reset_password.html', token=token)
        
        try:
            # 비밀번호 업데이트 및 토큰 초기화
            update_password_and_reset_token(user, new_password)
            
            # 보안 이벤트 로깅
            log_security_event(
                user, 
                'password_reset_success', 
                {'method': 'token_reset'}
            )
            
            flash('비밀번호가 성공적으로 변경되었습니다. 새 비밀번호로 로그인해주세요.', 'success')
            return redirect(url_for('main.login'))
        
        except Exception as e:
            # 보안 이벤트 로깅
            log_security_event(
                user, 
                'password_reset_failed', 
                {'error': str(e)}
            )
            
            # 통합 에러 로깅 및 처리
            current_app.logger.error(f"비밀번호 재설정 오류: {str(e)}")
            flash('비밀번호 변경 중 오류가 발생했습니다. 다시 시도해주세요.', 'error')
            return render_template('reset_password.html', token=token)
    
    return render_template('reset_password.html', token=token)


# 메인 대시보드 페이지
@bp.route('/dashboard', methods=['GET']) 
@login_required
@email_verified_required  # 이메일 인증 필수
def dashboard():
    # DB에서 서비스 내용 GET 요청 처리 - 서비스 목록 표시
    services = MyService.query.filter_by(user_id=current_user.id).order_by(MyService.created_at.desc()).all()
    return render_template('dashboard.html', services=services)





# 유저의 프로필 이미지를 로드하기위한 관련코드 (호출전용, 페이지없음)
@bp.route('/user/<user_id>/profile_image')
@login_required
def get_profile_image(user_id):
    profile_dir = os.path.join(BASE_DIR, 'static', 'userimg', str(user_id)) # 유저 프로필사진의 기본경로 지정
    filename = f'{user_id}_profile_img.webp' # 유저 프로필사진의 표준 파일이름 지정
    
    # 파일이 존재하는지 확인
    if os.path.exists(os.path.join(profile_dir, filename)):
        return send_from_directory(profile_dir, filename)
    else:
        # 파일이 존재하지 않을 경우 기본 이미지 또는 404 에러 반환
        return send_from_directory(os.path.join(BASE_DIR, 'static'), 'default_profile_img.webp'), 404
    


# 유저의 프로필 정보수정 페이지
@bp.route('/user/<user_id>', methods=['GET', 'POST'])
@login_required
@email_verified_required  # 이메일 인증 필수
def user_detail(user_id):
    user = UserModel.query.get_or_404(user_id)

    # 유저정보 수정 페이지에서 변경사항 저장버튼을 누를시.
    if request.method == 'POST':
        username = request.form.get('username')
        new_email = request.form.get('new_email')
        verification_code = request.form.get('verification_code')
        user_profileimg = request.files.get('user_profileimg')
        password = request.form.get('password')

        # 변경된 정보로 저장하기전, 비밀번호 검증
        if not user.check_password(password):
            flash('비밀번호가 일치하지 않습니다.', 'error')
            return redirect(url_for('main.user_detail', user_id=user.id))

        # 이메일 변경 요청을 할경우, 변경될 이메일의 인증을 위해, 토큰검증 관련코드.
        if new_email and new_email != user.email:
            # 이미 존재하는 이메일인지 확인
            existing_user = UserModel.query.filter_by(email=new_email).first()
            if existing_user:
                flash('이미 사용 중인 이메일입니다.', 'error')
                return redirect(url_for('main.user_detail', user_id=user.id))

            # 입력된 인증코드가 없을경우, 오류발생.
            if not verification_code:
                flash('인증 코드를 입력해야 합니다.', 'error')
                return redirect(url_for('main.user_detail', user_id=user.id))

            # 입력된 인증코드가 유효하지 않은경우, 오류발생.
            if verification_code != user.edit_email_verification_token:
                flash('유효하지 않은 인증 코드입니다.', 'error')
                return redirect(url_for('main.user_detail', user_id=user.id))

            user.email = new_email
            user.edit_email_verification_token = None  # 이메일 수정용 인증 코드 초기화

        # 사용자 이름(닉네임) 변경
        if username and username != user.username:
            user.username = username

        # 프로필 이미지 처리
        if user_profileimg:
            saved_image_path = save_profile_image(user_profileimg, user.id)  # user.id를 사용하여 이미지 저장
            if saved_image_path:
                user.user_profileimg = saved_image_path

        # DB에 변경된 사용자정보 저장
        db.session.commit()
        flash('프로필이 성공적으로 업데이트되었습니다.', 'success')
        return redirect(url_for('main.user_detail', user_id=user.id))

    # 프로필 이미지 경로를 설정하여 템플릿에 전달합니다.
    user.user_profileimg = user.user_profileimg or f'/static/userimg/{user.id}/{user.id}_profile_img.webp'  # 기본 이미지 경로 설정
    return render_template('my_profile.html', user=user)




# 유저의 프로필 정보수정 페이지 - 이메일 변경시 이메일 인증코드 발송
@bp.route('/user/<user_id>/request_edit_verification', methods=['POST'])
@login_required
@email_verified_required  # 이메일 인증 필수
def request_edit_verification(user_id):
    user = UserModel.query.get_or_404(user_id)

    new_email = request.form.get('new_email')  # 변경할 이메일
    password = request.form.get('email_password')  # 비밀번호 추가

    # 비밀번호 검증
    if not user.check_password(password):
        flash('비밀번호가 일치하지 않습니다.', 'error')
        return redirect(url_for('main.user_detail', user_id=user.id))

    # 현재 유저의 이메일과 변경될 이메일도 동일한지 검증
    if new_email and new_email != user.email:
        # 이미 존재하는 이메일인지 확인
        existing_user = UserModel.query.filter_by(email=new_email).first()
        if existing_user:
            flash('이미 사용 중인 이메일입니다.', 'error')
            return redirect(url_for('main.user_detail', user_id=user.id))

        # 인증 코드 생성 및 발송
        user.edit_email_address = new_email  # 이메일 발송전 변경될 이메일을 유저DB에 저장
        verification_token = ''.join([str(random.randint(0, 9)) for _ in range(6)])  # 이메일 인증용 6자리 숫자 토큰 생성
        user.edit_email_verification_token = verification_token  # 이메일 발송전 변경될 이메일 인증용 코드를 유저Db에 저장 user.edit_email_verification_expires_at = kst + timedelta(hours=1)  # 이메일 발송전 이메일 인증코드의 유효시간을 지정후, 유저DB에 저장

        # DB내용 저장
        db.session.commit()

        # 변경될 이메일주소로 인증코드 발송
        try:
            requests.post(
                f"https://api.mailgun.net/v3/{Config.MAILGUN_DOMAIN}/messages",
                auth=("api", Config.MAILGUN_API_KEY),  # Mailgun API키 가져오기 (config.py 참고)
                data={
                    "from": Config.MAILGUN_SENDER,  # Mailgun 보내는주소 가져오기 (config.py 참고)
                    "to": [new_email],  # 변경될 이메일주소
                    "subject": "아이디탭 - 이메일 변경 인증 코드",
                    "text": f"""인증 코드: {verification_token}\n\n1시간 내에 인증해주세요
                    
                    만약 본인이 요청하지 않았다면, 개발자에게 제보해주세요..!!!<br>
                    빠르게 파악 후, 조치하겠습니다.<br><br>

                    개발자 이메일 : kgw@geonwoo.dev<br><br>

                    감사합니다.
                    """
                }
            )
            flash('이메일 변경을 위한 인증 코드가 발송되었습니다. 이메일을 확인하세요.', 'info')
        except Exception as e:
            flash('이메일 인증 코드 발송에 실패했습니다.', 'error')
            logging.error(f"이메일 발송 오류발생: {e}")
    else:
        flash('유효한 새로운 이메일 주소를 입력하세요.', 'error')

    return redirect(url_for('main.user_detail', user_id=user.id))


# 유저의 프로필 정보수정 페이지 - 이메일 변경시 이메일 인증코드 검증 관련코드 (호출전용, 페이지없음)
@bp.route('/user/<user_id>/verify_edit_verification_code', methods=['POST'])
@login_required
@email_verified_required  # 이메일 인증 필수
def verify_edit_verification_code(user_id):
    user = UserModel.query.get_or_404(user_id)
    verification_code = request.form.get('verification_code')

    if verification_code == user.edit_email_verification_token:
        flash('인증 코드가 확인되었습니다. 이메일이 성공적으로 변경되었습니다.', 'success')

        # 현재 유저이메일을 변경될 유저 이메일로 값변경
        user.email = user.edit_email_address
        user.edit_email_verification_token = None  # 인증 코드 초기화
        db.session.commit()
    else:
        flash('유효하지 않은 인증 코드입니다.', 'error')

    return redirect(url_for('main.user_detail', user_id=user.id))


# 유저의 프로필 정보수정 페이지 - 이메일 변경시 이메일 인증코드 재발송 관련코드 (호출전용, 페이지없음)
@bp.route('/user/<user_id>/resend_edit_verification', methods=['POST'])
@login_required
@email_verified_required  # 이메일 인증 필수
def resend_edit_verification(user_id):
    user = UserModel.query.get_or_404(user_id)

    if user.edit_email_verification_token:
        verification_token = ''.join([str(random.randint(0, 9)) for _ in range(6)]) # 6자리 숫자로된 토큰 발급
        user.edit_email_verification_token = verification_token # 6자리 숫자 토큰을 DB에 저장
        user.edit_email_verification_expires_at = kst + timedelta(hours=1) # 토큰의 유효기간을 현재 한국표준시 + 1시간으로 지정

        db.session.commit()

        # 변경될 이메일주소로 인증코드 메일발송
        try:
            requests.post(
                f"https://api.mailgun.net/v3/{Config.MAILGUN_DOMAIN}/messages",
                auth=("api", Config.MAILGUN_API_KEY), # Mailgun API키 가져오기 (config.py 참고)
                data={
                    "from": Config.MAILGUN_SENDER, # Mailgun 보내는주소 가져오기 (config.py 참고)
                    "to": [user.edit_email_address], # DB에 저장되어있는 변경될 이메일주소 가져오기.
                    "subject": "아이디탭 - 이메일 변경 인증 코드 재발송",
                    "text": f"""인증 코드: {verification_token}\n\n1시간 내에 인증해주세요
                    
                    만약 본인이 요청하지 않았다면, 개발자에게 제보해주세요..!!!<br>
                    빠르게 파악 후, 조치하겠습니다.<br><br>

                    개발자 이메일 : kgw@geonwoo.dev<br><br>

                    감사합니다.
                    """
                }
            )
            flash('인증 코드가 재발송되었습니다. 이메일을 확인하세요.', 'info')
        except Exception as e:
            flash('인증 코드 재발송에 실패했습니다.', 'error')
            logging.error(f"이메일 재전송 오류발생 : {e}")
    else:
        flash('먼저 인증 코드를 요청하세요.', 'warning')

    return redirect(url_for('main.user_detail', user_id=user.id))



# 유저의 프로필 정보수정 페이지 - 프로필 이미지 변환 및 압축용 코드
def save_profile_image(user_profileimg, user_id):
    # 이미지 파일 저장 경로
    profile_dir = os.path.join(BASE_DIR, 'static', 'userimg', str(user_id)) # 유저 프로필사진의 기본경로 지정  # C:/Users/admin/Documents/GitHub/web-profile-card__console/static/userimg/{user_id}
    filename = f'{user_id}_profile_img.webp' # 유저 프로필사진의 표준 파일이름 지정
    save_path = os.path.join(profile_dir, filename) # 저장할 폴더 및 파일명 지정

    # 디렉토리가 존재하지 않으면 생성
    if not os.path.exists(profile_dir):
        os.makedirs(profile_dir)
        logging.info(f"Created directory: {profile_dir}")

    try:
        # 이미지 열기
        img = Image.open(user_profileimg)
        logging.info(f"Opened image: {user_profileimg.filename}")

        # 이미지 크기 확인
        width, height = img.size
        logging.info(f"Image size: {width}x{height}")

        # 1:1 비율로 이미지 크롭
        crop_size = min(width, height)
        left = (width - crop_size) // 2
        top = (height - crop_size) // 2
        img = img.crop((left, top, left + crop_size, top + crop_size))
        logging.info("Image cropped successfully.")

        # 300x300 사이즈로 이미지 리사이즈
        img = img.resize((300, 300), Image.LANCZOS)
        logging.info("Image resized successfully.")

        # 처리 완료된 이미지를 임시 폴더내로 저장
        temp_path = os.path.join(profile_dir, 'temp_image.webp')
        img.save(temp_path, format='WEBP', quality=80)
        logging.info(f"Temporary image saved at: {temp_path}")

        # 임시폴더내에 저장된 이미지를 최종경로로 이동 및 저장
        shutil.move(temp_path, save_path)
        logging.info(f"Image saved successfully at: {save_path}")

        return f'/static/userimg/{user_id}/{filename}'  # 저장된 이미지 경로 반환
    
    except Exception as e:
        flash('이미지 처리 중 오류가 발생했습니다.', 'error')
        logging.error(f"이미지 처리중 오류발생: {e}")
        return None  # 오류 발생 시 None 반환






# 로그아웃용 코드 (호출전용, 페이지없음)
@bp.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('main.index'))


# 나의 서비스 페이지
@bp.route('/my_services', methods=['GET', 'POST'])
@login_required
@email_verified_required  # 이메일 인증 필수
def my_services():
    if request.method == 'POST':
        # 서비스 생성
        name = request.form.get('name') # 서비스 이름
        description = request.form.get('description') # 서비스 설명

        # 사용자의 월간 서비스 카운트 초기화 (None 방지)
        if current_user.monthly_service_count is None:
            current_user.monthly_service_count = 0
        if current_user.current_active_services is None:
            current_user.current_active_services = 0

        # 서비스 생성 가능 여부 확인
        can_create, error_message = can_create_service(current_user)
        if not can_create:
            flash(error_message, 'error')
            return redirect(url_for('main.my_services'))

        # 중복된 이름의 서비스 체크
        existing_service = MyService.query.filter_by(user_id=current_user.id, name=name).first()
        if existing_service:
            flash('동일한 이름의 서비스가 이미 있습니다.', 'error')
            return redirect(url_for('main.my_services'))

        # 고유한 short_url 생성 - 서비스 배포시 사용
        short_url = generate_unique_short_url()

        # 새로운 서비스 UUID 생성
        new_service_uuid = str(uuid.uuid4())

        new_service = MyService(
            user_id=current_user.id,
            name=name,
            description=description,
            short_url=short_url,
            uuid=new_service_uuid  # UUID 추가
        )

        try:
            db.session.add(new_service)

            # 사용자 서비스 카운트 업데이트
            current_user.monthly_service_count += 1
            current_user.current_active_services += 1

            db.session.commit()


            # 유저 ID와 UUID를 사용하여 서비스 디렉토리 이름 생성
            service_dir_name = f"{current_user.uuid}_{new_service_uuid[:7]}"  # UUID의 첫 7자리 사용


            # 샘플 디렉토리와 서비스 디렉토리 경로 설정
            sample_dir = 'C:/Users/admin/Documents/GitHub/web-profile-card__console/app/sample'
            service_dir = f'C:/Users/admin/Documents/GitHub/web-profile-card__console/services/{service_dir_name}'

            # 서비스 디렉토리 생성
            os.makedirs(service_dir, exist_ok=True)


            # 샘플 디렉토리의 파일 및 폴더 복사
            for item in os.listdir(sample_dir):
                s = os.path.join(sample_dir, item)
                d = os.path.join(service_dir, item)
                if os.path.isdir(s):
                    shutil.copytree(s, d, False, None)
                else:
                    shutil.copy2(s, d)

            flash('성공적으로 서비스를 생성하였어요!', 'success')
            return redirect(url_for('main.my_services'))
        except Exception as e:
            db.session.rollback()
            flash(f'서비스 생성중, 오류발생 : {str(e)}', 'error')
            return redirect(url_for('main.my_services'))

    # GET 요청 처리 - 서비스 목록 표시
    services = MyService.query.filter_by(user_id=current_user.id).order_by(MyService.created_at.desc()).all()
    return render_template('my_services.html', services=services)




# 서비스 내용수정용 페이지
@bp.route('/edit_service/<uuid:service_uuid>', methods=['GET', 'POST'])
@login_required
@email_verified_required  # 이메일 인증 필수
def edit_service(service_uuid):
    # # UUID 형식 검증
    # try:
    #     valid_uuid = uuid.UUID(str(service_uuid))
    # except ValueError:
    #     flash('유효하지 않은 UUID 형식입니다.', 'error')
    #     return redirect(url_for('main.my_services'))

    # 서비스 조회
    service = MyService.query.filter_by(uuid=str(service_uuid)).first_or_404()

    # 서비스를 생성한 유저와 현재 유저의 id가 서로 일치하는지 체크 (혹시모를 보안용)
    if service.user_id != current_user.id:
        flash('이 서비스를 수정할 권한이 없습니다.', 'error')
        return redirect(url_for('main.my_services'))

    # 서비스 디렉토리 경로 설정
    service_dir_name = f"{current_user.uuid}_{service.uuid[:7]}" # 해당서비스의 폴더명 지정
    service_dir = f'C:/Users/admin/Documents/GitHub/web-profile-card__console/services/{service_dir_name}' # 서비스 폴더의 경로 지정

    data_file_path = os.path.join(service_dir, 'data.json') # data.json의 파일명 지정
    contact_file_path = os.path.join(service_dir, 'contact.json') # contact.json의 파일명 지정
    
    

    # 이미지 파일 경로들
    image_files = ['profile.webp', 'carousel_1.webp', 'carousel_2.webp', 'carousel_3.webp']
    image_paths = {}

    # 이미지 파일 존재 여부 확인
    for img_file in image_files:
        img_path = os.path.join(service_dir, img_file)
        if os.path.exists(img_path):
            with open(img_path, 'rb') as image_file:
                encoded_image = base64.b64encode(image_file.read()).decode('utf-8')
                image_paths[img_file.split('.')[0]] = f"data:image/webp;base64,{encoded_image}"
        else:
            image_paths[img_file.split('.')[0]] = 'C:/Users/admin/Documents/GitHub/web-profile-card__console/static/load_error.webp' # 이메일 로드 실패시 오류 이미지로 대체삽입.


    # json_data와 contact_data 초기화
    json_data = ""
    contact_data = ""


    # 서비스의 변경사항 저장 버튼을 누를시 실행되는 코드
    if request.method == 'POST':
        # 변경사항 저장시, 변경된내용을 Cloudflare R2에 저장하기 위한, S3 클라이언트 초기화코드 (함수 외부에서 선언)
        s3_client = boto3.client(
            's3',
            aws_access_key_id=Config.R2_ACCESS_KEY, # config.py에서 R2_ACCESS_KEY 로드
            aws_secret_access_key=Config.R2_SECRET_KEY, # config.py에서 R2_SECRET_KEY 로드
            endpoint_url=Config.R2_ENDPOINT_URL, # config.py에서 R2_ENDPOINT_URL 로드
            region_name='auto' # (클라우드 플레어 권장사항)
        )

        updated_data = request.form.get('data') # 변경된 data.json을 R2에 업로드하기 위해 가져오기
        updated_contact = request.form.get('contact') # 변경된 contact.json을 R2에 업로드하기 위해 가져오기

        

        # R2에 변경된 이미지를 업로드하기 위한 핸들
        image_files = {
            'profile_image': request.files.get('profile_image'),
            'carousel_image_1': request.files.get('carousel_image_1'),
            'carousel_image_2': request.files.get('carousel_image_2'),
            'carousel_image_3': request.files.get('carousel_image_3')
        }

        def save_and_convert_image(image_file, filename):
            # s3_client를 함수의 인자로 추가
            if image_file:
                try:
                    img = Image.open(image_file)
                    
                    # 프로필 이미지 특별 처리 (1. 300x300 사이즈, 2. 지정된 이름 및 WEBP로 확장명 변경, 3. 퀄리티 80으로 압축)
                    if filename == 'profileimage.webp':
                        filename = 'profile.webp'  # 파일명 수정
                        width, height = img.size
                        crop_size = min(width, height)
                        left = (width - crop_size) // 2
                        top = (height - crop_size) // 2
                        img = img.crop((left, top, left + crop_size, top + crop_size))
                        img = img.resize((300, 300), Image.LANCZOS) 
                    
                    elif filename in ['carousel1image.webp', 'carousel2image.webp', 'carousel3image.webp']:
                        # 캐러셀 이미지 파일명 매핑
                        mapping = {
                            'carousel1image.webp': 'carousel_1.webp',
                            'carousel2image.webp': 'carousel_2.webp', 
                            'carousel3image.webp': 'carousel_3.webp'
                        }
                        filename = mapping[filename]
                    
                    img = img.convert("RGBA")
                    local_path = os.path.join(service_dir, filename)
                    
                    # 로컬 저장
                    img.save(local_path, format='WEBP', quality=80) # webp 확장자 및 퀄리티 80으로 압축저장
                    
                    # R2 업로드를 위한 BytesIO 객체 생성
                    img_io = io.BytesIO()
                    img.save(img_io, format='WEBP', quality=80)
                    img_io.seek(0)
                    
                    return img_io, filename
                except Exception as e:
                    logging.error(f"이미지 처리중 오류발생 : {e}")
                    return None, None
            return None, None

        try:
            # JSON 파일로드 및 R2로 변경사항 저장
            def update_local_json(file_path, content):
                try:
                    parsed_json = json.loads(content)
                    with open(file_path, 'w', encoding='utf-8') as f:
                        json.dump(parsed_json, f, ensure_ascii=False, indent=4)
                    return parsed_json
                except json.JSONDecodeError:
                    logging.error(f"올바르지 않은 JSON파일 {file_path}")
                    return None


            # JSON 파일 처리
            local_data = update_local_json(data_file_path, updated_data)
            local_contact = update_local_json(contact_file_path, updated_contact)

            if local_data and local_contact:
                # R2에 JSON 업로드 - data.json, contact.json
                s3_client.put_object(
                    Bucket=Config.R2_BUCKET_NAME,
                    Key=f"{service.short_url}/data.json",
                    Body=json.dumps(local_data, ensure_ascii=False, indent=4)
                )
                s3_client.put_object(
                    Bucket=Config.R2_BUCKET_NAME,
                    Key=f"{service.short_url}/contact.json",
                    Body=json.dumps(local_contact, ensure_ascii=False, indent=4)
                )
            else:
                return jsonify({'success': False, 'error': 'JSON 파일 업데이트 실패'}), 400

            # 변경될 모든 이미지 처리 및 업로드
            image_files = {
                'profile_image': request.files.get('profile_image'),
                'carousel_image_1': request.files.get('carousel_image_1'),
                'carousel_image_2': request.files.get('carousel_image_2'),
                'carousel_image_3': request.files.get('carousel_image_3')
            }

            # 모든 이미지 파일명 매핑
            filename_mapping = {
                'profile_image': 'profileimage.webp',
                'carousel_image_1': 'carousel1image.webp',
                'carousel_image_2': 'carousel2image.webp',
                'carousel_image_3': 'carousel3image.webp'
            }

            # 모든 파일들을 업로드하기위한, 코드
            for key, file in image_files.items():
                if file:
                    filename = filename_mapping.get(key)
                    
                    if filename:
                        img_io, saved_filename = save_and_convert_image(file, filename)
                        
                        if img_io and saved_filename:
                            # R2에 이미지 업로드
                            s3_client.upload_fileobj(
                                img_io, 
                                Config.R2_BUCKET_NAME, 
                                f"{service.short_url}/{saved_filename}"
                            )

            return jsonify({'success': True, 'message': '성공적으로 업데이트되었습니다.'}), 200

        except Exception as e:
            logging.error(f"서비스 수정 중 오류발생: {e}")
            return jsonify({'success': False, 'error': str(e)}), 500

    # 기존 JSON 읽기 로직 (GET 요청 처리)
    try:
        with open(data_file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
            json_data = json.dumps(data, ensure_ascii=False, indent=4)
    except (FileNotFoundError, json.JSONDecodeError):
        json_data = json.dumps({"items": []}, ensure_ascii=False, indent=4)

    # contact.json 읽기 로직
    try:
        with open(contact_file_path, 'r', encoding='utf-8') as f:
            contact = json.load(f)
            contact_data = json.dumps(contact, ensure_ascii=False, indent=4)
    except (FileNotFoundError, json.JSONDecodeError):
        contact_data = json.dumps({"contacts": []}, ensure_ascii=False, indent=4)

    return render_template('edit_service.html', 
                        service=service, 
                        json_data=json_data, 
                        contact_data=contact_data,  
                        image_paths=image_paths)



# 생성된 서비스를 삭제하기 위한 코드 (호출전용, 페이지 없음)
@bp.route('/my_services/delete/<uuid:service_uuid>', methods=['POST'])
@login_required
@email_verified_required  # 이메일 인증 필수
def delete_service(service_uuid):
    # # UUID 형식 검증 (선택적)
    # try:
    #     valid_uuid = uuid.UUID(str(service_uuid))
    # except ValueError:
    #     flash('Invalid UUID format', 'error')
    #     return redirect(url_for('main.my_services'))

    # 기존 로직과 동일
    service = MyService.query.filter_by(uuid=str(service_uuid)).first_or_404()


    # 서비스를 생성한 유저와 현재 유저의 id가 서로 일치하는지 체크 (혹시모를 보안용)
    if service.user_id != current_user.id:
        flash('서비스에 접근할 권한이 없습니다.', 'error')
        return redirect(url_for('main.my_services'))


    # 배포 상태 확인 - 배포 중인 서비스는 삭제 불가
    if service.is_deployed:
        flash('활성화된 배포를 먼저 취소해주세요.', 'error')
        return redirect(url_for('main.my_services'))

    try:
        # Cloudflare R2에서 서비스 관련 객체들 모두삭제
        try:
            s3_client = boto3.client(
                's3',
                aws_access_key_id=Config.R2_ACCESS_KEY, # config.py에서 R2_ACCESS_KEY 로드
                aws_secret_access_key=Config.R2_SECRET_KEY, # config.py에서 R2_SECRET_KEY 로드
                endpoint_url=Config.R2_ENDPOINT_URL, # config.py에서 R2_ENDPOINT_URL 로드
                region_name='auto' # (클라우드 플레어 권장사항)
                
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
            logging.error(f"R2 객체 삭제 중 오류: {e}")
            # R2 삭제 실패해도 계속 진행 - (? 내가 뭘만든거지 대체...)

        # 유저 UUID를 가져옵니다.
        user_uuid = current_user.uuid
        
        # 서비스 디렉토리 이름 생성
        service_dir_name = f"{user_uuid}_{service.uuid[:7]}"  # UUID의 첫 7자리 사용
        
        # 서비스 디렉토리 경로 설정
        service_dir = f'C:/Users/admin/Documents/GitHub/web-profile-card__console/services/{service_dir_name}'


        # 서비스 폴더 삭제
        if os.path.exists(service_dir):
            shutil.rmtree(service_dir)

        

        # 서비스 배포 상태 업데이트
        service.is_deployed = False
        service.deployed_at = None


        # 관련된 모든 배포 기록 삭제
        ServiceDeploy = db.Model.registry._class_registry.get('ServiceDeploy')
        if ServiceDeploy:
            ServiceDeploy.query.filter_by(service_id=service.id).delete()

        # 사용자 배포 취소 카운트 업데이트
        current_user.current_active_deploys -= 1
        current_user.last_deploy_reset = kst


        # 서비스 삭제
        db.session.delete(service)
        db.session.commit()
        
        flash('해당 서비스를 정상적으로 삭제했어요.', 'success')
    
    except Exception as e:
        db.session.rollback()
        flash(f'서비스 삭제중, 오류발생 : {str(e)}', 'error')
        logging.error(f"서비스 삭제 중 오류: {e}")

    return redirect(url_for('main.my_services'))


# 서비스관련 코드들을 위한, 고유한 short_url 생성코드
def generate_unique_short_url():
    # 고유한 short_url 생성 로직
    return ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(6)) # 숫자와 영문자를 혼합한 6자리 문자열 생성



# 서비스를 퍼블릭으로 배포하기 위한, R2버킷 업로드 관련코드 (호출전용, 페이지 없음)
@bp.route('/deploy_service/<uuid:service_uuid>', methods=['POST'])
@login_required
@email_verified_required  # 이메일 인증 필수
def deploy_service(service_uuid):
    try:
        # 배포 가능 여부 확인 - 배포가능 횟수 초과시, 배포 오류발생
        can_deploy, error_message = can_deploy_service(current_user)
        if not can_deploy:
            flash(error_message, 'error')
            return redirect(url_for('main.my_services'))


        # 배포할 서비스 가져오기
        service = MyService.query.filter_by(uuid=str(service_uuid)).first_or_404()


        # 서비스를 생성한 유저와 현재 유저의 id가 서로 일치하는지 체크 (혹시모를 보안용)
        if service.user_id != current_user.id:
            flash('이 서비스를 배포할 권한이 없습니다.', 'error')
            return redirect(url_for('main.my_services'))

        # 서비스 디렉토리 경로 준비
        service_dir_name = f"{current_user.uuid}_{service.uuid[:7]}" # 서비스 폴더내의 해당 서비스 폴더명 지정
        service_dir = os.path.join(
            'C:/Users/admin/Documents/GitHub/web-profile-card__console/services', 
            service_dir_name
        )


        # Cloudflare R2용 S3 클라이언트 초기화
        try:
            s3_client = boto3.client(
                's3',
                aws_access_key_id=Config.R2_ACCESS_KEY, # config.py에서 R2_ACCESS_KEY 로드
                aws_secret_access_key=Config.R2_SECRET_KEY, # config.py에서 R2_SECRET_KEY 로드
                endpoint_url=Config.R2_ENDPOINT_URL, # config.py에서 R2_ENDPOINT_URL 로드
                region_name='auto' # (클라우드 플레어 권장사항)
            )
        except Exception as e:
            logging.error(f"S3 클라이언트 초기화 실패: {e}")
            flash('R2 클라이언트 초기화 중 오류 발생', 'error')
            return redirect(url_for('main.my_services'))

        # 업로드할 파일 목록들
        files_to_upload = [
            'carousel_1.webp',
            'carousel_2.webp',
            'carousel_3.webp',
            'index.html',
            'profile.webp',
            'data.json',
            'contact.json'
        ]

        # 업로드 제한 및 필터링 함수 - (혹시모를 보안 및 오류방지용)
        def is_allowed_file(filename):
            ALLOWED_EXTENSIONS = {
                'html', 'css', 'js', 'json', 
                'txt', 'png', 'jpg', 'jpeg', 
                'gif', 'webp', 'svg', 'ico'
            }
            return filename.lower().split('.')[-1] in ALLOWED_EXTENSIONS

        def get_mime_type(filename):
            mime_types = {
                'html': 'text/html',
                'css': 'text/css',
                'js': 'application/javascript',
                'json': 'application/json',
                'png': 'image/png',
                'jpg': 'image/jpeg',
                'jpeg': 'image/jpeg',
                'gif': 'image/gif',
                'webp': 'image/webp',
                'svg': 'image/svg+xml',
                'ico': 'image/x-icon'
            }
            ext = filename.lower().split('.')[-1]
            return mime_types.get(ext, 'application/octet-stream')


        # 파일 업로드 함수 개선 - 
        def upload_to_r2(local_path, r2_path):
            try:
                # 파일 크기 제한 (10MB) - 정상적인 경우 절대로 10MB가 초과되지않음.
                if os.path.getsize(local_path) > 10 * 1024 * 1024:
                    logging.warning(f"파일 크기 초과: {local_path}")
                    return False

                filename = os.path.basename(local_path)
                
                # 파일 확장자 검증
                if not is_allowed_file(filename):
                    logging.warning(f"허용되지 않는 파일 형식: {filename}")
                    return False

                # 메타데이터 및 콘텐츠 타입 설정
                extra_args = {
                    'ContentType': get_mime_type(filename),
                    'ACL': 'public-read'  # 공개 읽기 권한 설정
                }

                s3_client.upload_file(
                    local_path, 
                    Config.R2_BUCKET_NAME, 
                    r2_path,
                    ExtraArgs=extra_args
                )
                return True
            except Exception as e:
                logging.error(f"R2 업로드 실패 - {local_path}: {e}")
                return False

        # 각 파일을 업로드
        for filename in files_to_upload:
            local_file_path = os.path.join(service_dir, filename)  # 로컬 파일 경로
            r2_file_path = f"{service.short_url}/{filename}"  # R2에 업로드할 경로
            if not upload_to_r2(local_file_path, r2_file_path):
                flash(f'{filename} 업로드 실패', 'error')
                return redirect(url_for('main.my_services'))

        # 사용자 배포 카운트 업데이트
        current_user.monthly_deploy_count += 1
        current_user.current_active_deploys += 1
        current_user.last_deploy_reset = kst

        # 서비스 배포 상태 업데이트
        service.is_deployed = True
        service.deployed_at = kst
        db.session.commit()

        # 성공 메시지 추가
        flash('서비스 배포 성공!', 'success')
        return redirect(url_for('main.my_services'))

    except Exception as e:
        logging.error(f"서비스 배포 중 오류: {e}")
        flash(f'서비스 배포 중 오류 발생: {str(e)}', 'error')
        return redirect(url_for('main.my_services'))


# 배포된 서비스의 배포를 취소하는 코드 (호출전용, 페이지 없음)
@bp.route('/delete_deploy/<uuid:service_uuid>', methods=['POST'])
@login_required
@email_verified_required  # 이메일 인증 필수
def delete_deploy(service_uuid):
    # 배포 취소 가능 여부 확인
    can_delete, error_message = can_delete_deploy(current_user)
    if not can_delete:
        flash(error_message, 'error')
        return redirect(url_for('main.my_services'))
    
    # # UUID 유효성 검사
    # try:
    #     valid_uuid = uuid.UUID(str(service_uuid))
    # except ValueError:
    #     flash('잘못된 UUID 형식입니다.', 'error')
    #     return redirect(url_for('main.my_services'))

    # 배포할 서비스 가져오기
    service = MyService.query.filter_by(uuid=str(service_uuid)).first_or_404()

    # 서비스를 생성한 유저와 현재 유저의 id가 서로 일치하는지 체크 (혹시모를 보안용)
    if service.user_id != current_user.id:
        flash('이 서비스를 삭제할 권한이 없습니다.', 'error')
        return redirect(url_for('main.my_services'))


    # Cloudflare R2용 S3 클라이언트 초기화
    s3_client = boto3.client(
        's3',
        aws_access_key_id=Config.R2_ACCESS_KEY, # config.py에서 R2_ACCESS_KEY 로드
        aws_secret_access_key=Config.R2_SECRET_KEY, # config.py에서 R2_SECRET_KEY 로드
        endpoint_url=Config.R2_ENDPOINT_URL, # config.py에서 R2_ENDPOINT_URL 로드
        region_name='auto' # (클라우드 플레어 권장사항)
    )

    try:
        # 삭제할 폴더명 (서비스의 short_url)
        upload_folder_name = service.short_url


        # 해당 폴더의 모든 객체 나열(불러오기)
        response = s3_client.list_objects_v2(
            Bucket=Config.R2_BUCKET_NAME, 
            Prefix=f"{upload_folder_name}/"
        )

        # 삭제할 서비스의 모든 객체삭제
        if 'Contents' in response:
            objects_to_delete = [
                {'Key': obj['Key']} for obj in response['Contents']
            ]
            
            # 최대 1000개 객체 삭제 (R2의 기본제한) - 정상적인 경우 절대 1000개를 넘기지않음.
            s3_client.delete_objects(
                Bucket=Config.R2_BUCKET_NAME,
                Delete={'Objects': objects_to_delete}
            )


        # 사용자 배포 취소 카운트 업데이트
        current_user.current_active_deploys -= 1
        current_user.last_deploy_reset = kst

        # 서비스 배포 상태 업데이트
        service.is_deployed = False
        service.deployed_at = None
        db.session.commit()

        flash('서비스 배포가 성공적으로 취소되었습니다.', 'success')
    except Exception as e:
        flash(f'서비스 배포 취소 중 오류 발생: {str(e)}', 'error')

    return redirect(url_for('main.my_services'))


# 배포된 서비스를 공유하기 위한 코드 (호출전용, 페이지 없음)
@bp.route('/share_service/<uuid:service_uuid>', methods=['GET'])
@login_required
@email_verified_required  # 이메일 인증 필수
def share_view_service(service_uuid):
    # try:
    #     # UUID 형식 검증
    #     valid_uuid = uuid.UUID(str(service_uuid))
    # except ValueError:
    #     flash('유효하지 않은 UUID 형식입니다.', 'error')
    #     return redirect(url_for('main.my_services'))

    # 서비스 조회
    service = MyService.query.filter_by(uuid=str(service_uuid)).first_or_404()


    # 현재 사용자의 서비스인지 확인 - (혹시모를 보안용)
    if service.user_id != current_user.id:
        flash('이 서비스를 공유할 권한이 없습니다.', 'error')
        return redirect(url_for('main.my_services'))


    # 서비스 공개 URL 생성 (config.py 참고)
    public_url = f"https://{Config.PUBLIC_DOMAIN}/{service.short_url}/index.html" # 형식예시 : https://[config.py의 사용자지정 URL]/[해당 서비스의 short_url값]/index.html
    preview_url = f"https://{Config.PREVIEW_DOMAIN}/{service.short_url}/index.html" # 형식예시 : https://[config.py의 사용자지정 URL]/[해당 서비스의 short_url값]/index.html

    return render_template('my_services.html', 
                        service=service, 
                        public_url=public_url, 
                        preview_url=preview_url)


# 배포된 서비스의 url을 공유하기 위한 코드 (호출전용, 페이지 없음)
@bp.route('/get_service_url/<uuid:service_uuid>', methods=['GET'])
@login_required
@email_verified_required  # 이메일 인증 필수
def get_service_url(service_uuid):
    # try:
    #     # UUID 형식 검증
    #     valid_uuid = uuid.UUID(str(service_uuid))
    # except ValueError:
    #     return jsonify({
    #         'success': False, 
    #         'message': '유효하지 않은 UUID 형식입니다.'
    #     }), 400

    # 서비스 조회
    service = MyService.query.filter_by(uuid=str(service_uuid)).first_or_404()

    # 현재 사용자의 서비스인지 확인 - (혹시모를 보안용)
    if service.user_id != current_user.id:
        return jsonify({
            'success': False, 
            'message': '이 서비스를 공유할 권한이 없습니다.'
        }), 403

    # 서비스 공개 URL 생성 (config.py 참고)
    public_url = f"https://{Config.PUBLIC_DOMAIN}/{service.short_url}/index.html" # 형식예시 : https://[config.py의 사용자지정 URL]/[해당 서비스의 short_url값]/index.html
    preview_url = f"https://{Config.PREVIEW_DOMAIN}/{service.short_url}/index.html" # 형식예시 : https://[config.py의 사용자지정 URL]/[해당 서비스의 short_url값]/index.html


    return jsonify({
        'success': True,
        'public_url': public_url,
        'preview_url': preview_url
    })



# 월간 서비스 사용량 제한 관련로직
def reset_monthly_service_count(user):
    """
    한 달이 지났으면 월간 서비스 생성 카운트 리셋
    """
    now = kst
    if now - user.last_service_count_reset > timedelta(days=30):
        user.monthly_service_count = 0
        user.last_service_count_reset = now

def can_create_service(user):
    """
    사용자가 새 서비스를 생성할 수 있는지 확인
    
    조건:
    1. 월간 서비스 생성 제한 (10개)
    2. 현재 활성 서비스 제한 (3개)
    """
    # 월간 카운트 리셋 확인
    reset_monthly_service_count(user)

    # 값이 None인 경우 0으로 초기화
    monthly_count = user.monthly_service_count or 0
    active_services = user.current_active_services or 0

    
    # 월간 서비스 생성 제한 (10개)
    if monthly_count >= 10:
        return False, "월간 서비스 생성 한도(10개)를 초과했습니다."
    
    # 현재 활성 서비스 제한 (3개)
    if active_services >= 3:
        return False, "최대 보유 가능한 서비스 수(3개)를 초과했습니다."
    
    
    return True, ""



# 월간 deploy 사용량 제한 관련로직
def reset_monthly_deploy_count(user):
    """
    한 달이 지났으면 월간 배포 카운트 리셋
    """
    now = kst
    if user.last_deploy_reset is None or now - user.last_deploy_reset > timedelta(days=30):
        user.monthly_deploy_count = 0
        user.current_active_deploys = 0
        user.last_deploy_reset = now
        db.session.commit()

def can_deploy_service(user):
    """
    사용자가 서비스를 배포할 수 있는지 확인
    
    조건:
    1. 월간 배포 제한 (10개)
    2. 현재 활성 배포 제한 (3개)
    """
    reset_monthly_deploy_count(user)
    
    # 월간 배포 제한 (10개)
    if user.monthly_deploy_count >= 10:
        return False, "월간 서비스 배포 한도(10개)를 초과했습니다."
    
    # 현재 활성 배포 제한 (3개)
    if user.current_active_deploys >= 3:
        return False, "최대 배포 가능한 서비스 수(3개)를 초과했습니다."
    
    return True, ""

def can_delete_deploy(user):
    """
    사용자가 서비스 배포를 취소할 수 있는지 확인
    
    조건:
    1. 월간 배포 취소 제한 (20개)
    """
    reset_monthly_deploy_count(user)
    
    # 월간 배포 취소 제한 (20개)
    if user.monthly_deploy_count >= 20:
        return False, "월간 서비스 배포 취소 한도(20개)를 초과했습니다."
    
    return True, ""





# 회원탈퇴용 페이지
@bp.route('/withdrawal', methods=['GET', 'POST'])
@login_required
@email_verified_required  # 이메일 인증 필수
def withdrawal():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        verification_code = request.form.get('verification_code')
        
        # 이메일과 비밀번호 검증을 process_withdrawal 함수 내부로 이동
        result = process_withdrawal(current_user, email, password, verification_code)
        
        if result['success']:
            flash('성공적으로 회원 탈퇴되었습니다.', 'success')
            return redirect(url_for('main.index'))
        else:
            flash(result['message'], 'error')
            return render_template('withdrawal.html')
    
    return render_template('withdrawal.html')

# 회원탈퇴를 위한, 이메일 인증코드 발송 관련코드 (호출전용, 페이지 없음)
@bp.route('/send_withdrawal_verification', methods=['POST'])
@login_required
@email_verified_required  # 이메일 인증 필수
def send_withdrawal_verification():
    # 폼 데이터에서 이메일, 비밀번호 받기
    email = request.form.get('email')
    password = request.form.get('password')

    # 디버깅 로그
    # print(f"Received Email: {email}")
    # print(f"Current User Email: {current_user.email}")

    # 입력된 이메일이 현재 로그인된 사용자의 이메일과 일치하는지 확인
    if email != current_user.email:
        return jsonify({
            'success': False, 
            'message': '유효하지 않은 이메일입니다.'
        })

    # 비밀번호 검증 
    if not current_user.check_password(password):
        return jsonify({
            'success': False, 
            'message': '비밀번호가 올바르지 않습니다.'
        })

    # 이메일 인증 코드 발송 로직
    result = send_withdrawal_verification_email(current_user)
    
    if result['success']:
        return jsonify({'success': True})
    else:
        return jsonify({
            'success': False, 
            'message': result.get('message', '인증 코드 발송에 실패했습니다.')
        })

