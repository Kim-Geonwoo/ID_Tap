from functools import wraps
from flask import redirect, url_for, flash
from flask_login import current_user

# 이메일 인증이 완료된 사용자전용 페이지를 설정하기위한, 관련코드
def email_verified_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            flash('로그인이 필요합니다.', 'error')
            return redirect(url_for('main.login'))
        
        if not current_user.email_verified:
            flash('이메일 인증이 필요합니다.', 'error')
            return redirect(url_for('main.verify_email'))
        
        return f(*args, **kwargs)
    return decorated_function