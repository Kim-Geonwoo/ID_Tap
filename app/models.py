import uuid
from app import db, login_manager
from datetime import datetime, timedelta
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.orm import validates
import hashlib


now = datetime.now() # 한국 현재시간 계산 1
kst = now + timedelta(hours=17) # 한국 현재시간 계산 2



@login_manager.user_loader
def load_user(user_id):
    return UserModel.query.get(user_id)  # user_id를 정수로 변환하지 않고 그대로 사용


# request_loader 예제 (선택적)
# @login_manager.request_loader
# def load_user_from_request(request):
#     # 요청에서 사용자 인증 정보를 추출하는 로직을 추가합니다.
#     return None  # 인증 정보를 찾지 못한 경우 None을 반환합니다.


class UserModel(db.Model, UserMixin):
    __tablename__ = 'users'

    id = db.Column(db.String(5), primary_key=True)  # id를 문자열로 변경
    uuid = db.Column(db.String(36), unique=True, default=lambda: str(uuid.uuid4()), nullable=False)
    username = db.Column(db.String(150), unique=False, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=True)
    password_hash = db.Column(db.String(255), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=kst)
    user_title = db.Column(db.String(100), default='일반 사용자')
    user_profileimg = db.Column(db.String(255), default='userimg/default.webp')

    # 서비스 사용량제한 관련코드
    # 기본값을 0으로 명시적으로 설정
    monthly_service_count = db.Column(db.Integer, default=0, nullable=False)
    current_active_services = db.Column(db.Integer, default=0, nullable=False)
    last_service_count_reset = db.Column(db.DateTime, default=kst)

    # 월간 서비스 deploy 사용량 제한코드
    monthly_deploy_count = db.Column(db.Integer, default=0, nullable=False)
    current_active_deploys = db.Column(db.Integer, default=0, nullable=False)
    last_deploy_reset = db.Column(db.DateTime, default=kst)

    # 이메일 검증 관련필드 추가
    email_verified = db.Column(db.Boolean, default=False)
    email_verification_token = db.Column(db.String(100), nullable=True)
    email_verification_expires_at = db.Column(db.DateTime, nullable=True)

    # 이메일 수정 관련필드 추가
    is_edit_email_verification = db.Column(db.Boolean, default=True)
    edit_email_address = db.Column(db.String, nullable=True)  # 변경할 이메일
    edit_email_verification_token = db.Column(db.String, nullable=True)  # 인증 코드
    edit_email_verification_expires_at = db.Column(db.DateTime, nullable=True)  # 만료 시간

    # 회원탈퇴를 위한 관련필드 추가
    withdrawal_verification_token = db.Column(db.String(10), nullable=True)
    withdrawal_verification_expires_at = db.Column(db.DateTime, nullable=True)

    # 비밀번호 재설정용 url토큰관련 필드추가
    password_reset_token = db.Column(db.String(100), nullable=True)
    password_reset_expires_at = db.Column(db.DateTime, nullable=True)
    password_reset_attempts = db.relationship(
        'PasswordResetAttempt', 
        back_populates='user',
        overlaps="password_reset_attempts_list"
    )


    # 이메일 인증 시도 관계 설정
    email_verification_attempts = db.relationship(
        'EmailVerificationAttempt', 
        backref='user', 
        cascade='all, delete-orphan'
    )

    def get_verification_attempts_in_last_hour(self):
        """
        지난 1시간 동안의 이메일 인증 시도 횟수 확인
        """
        one_hour_ago = kst - timedelta(hours=1)
        return EmailVerificationAttempt.query.filter(
            EmailVerificationAttempt.user_id == self.id,
            EmailVerificationAttempt.created_at >= one_hour_ago
        ).count()


    @validates('monthly_service_count')
    def validate_monthly_service_count(self, key, monthly_service_count):
        """
        월간 서비스 카운트 음수 방지 및 최대값 제한
        """
        MAX_MONTHLY_SERVICES = 10  # 예시 최대값
        return max(0, min(monthly_service_count, MAX_MONTHLY_SERVICES))

    @validates('current_active_services')
    def validate_current_active_services(self, key, current_active_services):
        """
        현재 활성 서비스 카운트 음수 방지 및 최대값 제한
        """
        MAX_ACTIVE_SERVICES = 5  # 예시 최대값
        return max(0, min(current_active_services, MAX_ACTIVE_SERVICES))

    services = db.relationship('MyService', back_populates='user', cascade='all, delete-orphan')

    def set_password(self, password):
        """Set the user's password."""
        self.password_hash = generate_password_hash(password, method='pbkdf2:sha256')
        db.session.add(self)  # 변경사항을 세션에 추가

    def check_password(self, password):
        """Check the user's password."""
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f'<User    {self.username}, UUID: {self.uuid}>'

    @staticmethod
    def generate_unique_id():
        """Generate a unique 5-character ID based on UUID."""
        # UUID를 해시화하여 고유한 5글자 생성
        unique_id = hashlib.md5(str(uuid.uuid4()).encode()).hexdigest()[:5]
        return unique_id





class MyService(db.Model):
    __tablename__ = 'my_services'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=True)
    short_url = db.Column(db.String(6), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=kst)
    updated_at = db.Column(db.DateTime, default=kst, onupdate=kst)
    uuid = db.Column(db.String(36), unique=True, default=lambda: str(uuid.uuid4()), nullable=False)
    is_deployed = db.Column(db.Boolean, default=False)
    deployed_at = db.Column(db.DateTime, nullable=True)

    user = db.relationship('UserModel', back_populates='services')
    items = db.relationship('ServiceItem', back_populates='service', cascade='all, delete-orphan')

    def __repr__(self):
        return f'<MyService {self.name}, UUID: {self.uuid}>'


class ServiceItem(db.Model):
    __tablename__ = 'service_items'

    id = db.Column(db.Integer, primary_key=True)
    service_id = db.Column(db.Integer, db.ForeignKey('my_services.id'), nullable=False)
    item_type = db.Column(db.String(50), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=True)
    link = db.Column(db.String(200), nullable=True)
    title = db.Column(db.String(100), nullable=True)
    image = db.Column(db.String(200), nullable=True)
    chosen = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=kst)
    updated_at = db.Column(db.DateTime, default=kst, onupdate=kst)

    service = db.relationship('MyService', back_populates='items')

    def __repr__(self):
        return f'<ServiceItem {self.name} for Service ID {self.service_id}>'

class EmailVerificationAttempt(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=kst)

class PasswordResetAttempt(db.Model):
    __tablename__ = 'password_reset_attempts'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=kst)

    # overlaps 파라미터 추가
    user = db.relationship('UserModel', 
                        back_populates='password_reset_attempts', 
                        overlaps="password_reset_attempts_list")

    def __repr__(self):
        return f'<PasswordResetAttempt user_id={self.user_id}, created_at={self.created_at}>'