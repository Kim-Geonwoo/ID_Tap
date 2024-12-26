from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager
from flask_cors import CORS
from werkzeug.routing import BaseConverter, ValidationError
import uuid

# 데이터베이스와 관련된 인스턴스 생성
db = SQLAlchemy()
migrate = Migrate()
login_manager = LoginManager()

class UUIDConverter(BaseConverter):
    def to_python(self, value):
        try:
            return uuid.UUID(value)
        except ValueError:
            raise ValidationError()
    
    def to_url(self, value):
        return str(value)

def init_converters(app):
    app.url_map.converters['uuid'] = UUIDConverter

def create_app():
    app = Flask(__name__)
    
    # Config 클래스에서 설정 로드
    app.config.from_object('config.Config')  # config 모듈의 Config 클래스 사용
    CORS(app)  # 개발 중 CORS 허용

    # 데이터베이스 및 기타 확장 초기화
    db.init_app(app)
    migrate.init_app(app, db)
    login_manager.init_app(app)

    # URL 변환기 초기화
    init_converters(app)

    # 라우트 블루프린트 등록
    from . import routes
    app.register_blueprint(routes.bp)
    
    
    

    return app

