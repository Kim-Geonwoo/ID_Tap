from flask import Blueprint, render_template
from werkzeug.exceptions import HTTPException

# 블루프린트 생성
error_blueprint = Blueprint('error_handlers', __name__)


# 다양한 오류에 대한 커스텀 핸들러
@error_blueprint.errorhandler(400)
def bad_request(error: HTTPException):
    return render_template('errors/400.html', error_message=str(error)), 400

@error_blueprint.errorhandler(401)
def unauthorized(error: HTTPException):
    return render_template('errors/401.html', error_message=str(error)), 401

@error_blueprint.errorhandler(403)
def forbidden(error: HTTPException):
    return render_template('errors/403.html', error_message=str(error)), 403

@error_blueprint.errorhandler(404)
def not_found(error: HTTPException):
    return render_template('errors/404.html', error_message=str(error)), 404

@error_blueprint.errorhandler(500)
def internal_server_error(error: HTTPException):
    return render_template('errors/500.html', error_message=str(error)), 500

@error_blueprint.errorhandler(502)
def bad_gateway(error: HTTPException):
    return render_template('errors/502.html', error_message=str(error)), 502