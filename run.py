# run.py - 지속서버 형식으로 배포하기위한 파일
from waitress import serve
from app import create_app

app = create_app()

if __name__ == '__main__':
    serve(app, host='0.0.0.0', port=5000)