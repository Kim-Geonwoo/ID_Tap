# run-dev.py - 개발용 서버를 실행하기 위한 파일
from waitress import serve
from app import create_app

app = create_app()

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5001)