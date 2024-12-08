from flask import Flask, render_template, request, redirect
from werkzeug.security import generate_password_hash, check_password_hash
import psycopg2

app = Flask(__name__)

# Конфигурация для подключения к PostgreSQL
DB_CONFIG = {
    'dbname': 'lab7',
    'user': 'kali',
    'password': 'kali',
    'host': '192.168.0.11',
    'port': 5432
}


# Функция для подключения к базе данных
def get_db_connection():
    return psycopg2.connect(**DB_CONFIG)


# Инициализация базы данных
def init_db():
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id SERIAL PRIMARY KEY,
                    username VARCHAR(255) UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL
                )
            """)
            conn.commit()


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Хэширование пароля
        hashed_password = generate_password_hash(password)

        try:
            with get_db_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute("""
                        INSERT INTO users (username, password_hash)
                        VALUES (%s, %s)
                    """, (username, hashed_password))
                    conn.commit()
            return redirect('/login')
        except psycopg2.IntegrityError:
            return render_template('register.html', error="Пользователь уже существует.")

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT password_hash FROM users WHERE username = %s", (username,))
                result = cur.fetchone()

        if result is None:
            return render_template('login.html', error="Пользователь не найден.")

        password_hash = result[0]
        if not check_password_hash(password_hash, password):
            return render_template('login.html', error="Неправильный пароль.")

        # Успешный вход
        return render_template('welcome.html', username=username)

    return render_template('login.html')


@app.route('/')
@app.route('/welcome')
def welcome():
    return render_template('welcome.html', username="гость")


if __name__ == '__main__':
    print("Инициализация базы данных...")
    init_db()
    app.run(debug=True)
