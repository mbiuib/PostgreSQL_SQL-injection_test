from flask import Flask, render_template, request, redirect, url_for
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

# Включение или отключение защиты от SQL-инъекций
ENABLE_SQL_INJECTION_PROTECTION = True


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


@app.route('/toggle_protection_ajax', methods=['POST'])
def toggle_protection_ajax():
    global ENABLE_SQL_INJECTION_PROTECTION
    ENABLE_SQL_INJECTION_PROTECTION = not ENABLE_SQL_INJECTION_PROTECTION
    return {'protection': ENABLE_SQL_INJECTION_PROTECTION}


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        result = None

        with get_db_connection() as conn:
            try:
                with conn.cursor() as cur:
                    if ENABLE_SQL_INJECTION_PROTECTION:
                        cur.execute(f"""
                        PREPARE login(text) AS
                        SELECT password_hash FROM users WHERE username = $1;
                        EXECUTE login('{username}')""")
                    else:
                        query = f"SELECT password_hash FROM users WHERE username = '{username}'"
                        cur.execute(query)
                    result = cur.fetchone()
                    print(result)
            except Exception as e:
                print(e)

        if result is None:
            return render_template('login.html', error="Пользователь не найден.",
                                   protection=ENABLE_SQL_INJECTION_PROTECTION)

        password_hash = result[0]
        if not check_password_hash(password_hash, password):
            return render_template('login.html', error="Неправильный пароль.",
                                   protection=ENABLE_SQL_INJECTION_PROTECTION)

        return render_template('welcome.html', username=username)

    return render_template('login.html', protection=ENABLE_SQL_INJECTION_PROTECTION)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        hashed_password = generate_password_hash(password)

        try:
            with get_db_connection() as conn:
                with conn.cursor() as cur:
                    if ENABLE_SQL_INJECTION_PROTECTION:
                        cur.execute(f"""
                            PREPARE register(text, text) AS
                            INSERT INTO users (username, password_hash)
                            VALUES ($1, $2);
                            EXECUTE register('{username}', '{hashed_password}');
                        """)
                    else:
                        query = f"""
                            INSERT INTO users (username, password_hash)
                            VALUES ('{username}', '{hashed_password}')
                        """
                        cur.execute(query)
                    conn.commit()
            return redirect('/login')
        except psycopg2.IntegrityError:
            return render_template('register.html', error="Пользователь уже существует.",
                                   protection=ENABLE_SQL_INJECTION_PROTECTION)

    return render_template('register.html', protection=ENABLE_SQL_INJECTION_PROTECTION)


@app.route('/')
@app.route('/welcome')
def welcome():
    return render_template('welcome.html', username="гость")


if __name__ == '__main__':
    print("Инициализация базы данных...")
    init_db()
    print(f"Защита от SQL-инъекций включена: {ENABLE_SQL_INJECTION_PROTECTION}")
    app.run(debug=False)
