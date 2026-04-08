"""
KSEBE Platform — мультитенантный backend
"""

import os
import uuid
from functools import wraps
from datetime import datetime, timedelta

import psycopg2
import psycopg2.extras
from flask import Flask, request, jsonify, g
import jwt

app = Flask(__name__)

# ──────────────────────────────────────────────
# Конфигурация
# ──────────────────────────────────────────────

DATABASE_URL = os.environ.get('DATABASE_URL', '')
SECRET_KEY   = os.environ.get('SECRET_KEY', 'ksebe-dev-secret-2024')
PARTNER_TOKEN_YCLIENTS = os.environ.get('PARTNER_TOKEN', 'HFG35p0420g7Q2Pn0K8O')

app.config['SECRET_KEY'] = SECRET_KEY

# ──────────────────────────────────────────────
# База данных
# ──────────────────────────────────────────────

def get_db():
    """Получаем соединение с БД для текущего запроса."""
    if 'db' not in g:
        g.db = psycopg2.connect(
            DATABASE_URL,
            cursor_factory=psycopg2.extras.RealDictCursor
        )
    return g.db

def get_cursor(org_id=None):
    """
    Курсор с установленным org_id для Row-Level Security.
    Если org_id не передан — берём из g.org_id (установлен в auth).
    """
    conn = get_db()
    cur  = conn.cursor()
    oid  = org_id or getattr(g, 'org_id', None)
    if oid:
        cur.execute("SELECT set_config('app.current_org_id', %s, true)", (str(oid),))
    return cur

@app.teardown_appcontext
def close_db(error):
    db = g.pop('db', None)
    if db is not None:
        db.close()

# ──────────────────────────────────────────────
# Аутентификация
# ──────────────────────────────────────────────

def create_token(user_id, org_id, role):
    payload = {
        'user_id': str(user_id),
        'org_id':  str(org_id),
        'role':    role,
        'exp':     datetime.utcnow() + timedelta(days=30)
    }
    return jwt.encode(payload, SECRET_KEY, algorithm='HS256')

def require_auth(f):
    """Декоратор — проверяет JWT и устанавливает g.user_id, g.org_id, g.role."""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        if not token:
            return jsonify({'error': 'Токен не передан'}), 401
        try:
            payload  = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
            g.user_id = payload['user_id']
            g.org_id  = payload['org_id']
            g.role    = payload['role']
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Токен истёк'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Неверный токен'}), 401
        return f(*args, **kwargs)
    return decorated

def require_roles(*roles):
    """Декоратор — проверяет что роль пользователя входит в список."""
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if g.role not in roles:
                return jsonify({'error': 'Нет доступа'}), 403
            return f(*args, **kwargs)
        return decorated
    return decorator

# ──────────────────────────────────────────────
# Хелперы
# ──────────────────────────────────────────────

def ok(data=None, **kwargs):
    resp = {'success': True}
    if data is not None:
        resp['data'] = data
    resp.update(kwargs)
    return jsonify(resp)

def err(message, code=400):
    return jsonify({'success': False, 'error': message}), code

def commit():
    get_db().commit()

# ──────────────────────────────────────────────
# МАРШРУТЫ — Здоровье
# ──────────────────────────────────────────────

@app.route('/health')
def health():
    try:
        cur = get_db().cursor()
        cur.execute('SELECT COUNT(*) FROM organizations')
        count = cur.fetchone()[0]
        return ok({'status': 'ok', 'orgs': count, 'time': datetime.now().isoformat()})
    except Exception as e:
        return err(str(e), 500)

# ──────────────────────────────────────────────
# МАРШРУТЫ — Авторизация
# ──────────────────────────────────────────────

@app.route('/auth/login', methods=['POST'])
def login():
    """Вход по номеру телефона + код из Telegram/SMS."""
    data  = request.get_json() or {}
    phone = data.get('phone', '').strip()
    code  = data.get('code', '').strip()

    if not phone:
        return err('Укажите номер телефона')

    # TODO: проверка кода (пока принимаем любой для разработки)
    # В продакшне здесь будет проверка OTP из Telegram бота

    cur = get_cursor()

    # Ищем пользователя
    cur.execute('SELECT * FROM users WHERE phone = %s', (phone,))
    user = cur.fetchone()

    if not user:
        # Регистрируем нового
        cur.execute(
            'INSERT INTO users (phone) VALUES (%s) RETURNING *',
            (phone,)
        )
        user = cur.fetchone()
        commit()

    # Ищем членство в организациях
    cur.execute('''
        SELECT om.*, o.slug, o.name as org_name, o.type as org_type
        FROM org_members om
        JOIN organizations o ON o.id = om.org_id
        WHERE om.user_id = %s AND om.is_active = true
        LIMIT 10
    ''', (user['id'],))
    memberships = cur.fetchall()

    if not memberships:
        return err('Пользователь не привязан ни к одной организации', 403)

    # Если одна организация — сразу выдаём токен
    if len(memberships) == 1:
        m     = memberships[0]
        token = create_token(user['id'], m['org_id'], m['role'])
        return ok({
            'token':    token,
            'user':     dict(user),
            'org_id':   str(m['org_id']),
            'org_name': m['org_name'],
            'role':     m['role']
        })

    # Если несколько организаций — просим выбрать
    return ok({
        'user':         dict(user),
        'memberships':  [dict(m) for m in memberships],
        'choose_org':   True
    })

@app.route('/auth/select-org', methods=['POST'])
def select_org():
    """Выбор организации когда у пользователя их несколько."""
    data    = request.get_json() or {}
    user_id = data.get('user_id')
    org_id  = data.get('org_id')

    cur = get_cursor()
    cur.execute('''
        SELECT om.role FROM org_members om
        WHERE om.user_id = %s AND om.org_id = %s AND om.is_active = true
    ''', (user_id, org_id))
    member = cur.fetchone()

    if not member:
        return err('Нет доступа к этой организации', 403)

    token = create_token(user_id, org_id, member['role'])
    return ok({'token': token, 'role': member['role']})

# ──────────────────────────────────────────────
# МАРШРУТЫ — Организации и филиалы
# ──────────────────────────────────────────────

@app.route('/org/info')
@require_auth
def org_info():
    """Информация о текущей организации и её филиалах."""
    cur = get_cursor()

    cur.execute('SELECT * FROM organizations WHERE id = %s', (g.org_id,))
    org = cur.fetchone()

    cur.execute(
        'SELECT * FROM locations WHERE org_id = %s AND is_active = true ORDER BY name',
        (g.org_id,)
    )
    locations = cur.fetchall()

    return ok({
        'org':       dict(org),
        'locations': [dict(l) for l in locations]
    })

# ──────────────────────────────────────────────
# МАРШРУТЫ — Клиенты
# ──────────────────────────────────────────────

@app.route('/clients', methods=['GET'])
@require_auth
def clients_list():
    """Список клиентов организации."""
    search = request.args.get('search', '').strip()
    limit  = min(int(request.args.get('limit', 50)), 200)
    offset = int(request.args.get('offset', 0))

    cur = get_cursor()

    if search:
        cur.execute('''
            SELECT c.*, cd.balance, cd.bonus_balance
            FROM clients c
            LEFT JOIN client_deposits cd ON cd.client_id = c.id AND cd.org_id = c.org_id
            WHERE c.org_id = %s
              AND (c.phone ILIKE %s OR c.name ILIKE %s)
            ORDER BY c.created_at DESC
            LIMIT %s OFFSET %s
        ''', (g.org_id, f'%{search}%', f'%{search}%', limit, offset))
    else:
        cur.execute('''
            SELECT c.*, cd.balance, cd.bonus_balance
            FROM clients c
            LEFT JOIN client_deposits cd ON cd.client_id = c.id AND cd.org_id = c.org_id
            WHERE c.org_id = %s
            ORDER BY c.created_at DESC
            LIMIT %s OFFSET %s
        ''', (g.org_id, limit, offset))

    clients = cur.fetchall()
    return ok([dict(c) for c in clients])

@app.route('/clients/<client_id>', methods=['GET'])
@require_auth
def client_detail(client_id):
    """Карточка клиента с историей визитов и депозитом."""
    cur = get_cursor()

    cur.execute('''
        SELECT c.*, cd.balance, cd.bonus_balance
        FROM clients c
        LEFT JOIN client_deposits cd ON cd.client_id = c.id AND cd.org_id = c.org_id
        WHERE c.id = %s AND c.org_id = %s
    ''', (client_id, g.org_id))
    client = cur.fetchone()

    if not client:
        return err('Клиент не найден', 404)

    # Последние визиты
    cur.execute('''
        SELECT b.*, p.name as program_name, p.duration_min,
               om.user_id as staff_user_id
        FROM bookings b
        LEFT JOIN programs p ON p.id = b.program_id
        LEFT JOIN org_members om ON om.id = b.staff_id
        WHERE b.client_id = %s AND b.org_id = %s
        ORDER BY b.starts_at DESC
        LIMIT 20
    ''', (client_id, g.org_id))
    bookings = cur.fetchall()

    # Активные абонементы
    cur.execute('''
        SELECT * FROM subscriptions
        WHERE client_id = %s AND org_id = %s AND is_active = true
        ORDER BY created_at DESC
    ''', (client_id, g.org_id))
    subscriptions = cur.fetchall()

    return ok({
        'client':        dict(client),
        'bookings':      [dict(b) for b in bookings],
        'subscriptions': [dict(s) for s in subscriptions]
    })

@app.route('/clients', methods=['POST'])
@require_auth
def client_create():
    """Создание нового клиента."""
    data  = request.get_json() or {}
    phone = data.get('phone', '').strip()

    if not phone:
        return err('Укажите номер телефона')

    cur = get_cursor()

    # Проверяем дубль
    cur.execute(
        'SELECT id FROM clients WHERE org_id = %s AND phone = %s',
        (g.org_id, phone)
    )
    if cur.fetchone():
        return err('Клиент с таким номером уже существует', 409)

    client_id = str(uuid.uuid4())
    cur.execute('''
        INSERT INTO clients (id, org_id, phone, name, source, utm_source, utm_medium, utm_campaign, tags)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
        RETURNING *
    ''', (
        client_id, g.org_id, phone,
        data.get('name'),
        data.get('source'),
        data.get('utm_source'),
        data.get('utm_medium'),
        data.get('utm_campaign'),
        data.get('tags', [])
    ))
    client = cur.fetchone()

    # Создаём депозитный счёт
    cur.execute('''
        INSERT INTO client_deposits (org_id, client_id, balance, bonus_balance)
        VALUES (%s, %s, 0, 0)
    ''', (g.org_id, client_id))

    commit()
    return ok(dict(client)), 201

# ──────────────────────────────────────────────
# МАРШРУТЫ — Бронирования
# ──────────────────────────────────────────────

@app.route('/bookings', methods=['GET'])
@require_auth
def bookings_list():
    """Список бронирований (журнал записей)."""
    date_from = request.args.get('from', datetime.now().strftime('%Y-%m-%d'))
    date_to   = request.args.get('to',   datetime.now().strftime('%Y-%m-%d'))
    location  = request.args.get('location_id')
    staff     = request.args.get('staff_id')

    cur = get_cursor()

    query = '''
        SELECT b.*,
               c.name as client_name, c.phone as client_phone,
               p.name as program_name, p.duration_min,
               u.name as staff_name
        FROM bookings b
        LEFT JOIN clients c    ON c.id = b.client_id
        LEFT JOIN programs p   ON p.id = b.program_id
        LEFT JOIN org_members om ON om.id = b.staff_id
        LEFT JOIN users u      ON u.id = om.user_id
        WHERE b.org_id = %s
          AND DATE(b.starts_at) BETWEEN %s AND %s
    '''
    params = [g.org_id, date_from, date_to]

    if location:
        query += ' AND b.location_id = %s'
        params.append(location)
    if staff:
        query += ' AND b.staff_id = %s'
        params.append(staff)

    query += ' ORDER BY b.starts_at ASC'

    cur.execute(query, params)
    bookings = cur.fetchall()
    return ok([dict(b) for b in bookings])

@app.route('/bookings', methods=['POST'])
@require_auth
def booking_create():
    """Создание новой записи."""
    data = request.get_json() or {}

    required = ['location_id', 'program_id', 'staff_id', 'starts_at']
    for field in required:
        if not data.get(field):
            return err(f'Поле {field} обязательно')

    cur = get_cursor()

    # Получаем программу для расчёта цены и времени окончания
    cur.execute(
        'SELECT * FROM programs WHERE id = %s AND org_id = %s',
        (data['program_id'], g.org_id)
    )
    program = cur.fetchone()
    if not program:
        return err('Программа не найдена', 404)

    starts_at = datetime.fromisoformat(data['starts_at'])
    ends_at   = starts_at + timedelta(minutes=program['duration_min'])

    # Проверяем конфликт расписания мастера
    cur.execute('''
        SELECT id FROM bookings
        WHERE staff_id = %s AND org_id = %s
          AND status NOT IN ('cancelled', 'noshow')
          AND starts_at < %s AND ends_at > %s
    ''', (data['staff_id'], g.org_id, ends_at, starts_at))
    if cur.fetchone():
        return err('Мастер занят в это время', 409)

    booking_id = str(uuid.uuid4())
    cur.execute('''
        INSERT INTO bookings (
            id, org_id, location_id, client_id, program_id,
            staff_id, starts_at, ends_at, total_price,
            source, utm_source, comment, created_by
        )
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
        RETURNING *
    ''', (
        booking_id, g.org_id, data['location_id'],
        data.get('client_id'), data['program_id'], data['staff_id'],
        starts_at, ends_at, program['base_price'],
        data.get('source'), data.get('utm_source'),
        data.get('comment'), g.user_id
    ))
    booking = cur.fetchone()
    commit()
    return ok(dict(booking)), 201

@app.route('/bookings/<booking_id>/status', methods=['PATCH'])
@require_auth
def booking_update_status(booking_id):
    """Обновление статуса записи."""
    data   = request.get_json() or {}
    status = data.get('status')

    valid = ['new','confirmed','in_progress','done','cancelled','noshow']
    if status not in valid:
        return err(f'Статус должен быть одним из: {", ".join(valid)}')

    cur = get_cursor()
    cur.execute('''
        UPDATE bookings SET status = %s
        WHERE id = %s AND org_id = %s
        RETURNING *
    ''', (status, booking_id, g.org_id))
    booking = cur.fetchone()

    if not booking:
        return err('Запись не найдена', 404)

    commit()
    return ok(dict(booking))

# ──────────────────────────────────────────────
# МАРШРУТЫ — Программы
# ──────────────────────────────────────────────

@app.route('/programs', methods=['GET'])
@require_auth
def programs_list():
    cur = get_cursor()
    cur.execute('''
        SELECT * FROM programs
        WHERE org_id = %s AND is_active = true
        ORDER BY sort_order, name
    ''', (g.org_id,))
    return ok([dict(p) for p in cur.fetchall()])

# ──────────────────────────────────────────────
# МАРШРУТЫ — Финансы
# ──────────────────────────────────────────────

@app.route('/finance/summary', methods=['GET'])
@require_auth
@require_roles('owner', 'director', 'ops_director', 'manager')
def finance_summary():
    """Сводка P&L за период."""
    date_from = request.args.get('from', datetime.now().strftime('%Y-%m-01'))
    date_to   = request.args.get('to',   datetime.now().strftime('%Y-%m-%d'))

    cur = get_cursor()

    # Выручка из платежей
    cur.execute('''
        SELECT
            COALESCE(SUM(CASE WHEN status = 'done' THEN amount ELSE 0 END), 0) as revenue,
            COALESCE(SUM(CASE WHEN status = 'done' THEN 1 ELSE 0 END), 0)      as payments_count
        FROM payments
        WHERE org_id = %s
          AND DATE(created_at) BETWEEN %s AND %s
    ''', (g.org_id, date_from, date_to))
    payments = cur.fetchone()

    # Расходы
    cur.execute('''
        SELECT
            COALESCE(SUM(amount), 0) as total_expenses,
            category,
            COALESCE(SUM(amount), 0) as category_amount
        FROM expenses
        WHERE org_id = %s
          AND expense_date BETWEEN %s AND %s
        GROUP BY category
        ORDER BY category_amount DESC
    ''', (g.org_id, date_from, date_to))
    expenses_by_cat = cur.fetchall()

    total_expenses = sum(e['category_amount'] for e in expenses_by_cat)
    revenue        = float(payments['revenue'])

    return ok({
        'period':         {'from': date_from, 'to': date_to},
        'revenue':        revenue,
        'expenses':       total_expenses,
        'profit':         revenue - total_expenses,
        'margin_pct':     round((revenue - total_expenses) / revenue * 100, 1) if revenue else 0,
        'payments_count': payments['payments_count'],
        'expenses_by_category': [dict(e) for e in expenses_by_cat]
    })

@app.route('/finance/expenses', methods=['POST'])
@require_auth
@require_roles('owner', 'director', 'ops_director', 'manager', 'admin')
def expense_create():
    """Добавление расхода (вручную или из чека)."""
    data = request.get_json() or {}

    required = ['category', 'amount', 'expense_date']
    for field in required:
        if not data.get(field):
            return err(f'Поле {field} обязательно')

    cur = get_cursor()
    cur.execute('''
        INSERT INTO expenses (
            org_id, location_id, category, subcategory,
            amount, description, receipt_url, expense_date, created_by
        )
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
        RETURNING *
    ''', (
        g.org_id,
        data.get('location_id'),
        data['category'],
        data.get('subcategory'),
        data['amount'],
        data.get('description'),
        data.get('receipt_url'),
        data['expense_date'],
        g.user_id
    ))
    expense = cur.fetchone()
    commit()
    return ok(dict(expense)), 201

# ──────────────────────────────────────────────
# МАРШРУТЫ — Депозиты
# ──────────────────────────────────────────────

@app.route('/clients/<client_id>/deposit', methods=['GET'])
@require_auth
def deposit_get(client_id):
    """Баланс депозита клиента."""
    cur = get_cursor()
    cur.execute('''
        SELECT cd.*, c.name, c.phone
        FROM client_deposits cd
        JOIN clients c ON c.id = cd.client_id
        WHERE cd.client_id = %s AND cd.org_id = %s
    ''', (client_id, g.org_id))
    deposit = cur.fetchone()
    if not deposit:
        return err('Депозит не найден', 404)
    return ok(dict(deposit))

@app.route('/clients/<client_id>/deposit/topup', methods=['POST'])
@require_auth
def deposit_topup(client_id):
    """Пополнение депозита клиента."""
    data   = request.get_json() or {}
    amount = float(data.get('amount', 0))

    if amount <= 0:
        return err('Сумма должна быть больше нуля')

    cur = get_cursor()

    # Обновляем баланс
    cur.execute('''
        UPDATE client_deposits
        SET balance = balance + %s, updated_at = now()
        WHERE client_id = %s AND org_id = %s
        RETURNING balance
    ''', (amount, client_id, g.org_id))
    result = cur.fetchone()

    if not result:
        return err('Депозит не найден', 404)

    # Пишем транзакцию
    cur.execute('''
        INSERT INTO deposit_transactions
            (org_id, client_id, type, amount, balance_after, description, created_by)
        VALUES (%s, %s, 'topup', %s, %s, %s, %s)
    ''', (
        g.org_id, client_id, amount,
        result['balance'],
        data.get('description', 'Пополнение депозита'),
        g.user_id
    ))

    commit()
    return ok({'balance': float(result['balance']), 'added': amount})

# ──────────────────────────────────────────────
# МАРШРУТЫ — Сотрудники
# ──────────────────────────────────────────────

@app.route('/staff', methods=['GET'])
@require_auth
def staff_list():
    """Список сотрудников организации."""
    location = request.args.get('location_id')
    cur = get_cursor()

    query = '''
        SELECT om.*, u.name, u.phone, u.telegram_id, l.name as location_name
        FROM org_members om
        JOIN users u ON u.id = om.user_id
        LEFT JOIN locations l ON l.id = om.location_id
        WHERE om.org_id = %s AND om.is_active = true
    '''
    params = [g.org_id]

    if location:
        query += ' AND (om.location_id = %s OR om.location_id IS NULL)'
        params.append(location)

    query += ' ORDER BY om.role, u.name'
    cur.execute(query, params)
    return ok([dict(s) for s in cur.fetchall()])

@app.route('/staff/<member_id>/schedule', methods=['GET'])
@require_auth
def staff_schedule(member_id):
    """Расписание сотрудника."""
    date_from = request.args.get('from', datetime.now().strftime('%Y-%m-%d'))
    date_to   = request.args.get('to', (datetime.now() + timedelta(days=30)).strftime('%Y-%m-%d'))

    cur = get_cursor()
    cur.execute('''
        SELECT * FROM staff_schedules
        WHERE member_id = %s AND org_id = %s
          AND date BETWEEN %s AND %s
        ORDER BY date
    ''', (member_id, g.org_id, date_from, date_to))
    return ok([dict(s) for s in cur.fetchall()])

# ──────────────────────────────────────────────
# МАРШРУТЫ — Задачи
# ──────────────────────────────────────────────

@app.route('/tasks', methods=['GET'])
@require_auth
def tasks_list():
    """Список задач."""
    status   = request.args.get('status')
    assignee = request.args.get('assignee_id')
    cur = get_cursor()

    query  = 'SELECT t.*, u.name as assignee_name FROM tasks t LEFT JOIN org_members om ON om.id = t.assignee_id LEFT JOIN users u ON u.id = om.user_id WHERE t.org_id = %s'
    params = [g.org_id]

    if status:
        query += ' AND t.status = %s'
        params.append(status)
    if assignee:
        query += ' AND t.assignee_id = %s'
        params.append(assignee)

    # Пармастера видят только свои задачи
    if g.role in ('parmaster_1', 'parmaster_2', 'cleaner', 'stoker', 'laundry', 'repair'):
        query += ' AND om.user_id = %s'
        params.append(g.user_id)

    query += ' ORDER BY t.priority DESC, t.due_at ASC NULLS LAST'
    cur.execute(query, params)
    return ok([dict(t) for t in cur.fetchall()])

@app.route('/tasks', methods=['POST'])
@require_auth
def task_create():
    """Создание задачи."""
    data = request.get_json() or {}
    if not data.get('title'):
        return err('Укажите название задачи')

    cur = get_cursor()
    cur.execute('''
        INSERT INTO tasks
            (org_id, location_id, assignee_id, created_by, title,
             description, type, priority, due_at, booking_id)
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
        RETURNING *
    ''', (
        g.org_id,
        data.get('location_id'),
        data.get('assignee_id'),
        g.user_id,
        data['title'],
        data.get('description'),
        data.get('type', 'other'),
        data.get('priority', 'medium'),
        data.get('due_at'),
        data.get('booking_id')
    ))
    task = cur.fetchone()
    commit()
    return ok(dict(task)), 201

@app.route('/tasks/<task_id>/complete', methods=['PATCH'])
@require_auth
def task_complete(task_id):
    """Отметить задачу выполненной."""
    cur = get_cursor()
    cur.execute('''
        UPDATE tasks
        SET status = 'done', completed_at = now()
        WHERE id = %s AND org_id = %s
        RETURNING *
    ''', (task_id, g.org_id))
    task = cur.fetchone()
    if not task:
        return err('Задача не найдена', 404)
    commit()
    return ok(dict(task))

# ──────────────────────────────────────────────
# Запуск
# ──────────────────────────────────────────────

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)

web: gunicorn app:app --bind 0.0.0.0:$PORT --workers 2

flask==3.0.3
psycopg2-binary==2.9.9
pyjwt==2.8.0
requests==2.32.3
gunicorn==22.0.0
python-dotenv==1.0.1
