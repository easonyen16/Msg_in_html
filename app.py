from functools import wraps
import threading
from flask import Flask, abort, jsonify, render_template, request, redirect, url_for, flash, session
from flask_login import LoginManager, current_user, login_required, login_user, logout_user, UserMixin
import os
import re
from datetime import date, datetime, timedelta
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from models import db, User, Role
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from sqlalchemy import Column, Integer, String, DateTime, func, extract, or_
from collections import defaultdict
import pytz
import schedule
import time
from flask_mail import Mail
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadTimeSignature, BadSignature
from flask_mail import Message as MailMessage
from dateutil import tz
app = Flask(__name__)

app.config['REMEMBER_COOKIE_DURATION'] = timedelta(days=7)
app.config['MAIL_DEFAULT_SENDER'] = 'EXAMPLE@MAIL.COM'
app.config['MAIL_SERVER']='SMTP.MAIL.COM'
app.config['MAIL_PORT'] = 'MAIL_PORT'
app.config['MAIL_USERNAME'] = 'EXAMPLE@MAIL.COM'
app.config['MAIL_PASSWORD'] = 'MAIL_PASSWORD'
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
mail = Mail(app)

app.secret_key = 'HASH'  # 替換為您自己的密鑰
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'  # 用戶數據將存儲在 users.db 文件中
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
migrate = Migrate(app, db)

login_manager = LoginManager(app)
with app.app_context():
    db.create_all()

class Role(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False)

class Message(db.Model):
    message_id = db.Column(db.Integer, primary_key=True, unique=False)
    member_id = db.Column(db.Integer, db.ForeignKey('member.id'), nullable=False)
    message_type = db.Column(db.Integer, nullable=False)
    content = db.Column(db.Text, nullable=True)
    image_path = db.Column(db.String(255), nullable=True)
    audio_path = db.Column(db.String(255), nullable=True)
    video_path = db.Column(db.String(255), nullable=True)
    timestamp = db.Column(db.DateTime, nullable=False)

    def __repr__(self):
        return f'<Message {self.message_id}>'


def init_db():
    with app.app_context():
        db.create_all()
        Role.__table__.create(db.engine, checkfirst=True)
        User.__table__.create(db.engine, checkfirst=True)
        Member.__table__.create(db.engine, checkfirst=True)

        # Check if the "admin" role exists, and create it if it doesn't
        admin_role = Role.query.filter_by(name='admin').first()
        if admin_role is None:
            admin_role = Role(name='admin')
            db.session.add(admin_role)
            db.session.commit()
        user_role = Role.query.filter_by(name='user').first()
        if user_role is None:
            user_role = Role(name='user')
            db.session.add(user_role)
            db.session.commit()
        admin_user = User.query.filter_by(username='admin').first()
        if admin_user is None:
            admin_user = User(username='ADMIN_USER_NAME', email='ADMIN_MAIL', password=generate_password_hash('ADMIN_PASSWORD'), role_id=admin_role.id)
            db.session.add(admin_user)
            db.session.commit()

        base_path = "./static/data/message/"
        for member_name in os.listdir(base_path):
            member_path = os.path.join(base_path, member_name)
            if os.path.isdir(member_path):
                # 檢查成員是否存在，如果不存在，創建它
                member = Member.query.filter_by(name=member_name).first()
                if member is None:
                    avatar_path = f"/static/data/avatar/{member_name}.jpg"
                    member = Member(name=member_name, avatar=avatar_path, group="nogizaka")
                    db.session.add(member)
                    db.session.commit()

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    additional_info = db.Column(db.Text, nullable=True)  # 額外資訊
    role_id = db.Column(db.Integer, db.ForeignKey('role.id'), nullable=False)
    is_active = db.Column(db.Boolean, default=False)  # 添加 is_active 属性
    registration_date = Column(DateTime, nullable=False, default=datetime.utcnow)
    role = db.relationship('Role', backref='users')  

    def set_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password)
    
    @staticmethod
    def verify_reset_password_token(token):
        s = URLSafeTimedSerializer(app.config['SECRET_KEY'], salt='reset-password-salt')
        try:
            email = s.loads(token, max_age=1800)  # 設置令牌有效期為 1800 秒（30 分鐘）
        except (SignatureExpired, BadTimeSignature, BadSignature):
            return None
        return User.query.filter_by(email=email).first()
    
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role.name != 'admin':
            abort(403)  # Forbidden
        return f(*args, **kwargs)
    return decorated_function

class Member(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False)
    group = db.Column(db.String(50), nullable=False) 
    avatar = db.Column(db.String(120), unique=True, nullable=False)

class UserMemberAccess(db.Model):
    __tablename__ = 'user_member_access'
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), primary_key=True)
    member_id = db.Column(db.Integer, db.ForeignKey('member.id'), primary_key=True)

    user = db.relationship("User", back_populates="accessible_members")
    member = db.relationship("Member", back_populates="accessible_by_users")

User.accessible_members = db.relationship("UserMemberAccess", back_populates="user")
Member.accessible_by_users = db.relationship("UserMemberAccess", back_populates="member")

def get_user_access(user_id):
    user_access = UserMemberAccess.query.filter_by(user_id=user_id).all()
    accessible_member_ids = [access.member_id for access in user_access]
    return accessible_member_ids

def get_members():
    members = []
    base_path = "./static/data/message/"

    for member_name in os.listdir(base_path):
        member_path = os.path.join(base_path, member_name)
        if os.path.isdir(member_path):
            member = {
                "name": member_name,
                "avatar": f"/static/data/avatar/{member_name}.jpg"
            }
            members.append(member)

    return members

def migrate_messages_to_db():
    base_path = "./static/data/message/"

    # 獲取30分鐘前的時間
    time_cutoff = datetime.now() - timedelta(minutes=15)

    for member_name in os.listdir(base_path):
        member_path = os.path.join(base_path, member_name)
        if os.path.isdir(member_path):
            member = Member.query.filter_by(name=member_name).first()
            if member is None:
                continue

            # 使用 os.scandir() 更高效地檢查檔案修改時間
            with os.scandir(member_path) as entries:
                for entry in entries:
                    if entry.is_file():
                        file_name = entry.name
                        file_path = os.path.join(member_path, file_name)

                        # 檢查檔案修改時間是否在30分鐘內
                        file_modified_time = datetime.fromtimestamp(entry.stat().st_mtime)
                        if file_modified_time < time_cutoff:
                            continue

                        match = re.match(r"(\d+)_(\d+)_(\d+)", file_name)
                        if match:
                            message_id, message_type, timestamp = match.groups()
                        else:
                            continue

                        dt = datetime.strptime(timestamp, "%Y%m%d%H%M%S")
                        dt = dt + timedelta(hours=9)

                        existing_message = Message.query.filter_by(message_id=int(message_id), member_id=member.id, message_type=int(message_type), timestamp=dt).first()
                        if existing_message is not None:
                            continue
                        
                        message = Message(message_id=int(message_id), member_id=member.id, message_type=int(message_type), timestamp=dt)

                        if message_type == "0" and file_name.endswith(".txt"):
                            with open(file_path, "r", encoding="utf-8") as f:
                                message.content = f.read()

                        elif message_type == "1":
                            txt_file_path = os.path.join(member_path, f"{message_id}_1_{timestamp}.txt")
                            jpg_file_path = os.path.join(member_path, f"{message_id}_1_{timestamp}.jpg")
                            if os.path.isfile(txt_file_path) and os.path.isfile(jpg_file_path):
                                with open(txt_file_path, "r", encoding="utf-8") as f:
                                    message.content = f.read()
                                message.image_path = os.path.join("/static/data/message", member_name, f"{message_id}_1_{timestamp}.jpg")

                        elif message_type == "3" and file_name.endswith(".m4a"):
                            message.audio_path = os.path.join("/static/data/message", member_name, file_name)

                        elif message_type == "4" and file_name.endswith(".mp4"):
                            message.video_path = os.path.join("/static/data/message", member_name, file_name)

                        # Save the message to the database
                        db.session.add(message)
                        db.session.commit()

def get_monthly_messages_count_by_group(year, month):
    results = (
        db.session.query(
            Member.group,
            Member.name,
            Message.member_id,
            Message.message_type,
            func.count(Message.message_id),
            extract("year", Message.timestamp),
            extract("month", Message.timestamp),
        )
        .join(Member, Member.id == Message.member_id)
        .filter(extract("year", Message.timestamp) == year)
        .filter(extract("month", Message.timestamp) == month)
        .group_by(
            Member.group,
            Member.name,
            Message.member_id,
            Message.message_type,
            extract("year", Message.timestamp),
            extract("month", Message.timestamp),
        )
        .order_by(
            Member.group,
            Member.name,
            Message.message_type,
            extract("year", Message.timestamp),
            extract("month", Message.timestamp),
        )
        .all()
    )

    # 將查詢結果轉換為方便處理的結構
    stats = defaultdict(lambda: defaultdict(lambda: defaultdict(int)))
    for row in results:
        group, member_name, member_id, message_type, count, year, month = row
        stats[group][member_name][message_type] = count
        stats[group][member_name]["total"] += count

    return stats

def get_daily_messages_count_by_group(target_date):
    results = (
        db.session.query(
            Member.group,
            Member.name,
            Message.member_id,
            Message.message_type,
            func.count(Message.message_id),
            func.date(Message.timestamp)
        )
        .join(Member, Member.id == Message.member_id)
        .filter(func.date(Message.timestamp) == target_date)
        .group_by(
            Member.group,
            Member.name,
            Message.member_id,
            Message.message_type,
            func.date(Message.timestamp)
        )
        .order_by(
            Member.group,
            Member.name,
            Message.message_type,
            func.date(Message.timestamp)
        )
        .all()
    )

    # 將查詢結果轉換為方便處理的結構
    stats = defaultdict(lambda: defaultdict(lambda: defaultdict(int)))
    for row in results:
        group, member_name, member_id, message_type, count, date_ = row
        stats[group][member_name][message_type] = count
        stats[group][member_name]["total"] += count

    return stats

def schedule_migrate_messages_to_db():
    run_migrate_messages_to_db()
    threading.Timer(30, schedule_migrate_messages_to_db).start()

def run_migrate_messages_to_db():
    with app.app_context():
        migrate_messages_to_db()

@app.route('/')
def home():
    members = get_members()
    return render_template('new_home.html', members=members)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/nogizaka')
def nogizaka():
    members = Member.query.filter_by(group='nogizaka').all()
    return render_template('index.html', members=members, groupname='乃木坂46')

@app.route('/hinatazaka')
def hinatazaka():
    members = Member.query.filter_by(group='hinatazaka').all()
    return render_template('index.html', members=members, groupname='日向坂46')

@app.route('/sakurazaka')
def sakurazaka():
    members = Member.query.filter_by(group='sakurazaka').all()
    return render_template('index.html', members=members, groupname='櫻坂46')

@app.route('/member/<member_name>')
@login_required
def member(member_name):
    member = Member.query.filter_by(name=member_name).first()
    if member is None:
        abort(404)

    user_has_access = UserMemberAccess.query.filter_by(user_id=current_user.id, member_id=member.id).first() is not None
    if not user_has_access:
        abort(403)

    return render_template('member.html', member_name=member_name)

@app.route('/api/member/<member_name>/messages/<int:offset>/<int:limit>', methods=['GET'])
@login_required
def api_get_member_messages(member_name, offset, limit):
    search = request.args.get('search', default='', type=str)
    member = Member.query.filter_by(name=member_name).first()

    # 檢查當前用戶是否有權訪問此成員
    user_member_access = UserMemberAccess.query.filter_by(user_id=current_user.id, member_id=member.id).first()
    if limit > 10:
        limit = 10
    if member and user_member_access:
        query = Message.query.filter_by(member_id=member.id)
        if search:
            query = query.filter(Message.content.like(f"%{search}%"))
        messages = query.order_by(Message.timestamp.desc()).offset(offset).limit(limit).all()
        response = []
        for message in messages:
            message_data = {
                "id": message.message_id,
                "message_type": message.message_type,
                "timestamp": message.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                "content": message.content,
                "image_path": message.image_path,
                "audio_path": message.audio_path,
                "video_path": message.video_path,
            }
            response.append(message_data)
        response.reverse()
        return jsonify(response)
    else:
        return jsonify([])

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    
    if request.method == 'GET':
        return render_template('login.html')
    
    username = request.form['username']
    password = request.form['password']
    remember = request.form.get('remember', False)
    user = User.query.filter_by(username=username).first()

    if user is not None and user.check_password(password):
        if user.is_active:
            login_user(user, remember=remember)
            flash('登入成功！', 'success')
            next_url = request.args.get('next')  # 獲取 next 參數
            return redirect(next_url or url_for('home'))  # 重定向到 next 或首頁
        else:
            flash('您的帳號尚未啟用，請等待管理員審核。', 'warning')
    else:
        flash('無效的使用者名稱或密碼。', 'danger')

    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    if request.method == 'GET':
        return render_template('register.html')
    username = request.form['username']
    email = request.form['email']
    password = request.form['password']
    additional_info = request.form['additional_info']

    # 檢查使用者名稱和電子郵件是否已被使用
    if User.query.filter_by(username=username).first() is not None:
        flash('使用者名稱已被使用，請選擇其他使用者名稱。', 'danger')
        return redirect(url_for('register'))
    if User.query.filter_by(email=email).first() is not None:
        flash('電子郵件已被使用，請選擇其他電子郵件。', 'danger')
        return redirect(url_for('register'))

    # 新增用戶到數據庫

    utc_now = datetime.utcnow()
    taipei_tz = tz.gettz('Asia/Taipei')
    registration_date = utc_now.replace(tzinfo=tz.tzutc()).astimezone(taipei_tz)

    new_user = User(username=username, email=email, additional_info=additional_info, registration_date=registration_date)
    new_user.set_password(password)

    # 为新用户分配角色
    user_role = Role.query.filter_by(name='user').first()
    new_user.role_id = user_role.id

    db.session.add(new_user)
    db.session.commit()

    admin_email = 'ADMIN_MAIL'  # 將此替換為管理員的電子郵件地址
    subject = '新用戶註冊通知'
    body = f'用戶名稱: {username}\n電子郵件: {email}\n附加信息: {additional_info}\n註冊日期: {registration_date.strftime("%Y-%m-%d %H:%M:%S")}'

    message = MailMessage(subject, recipients=[admin_email], body=body)
    mail.send(message)

    flash('註冊成功，請等待管理員審核。', 'success')
    return redirect(url_for('login'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('您已成功登出。', 'success')
    return redirect(url_for('login'))

# 忘記密碼頁面
@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'GET':
        return render_template('forgot_password.html')

    email = request.form['email']
    user = User.query.filter_by(email=email).first()

    if user:
        # 創建一個安全標記
        s = URLSafeTimedSerializer(app.config['SECRET_KEY'])

        # 為用戶生成一個標記
        token = s.dumps(user.email, salt='reset-password-salt')

        # 創建一個重置密碼的鏈接
        reset_url = url_for('reset_password', token=token, _external=True)

        # 發送包含重置鏈接的電子郵件
        msg = MailMessage(
            subject='重置您的密碼',
            sender='EXAMPLE@MAIL.COM',
            recipients=[user.email]
        )

        msg.body = f'請點擊以下鏈接以重置您的密碼：\n\n{reset_url}'
        mail.send(msg)

        flash('我們已向您發送了一封包含重置密碼鏈接的電子郵件。', 'info')
    else:
        flash('未找到該電子郵件地址。', 'danger')

    return redirect(url_for('forgot_password'))

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    if current_user.is_authenticated:
        return redirect(url_for('home'))

    user = User.verify_reset_password_token(token)
    if not user:
        flash('無效的重置密碼令牌。', 'danger')
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        password = request.form['password']
        user.set_password(password)
        db.session.commit()
        flash('您的密碼已成功重置！', 'success')
        return redirect(url_for('login'))

    return render_template('reset_password.html', token=token)

@app.route('/users')
@login_required
@admin_required
def show_users():
    users = User.query.all()
    members = Member.query.all() 
    return render_template('users.html', users=users, members=members) 

@app.route('/users/activate/<int:user_id>', methods=['POST'])
def activate_user(user_id):
    user = User.query.get(user_id)

    if user is not None:
        user.is_active = True
        db.session.commit()
        flash('用戶帳戶已成功啟用。', 'success')
        send_activation_email(user)
    else:
        flash('用戶不存在。', 'danger')

    return redirect(url_for('show_users'))
def send_activation_email(user):
    subject = "帳戶開通成功"
    recipients = [user.email]
    base_url = "SITE"  # 將此替換為您的網站網址
    body = f"""
    <p>親愛的 {user.username}，</p>
    <p>您的帳戶已成功開通！您現在可以登錄並開始使用我們的服務。</p>
    <p>祝您使用愉快！</p>
    <p><a href="{base_url}">點擊這裡訪問我們的網站</a></p>
    """

    message = MailMessage(subject, recipients=recipients, html=body)
    try:
        mail.send(message)
    except Exception:
        flash('無法寄送電子郵件', 'warning')

@app.route('/users/reject', methods=['POST'])
def reject_user():
    user_id = request.form['user_id']
    reject_reason = request.form['reject_reason']
    user = User.query.get(user_id)

    # 設定一個預設的罐頭拒絕訊息
    default_reject_message = "很抱歉，您的申請未符合我們的要求。"

    if user is not None:
        # 寄送拒絕通知電子郵件
        subject = "您的帳戶申請已被拒絕"
        # 使用預設的罐頭拒絕訊息，如果拒絕原因為空
        body = f"親愛的 {user.username},\n\n您的帳戶申請已被拒絕，原因如下：\n\n{reject_reason if reject_reason else default_reject_message}\n\n如有疑問，請與我們聯繫。\n\n謝謝您,\nE.Y. Studio"
        message = MailMessage(subject, recipients=[user.email], body=body)

        try:
            mail.send(message)
        except Exception as e:
            print(f"無法寄送電子郵件：{e}")
            flash('電子郵件無法寄送，但用戶已被拒絕並刪除。', 'warning')

        # 從資料庫刪除用戶
        db.session.delete(user)
        db.session.commit()

        flash('已成功拒絕並刪除用戶。', 'success')
    else:
        flash('用戶不存在。', 'danger')

    return redirect(url_for('show_users'))

@app.route('/users/delete', methods=['POST'])
def delete_user():
    user_id = request.form['user_id']
    delete_reason = request.form['delete_reason']
    user = User.query.get(user_id)

    # 設定一個預設的罐頭刪除訊息
    default_delete_message = "很抱歉，您的帳戶已被我們刪除。"

    if user is not None:
        # 寄送刪除通知電子郵件
        subject = "您的帳戶已被刪除"
        # 使用預設的罐頭刪除訊息，如果刪除原因為空
        body = f"親愛的 {user.username},\n\n您的帳戶已被刪除，原因如下：\n\n{delete_reason if delete_reason else default_delete_message}\n\n如有疑問，請與我們聯繫。\n\n謝謝您,\nE.Y. Studio"
        message = MailMessage(subject, recipients=[user.email], body=body)

        try:
            mail.send(message)
        except Exception as e:
            print(f"無法寄送電子郵件：{e}")
            flash('電子郵件無法寄送，但用戶已被刪除。', 'warning')

        # 從資料庫刪除用戶
        user_member_accesses = UserMemberAccess.query.filter_by(user_id=user_id).all()
        for access in user_member_accesses:
            db.session.delete(access)
        db.session.delete(user)
        db.session.commit()

        flash('已成功刪除用戶。', 'success')
    else:
        flash('用戶不存在。', 'danger')

    return redirect(url_for('show_users'))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/users/update_member_access', methods=['POST'])
@login_required
@admin_required
def update_member_access():
    user_id = request.form['user_id']
    member_ids = request.form.getlist('member_access[]')

    user = User.query.get(user_id)
    if user is not None:
        # 移除用戶之前的所有成員訪問權限
        UserMemberAccess.query.filter_by(user_id=user_id).delete()

        # 為用戶添加新的成員訪問權限
        for member_id in member_ids:
            member_access = UserMemberAccess(user_id=user_id, member_id=member_id)
            db.session.add(member_access)

        db.session.commit()
        flash('成員訪問權限已成功更新。', 'success')
    else:
        flash('用戶不存在。', 'danger')

    return redirect(url_for('show_users'))

@app.route('/permissions')
@login_required
def permissions():
    user_id = current_user.id
    username = current_user.username  # 新增這一行
    accessible_member_ids = get_user_access(user_id)
    accessible_members = Member.query.filter(Member.id.in_(accessible_member_ids)).all()
    return render_template('permissions.html', user_id=user_id, accessible_members=accessible_members, username=username)  # 在這裡添加 username

@app.route('/api/get_user_access/<int:user_id>', methods=['GET'])
@login_required
@admin_required
def api_get_user_access(user_id):
    accessible_member_ids = get_user_access(user_id)
    return jsonify(accessible_member_ids)

@app.route('/change_group')
@login_required
@admin_required
def change_group():
    members = Member.query.all()
    return render_template('change_group.html', members=members)

@app.route('/update_member_group', methods=['POST'])
@login_required
@admin_required
def update_member_group():
    for member in Member.query.all():
        new_group = request.form[f'group_{member.id}']
        if member.group != new_group:
            member.group = new_group
            db.session.commit()

    flash('成員組已成功更新。', 'success')
    return redirect(url_for('change_group'))

@app.route("/stats", methods=["GET", "POST"])
def stats():
    year = request.args.get("year", datetime.now().year, int)
    month = request.args.get("month", datetime.now().month, int)
    monthly_messages_count = get_monthly_messages_count_by_group(year, month)
    return render_template("stats.html", data=monthly_messages_count, selected_year=year, selected_month=month)

@app.route('/daily_stats', methods=['GET', 'POST'])
def daily_stats():
    target_date = date.today()

    if request.method == 'POST':
        input_date = request.form['date']
        target_date = datetime.strptime(input_date, '%Y-%m-%d').date()

    stats = get_daily_messages_count_by_group(target_date)
    return render_template('daily_stats.html', stats=stats, target_date=target_date)


@app.errorhandler(403)
def forbidden(e):
    return render_template('403.html'), 403

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

init_db()
schedule_migrate_messages_to_db()

if __name__ == '__main__':
    #init_db()
    #schedule_migrate_messages_to_db()
    app.run(host='0.0.0.0')