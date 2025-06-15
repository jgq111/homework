from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from functools import wraps
from datetime import datetime, timedelta
import os
import re
from werkzeug.security import generate_password_hash
from flask import request, redirect, url_for, flash, render_template
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger
from werkzeug.security import check_password_hash,generate_password_hash
from sqlalchemy import or_, and_
from datetime import datetime, time

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///reservation.db'
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


# 然后定义模板过滤器
@app.template_filter('datetime')
def parse_datetime(value):
    return datetime.strptime(value, '%Y-%m-%d %H:%M')


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            flash('只有管理员可以访问该页面')
            return redirect(url_for('index'))
        return f(*args, **kwargs)

    return decorated_function


# 用户模型
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    reservations = db.relationship('Reservation', backref='user', lazy=True)


# 教室模型
class Classroom(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    capacity = db.Column(db.Integer, nullable=False)
    seats = db.relationship('Seat', backref='classroom', cascade="all, delete",lazy=True)


# 座位模型
class Seat(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    seat_number = db.Column(db.String(10), nullable=False)
    classroom_id = db.Column(db.Integer, db.ForeignKey('classroom.id'), nullable=False)
    reservations = db.relationship('Reservation', backref='seat', lazy=True)
    classroom_id = db.Column(db.Integer, db.ForeignKey('classroom.id', ondelete='CASCADE'), nullable=False)


# 预约模型
class Reservation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    seat_id = db.Column(db.Integer, db.ForeignKey('seat.id'), nullable=False)
    date = db.Column(db.Date, nullable=False)
    start_time = db.Column(db.String(5), nullable=False)
    end_time = db.Column(db.String(5), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    checked_in = db.Column(db.Boolean, default=False)  # 新增：签到状态
    check_in_deadline = db.Column(db.DateTime)  # 新增：签到截止时间


# 添加签到路由
@app.route('/check_in/<int:reservation_id>')
@login_required
def check_in(reservation_id):
    reservation = Reservation.query.get_or_404(reservation_id)

    if reservation.user_id != current_user.id:
        flash('您没有权限签到此预约')
        return redirect(url_for('my_reservations'))

    now = datetime.now()
    reservation_start = datetime.combine(
        reservation.date,
        datetime.strptime(reservation.start_time, '%H:%M').time()
    )
    check_in_deadline = reservation_start + timedelta(minutes=20)

    if now < reservation_start:
        flash('还未到预约时间，不能签到')
        return redirect(url_for('my_reservations'))

    if now > check_in_deadline:
        # 超过签到时间，取消预约
        db.session.delete(reservation)
        db.session.commit()
        flash('已超过签到时间，预约已自动取消')
        return redirect(url_for('my_reservations'))

    reservation.checked_in = True
    db.session.commit()
    flash('签到成功')
    return redirect(url_for('my_reservations'))


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


@app.route('/')
def index():
    classrooms = Classroom.query.all()
    return render_template('index.html', classrooms=classrooms)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        # 修改为使用密码哈希验证
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('index'))
        flash('用户名或密码错误')
    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        # 空值校验
        if not username or not password or not confirm_password:
            flash('用户名和密码不能为空')
            return redirect(url_for('register'))

        # 确认密码一致性校验
        if password != confirm_password:
            flash('两次输入的密码不一致')
            return redirect(url_for('register'))

        # 密码强度校验：至少8位，包含字母和数字
        if len(password) < 8 or not re.search(r'[A-Za-z]', password) or not re.search(r'[0-9]', password):
            flash('密码强度不够，需至少8位并包含字母和数字')
            return redirect(url_for('register'))

        # 用户名是否存在
        if User.query.filter_by(username=username).first():
            flash('用户名已存在')
            return redirect(url_for('register'))

        # 注册用户
        try:
            hashed_password = generate_password_hash(password)
            user = User(username=username, password=hashed_password)
            db.session.add(user)
            db.session.commit()
            flash('注册成功，请登录')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            flash(f'注册失败: {str(e)}')
            return redirect(url_for('register'))

    return render_template('register.html')



@app.route('/classroom/<int:classroom_id>')
@login_required
def classroom_detail(classroom_id):
    classroom = Classroom.query.get_or_404(classroom_id)
    today = datetime.now().strftime('%Y-%m-%d')
    return render_template('classroom.html', classroom=classroom, today=today)


@app.route('/reserve/<int:seat_id>', methods=['POST'])
@login_required
def reserve_seat(seat_id):
    try:
        seat = Seat.query.get_or_404(seat_id)
        date = request.form.get('date')
        start_time = request.form.get('start_time')
        end_time = request.form.get('end_time')

        if not all([date, start_time, end_time]):
            return jsonify({
                'success': False,
                'message': '请填写完整的预约信息'
            })

        # 验证时间格式
        try:
            reservation_date = datetime.strptime(date, '%Y-%m-%d').date()
            reservation_datetime = datetime.strptime(f"{date} {start_time}", '%Y-%m-%d %H:%M')
            end_datetime = datetime.strptime(f"{date} {end_time}", '%Y-%m-%d %H:%M')
        except ValueError:
            return jsonify({
                'success': False,
                'message': '时间格式错误'
            })

        # 验证是否在7天内
        today = datetime.now().date()
        max_date = today + timedelta(days=7)
        if reservation_date > max_date:
            return jsonify({
                'success': False,
                'message': '只能预约未来7天内的座位'
            })

        # 验证预约时间不能早于当前时间
        if reservation_datetime < datetime.now():
            return jsonify({
                'success': False,
                'message': '预约时间不能早于当前时间'
            })

        # 验证结束时间必须晚于开始时间
        if end_datetime <= reservation_datetime:
            return jsonify({
                'success': False,
                'message': '结束时间必须晚于开始时间'
            })

        # 验证预约时长不能超过2小时
        duration = (end_datetime - reservation_datetime).total_seconds() / 3600
        if duration > 2:
            return jsonify({
                'success': False,
                'message': '预约时长不能超过2小时'
            })

        # 检查用户当天的预约次数
        daily_reservations = Reservation.query.filter_by(
            user_id=current_user.id,
            date=reservation_date
        ).count()

        if daily_reservations >= 3:
            return jsonify({
                'success': False,
                'message': f'您在{reservation_date}已经预约了3次，每天最多只能预约3次'
            })

        # 检查用户在同一时间段是否已有其他预约
        user_existing_reservation = Reservation.query.filter_by(
            user_id=current_user.id,
            date=reservation_date
        ).filter(
            ((Reservation.start_time <= start_time) & (Reservation.end_time > start_time)) |
            ((Reservation.start_time < end_time) & (Reservation.end_time >= end_time))
        ).first()

        if user_existing_reservation:
            return jsonify({
                'success': False,
                'message': f'您在该时间段已有其他预约（座位号：{user_existing_reservation.seat.seat_number}），同一时段不能预约多个座位'
            })

        # 检查座位在该时间段是否已被预约
        seat_existing_reservation = Reservation.query.filter_by(
            seat_id=seat_id,
            date=reservation_date
        ).filter(
            ((Reservation.start_time <= start_time) & (Reservation.end_time > start_time)) |
            ((Reservation.start_time < end_time) & (Reservation.end_time >= end_time))
        ).first()

        if seat_existing_reservation:
            return jsonify({
                'success': False,
                'message': '该座位在此时间段已被预约'
            })

        # 创建新预约
        reservation = Reservation(
            user_id=current_user.id,
            seat_id=seat_id,
            date=reservation_date,
            start_time=start_time,
            end_time=end_time,
            check_in_deadline=reservation_datetime + timedelta(minutes=20)
        )
        db.session.add(reservation)
        db.session.commit()

        return jsonify({
            'success': True,
            'message': '预约成功'
        })

    except Exception as e:
        db.session.rollback()
        print(f"Error in reserve_seat: {str(e)}")  # 添加日志输出
        return jsonify({
            'success': False,
            'message': '系统错误，请稍后重试'
        })


# 添加定时任务，检查未签到的预约
def check_expired_reservations():
    now = datetime.now()
    expired_reservations = Reservation.query.filter(
        Reservation.checked_in == False,
        Reservation.check_in_deadline < now
    ).all()

    for reservation in expired_reservations:
        db.session.delete(reservation)

    db.session.commit()


@app.route('/admin/add_classroom', methods=['GET', 'POST'])
@login_required
@admin_required
def add_classroom():
    if request.method == 'POST':
        name = request.form.get('name').strip()  # 去除前后空格
        rows_str = request.form.get('rows')
        cols_str = request.form.get('cols')
        prefix = request.form.get('prefix').strip()

        # 1. 验证必要字段
        if not name or not rows_str or not cols_str or not prefix:
            flash('所有字段都必须填写', 'error')
            return redirect(url_for('add_classroom'))

        # 2. 验证整数格式
        try:
            rows = int(rows_str)
            cols = int(cols_str)
            if rows <= 0 or cols <= 0:
                flash('行数和列数必须大于0', 'error')
                return redirect(url_for('add_classroom'))

        except ValueError:
            flash('行数和列数必须是正整数', 'error')
            return redirect(url_for('add_classroom'))

        # 计算总座位数
        capacity = rows * cols

        try:
            # 创建教室
            classroom = Classroom(name=name, capacity=capacity)
            db.session.add(classroom)
            db.session.flush()  # 获取教室ID

            # 按行列创建座位
            for i in range(rows):
                for j in range(cols):
                    seat_number = f"{prefix}{i * cols + j + 1}"
                    seat = Seat(seat_number=seat_number, classroom_id=classroom.id)
                    db.session.add(seat)

            db.session.commit()
            flash('教室添加成功', 'success')
            return redirect(url_for('admin_dashboard'))

        except Exception as e:
            db.session.rollback()
            # 添加更具体的错误处理
            error_message = f'添加教室失败: {str(e)}'
            app.logger.error(error_message)
            flash(error_message, 'error')
            return redirect(url_for('add_classroom'))

    return render_template('add_classroom.html')


@app.route('/admin/delete_user/<int:user_id>')
@login_required
@admin_required
def delete_user(user_id):
    try:
        user = User.query.get_or_404(user_id)

        # 不能删除超级管理员
        if user.username == 'admin':
            flash('不能删除超级管理员账号')
            return redirect(url_for('admin_dashboard'))

        # 只有超级管理员可以删除管理员账号
        if user.is_admin and current_user.username != 'admin':
            flash('只有超级管理员可以删除管理员账号')
            return redirect(url_for('admin_dashboard'))

        # 删除用户的所有预约
        Reservation.query.filter_by(user_id=user.id).delete()

        # 删除用户
        db.session.delete(user)
        db.session.commit()
        flash('用户已删除')

    except Exception as e:
        db.session.rollback()
        flash(f'删除用户失败: {str(e)}')

    return redirect(url_for('admin_dashboard'))


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


# 用户取消自己的预约
@app.route('/cancel_reservation/<int:reservation_id>')
@login_required
def cancel_reservation(reservation_id):
    reservation = Reservation.query.get_or_404(reservation_id)
    # 检查是否是当前用户的预约
    if reservation.user_id != current_user.id and not current_user.is_admin:
        flash('您没有权限取消这个预约')
        return redirect(url_for('index'))

    db.session.delete(reservation)
    db.session.commit()
    flash('预约已取消')

    # 如果是管理员从管理界面取消的，返回管理界面
    if current_user.is_admin and request.referrer and 'admin' in request.referrer:
        return redirect(url_for('admin_dashboard'))
    return redirect(url_for('index'))


# 添加一个查看用户预约的路由
@app.route('/my_reservations')
@login_required
def my_reservations():
    # 按日期降序排序，显示最近的预约在前面
    reservations = Reservation.query.filter_by(user_id=current_user.id) \
        .order_by(Reservation.date.desc(), Reservation.start_time.asc()).all()

    # 传递datetime和timedelta对象到模板
    return render_template('my_reservations.html',
                           reservations=reservations,
                           datetime=datetime,
                           timedelta=timedelta)


# 修改管理员后台，添加所有预约的显示
@app.route('/admin')
@login_required
@admin_required
def admin_dashboard():
    classrooms = Classroom.query.all()
    users = User.query.all()
    # 获取所有预约信息
    reservations = Reservation.query.order_by(Reservation.date.desc()).all()
    return render_template('admin_dashboard.html',
                           classrooms=classrooms,
                           users=users,
                           reservations=reservations,
                           datetime=datetime,
                           timedelta=timedelta)


@app.route('/admin/edit_classroom/<int:classroom_id>', methods=['POST'])
@login_required
@admin_required
def edit_classroom(classroom_id):
    classroom = Classroom.query.get_or_404(classroom_id)
    name = request.form.get('name')
    capacity = int(request.form.get('capacity'))

    try:
        # 更新教室信息
        classroom.name = name

        # 如果新容量小于当前座位数，需要删除多余的座位
        current_seats = len(classroom.seats)
        if capacity < current_seats:
            # 检查要删除的座位是否有未完成的预约
            seats_to_remove = classroom.seats[capacity:]

            # 获取当前时间
            now = datetime.utcnow()

            # 修改后的预约检查逻辑
            for seat in seats_to_remove:
                # 检查该座位是否有当前未结束的预约
                active_reservations = Reservation.query.filter(
                    Reservation.seat_id == seat.id,
                    Reservation.checked_in == False,
                    Reservation.date >= now.date(),  # 预约日期在今天或之后
                    or_(  # 包含今天可能正在进行或尚未开始的预约
                        and_(
                            Reservation.date == now.date(),
                            Reservation.start_time <= now.strftime('%H:%M'),
                            Reservation.end_time > now.strftime('%H:%M')
                        ),
                        Reservation.date > now.date()
                    )
                ).first()

                if active_reservations:
                    flash('无法减少座位数，有座位存在未完成的预约')
                    return redirect(url_for('admin_dashboard'))

                db.session.delete(seat)

        # 如果新容量大于当前座位数，需要添加新座位
        elif capacity > current_seats:
            # 获取最后一个座位的编号前缀和数字
            last_seat = classroom.seats[-1] if classroom.seats else None
            if last_seat:
                prefix = ''.join(filter(str.isalpha, last_seat.seat_number))
                last_num = int(''.join(filter(str.isdigit, last_seat.seat_number)))
            else:
                prefix = 'A'
                last_num = 0

            # 添加新座位
            for i in range(current_seats + 1, capacity + 1):
                seat_number = f"{prefix}{i}"
                new_seat = Seat(seat_number=seat_number, classroom_id=classroom.id)
                db.session.add(new_seat)

        classroom.capacity = capacity
        db.session.commit()
        flash('教室信息更新成功')

    except Exception as e:
        db.session.rollback()
        flash(f'更新失败: {str(e)}')

    return redirect(url_for('admin_dashboard'))


@app.route('/admin/delete_classroom/<int:classroom_id>')
@login_required
@admin_required
def delete_classroom(classroom_id):
    classroom = Classroom.query.get_or_404(classroom_id)
    now = datetime.utcnow()
    today = now.date()
    current_time = now.strftime('%H:%M')

    try:
        # 检查是否有未完成的预约
        for seat in classroom.seats:
            active_reservations = Reservation.query.filter(
                Reservation.seat_id == seat.id,
                Reservation.checked_in == False,
                or_(
                    # 今天开始但未结束的预约
                    and_(
                        Reservation.date == today,
                        Reservation.start_time <= current_time,
                        Reservation.end_time > current_time
                    ),
                    # 未来的预约
                    Reservation.date > today
                )
            ).first()

            if active_reservations:
                flash('无法删除教室，存在未完成的预约')
                return redirect(url_for('admin_dashboard'))
        # 删除教室（级联删除座位和预约）
        db.session.delete(classroom)
        db.session.commit()
        flash('教室删除成功')

    except Exception as e:
        db.session.rollback()
        flash(f'删除失败: {str(e)}')

    return redirect(url_for('admin_dashboard'))


@app.route('/end_reservation/<int:reservation_id>')
@login_required
def end_reservation(reservation_id):
    try:
        reservation = Reservation.query.get_or_404(reservation_id)

        # 检查权限（必须是预约用户本人或管理员）
        if reservation.user_id != current_user.id and not current_user.is_admin:
            flash('您没有权限结束这个预约')
            return redirect(url_for('my_reservations'))

        # 检查预约是否已签到
        if not reservation.checked_in:
            flash('只能结束已签到的预约')
            return redirect(url_for('my_reservations'))

        # 检查是否在结束时间之前
        now = datetime.now()
        end_datetime = datetime.combine(
            reservation.date,
            datetime.strptime(reservation.end_time, '%H:%M').time()
        )

        if now >= end_datetime:
            flash('预约已经结束')
            return redirect(url_for('my_reservations'))

        # 更新结束时间为当前时间
        current_time = now.strftime('%H:%M')
        reservation.end_time = current_time
        db.session.commit()
        flash('预约已提前结束')

        # 根据用户类型返回不同页面
        if current_user.is_admin and request.referrer and 'admin' in request.referrer:
            return redirect(url_for('admin_dashboard'))
        return redirect(url_for('my_reservations'))

    except Exception as e:
        db.session.rollback()
        flash('操作失败，请稍后重试')
        print(f"Error in end_reservation: {str(e)}")  # 添加日志输出
        return redirect(url_for('my_reservations'))


@app.route('/admin/add_user', methods=['POST'])
@login_required
@admin_required
def add_user():
    try:
        username = request.form.get('username')
        password = request.form.get('password')
        is_admin = request.form.get('is_admin') == 'on'

        # 只有超级管理员（admin）可以创建管理员账号
        if is_admin and current_user.username != 'admin':
            flash('只有超级管理员可以创建管理员账号')
            return redirect(url_for('admin_dashboard'))

        # 检查用户名是否已存在
        if User.query.filter_by(username=username).first():
            flash('用户名已存在')
            return redirect(url_for('admin_dashboard'))

        # 创建新用户 - 重要：添加密码哈希处理
        hashed_password = generate_password_hash(password)
        user = User(username=username, password=hashed_password, is_admin=is_admin)

        db.session.add(user)
        db.session.commit()
        flash('用户添加成功')

    except Exception as e:
        db.session.rollback()
        flash(f'添加用户失败: {str(e)}')

    return redirect(url_for('admin_dashboard'))


@app.route('/admin/edit_user/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def edit_user(user_id):
    try:
        user = User.query.get_or_404(user_id)
        username = request.form.get('username')
        password = request.form.get('password')
        is_admin = request.form.get('is_admin') == 'on'

        # 检查权限
        if current_user.username != 'admin':
            if user.is_admin or is_admin:
                flash('只有超级管理员可以修改管理员账号')
                return redirect(url_for('admin_dashboard'))

        # 不允许修改超级管理员的管理员状态
        if user.username == 'admin':
            is_admin = True

        # 检查新用户名是否与其他用户重复
        existing_user = User.query.filter_by(username=username).first()
        if existing_user and existing_user.id != user.id:
            flash('用户名已存在')
            return redirect(url_for('admin_dashboard'))

        # 更新用户信息
        user.username = username
        if password:  # 如果提供了新密码
            user.password = password
        user.is_admin = is_admin

        db.session.commit()
        flash('用户信息更新成功')

    except Exception as e:
        db.session.rollback()
        flash(f'更新用户失败: {str(e)}')

    return redirect(url_for('admin_dashboard'))


# 修改后的自动取消函数（添加时区处理）
def auto_cancel_expired_reservations():
    with app.app_context():
        # 使用 UTC 时区的时间
        now = datetime.utcnow()

        # 打印调试信息
        print(f"[自动取消] 当前时间 (UTC): {now}")

        expired_reservations = Reservation.query.filter(
            Reservation.checked_in == False,
            Reservation.check_in_deadline < now
        ).all()

        for reservation in expired_reservations:
            print(f"自动取消超时预约 ID: {reservation.id}, 用户: {reservation.user.username}")
            # 打印预约的详细信息
            print(f" - 签到截止时间: {reservation.check_in_deadline}")
            print(f" - 当前时间: {now}")
            print(f" - 是否过期: {reservation.check_in_deadline < now}")

            db.session.delete(reservation)

        if expired_reservations:
            db.session.commit()
            result = f"已自动取消 {len(expired_reservations)} 个超时预约"
        else:
            result = "没有需要取消的预约"

        print(result)
        return result


# 初始化定时任务
def init_scheduler():
    scheduler = BackgroundScheduler()
    # 每分钟执行一次自动取消任务
    scheduler.add_job(
        auto_cancel_expired_reservations,
        trigger=IntervalTrigger(minutes=1),
        id='auto_cancel_job',
        replace_existing=True
    )
    scheduler.start()
    print("定时任务已启动：自动取消超时预约(每分钟检查一次)")


if __name__ == '__main__':
    with app.app_context():
        db.create_all()


        # 添加示例数据
        if not Classroom.query.first():
            classroom = Classroom(name='自习室A', capacity=20)
            db.session.add(classroom)
            for i in range(1, 21):
                seat = Seat(seat_number=f'A{i}', classroom_id=1)
                db.session.add(seat)
            db.session.commit()
        # 添加管理员账号
        # 添加管理员账号
        admin_username = 'admin'
        admin_user = User.query.filter_by(username=admin_username).first()

        # 1. 如果管理员存在但使用明文密码，则更新为哈希密码
        if admin_user and admin_user.password == 'admin':
            admin_user.password = generate_password_hash('admin')
            db.session.commit()
            print(f"更新了管理员 '{admin_username}' 的密码存储方式")

        # 2. 如果管理员不存在，则创建新管理员账号
        elif not admin_user:
            hashed_password = generate_password_hash('admin')
            new_admin = User(
                username=admin_username,
                password=hashed_password,
                is_admin=True
            )
            db.session.add(new_admin)
            db.session.commit()
            print(f"创建了新管理员账号 '{admin_username}'")

        # 启动定时任务
        init_scheduler()

    app.run(debug=True, port=5001)