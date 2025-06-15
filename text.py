import unittest
import os
import sys
from datetime import datetime, timezone, timedelta,date,time
from werkzeug.security import generate_password_hash
import unittest.mock
import warnings
import warnings
from sqlalchemy.exc import SADeprecationWarning

# 忽略 SQLAlchemy 相关的弃用警告
warnings.filterwarnings("ignore", category=SADeprecationWarning)
warnings.filterwarnings("ignore", category=DeprecationWarning, module="sqlalchemy")
warnings.filterwarnings("ignore", category=DeprecationWarning, module="flask_sqlalchemy")
# 忽略弃用警告
warnings.filterwarnings("ignore", category=DeprecationWarning, module="sqlalchemy")

# 添加项目根目录到Python路径
sys.path.append(os.path.abspath(os.path.dirname(__file__)))

# 现在导入应用组件
from __init__ import app, db, User, Classroom, Seat, Reservation, auto_cancel_expired_reservations


class ReservationTestCase(unittest.TestCase):

    def login_user(self, user):
        """用于登录指定用户的辅助方法"""
        with self.app.session_transaction() as sess:
            sess['_user_id'] = user.id

    def logout_user(self):
        """注销当前用户的辅助方法"""
        with self.app.session_transaction() as sess:
            if '_user_id' in sess:
                del sess['_user_id']

    def setUp(self):
        # 配置测试环境
        app.config['TESTING'] = True
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        app.config['WTF_CSRF_ENABLED'] = False

        # 创建测试客户端
        self.app = app.test_client()
        self.app_context = app.app_context()
        self.app_context.push()

        # 创建数据库
        db.create_all()

        # 创建测试用户
        self.user1 = User.query.filter_by(username='test_user1').first()
        if not self.user1:
            hashed_password = generate_password_hash('password123')
            self.user1 = User(username='test_user1', password=hashed_password)
            db.session.add(self.user1)

        self.user2 = User.query.filter_by(username='test_user2').first()
        if not self.user2:
            hashed_password = generate_password_hash('password123')
            self.user2 = User(username='test_user2', password=hashed_password)
            db.session.add(self.user2)

        self.admin = User.query.filter_by(username='admin').first()
        if not self.admin:
            admin_password = generate_password_hash('admin')
            self.admin = User(username='admin', password=admin_password, is_admin=True)
            db.session.add(self.admin)

        # 确保提交用户对象
        db.session.commit()

        # 创建测试教室
        self.classroom = Classroom.query.filter_by(name='Test Room').first()
        if not self.classroom:
            self.classroom = Classroom(name='Test Room', capacity=3)
            db.session.add(self.classroom)
            db.session.commit()

        # 创建座位（无论教室是否已存在）
        self.seat1 = Seat.query.filter_by(seat_number='A1', classroom_id=self.classroom.id).first()
        if not self.seat1:
            self.seat1 = Seat(seat_number='A1', classroom=self.classroom)
            db.session.add(self.seat1)

        self.seat2 = Seat.query.filter_by(seat_number='A2', classroom_id=self.classroom.id).first()
        if not self.seat2:
            self.seat2 = Seat(seat_number='A2', classroom=self.classroom)
            db.session.add(self.seat2)

        self.seat3 = Seat.query.filter_by(seat_number='A3', classroom_id=self.classroom.id).first()
        if not self.seat3:
            self.seat3 = Seat(seat_number='A3', classroom=self.classroom)
            db.session.add(self.seat3)

        # 确保提交座位对象
        db.session.commit()

        # 模拟登录用户
        self.login_user(self.user1)

        # 设置日期变量
        self.now = datetime.now(timezone.utc)
        self.future_date = (self.now + timedelta(days=1)).strftime('%Y-%m-%d')
        self.past_date = (self.now - timedelta(days=1)).strftime('%Y-%m-%d')
        self.too_future_date = (self.now + timedelta(days=8)).strftime('%Y-%m-%d')
        self.current_time = self.now.strftime('%H:%M')

        # 设置独立的时间段分配器，避免测试用例冲突
        self.time_slot_counter = 0

    def get_unique_time_slot(self):
        """为每个测试用例生成唯一的时间段"""
        # 每个时间段增加2小时以避免重叠
        start_hour = 10 + (self.time_slot_counter * 2)
        end_hour = start_hour + 1
        start_time = f"{start_hour:02d}:00"
        end_time = f"{end_hour:02d}:30"

        # 递增计数器，确保每个测试用例使用不同的时间段
        self.time_slot_counter += 1

        return start_time, end_time

    def tearDown(self):
        self.logout_user()
        db.session.remove()
        db.drop_all()
        self.app_context.pop()

    # ========== 用户认证测试 ==========

    # TC-0101: 新用户成功注册
    def test_successful_registration(self):
        self.logout_user()
        response = self.app.post('/register', data={
            'username': 'new_user_123',
            'password': 'TestPass123!'
        }, follow_redirects=True)

        self.assertEqual(response.status_code, 200)
        self.assertIn(b'login', response.data.lower())

    # TC-0102: 用户名已存在
    def test_existing_username_registration(self):
        # 提供完整的表单数据
        error_msg = '用户名已存在'.encode('utf-8')
        response = self.app.post('/register', data={
            'username': 'test_user1',
            'password': 'AnyPassword123',
            'confirm_password': 'AnyPassword123'  # 添加确认密码字段
        }, follow_redirects=True)
        self.assertIn(error_msg, response.data)

    # TC-0103: 用户成功登录
    def test_successful_login(self):
        response = self.app.post('/login', data={
            'username': 'test_user1',
            'password': 'password123'
        }, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'classroom', response.data.lower())

    # TC-0104: 用户登录失败
    def test_failed_login(self):
        error_msg = '用户名或密码错误'.encode('utf-8')
        # 用户名错误
        response = self.app.post('/login', data={
            'username': 'wrong_user',
            'password': 'password123'
        })
        self.assertIn(error_msg, response.data)

        # 密码错误
        response = self.app.post('/login', data={
            'username': 'test_user1',
            'password': 'wrong_password'
        })
        self.assertIn(error_msg, response.data)

    # TC-0105: 用户成功登出
    def test_successful_logout(self):
        self.app.post('/login', data={
            'username': 'test_user1',
            'password': 'password123'
        })
        response = self.app.get('/logout', follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'login', response.data.lower())

    # TC-0106: 空用户名/密码注册
    def test_empty_credentials_registration(self):
        error_msg = '用户名和密码不能为空'.encode('utf-8')
        response = self.app.post('/register', data={
            'username': '',
            'password': 'ValidPass123!'
        }, follow_redirects=True)
        self.assertIn(error_msg, response.data)

    # TC-0107: 未登录访问预约页
    def test_access_classroom_without_login(self):
        self.logout_user()
        with app.app_context():
            classroom = Classroom.query.first()
            classroom_id = classroom.id
        response = self.app.get(f'/classroom/{classroom_id}', follow_redirects=True)
        self.assertIn(b'login', response.data.lower())


    # ========== 预约管理测试 ==========

    # TC-0201: 成功预约座位
    def test_successful_reservation(self):
        # 获取唯一的时间段
        start_time, end_time = self.get_unique_time_slot()

        response = self.app.post(f'/reserve/{self.seat1.id}', data={
            'date': self.future_date,
            'start_time': start_time,
            'end_time': end_time
        })
        data = response.get_json()
        self.assertTrue(data['success'])
        self.assertEqual(data['message'], '预约成功')

    # TC-0202: 超过每日预约上限
    def test_exceed_daily_limit(self):
        # 使用明天的日期（确保所有预约都在同一天）
        tomorrow = (datetime.now(timezone.utc) + timedelta(days=1)).date()
        tomorrow_str = tomorrow.strftime('%Y-%m-%d')

        # 清理该用户明天的所有预约
        Reservation.query.filter_by(user_id=self.user1.id, date=tomorrow).delete()
        db.session.commit()

        # 设置固定时间（10:00-11:00）
        start_time = "10:00"
        end_time = "11:00"

        # 创建3个有效的预约（消耗明天的预约次数）
        seats = [self.seat1, self.seat2, self.seat3]
        for seat in seats:
            reservation = Reservation(
                user_id=self.user1.id,
                seat_id=seat.id,
                date=tomorrow,
                start_time=start_time,
                end_time=end_time,
                created_at=datetime.now(timezone.utc)
            )
            db.session.add(reservation)
        db.session.commit()

        # 尝试第4个预约（同样使用明天）
        response = self.app.post(f'/reserve/{self.seat1.id}', data={
            'date': tomorrow_str,
            'start_time': start_time,
            'end_time': end_time
        })
        data = response.get_json()
        self.assertFalse(data['success'])

        # 使用正确的错误消息格式
        expected_message = f'您在{tomorrow_str}已经预约了3次，每天最多只能预约3次'
        self.assertEqual(data['message'], expected_message)

     # TC-0203: 用户在同一时间段预约多个座位
    def test_overlapping_reservations_same_user(self):
        # 使用未来的日期确保预约有效
        tomorrow = (datetime.now(timezone.utc) + timedelta(days=1)).date()
        tomorrow_str = tomorrow.strftime('%Y-%m-%d')

        # 获取唯一的时间段
        slot_start, slot_end = self.get_unique_time_slot()

        # 用户1预约第一个座位
        response1 = self.app.post(f'/reserve/{self.seat1.id}', data={
            'date': tomorrow_str,
            'start_time': slot_start,
            'end_time': slot_end
        })
        data1 = response1.get_json()
        self.assertTrue(data1['success'])

        # 用户1尝试在同一时间段预约第二个座位
        response2 = self.app.post(f'/reserve/{self.seat2.id}', data={
            'date': tomorrow_str,
            'start_time': slot_start,
            'end_time': slot_end
        })
        data2 = response2.get_json()
        self.assertFalse(data2['success'])

        # 验证错误消息格式
        expected_message = f'您在该时间段已有其他预约（座位号：{self.seat1.seat_number}），同一时段不能预约多个座位'
        self.assertEqual(data2['message'], expected_message)

    # TC-0204: 超过2小时限制
    def test_exceed_duration_limit(self):
        response = self.app.post(f'/reserve/{self.seat1.id}', data={
            'date': self.future_date,
            'start_time': '10:00',
            'end_time': '13:00'  # 超过2小时
        })
        data = response.get_json()
        self.assertFalse(data['success'])
        self.assertIn('预约时长不能超过2小时', data['message'])

     # TC-0205: 预约过去时间
    def test_reserve_past_time(self):
        response = self.app.post(f'/reserve/{self.seat1.id}', data={
            'date': self.past_date,
            'start_time': '10:00',
            'end_time': '11:00'
        })
        data = response.get_json()
        self.assertFalse(data['success'])
        self.assertIn('预约时间不能早于当前时间', data['message'])

    # TC-0206: 超过7天限制
    def test_exceed_future_limit(self):
        response = self.app.post(f'/reserve/{self.seat1.id}', data={
            'date': self.too_future_date,
            'start_time': '10:00',
            'end_time': '11:00'
        })
        data = response.get_json()
        self.assertFalse(data['success'])
        self.assertIn('只能预约未来7天内的座位', data['message'])

    # TC-0207: 结束早于开始时间
    def test_end_before_start(self):
        response = self.app.post(f'/reserve/{self.seat1.id}', data={
            'date': self.future_date,
            'start_time': '11:00',
            'end_time': '10:00'
        })
        data = response.get_json()  # 获取JSON响应
        self.assertFalse(data['success'])
        self.assertEqual(data['message'], '结束时间必须晚于开始时间')

    # TC-0208: 表单数据不完整
    def test_incomplete_form_data(self):
        response = self.app.post(f'/reserve/{self.seat1.id}', data={
            'start_time': '10:00',
            'end_time': '11:00'
        })
        data = response.get_json()
        self.assertFalse(data['success'])
        self.assertIn('请填写完整的预约信息', data['message'])

    # TC-0209: 用户取消预约
    def test_user_cancel_reservation(self):
        with app.app_context():
            reservation = Reservation(
                user_id=self.user1.id,
                seat_id=self.seat1.id,
                date=datetime.strptime(self.future_date, '%Y-%m-%d').date(),
                start_time='10:00',
                end_time='11:30'
            )
            db.session.add(reservation)
            db.session.commit()

            response = self.app.get(f'/cancel_reservation/{reservation.id}', follow_redirects=True)
            self.assertIn('预约已取消', response.get_data(as_text=True))

    # TC-0210: 管理员取消预约
    def test_admin_cancel_reservation(self):
        with self.app.session_transaction() as sess:
            sess['_user_id'] = self.admin.id

        with app.app_context():
            reservation = Reservation(
                user_id=self.user1.id,
                seat_id=self.seat1.id,
                date=datetime.strptime(self.future_date, '%Y-%m-%d').date(),
                start_time='10:00',
                end_time='11:30'
            )
            db.session.add(reservation)
            db.session.commit()

            response = self.app.get(f'/cancel_reservation/{reservation.id}', follow_redirects=True)
            self.assertIn('预约已取消', response.get_data(as_text=True))

    # TC-0211: 时间格式无效
    def test_invalid_time_format(self):
        response = self.app.post(f'/reserve/{self.seat1.id}', data={
            'date': self.future_date,
            'start_time': '25:00',
            'end_time': '26:00'
        })
        data = response.get_json()
        self.assertFalse(data['success'])
        self.assertIn('时间格式错误', data['message'])


    # TC-0212: 用户成功签到
    def test_successful_check_in(self):
        # 创建预约，设置开始时间为5分钟前
        start_time = (datetime.now() - timedelta(minutes=5)).time().strftime('%H:%M')
        start_datetime = datetime.now() - timedelta(minutes=5)

        # 计算视图函数会使用的签到截止时间（开始时间+20分钟）
        deadline = start_datetime + timedelta(minutes=20)

        # 创建预约对象
        reservation = Reservation(
            user_id=self.user1.id,
            seat_id=self.seat1.id,
            date=datetime.now().date(),
            start_time=start_time,
            end_time=(datetime.now() + timedelta(hours=1)).strftime('%H:%M'),
            check_in_deadline=deadline  # 正确设置视图函数会使用的截止时间
        )
        db.session.add(reservation)
        db.session.commit()
        reservation_id = reservation.id

        # 用户尝试签到
        response = self.app.get(f'/check_in/{reservation_id}', follow_redirects=True)
        response_text = response.get_data(as_text=True)

        # 验证预约状态已更新
        updated_reservation = db.session.get(Reservation, reservation_id)
        self.assertIsNotNone(updated_reservation, "预约不存在")
        self.assertTrue(updated_reservation.checked_in, "签到状态未更新")
        # 验证返回消息
        self.assertIn('签到成功', response_text)

    # TC-0213: 未到签到时间
    def test_check_in_too_early(self):
        # 创建预约，开始时间设置为30分钟后
        future_time = datetime.now() + timedelta(minutes=30)
        reservation = Reservation(
            user_id=self.user1.id,
            seat_id=self.seat1.id,
            date=future_time.date(),
            start_time=future_time.strftime('%H:%M'),
            end_time=(future_time + timedelta(hours=1)).strftime('%H:%M'),
            # 计算视图函数会使用的签到截止时间（开始时间+20分钟）
            check_in_deadline=future_time + timedelta(minutes=20)
        )
        db.session.add(reservation)
        db.session.commit()
        reservation_id = reservation.id

        # 用户尝试签到
        response = self.app.get(f'/check_in/{reservation_id}', follow_redirects=True)
        response_text = response.get_data(as_text=True)

        # 验证预约状态未更新
        updated_reservation = db.session.get(Reservation, reservation_id)
        self.assertIsNotNone(updated_reservation, "预约不存在")
        self.assertFalse(updated_reservation.checked_in, "签到状态错误更新")
        # 验证返回消息
        self.assertIn('还未到预约时间，不能签到', response_text)

    # TC-0214: 超时未签到
    def test_check_in_too_late(self):
        # 创建预约，设置开始时间为30分钟前，截止时间为10分钟前
        past_time = datetime.now() - timedelta(minutes=30)
        reservation = Reservation(
            user_id=self.user1.id,
            seat_id=self.seat1.id,
            date=past_time.date(),
            start_time=past_time.strftime('%H:%M'),
            end_time=(past_time + timedelta(hours=1)).strftime('%H:%M'),
            # 设置截止时间为10分钟前
            check_in_deadline=past_time + timedelta(minutes=10)
        )
        db.session.add(reservation)
        db.session.commit()
        reservation_id = reservation.id

        # 用户尝试签到
        response = self.app.get(f'/check_in/{reservation_id}', follow_redirects=True)
        response_text = response.get_data(as_text=True)

        # 验证预约已被删除
        deleted_reservation = db.session.get(Reservation, reservation_id)
        self.assertIsNone(deleted_reservation, "预约未被正确删除")
        # 验证返回消息
        self.assertIn('已超过签到时间，预约已自动取消', response_text)

    # TC-0215: 非本人签到尝试
    def test_unauthorized_check_in(self):
        reservation_datetime = datetime.now(timezone.utc) + timedelta(minutes=5)

        with app.app_context():
            reservation = Reservation(
                user_id=self.admin.id,
                seat_id=self.seat1.id,
                date=reservation_datetime.date(),
                start_time=reservation_datetime.strftime('%H:%M'),
                end_time=(reservation_datetime + timedelta(hours=1)).strftime('%H:%M'),
                check_in_deadline=reservation_datetime + timedelta(minutes=20)
            )
            db.session.add(reservation)
            db.session.commit()

            response = self.app.get(f'/check_in/{reservation.id}', follow_redirects=True)
            self.assertIn('没有权限', response.get_data(as_text=True))

    # TC-0216: 用户提前结束已签到的预约
    def test_user_end_checked_in_reservation(self):
        """测试用户提前结束已签到的预约"""
        # 获取当前本地时间（无时区）
        now_local = datetime.now()

        # 创建已签到的预约（在当前时间之后开始）
        reservation_start = now_local - timedelta(minutes=10)  # 10分钟前开始的预约
        reservation_date = reservation_start.date()
        start_time_str = reservation_start.strftime('%H:%M')
        end_time_str = (now_local + timedelta(minutes=50)).strftime('%H:%M')  # 50分钟后结束

        # 创建预约并标记为已签到
        reservation = Reservation(
            user_id=self.user1.id,
            seat_id=self.seat1.id,
            date=reservation_date,
            start_time=start_time_str,
            end_time=end_time_str,
            checked_in=True
        )
        db.session.add(reservation)
        db.session.commit()

        # 获取预约ID
        reservation_id = reservation.id

        # 用户结束预约
        response = self.app.get(f'/end_reservation/{reservation_id}', follow_redirects=True)

        # 验证响应状态和消息
        self.assertEqual(response.status_code, 200)
        self.assertIn('预约已提前结束'.encode('utf-8'), response.data)

        # 刷新预约对象获取最新数据
        db.session.refresh(reservation)

        # 验证重定向到我的预约页面
        self.assertTrue('/my_reservations' in response.request.path)

    # TC-0217: 用户提前结束(未签到)
    def test_user_end_unchecked_reservation(self):
        reservation_datetime = datetime.now(timezone.utc) - timedelta(minutes=10)

        with app.app_context():
            reservation = Reservation(
                user_id=self.user1.id,
                seat_id=self.seat1.id,
                date=reservation_datetime.date(),
                start_time=reservation_datetime.strftime('%H:%M'),
                end_time=(reservation_datetime + timedelta(hours=1)).strftime('%H:%M'),
                check_in_deadline=reservation_datetime + timedelta(minutes=20),
                checked_in=False
            )
            db.session.add(reservation)
            db.session.commit()

            response = self.app.get(f'/end_reservation/{reservation.id}', follow_redirects=True)
            self.assertIn('只能结束已签到的预约', response.get_data(as_text=True))

    # TC-0218: 管理员提前结束已签到的预约(成功)
    def test_admin_end_reservation(self):
        # 模拟管理员登录
        self.login_user(self.admin)
        # 创建已签到的预约（在当前时间之后开始）
        now_local = datetime.now()
        reservation_start = now_local - timedelta(minutes=10)  # 10分钟前开始的预约
        reservation_date = reservation_start.date()
        start_time_str = reservation_start.strftime('%H:%M')
        end_time_str = (now_local + timedelta(minutes=50)).strftime('%H:%M')  # 50分钟后结束
        # 创建预约并标记为已签到
        reservation = Reservation(
            user_id=self.user1.id,
            seat_id=self.seat1.id,
            date=reservation_date,
            start_time=start_time_str,
            end_time=end_time_str,
            checked_in=True
        )
        db.session.add(reservation)
        db.session.commit()
        # 获取预约ID
        reservation_id = reservation.id
        # 管理员结束预约
        response = self.app.get(f'/end_reservation/{reservation_id}', follow_redirects=True)
        # 验证响应状态和消息
        self.assertEqual(response.status_code, 200)
        self.assertIn('预约已提前结束'.encode('utf-8'), response.data)
        # 刷新预约对象获取最新数据
        db.session.refresh(reservation)

    # TC-0219: 管理员提前结束未签到预约
    def test_admin_end_unchecked_reservation(self):
        # 模拟管理员登录
        self.login_user(self.admin)

        # 创建未签到的预约
        now_local = datetime.now()
        reservation_start = now_local - timedelta(minutes=10)
        reservation_date = reservation_start.date()
        start_time_str = reservation_start.strftime('%H:%M')
        end_time_str = (now_local + timedelta(hours=1)).strftime('%H:%M')

        # 创建预约（未签到）
        reservation = Reservation(
            user_id=self.user1.id,
            seat_id=self.seat1.id,
            date=reservation_date,
            start_time=start_time_str,
            end_time=end_time_str,
            checked_in=False  # 关键：未签到
        )
        db.session.add(reservation)
        db.session.commit()

        # 获取预约ID
        reservation_id = reservation.id

        # 管理员尝试结束预约
        response = self.app.get(f'/end_reservation/{reservation_id}', follow_redirects=True)

        # 验证响应状态和消息
        self.assertEqual(response.status_code, 200)
        self.assertIn('只能结束已签到的预约'.encode('utf-8'), response.data)

        # 验证重定向到我的预约页面
        self.assertTrue('/my_reservations' in response.request.path)

        # 刷新对象并确认结束时间未改变
        db.session.refresh(reservation)
        self.assertEqual(reservation.end_time, end_time_str)  # 结束时间未更新

    # TC-0220: 自动取消超时未签到的预约
    def test_auto_cancel_expired_reservations(self):
        """测试自动取消超时预约功能"""
        # 使用UTC时间，无时区信息
        now = datetime.utcnow()

        # 创建三个预约项：2个过期的，1个有效的
        # 1. 过期预约1
        expired_time1 = now - timedelta(minutes=20)
        expired_reservation1 = Reservation(
            user_id=self.user1.id,
            seat_id=self.seat1.id,
            date=expired_time1.date(),
            start_time=expired_time1.strftime('%H:%M'),
            end_time=(expired_time1 + timedelta(hours=1)).strftime('%H:%M'),
            check_in_deadline=expired_time1 + timedelta(minutes=5),
            checked_in=False
        )
        db.session.add(expired_reservation1)

        # 2. 过期预约2
        expired_time2 = now - timedelta(minutes=15)
        expired_reservation2 = Reservation(
            user_id=self.user1.id,
            seat_id=self.seat2.id,
            date=expired_time2.date(),
            start_time=expired_time2.strftime('%H:%M'),
            end_time=(expired_time2 + timedelta(hours=1)).strftime('%H:%M'),
            check_in_deadline=expired_time2 + timedelta(minutes=5),
            checked_in=False
        )
        db.session.add(expired_reservation2)

        # 3. 有效预约
        valid_time = now - timedelta(minutes=4)
        valid_reservation = Reservation(
            user_id=self.user1.id,
            seat_id=self.seat3.id,
            date=valid_time.date(),
            start_time=valid_time.strftime('%H:%M'),
            end_time=(valid_time + timedelta(hours=1)).strftime('%H:%M'),
            check_in_deadline=now + timedelta(minutes=1),
            checked_in=False
        )
        db.session.add(valid_reservation)

        # 提交所有预约到数据库
        db.session.commit()

        # 记录预约ID用于后续验证
        expired_id1 = expired_reservation1.id
        expired_id2 = expired_reservation2.id
        valid_id = valid_reservation.id

        # 调用自动取消函数
        with app.app_context():
            result = auto_cancel_expired_reservations()

        # 刷新数据库会话，确保看到最新状态
        db.session.expire_all()

        # 验证过期预约已被删除
        expired1_after = Reservation.query.get(expired_id1)
        expired2_after = Reservation.query.get(expired_id2)
        valid_after = Reservation.query.get(valid_id)

        # 检查预约状态
        self.assertIsNone(expired1_after, f"过期预约1(id={expired_id1})应该已被取消")
        self.assertIsNone(expired2_after, f"过期预约2(id={expired_id2})应该已被取消")
        self.assertIsNotNone(valid_after, f"有效预约(id={valid_id})应该仍然存在")

        # 验证返回值
        self.assertEqual(result, "已自动取消 2 个超时预约", f"返回值不正确: {result}")

        print("TC-0127 测试通过：自动取消超时预约成功")


    # ========== 教室管理测试用例 (管理员操作) ==========

    # TC-0301: 成功添加教室
    def test_admin_add_classroom_success(self):
        """测试管理员成功添加教室"""
        # 模拟管理员登录
        self.login_user(self.admin)
        # 准备表单数据
        data = {
            'name': 'New Classroom',
            'rows': '2',
            'cols': '3',
            'prefix': 'B'
        }
        response = self.app.post('/admin/add_classroom', data=data, follow_redirects=True)
        response_text = response.get_data(as_text=True)
        # 修复: 使用正确的路径检查
        self.assertEqual(response.request.path, '/admin', "未重定向到管理员面板")

        # 验证成功消息
        self.assertIn('教室添加成功', response_text)

        # 验证教室已创建
        new_classroom = Classroom.query.filter_by(name='New Classroom').first()
        self.assertIsNotNone(new_classroom, "新教室未创建")
        self.assertEqual(new_classroom.capacity, 6, "座位数计算错误")

        # 验证座位已创建
        seats = Seat.query.filter_by(classroom_id=new_classroom.id).all()
        self.assertEqual(len(seats), 6, "实际创建的座位数量不正确")
        seat_numbers = {seat.seat_number for seat in seats}
        expected_seat_numbers = {'B1', 'B2', 'B3', 'B4', 'B5', 'B6'}
        self.assertEqual(seat_numbers, expected_seat_numbers, "座位编号生成错误")

    # TC-0302: 无效输入
    def test_admin_add_classroom_invalid_input(self):
        """测试添加教室时的无效输入"""
        # 模拟管理员登录
        self.login_user(self.admin)

        # 测试空名称
        response = self.app.post('/admin/add_classroom', data={
            'name': '',
            'rows': '2',
            'cols': '3',
            'prefix': 'C'
        }, follow_redirects=True)
        response_text = response.get_data(as_text=True)

        # 修改为验证实际出现的错误消息
        self.assertIn('所有字段都必须填写', response_text)

        # 测试负值容量
        response = self.app.post('/admin/add_classroom', data={
            'name': 'Invalid Classroom',
            'rows': '-1',
            'cols': '3',
            'prefix': 'D'
        }, follow_redirects=True)
        response_text = response.get_data(as_text=True)

        # 修改为验证实际出现的错误消息
        self.assertIn('行数和列数必须大于0', response_text)

    # TC-0303: 修改教室名称
    def test_admin_edit_classroom_name(self):
        """测试管理员修改教室名称"""
        # 模拟管理员登录
        self.login_user(self.admin)

        # 准备要修改的教室
        classroom = Classroom(name='Old Classroom', capacity=3)
        db.session.add(classroom)
        # 添加3个座位
        for i in range(1, 4):
            seat = Seat(seat_number=f'C{i}', classroom=classroom)
            db.session.add(seat)
        db.session.commit()

        # 修改教室名称
        response = self.app.post(f'/admin/edit_classroom/{classroom.id}', data={
            'name': 'Updated Classroom',
            'capacity': '3'  # 保持相同容量
        }, follow_redirects=True)

        # 验证成功消息
        response_text = response.get_data(as_text=True)
        self.assertIn('教室信息更新成功', response_text)

        # 验证教室名称已更新
        updated_classroom = Classroom.query.get(classroom.id)
        self.assertEqual(updated_classroom.name, 'Updated Classroom', "教室名称未更新")

    # TC-0304: 增加教室容量
    def test_admin_increase_classroom_capacity(self):
        """测试增加教室容量并添加新座位"""
        # 模拟管理员登录
        self.login_user(self.admin)

        # 准备教室（初始容量3）
        classroom = Classroom(name='Growing Classroom', capacity=3)
        db.session.add(classroom)
        # 添加3个座位
        for i in range(1, 4):
            seat = Seat(seat_number=f'A{i}', classroom=classroom)
            db.session.add(seat)
        db.session.commit()

        # 增加容量到6
        response = self.app.post(f'/admin/edit_classroom/{classroom.id}', data={
            'name': 'Growing Classroom',
            'capacity': '6'
        }, follow_redirects=True)

        # 验证成功消息
        response_text = response.get_data(as_text=True)
        self.assertIn('教室信息更新成功', response_text)

        # 验证容量已更新
        updated_classroom = Classroom.query.get(classroom.id)
        self.assertEqual(updated_classroom.capacity, 6, "容量未更新")

        # 验证新增座位
        seats = Seat.query.filter_by(classroom_id=classroom.id).all()
        self.assertEqual(len(seats), 6, "未添加新座位")
        seat_numbers = {seat.seat_number for seat in seats}
        expected_seat_numbers = {'A1', 'A2', 'A3', 'A4', 'A5', 'A6'}
        self.assertEqual(seat_numbers, expected_seat_numbers, "新座位编号生成错误")

    # TC-0305: 减少教室容量(有预约)
    def test_admin_reduce_classroom_capacity_with_reservation(self):
        """测试减少教室容量时存在活跃预约会失败"""
        # 模拟管理员登录
        self.login_user(self.admin)

        # 创建活跃预约 - 在第三个座位上创建未来的预约
        tomorrow = (datetime.now(timezone.utc) + timedelta(days=1)).date()
        reservation = Reservation(
            user_id=self.user1.id,
            seat_id=self.seat3.id,
            date=tomorrow,
            start_time="10:00",
            end_time="12:00",
            checked_in=False
        )
        db.session.add(reservation)
        db.session.commit()

        # 获取教室当前的座位信息
        original_capacity = self.classroom.capacity
        original_seat_ids = [s.id for s in self.classroom.seats]

        # 尝试减少教室容量（从3减少到2）
        response = self.app.post(f'/admin/edit_classroom/{self.classroom.id}', data={
            'name': self.classroom.name,
            'capacity': '2'  # 尝试减少到2个座位
        }, follow_redirects=True)

        # 验证操作失败
        response_text = response.get_data(as_text=True)
        self.assertIn('无法减少座位数，有座位存在未完成的预约', response_text)

        # 验证教室容量未改变
        updated_classroom = Classroom.query.get(self.classroom.id)
        self.assertEqual(updated_classroom.capacity, original_capacity, "教室容量不应改变")

        # 验证座位数量未改变
        self.assertEqual(len(updated_classroom.seats), 3, "座位数量不应减少")

        # 验证所有座位仍然存在
        for seat_id in original_seat_ids:
            self.assertIsNotNone(Seat.query.get(seat_id), f"座位{seat_id}不应被删除")

        # 验证预约仍然存在
        self.assertIsNotNone(Reservation.query.get(reservation.id), "预约不应被删除")

    # TC-0306: 减少座位(无预约)
    def test_admin_reduce_classroom_capacity_without_reservation(self):
        """测试在没有活跃预约时成功减少教室容量"""
        # 模拟管理员登录
        self.login_user(self.admin)

        # 在第一个座位上创建过去的预约 - 不影响操作
        yesterday = (datetime.now(timezone.utc) - timedelta(days=1)).date()
        reservation = Reservation(
            user_id=self.user1.id,
            seat_id=self.seat1.id,
            date=yesterday,
            start_time="10:00",
            end_time="12:00",
            checked_in=False
        )
        db.session.add(reservation)
        db.session.commit()

        # 获取教室当前的座位信息
        original_seat_ids = [s.id for s in self.classroom.seats]

        # 尝试减少教室容量（从3减少到2）
        response = self.app.post(f'/admin/edit_classroom/{self.classroom.id}', data={
            'name': self.classroom.name,
            'capacity': '2'  # 减少到2个座位
        }, follow_redirects=True)

        # 验证操作成功
        response_text = response.get_data(as_text=True)
        self.assertIn('教室信息更新成功', response_text)

        # 验证教室容量已更新
        updated_classroom = Classroom.query.get(self.classroom.id)
        self.assertEqual(updated_classroom.capacity, 2, "教室容量应更新为2")

        # 验证座位数量已减少
        updated_seats = updated_classroom.seats
        self.assertEqual(len(updated_seats), 2, "座位数量应减少到2")

        # 验证保留的座位是前两个
        self.assertIn(original_seat_ids[0], [s.id for s in updated_seats], "第一个座位应保留")
        self.assertIn(original_seat_ids[1], [s.id for s in updated_seats], "第二个座位应保留")

        # 验证第三个座位被删除
        deleted_seat = Seat.query.get(original_seat_ids[2])
        self.assertIsNone(deleted_seat, "第三个座位应被删除")

        # 验证删除座位的预约也被删除（级联删除）
        deleted_reservations = Reservation.query.filter_by(seat_id=original_seat_ids[2]).all()
        self.assertEqual(len(deleted_reservations), 0, "被删除座位的预约应被级联删除")

        # 验证其他座位的预约仍然存在
        self.assertIsNotNone(Reservation.query.get(reservation.id), "其他座位的预约应保留")

    # TC-0307: 删除无预约教室
    def test_admin_delete_classroom_without_reservations(self):
        """测试成功删除无预约的教室"""
        # 模拟管理员登录
        self.login_user(self.admin)

        # 创建无预约的教室
        classroom = Classroom(name='Empty Classroom', capacity=2)
        db.session.add(classroom)
        seat1 = Seat(seat_number='E1', classroom=classroom)
        seat2 = Seat(seat_number='E2', classroom=classroom)
        db.session.add_all([seat1, seat2])
        db.session.commit()

        classroom_id = classroom.id
        seat1_id = seat1.id
        seat2_id = seat2.id

        # 删除教室
        response = self.app.get(f'/admin/delete_classroom/{classroom_id}', follow_redirects=True)
        response_text = response.get_data(as_text=True)

        # 验证成功消息
        self.assertIn('教室删除成功', response_text)

        # 验证教室已被删除
        self.assertIsNone(Classroom.query.get(classroom_id), "教室应被删除")

        # 验证座位已被级联删除
        self.assertIsNone(Seat.query.get(seat1_id), "座位1应被删除")
        self.assertIsNone(Seat.query.get(seat2_id), "座位2应被删除")

    # TC-0308: 删除有预约教室
    def test_admin_delete_classroom_with_reservations(self):
        """测试删除有活跃预约的教室会失败"""
        # 模拟管理员登录
        self.login_user(self.admin)

        # 创建活跃预约 - 在教室的座位上创建未来的预约
        tomorrow = (datetime.now(timezone.utc) + timedelta(days=1)).date()
        reservation = Reservation(
            user_id=self.user1.id,
            seat_id=self.seat1.id,
            date=tomorrow,
            start_time="10:00",
            end_time="12:00",
            checked_in=False
        )
        db.session.add(reservation)
        db.session.commit()

        # 尝试删除教室
        response = self.app.get(f'/admin/delete_classroom/{self.classroom.id}', follow_redirects=True)
        response_text = response.get_data(as_text=True)

        # 验证操作失败消息
        self.assertIn('无法删除教室，存在未完成的预约', response_text)

        # 验证教室仍然存在
        self.assertIsNotNone(Classroom.query.get(self.classroom.id), "教室不应被删除")

        # 验证座位仍然存在
        self.assertIsNotNone(Seat.query.get(self.seat1.id), "座位1不应被删除")
        self.assertIsNotNone(Seat.query.get(self.seat2.id), "座位2不应被删除")
        self.assertIsNotNone(Seat.query.get(self.seat3.id), "座位3不应被删除")

        # 验证预约仍然存在
        self.assertIsNotNone(Reservation.query.get(reservation.id), "预约不应被删除")

    # TC-0308: 删除有预约教室
    def test_admin_delete_classroom_with_reservations(self):
        """测试删除有活跃预约的教室会失败"""
        # 模拟管理员登录
        self.login_user(self.admin)

        # 创建活跃预约 - 在教室的座位上创建未来的预约
        tomorrow = (datetime.now(timezone.utc) + timedelta(days=1)).date()
        reservation = Reservation(
            user_id=self.user1.id,
            seat_id=self.seat1.id,
            date=tomorrow,
            start_time="10:00",
            end_time="12:00",
            checked_in=False
        )
        db.session.add(reservation)
        db.session.commit()

        # 尝试删除教室
        response = self.app.get(f'/admin/delete_classroom/{self.classroom.id}', follow_redirects=True)
        response_text = response.get_data(as_text=True)

        # 验证操作失败消息
        self.assertIn('无法删除教室，存在未完成的预约', response_text)

        # 验证教室仍然存在
        self.assertIsNotNone(Classroom.query.get(self.classroom.id), "教室不应被删除")

        # 验证座位仍然存在
        self.assertIsNotNone(Seat.query.get(self.seat1.id), "座位1不应被删除")
        self.assertIsNotNone(Seat.query.get(self.seat2.id), "座位2不应被删除")
        self.assertIsNotNone(Seat.query.get(self.seat3.id), "座位3不应被删除")

        # 验证预约仍然存在
        self.assertIsNotNone(Reservation.query.get(reservation.id), "预约不应被删除")

#===================管理员测试权限用例=================
    def test_0401_super_admin_add_user(self):
        """TC-0401: 超级管理员添加各类用户"""
        # 登录超级管理员
        self.login_user(self.admin)

        # 添加普通用户
        res = self.app.post('/admin/add_user', data={
            'username': 'new_user1',
            'password': 'password',
            'is_admin': False
        }, follow_redirects=True)
        self.assertIn('用户添加成功'.encode('utf-8'), res.data)

        # 添加管理员用户
        res = self.app.post('/admin/add_user', data={
            'username': 'new_admin1',
            'password': 'password',
            'is_admin': True
        }, follow_redirects=True)
        self.assertIn('用户添加成功'.encode('utf-8'), res.data)

    def test_0402_normal_admin_add_user(self):
        """TC-0402: 普通管理员添加用户"""
        # 创建一个普通管理员
        normal_admin = User(username='normal_admin', password='password', is_admin=True)
        db.session.add(normal_admin)
        db.session.commit()

        # 登录普通管理员
        self.login_user(normal_admin)

        # 添加普通用户 - 应该成功
        res = self.app.post('/admin/add_user', data={
            'username': 'new_user2',
            'password': 'password',
            'is_admin': 'off'  # 明确设置为非管理员
        }, follow_redirects=True)
        self.assertIn('用户添加成功'.encode('utf-8'), res.data)

        # 检查用户是否被正确创建
        created_user = User.query.filter_by(username='new_user2').first()
        self.assertIsNotNone(created_user)
        self.assertFalse(created_user.is_admin)

        # 尝试添加管理员 - 应该失败
        res = self.app.post('/admin/add_user', data={
            'username': 'new_admin2',
            'password': 'password',
            'is_admin': 'on'  # 注意：使用字符串'on'而不是布尔值
        }, follow_redirects=True)
        self.assertIn('只有超级管理员可以创建管理员账号'.encode('utf-8'), res.data)

        # 验证管理员账户没有被创建
        admin_user = User.query.filter_by(username='new_admin2').first()
        self.assertIsNone(admin_user)

    def test_0403_normal_admin_edit_user(self):
        """TC-0403: 普通管理员编辑用户"""
        # 创建一个普通管理员
        normal_admin = User(username='normal_admin', password='password', is_admin=True)
        # 创建普通用户
        regular_user = User(username='regular_user', password='password')
        db.session.add_all([normal_admin, regular_user])
        db.session.commit()

        # 登录普通管理员
        self.login_user(normal_admin)

        # 编辑普通用户 - 应该成功
        res = self.app.post(f'/admin/edit_user/{regular_user.id}', data={
            'username': 'regular_user_updated',
            'is_admin': 'off'  # 保持非管理员
        }, follow_redirects=True)
        self.assertIn('用户信息更新成功'.encode('utf-8'), res.data)

        # 尝试赋予管理员权限 - 应该失败
        res = self.app.post(f'/admin/edit_user/{regular_user.id}', data={
            'username': 'regular_user_updated',
            'is_admin': 'on'  # 尝试设置为管理员
        }, follow_redirects=True)
        self.assertIn('只有超级管理员可以修改管理员账号'.encode('utf-8'), res.data)

        # 检查用户没有被提升为管理员
        updated_user = User.query.get(regular_user.id)
        self.assertFalse(updated_user.is_admin)

    def test_0404_super_admin_edit_user(self):
        """TC-0404: 超级管理员编辑各类用户"""
        # 登录超级管理员
        self.login_user(self.admin)

        # 编辑普通用户
        res = self.app.post(f'/admin/edit_user/{self.user1.id}', data={
            'username': 'user1_updated',
            'password': 'newpass',
            'is_admin': 'on'  # 设置为管理员
        }, follow_redirects=True)
        self.assertIn('用户信息更新成功'.encode('utf-8'), res.data)

        # 检查用户已被提升为管理员
        updated_user = User.query.get(self.user1.id)
        self.assertTrue(updated_user.is_admin)

    def test_0405_add_duplicate_user(self):
        """TC-0405: 添加重名用户"""
        # 登录管理员（使用超级管理员）
        self.login_user(self.admin)

        # 尝试添加已存在的用户名
        res = self.app.post('/admin/add_user', data={
            'username': 'test_user1',  # 这个用户已在setUp中创建
            'password': 'password',
            'is_admin': False
        }, follow_redirects=True)

        self.assertIn('用户名已存在'.encode('utf-8'), res.data)

    def test_0406_normal_admin_delete_user(self):
        """TC-0406: 普通管理员删除用户"""
        # 创建普通管理员
        normal_admin = User(username='normal_admin', password='password', is_admin=True)
        # 创建普通用户1（将被删除）
        regular_user1 = User(username='regular_user1', password='password')
        # 创建普通用户2（测试预约）
        regular_user2 = User(username='regular_user2', password='password')
        # 创建管理员用户（将被尝试删除）
        admin_user = User(username='admin_user', password='password', is_admin=True)

        # 添加座位（用于预约）
        seat = Seat(seat_number='TestSeat', classroom=self.classroom)

        # 为普通用户1创建预约
        reservation = Reservation(
            user=regular_user1,
            seat=seat,
            date=date.today(),
            start_time=time(10, 0).strftime('%H:%M'),
            end_time=time(11, 0).strftime('%H:%M')
        )

        db.session.add_all([normal_admin, regular_user1, regular_user2, admin_user, seat, reservation])
        db.session.commit()

        # 登录普通管理员
        self.login_user(normal_admin)

        # 1. 删除普通用户（应成功）
        res = self.app.get(f'/admin/delete_user/{regular_user1.id}', follow_redirects=True)
        self.assertIn('用户已删除'.encode('utf-8'), res.data)

        # 验证用户及其预约已被删除
        deleted_user = User.query.get(regular_user1.id)
        self.assertIsNone(deleted_user)
        reservations = Reservation.query.filter_by(user_id=regular_user1.id).all()
        self.assertEqual(len(reservations), 0)

        # 2. 尝试删除管理员（应失败）
        res = self.app.get(f'/admin/delete_user/{admin_user.id}', follow_redirects=True)
        self.assertIn('只有超级管理员可以删除管理员账号'.encode('utf-8'), res.data)

        # 验证管理员未被删除
        not_deleted_admin = User.query.get(admin_user.id)
        self.assertIsNotNone(not_deleted_admin)

    def test_0407_super_admin_delete_user(self):
        """TC-0407: 超级管理员删除用户"""
        # 登录超级管理员
        self.login_user(self.admin)

        # 创建普通用户
        regular_user = User(username='regular_user', password='password')
        # 创建管理员用户
        admin_user = User(username='admin_user', password='password', is_admin=True)

        # 添加座位（用于预约）
        seat = Seat(seat_number='TestSeat', classroom=self.classroom)

        # 为普通用户创建预约
        reservation1 = Reservation(
            user=regular_user,
            seat=seat,
            date=date.today(),
            start_time=time(10, 0).strftime('%H:%M'),
            end_time=time(11, 0).strftime('%H:%M')
        )

        # 为管理员用户创建预约
        reservation2 = Reservation(
            user=admin_user,
            seat=seat,
            date=date.today() + timedelta(days=1),
            start_time=time(10, 0).strftime('%H:%M'),
            end_time=time(11, 0).strftime('%H:%M')
        )

        db.session.add_all([regular_user, admin_user, seat, reservation1, reservation2])
        db.session.commit()

        # 1. 删除普通用户
        res = self.app.get(f'/admin/delete_user/{regular_user.id}', follow_redirects=True)
        self.assertIn('用户已删除'.encode('utf-8'), res.data)

        # 验证用户及其预约已被删除
        deleted_user = User.query.get(regular_user.id)
        self.assertIsNone(deleted_user)
        reservations = Reservation.query.filter_by(user_id=regular_user.id).all()
        self.assertEqual(len(reservations), 0)

        # 2. 删除管理员用户
        res = self.app.get(f'/admin/delete_user/{admin_user.id}', follow_redirects=True)
        self.assertIn('用户已删除'.encode('utf-8'), res.data)

        # 验证管理员用户及其预约已被删除
        deleted_admin = User.query.get(admin_user.id)
        self.assertIsNone(deleted_admin)
        reservations = Reservation.query.filter_by(user_id=admin_user.id).all()
        self.assertEqual(len(reservations), 0)

if __name__ == '__main__':
    unittest.main()