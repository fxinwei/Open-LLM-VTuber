from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Boolean, Date
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.sql import func
from passlib.context import CryptContext
import uuid
import boto3
from botocore.exceptions import ClientError
import os
from dotenv import load_dotenv
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders

load_dotenv()

Base = declarative_base()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def send_email(recipient_email, subject, body, attachment_path=None):

    smtp_server = 'sv1113.xserver.jp'
    port = 587
    sender_email = 'info@rinsouken.jp'
    sender_password = 'gyfdez-bysrin-hoMca9'  
    
    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = recipient_email
    msg['Subject'] = subject

    msg.attach(MIMEText(body, 'plain'))

    if attachment_path and os.path.exists(attachment_path):
        with open(attachment_path, 'rb') as attachment_file:
            part = MIMEBase('application', 'octet-stream')
            part.set_payload(attachment_file.read())
            encoders.encode_base64(part)  
            part.add_header(
                'Content-Disposition',
                f'attachment; filename={os.path.basename(attachment_path)}', 
            )
            msg.attach(part)
    try:
        with smtplib.SMTP(smtp_server, port) as server:
            server.starttls() 
            server.login(sender_email, sender_password)
            server.send_message(msg)
            print("send mail successfully")
    except Exception as e:
        print(f"email return code: {e}")

class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    first_name = Column(String)
    last_name = Column(String)
    date_of_birth = Column(Date)
    country = Column(String)
    address = Column(String)
    gender = Column(String)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    is_verified = Column(Boolean, default=False)
    vip_level = Column(Integer, default=0)

    
    @staticmethod
    def verify_password(plain_password, hashed_password):
        return pwd_context.verify(plain_password, hashed_password)
    
    @staticmethod
    def get_password_hash(password):
        return pwd_context.hash(password)
    
class LoginAttempt(Base):
    __tablename__ = "login_attempts"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    session_id = Column(String, unique=True, index=True)
    login_datetime = Column(DateTime(timezone=True), server_default=func.now())
    logout_datetime = Column(DateTime(timezone=True))
class ActiveSession(Base):
    __tablename__ = "active_sessions"
    
    id = Column(Integer, primary_key=True, index=True)
    session_id = Column(String, unique=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    login_datetime = Column(DateTime(timezone=True), server_default=func.now())
    last_active = Column(DateTime(timezone=True), server_default=func.now())
    expire_datetime = Column(DateTime(timezone=True))

class ConversationRecord(Base):
    __tablename__ = "conversation_record"
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, ForeignKey("users.username"), nullable=False)
    session_id = Column(String, unique=True, index=True)
    process_start_datetime = Column(DateTime(timezone=True))
    process_end_datetime = Column(DateTime(timezone=True))
    data = Column(String)
    data_analyzed = Column(String)

# the user who is registed but not verified yet
class RegisteredUser(Base):
    __tablename__ = "registered_users"
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    first_name = Column(String)
    last_name = Column(String)
    date_of_birth = Column(Date)
    country = Column(String)
    address = Column(String)
    gender = Column(String)
    verification_token = Column(String)
    is_verified = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    @staticmethod
    def send_verification_email(recipient_email: str, verification_link: str) -> bool:
        # AWS SES setting
        if os.getenv("MAIL_SERVER") == "AWS":
            ses_client = boto3.client(
                'ses',
                aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID"),
                aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY"),
                region_name=os.getenv("AWS_SES_REGION")
            )

            SENDER = os.getenv("AWS_SES_SENDER")  # Verified sender email in SES
            SUBJECT = "メールを確認してください"
            BODY_TEXT = f"""\
            以下のリンクをクリックして、メールアドレスを確認してください：
            
            {verification_link}
            
            このメールに心当たりがない場合は、無視してください。
            """
            BODY_HTML = f"""\
            <html>
            <head></head>
            <body>
                <p>以下のリンクをクリックして、メールアドレスを確認してください：</p>
                <p><a href="{verification_link}">メールを確認する</a></p>
                <p>このメールに心当たりがない場合は、無視してください。</p>
            </body>
            </html>
            """
            CHARSET = "UTF-8"
            
            try:
                response = ses_client.send_email(
                    Source=SENDER,
                    Destination={
                        'ToAddresses': [
                            recipient_email,
                        ],
                    },
                    Message={
                        'Subject': {
                            'Data': SUBJECT,
                            'Charset': CHARSET
                        },
                        'Body': {
                            'Text': {
                                'Data': BODY_TEXT,
                                'Charset': CHARSET
                            },
                            'Html': {
                                'Data': BODY_HTML,
                                'Charset': CHARSET
                            }
                        }
                    }
                )
            except ClientError as e:
                # Log error with logger.error(e)
                return False
            return True
        else:
            subject = "メールを確認してください"
            body = f"""\
            以下のリンクをクリックして、メールアドレスを確認してください：

            {verification_link}

            このメールは、AIアシスタントアプリケーションのアカウント登録を試みたため送信されました。
            このメールに心当たりがない場合は、無視してください。
            """
            send_email(recipient_email, subject, body)
            return True

class ResetPasswordUser(Base):
    __tablename__ = "reset_password_users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    email = Column(String, unique=True, index=True)
    reset_token = Column(String)
    reset_finished = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    @staticmethod
    def send_reset_email(username: str, recipient_email: str, reset_link: str) -> bool:
        # AWS SES setting
        if os.getenv("MAIL_SERVER") == "AWS":
            ses_client = boto3.client(
                'ses',
                aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID"),
                aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY"),
                region_name=os.getenv("AWS_SES_REGION")
            )

            SENDER = os.getenv("AWS_SES_SENDER")
            SUBJECT = "パスワードリセット"
            BODY_TEXT = f"以下のリンクをクリックして、パスワードをリセットしてください：\n{reset_link}"
            BODY_HTML = f"""
            <html>
            <head></head>
            <body>
                <p>あなたのユーザー名は： {username}</p>
                <p>以下のリンクをクリックして、パスワードをリセットしてください：</p>
                <p><a href="{reset_link}">パスワードをリセット</a></p>
            </body>
            </html>
            """
            CHARSET = "UTF-8"
            
            try:
                response = ses_client.send_email(
                    Source=SENDER,
                    Destination={
                        'ToAddresses': [
                            recipient_email,
                        ],
                    },
                    Message={
                        'Subject': {
                            'Data': SUBJECT,
                            'Charset': CHARSET
                        },
                        'Body': {
                            'Text': {
                                'Data': BODY_TEXT,
                                'Charset': CHARSET
                            },
                            'Html': {
                                'Data': BODY_HTML,
                                'Charset': CHARSET
                            }
                        }
                    }
                )
            except ClientError as e:
                # Log error with logger.error(e)
                return False
            return True
        else:
            # Send email using SMTP
            subject = f"パスワードをリセット"
            body = f"""
            あなたのユーザー名は：{username}

            以下のリンクをクリックして、パスワードをリセットしてください：
            
            {reset_link}

            このメールは、AIアシスタントアプリケーションのパスワードリセットを試みたため送信されました。
            このメールに心当たりがない場合は、無視してください。            
            """
            send_email(recipient_email, subject, body)

            return True
