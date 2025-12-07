from fastapi import FastAPI, HTTPException, Depends
from pydantic import BaseModel, EmailStr
from sqlalchemy import Column, Integer, String, create_engine
from sqlalchemy.orm import sessionmaker, declarative_base, Session
from passlib.context import CryptContext

# -----------------------------------
# DataBase
# -----------------------------------
DATABASE_URL = "sqlite:///./users.db"

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()

# -----------------------------------
# User model (DB)
# -----------------------------------
class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    password = Column(String)

Base.metadata.create_all(bind=engine)

# -----------------------------------
# Password tools
# -----------------------------------
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password(password: str):
    return pwd_context.hash(password)

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

# -----------------------------------
# Request Models
# -----------------------------------
class RegisterModel(BaseModel):
    email: EmailStr
    password: str

class LoginModel(BaseModel):
    email: EmailStr
    password: str

# -----------------------------------
# FastAPI app
# -----------------------------------
app = FastAPI(title="Register/Login API")


# Dependency (DB session)
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# -----------------------------------
# REGISTER
# -----------------------------------
@app.post("/register")
def register_user(user: RegisterModel, db: Session = Depends(get_db)):

    # Check if user already exists
    existing = db.query(User).filter(User.email == user.email).first()
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")

    new_user = User(
        email=user.email,
        password=hash_password(user.password)
    )

    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return {"message": "User registered!", "user_id": new_user.id}


# -----------------------------------
# LOGIN
# -----------------------------------
@app.post("/login")
def login_user(user: LoginModel, db: Session = Depends(get_db)):

    db_user = db.query(User).filter(User.email == user.email).first()

    if not db_user:
        raise HTTPException(status_code=400, detail="Email not found")

    if not verify_password(user.password, db_user.password):
        raise HTTPException(status_code=400, detail="Password incorrect")

    return {"message": "Login successful!", "user_id": db_user.id}
