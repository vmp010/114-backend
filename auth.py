from fastapi import FastAPI, Depends, HTTPException, status, Response, Cookie
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from jose import JWTError, jwt
from datetime import datetime, timedelta
from typing import Optional

app = FastAPI()

# 假資料
fake_users_db = {
    "alice": {"username": "alice", "password": "secret123"}
}

# JWT 設定
SECRET_KEY = "super-secret-key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
REFRESH_TOKEN_EXPIRE_DAYS = 7

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

def create_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def create_access_token(data: dict):
    return create_token(data, expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))

def create_refresh_token(data: dict):
    return create_token(data, expires_delta=timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS))

def verify_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)
        return username
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)

@app.post("/login")
def login(form_data: OAuth2PasswordRequestForm = Depends(), response: Response = None):
    user = fake_users_db.get(form_data.username)
    if not user or user["password"] != form_data.password:
        raise HTTPException(status_code=400, detail="Invalid credentials")

    access_token = create_access_token({"sub": user["username"]})
    refresh_token= create_refresh_token({"sub": user["username"]})

    # 同時回傳 token 並設定 cookie
    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,
        samesite="lax",
        max_age=REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 * 60,
        path="/refresh"
    )
    return {"access_token": access_token,
            "refresh_token": refresh_token,
             "token_type": "bearer"}

@app.post("/refresh")
def refresh_token(refresh_token: Optional[str] = Cookie(None), response: Response = None):
    if not refresh_token:
        raise HTTPException(status_code=401, detail="Refresh token missing")

    username = verify_token(refresh_token)
    if username not in fake_users_db:
        raise HTTPException(status_code=401, detail="user not found")
    
    new_access_token = create_access_token(data={"sub": username})

    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,
        samesite="lax",
        max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        path="/refresh"
    )
    return {"access_token": new_access_token, "token_type": "bearer"}

@app.get("/protected")
def protected(token: Optional[str] = Depends(oauth2_scheme), access_token: Optional[str] = Cookie(None)):
    # 允許兩種登入方式：header 或 cookie
    if token:
        username = verify_token(token)

    elif access_token:
        username = verify_token(access_token)

    else:
        raise HTTPException(status_code=401, detail="Missing token or cookie")

    return {"message": f"Hello, {username}! You are authenticated."}

@app.post("/logout")
def logout(response: Response):
    response.delete_cookie(key="access_token", path="/")
    response.delete_cookie(key="refresh_token", path="/refresh")
    return {"message": "Successfully logged out"}