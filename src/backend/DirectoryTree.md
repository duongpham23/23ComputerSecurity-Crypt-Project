backend/
├── main.py	# Điểm neo chạy backend, setup router tổng
├── .env.example
├── requirements.txt
├── (Dockerfile)
│           
├── core/
│   ├──  
│   ├── config.py         # Pydantic BaseSetting
│   ├── middleware.py     # Log, auth,....
│   └── security.py       # service về jwt, bcrypt, hash,....
│     
│   
├── features/             
│   │ 
│   ├── auth/             # --- TÍNH NĂNG AUTH (Đăng nhập/Đăng ký) ---
│   │   ├── handler.py    # Hứng API request
│   │   ├── repository.py # Tương tác với Supabase
│   │   ├── service.py    # Chứa các logic xử lý
│   │   ├── schemas.py    # DB Entity mapping / DTO dùng chung cho các API
│   │   └── routes.py     # Đăng ký các endpoint (/api/v1/login)
│   │
│   ├── kv/               # --- FEATURE 1: Secure Storage — KV Engine  ---
│   │   ├── handler.py    
│   │   ├── repository.py 
│   │   ├── service.py
│   │   ├── schemas.py     
│   │   └── routes.py     
│   │
│   ├── transit/          # --- FEATURE 2: Encryption & Signing as a Service — Transit Engine   ---
│   │   ├── handler.py    
│   │   ├── repository.py 
│   │   ├── models.py  
│   │   ├── schemas.py
│   │   └── routes.py