# Django Authentication API

This repository contains a Django-based authentication system with **cookie-based authentication**, **OTP-based registration**, and **CSRF protection**. The project is set up to work with **Windows, macOS, and Ubuntu**.

## Setup Instructions

### **1. Clone the Repository**
```sh
git clone https://github.com/kaushiki25/app.git
cd app
```

---

## **2. Create a Virtual Environment**
You need to create and activate a virtual environment depending on your OS.

### **For Windows (Command Prompt / PowerShell)**
```sh
python -m venv venv
venv\Scripts\activate

# Do this in case you run into security issues with running scripts locally
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

### **For macOS / Ubuntu (Terminal)**
```sh
python3 -m venv venv
source venv/bin/activate
```

---

## **3. Install Dependencies**
After activating the virtual environment, install the required packages:
```sh
pip install -r requirements.txt
```

---

## **4. Set Up Database locally (SQLite)**
Run the following command to apply migrations:
```sh
python manage.py migrate
```

---

## **5. Run the Django Server**
Now, start the development server:
```sh
python manage.py runserver
```
Your application should now be running at **http://127.0.0.1:8000/**.

---

## **6. Access API Documentation**
Swagger UI is available at:
```
http://127.0.0.1:8000/swagger/
```
You can use it to test API endpoints interactively.
