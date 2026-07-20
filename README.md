# 🎓 Quizeers

> **Learn • Challenge • Achieve**

Quizeers is a modern online quiz platform that helps students improve their knowledge through interactive quizzes, real-time scoring, leaderboards, performance analytics, and data engineering pipelines.

---

## 🚀 Features

- 🔐 User Authentication (Register & Login)
- 📚 Interactive Quizzes
- 🏆 Leaderboards
- 📊 Student Performance Analytics
- 👤 User Profiles
- ⚙️ Admin Dashboard
- 🗄️ PostgreSQL Database
- 📈 ETL Data Engineering Pipeline
- 📱 Responsive User Interface

---

## 🛠 Tech Stack

### Frontend
- HTML5
- CSS3
- Bootstrap 5
- JavaScript

### Backend
- FastAPI
- SQLAlchemy
- Pydantic

### Database
- PostgreSQL

### Data Engineering
- Pandas
- NumPy
- SQL
- ETL Pipelines

### Deployment
- GitHub Pages (Frontend)
- FastAPI (Backend)
- PostgreSQL Database

---

## 📂 Project Structure

```text
quizeers/
│
├── app/                    # FastAPI backend
│   ├── database/
│   ├── models/
│   ├── routers/
│   ├── schemas/
│   ├── services/
│   ├── security/
│   └── main.py
│
├── data_engineering/
│   ├── etl/
│   ├── pipelines/
│   ├── analytics/
│   └── reports/
│
├── docs/                   # GitHub Pages frontend
│   ├── css/
│   ├── js/
│   ├── assets/
│   ├── index.html
│   └── ...
│
├── tests/
├── requirements.txt
└── README.md
```

---

## ⚙️ Installation

### Clone the repository

```bash
git clone https://github.com/yourusername/quizeers.git

cd quizeers
```

### Create a virtual environment

```bash
python -m venv venv
```

Activate it:

**Windows**

```bash
venv\Scripts\activate
```

**macOS/Linux**

```bash
source venv/bin/activate
```

### Install dependencies

```bash
pip install -r requirements.txt
```

---

## 🗄 Configure Environment

Create a `.env` file.

```env
DATABASE_URL=postgresql://username:password@localhost/quizeers

SECRET_KEY=your_secret_key

ALGORITHM=HS256
```

---

## ▶ Run the Backend

```bash
uvicorn app.main:app --reload
```

API Documentation:

```
http://127.0.0.1:8000/docs
```

---

## 📊 Run the ETL Pipeline

```bash
python -m data_engineering.pipelines.quiz_pipeline
```

---

## 🌍 Deploy Frontend

The frontend is located inside the **docs/** folder.

Deploy using **GitHub Pages**:

```
Settings
→ Pages
→ Deploy from Branch
→ main
→ /docs
```

---

## 📸 Screenshots

Add screenshots of:

- Home Page
- Login Page
- Quiz Page
- Results Page
- Leaderboard
- Analytics Dashboard
- Admin Dashboard

---

## 🧪 Running Tests

```bash
pytest
```

---

## 🔮 Future Improvements

- AI-generated quizzes
- Quiz recommendations
- Email verification
- Dark mode
- Multiplayer quizzes
- Docker support
- Cloud deployment
- Advanced analytics dashboards

---

## 👨‍💻 Author

**Your Name**

- GitHub: https://github.com/Sanieeme


---

## 📄 License

This project is licensed under the MIT License.