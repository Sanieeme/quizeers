from flask import Flask, render_template, redirect, url_for, request, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
import json

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Make sure to set this for session management
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///quizeers.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

# User Model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

# Quiz Model
class Quiz(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(120), nullable=False)
    description = db.Column(db.Text, nullable=True)
    questions = db.relationship('Question', backref='quiz', lazy=True)

# Question Model
class Question(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String(255), nullable=False)
    correct_answer = db.Column(db.String(255), nullable=False)
    quiz_id = db.Column(db.Integer, db.ForeignKey('quiz.id'), nullable=False)
    answers = db.relationship('Answer', backref='question', lazy=True)

# Answer Model
class Answer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String(255), nullable=False)
    question_id = db.Column(db.Integer, db.ForeignKey('question.id'), nullable=False)

# Result Model
class Result(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    quiz_id = db.Column(db.Integer, db.ForeignKey('quiz.id'), nullable=False)
    score = db.Column(db.Integer, nullable=False)
    answers_given = db.Column(db.Text, nullable=False)  # Store answers as JSON
    user = db.relationship('User', backref='results', lazy=True)
    quiz = db.relationship('Quiz', backref='results', lazy=True)

# Routes
@app.route('/')
def home():
    page = request.args.get('page', 1, type=int)  # Get the page number from the URL (defaults to 1)
    quizzes = Quiz.query.paginate(page=page, per_page=2)  # Pagination: 2 quizzes per page
    return render_template('home.html', quizzes=quizzes)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        is_admin = 'is_admin' in request.form

        if User.query.filter_by(email=email).first():
            flash('Email already registered!', 'danger')
            return redirect(url_for('register'))

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(email=email, password=hashed_password, is_admin=is_admin)
        db.session.add(new_user)
        db.session.commit()

        flash('Registration successful!', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()

        if user and bcrypt.check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['is_admin'] = user.is_admin
            session['email'] = user.email  # Store the email in the session for personalized greetings
            flash('Login successful!', 'success')
            return redirect(url_for('home'))
        flash('Invalid credentials!', 'danger')
    return render_template('login.html')


@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully!', 'info')
    return redirect(url_for('home'))

# Routes for Admin (Managing Quizzes and Questions)
@app.route('/admin/add_quiz', methods=['GET', 'POST'])
def admin_add_quiz():
    if not session.get('is_admin'):
        flash('Unauthorized access!', 'danger')
        return redirect(url_for('home'))

    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        
        # Create the new quiz object
        new_quiz = Quiz(title=title, description=description)
        db.session.add(new_quiz)
        db.session.commit()

        flash('Quiz added successfully! Now, add questions to the quiz.', 'success')
        return redirect(url_for('admin_add_questions', quiz_id=new_quiz.id))

    return render_template('admin_add_quiz.html')

@app.route('/admin/add_questions/<int:quiz_id>', methods=['GET', 'POST'])
def admin_add_questions(quiz_id):
    if not session.get('is_admin'):
        flash('Unauthorized access!', 'danger')
        return redirect(url_for('home'))

    quiz = Quiz.query.get_or_404(quiz_id)

    if request.method == 'POST':
        question_text = request.form['question_text']
        option_a = request.form['option_a']
        option_b = request.form['option_b']
        option_c = request.form['option_c']
        option_d = request.form['option_d']
        correct_answer = request.form['correct_answer']

        # Create a new question for the quiz
        new_question = Question(
            text=question_text, 
            correct_answer=correct_answer, 
            quiz_id=quiz_id
        )
        db.session.add(new_question)
        db.session.commit()

        # Add the answer options
        answers = [
            Answer(text=option_a, question_id=new_question.id),
            Answer(text=option_b, question_id=new_question.id),
            Answer(text=option_c, question_id=new_question.id),
            Answer(text=option_d, question_id=new_question.id)
        ]
        db.session.add_all(answers)
        db.session.commit()

        flash('Question added successfully!', 'success')

    return render_template('admin_add_questions.html', quiz=quiz)

@app.route('/admin/edit_quiz/<int:quiz_id>', methods=['GET', 'POST'])
def admin_edit_quiz(quiz_id):
    if not session.get('is_admin'):
        flash('Unauthorized access!', 'danger')
        return redirect(url_for('home'))

    quiz = Quiz.query.get_or_404(quiz_id)

    if request.method == 'POST':
        # Loop through the questions and update their content
        for question in quiz.questions:
            question_text = request.form.get(f'question_{question.id}')
            option_a = request.form.get(f'option_a_{question.id}')
            option_b = request.form.get(f'option_b_{question.id}')
            option_c = request.form.get(f'option_c_{question.id}')
            option_d = request.form.get(f'option_d_{question.id}')
            correct_option = request.form.get(f'correct_option_{question.id}')
            
            # Update the question fields
            question.text = question_text
            question.correct_answer = correct_option
        
        db.session.commit()
        flash('Quiz questions updated successfully!', 'success')
        return redirect(url_for('admin_panel'))

    return render_template('admin_edit_quiz.html', quiz=quiz)

@app.route('/admin/delete_quiz/<int:quiz_id>', methods=['GET', 'POST'])
def admin_delete_quiz(quiz_id):
    if not session.get('is_admin'):
        flash('Unauthorized access!', 'danger')
        return redirect(url_for('home'))

    quiz = Quiz.query.get(quiz_id)
    
    if not quiz:
        flash('Quiz not found!', 'danger')
        return redirect(url_for('admin_panel'))

    try:
        Result.query.filter_by(quiz_id=quiz.id).delete()
        db.session.delete(quiz)
        db.session.commit()
        flash('Quiz and related results have been deleted.', 'success')
    
    except Exception as e:
        db.session.rollback()
        flash(f'Error occurred: {str(e)}', 'danger')
    
    return redirect(url_for('admin_panel'))

@app.route('/admin/panel', endpoint='admin_panel')
def admin_panel():
    if not session.get('is_admin'):
        flash('Unauthorized access!', 'danger')
        return redirect(url_for('home'))

    quizzes = Quiz.query.all()
    return render_template('admin_panel.html', quizzes=quizzes)

@app.route('/admin/view_results')
def admin_view_results():
    if not session.get('is_admin'):
        flash('Unauthorized access!', 'danger')
        return redirect(url_for('home'))

    results = Result.query.all()
    return render_template('admin_view_results.html', results=results)

# Routes for Users (Taking Quizzes and Viewing Results)
@app.route('/user/results')
def user_view_results():
    if 'user_id' not in session:
        return redirect(url_for('login'))  # If the user is not logged in

    user_id = session['user_id']
    results = Result.query.filter_by(user_id=user_id).all()
    return render_template('results.html', results=results)

@app.route('/quiz/<int:quiz_id>', methods=['GET', 'POST'])
def take_quiz(quiz_id):
    quiz = Quiz.query.get_or_404(quiz_id)
    questions = Question.query.filter_by(quiz_id=quiz_id).all()

    if request.method == 'POST':
        score = 0
        total_questions = len(questions)
        answers_given = []

        for question in questions:
            selected_answer = request.form.get(f'question_{question.id}')
            if selected_answer == question.correct_answer:
                score += 1
            answers_given.append({'question_id': question.id, 'answer': selected_answer})

        new_result = Result(user_id=session['user_id'], quiz_id=quiz_id, score=score, answers_given=json.dumps(answers_given))
        db.session.add(new_result)
        db.session.commit()

        flash(f'You scored {score}/{total_questions}!', 'success')
        return redirect(url_for('home'))

    return render_template('take_quiz.html', quiz=quiz, questions=questions)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
