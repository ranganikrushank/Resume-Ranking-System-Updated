from flask import Flask, render_template, request, redirect, url_for, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from utils.parser import extract_text
from models.ranker import rank_resume
from datetime import datetime
import pandas as pd, os
import pickle


from datetime import timedelta

apermanent_session_lifetime = timedelta(minutes=5)

app = Flask(__name__)
app.secret_key = 'cfd330305bda3b6dcecd7e9e76947bdc52a7478be281f825d4c8dab230b3df29'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['UPLOAD_FOLDER'] = 'resumes'

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_view = 'login'  # for user login required redirects
login_manager.login_message_category = "info"


# Load model and vectorizer once
job_model = pickle.load(open("job_classifier_model.pkl", "rb"))
vectorizer = pickle.load(open("vectorizer.pkl", "rb"))

def predict_job_role(text):
    vec = vectorizer.transform([text])
    role = job_model.predict(vec)[0]
    return role



# @app.route('/fix-db')
# def fix_db():
#     from sqlalchemy import text
#     try:
#         db.session.execute(text('ALTER TABLE resume_upload ADD COLUMN predicted_role TEXT'))
#         db.session.commit()
#         return "✅ Column 'predicted_role' added to resume_upload table."
#     except Exception as e:
#         return f"❌ Error: {e}"




@app.after_request
def add_no_cache_headers(response):
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response



# === Models ===
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True)
    password = db.Column(db.String(256))
    role = db.Column(db.String(10))  # 'user' or 'admin'

class ResumeUpload(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    filename = db.Column(db.String(150))
    score = db.Column(db.Float)
    similarity = db.Column(db.Float)
    upload_time = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship('User', backref='uploads')
    predicted_role = db.Column(db.String(100))  # 👈 Add this line
    

class ShortlistedResume(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    filename = db.Column(db.String(120), nullable=False)
    score = db.Column(db.Float, nullable=False)
    note = db.Column(db.String(250))
    added_on = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship('User', backref='shortlisted')




with app.app_context():
    db.create_all()

    # Automatically create an admin user if not exists
    from werkzeug.security import generate_password_hash

    if not User.query.filter_by(email='admin@example.com').first():
        admin_user = User(
            email='admin@example.com',
            password=generate_password_hash('admin123'),
            role='admin'
        )
        db.session.add(admin_user)
        db.session.commit()
        print("✅ Admin user created: admin@example.com / admin123")

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# === Routes ===
@app.route('/')
def index():
    return redirect('/login')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User(email=email, password=generate_password_hash(password), role='user')
        db.session.add(user)
        db.session.commit()
        return redirect('/login')
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect('/upload') if user.role == 'user' else redirect('/admin')
    return render_template('login.html')

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    if request.method == 'POST':
        jd = request.form['jd']
        resumes = request.files.getlist("resumes")
        shortlist_count = int(request.form['shortlist_count'])

        results = []

        for file in resumes:
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
            file.save(filepath)
            text = extract_text(filepath)
            score, sim = rank_resume(text, jd)
            role = predict_job_role(text)

            # Save to DB
            upload_entry = ResumeUpload(
                user_id=current_user.id,
                filename=file.filename,
                score=score,
                similarity=sim,
                predicted_role=role
            )
            db.session.add(upload_entry)
            results.append({
                'filename': file.filename,
                'score': round(score, 2),
                'similarity': round(sim, 2),
                'predicted_role': role
            })

        db.session.commit()

        results = sorted(results, key=lambda x: x['score'], reverse=True)
        shortlisted = results[:shortlist_count]

        return render_template("shortlist_result.html",
                               shortlisted=shortlisted,
                               total=len(results),
                               requested=shortlist_count)

    # GET method
    return render_template("upload.html")





@app.route('/admin')
def admin():
    if not current_user.is_authenticated:
        return redirect('/admin-login')  # Not logged in

    if current_user.role != 'admin':
        logout_user()  # Log out user if not admin
        return redirect('/admin-login')  # Force new login for admin

    users = User.query.filter(User.role != 'admin').all()
    return render_template('admin.html', users=users)




@app.route('/admin-login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email, role='admin').first()

        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect('/admin')
        else:
            return "Invalid admin credentials", 401

    return render_template('admin_login.html')





@app.route('/download')
@login_required
def download():
    if current_user.role != 'admin': return redirect('/')
    uid = request.args.get("user_id")
    uploads = ResumeUpload.query.filter_by(user_id=uid).all()
    data = [{
        'filename': r.filename,
        'score': r.score,
        'similarity': r.similarity,
        'timestamp': r.upload_time
    } for r in uploads]
    df = pd.DataFrame(data)
    df.to_csv("user_uploads.csv", index=False)
    return send_file("user_uploads.csv", as_attachment=True)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect('/login')



from functools import wraps
from flask import redirect, url_for
from flask_login import current_user

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            return redirect('/admin-login')
        return f(*args, **kwargs)
    return decorated_function



from werkzeug.security import generate_password_hash

@app.route('/admin/reset-password/<int:user_id>', methods=['GET', 'POST'])
@admin_required
def reset_password(user_id):
    user = User.query.get_or_404(user_id)

    if request.method == 'POST':
        new_password = request.form['new_password']
        user.password = generate_password_hash(new_password)
        db.session.commit()
        return redirect('/admin')

    return render_template('reset_password.html', user=user)


@app.route('/admin/edit-user/<int:user_id>', methods=['GET', 'POST'])
@admin_required
def edit_user(user_id):
    user = User.query.get_or_404(user_id)

    if request.method == 'POST':
        new_email = request.form['email']
        user.email = new_email
        db.session.commit()
        return redirect('/admin')

    return render_template('edit_user.html', user=user)


@app.route('/admin/delete-user/<int:user_id>')
@admin_required
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    ResumeUpload.query.filter_by(user_id=user_id).delete()  # Clean uploads
    db.session.delete(user)
    db.session.commit()
    return redirect('/admin')


@app.route('/admin/delete-resume/<int:upload_id>')
@admin_required
def delete_resume(upload_id):
    upload = ResumeUpload.query.get_or_404(upload_id)
    user_id = upload.user_id
    db.session.delete(upload)
    db.session.commit()
    return redirect(f'/admin/user/{user_id}')


@app.route('/admin/user/<int:user_id>')
@admin_required
def view_user_analysis(user_id):
    user = User.query.get_or_404(user_id)
    uploads = ResumeUpload.query.filter_by(user_id=user_id).order_by(ResumeUpload.upload_time.desc()).all()
    shortlisted = ShortlistedResume.query.filter_by(user_id=user_id).order_by(ShortlistedResume.added_on.desc()).all()

    matched = 0
    mismatched = 0

    for u in uploads:
        if u.predicted_role and u.predicted_role.lower() in u.filename.lower():  # crude match logic
            matched += 1
        else:
            mismatched += 1

    return render_template('user_analysis.html',
                           user=user,
                           uploads=uploads,
                           shortlisted=shortlisted,
                           matched=matched,
                           mismatched=mismatched)





@app.route('/admin/shortlist/add/<int:user_id>', methods=['POST'])
@admin_required
def add_shortlisted_resume(user_id):
    filename = request.form['filename']
    score = float(request.form['score'])
    note = request.form.get('note')
    entry = ShortlistedResume(user_id=user_id, filename=filename, score=score, note=note)
    db.session.add(entry)
    db.session.commit()
    return redirect(f'/admin/user/{user_id}')


@app.route('/admin/shortlist/edit/<int:id>', methods=['GET', 'POST'])
@admin_required
def edit_shortlisted_resume(id):
    resume = ShortlistedResume.query.get_or_404(id)
    if request.method == 'POST':
        resume.filename = request.form['filename']
        resume.score = float(request.form['score'])
        resume.note = request.form['note']
        db.session.commit()
        return redirect(f'/admin/user/{resume.user_id}')
    return render_template('edit_shortlisted.html', resume=resume)


@app.route('/admin/shortlist/delete/<int:id>')
@admin_required
def delete_shortlisted_resume(id):
    resume = ShortlistedResume.query.get_or_404(id)
    user_id = resume.user_id
    db.session.delete(resume)
    db.session.commit()
    return redirect(f'/admin/user/{user_id}')




@app.template_filter('format_date')
def format_date(value):
    return value.strftime('%Y-%m-%d')





if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000, debug=True)