import os
import secrets
from datetime import datetime, timedelta, timezone
from flask import Flask, render_template, redirect, url_for, flash, request, send_file, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import pandas as pd
import cloudinary
import cloudinary.uploader
import cloudinary.api
import io
from dotenv import load_dotenv

load_dotenv()

# Initialize App
app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(16)
# Database Configuration
database_url = os.environ.get('DATABASE_URL', 'sqlite:///iqac_portal.db')
# Fix for Render's postgres:// vs SQLAlchemy's postgresql://
if database_url and database_url.startswith("postgres://"):
    database_url = database_url.replace("postgres://", "postgresql://", 1)

app.config['SQLALCHEMY_DATABASE_URI'] = database_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Cloudinary Config - REPLACE WITH YOUR KEYS
# You can also set these via environment variables
cloudinary.config(
    cloud_name = os.environ.get('CLOUDINARY_CLOUD_NAME', 'your_cloud_name'),
    api_key = os.environ.get('CLOUDINARY_API_KEY', 'your_api_key'),
    api_secret = os.environ.get('CLOUDINARY_API_SECRET', 'your_api_secret'),
    secure = True
)

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# IST Timezone (UTC+5:30)
IST = timezone(timedelta(hours=5, minutes=30))

def get_ist_now():
    return datetime.now(IST)

@app.template_filter('to_ist')
def to_ist_filter(dt):
    if dt is None:
        return ''
    # Convert UTC to IST
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    ist_time = dt.astimezone(IST)
    return ist_time.strftime('%b %d, %Y at %I:%M %p')

# --- Models ---

class Department(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    users = db.relationship('User', backref='department', lazy=True)
    submissions = db.relationship('Submission', backref='department', lazy=True)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), nullable=False)  # 'student', 'sub-admin', 'admin'
    department_id = db.Column(db.Integer, db.ForeignKey('department.id'), nullable=True) # Admin might not have a dept or default

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Submission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    image_filename = db.Column(db.String(300), nullable=True)  # Optional - can be None for report-only
    description = db.Column(db.Text, nullable=True)
    event_type = db.Column(db.String(50), nullable=False)
    status = db.Column(db.String(20), default='pending')  # 'pending', 'approved', 'rejected'
    department_id = db.Column(db.Integer, db.ForeignKey('department.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    rejected_at = db.Column(db.DateTime, nullable=True)  # For 90-day restore tracking

    user = db.relationship('User', backref='submissions', lazy=True)

class EventType(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- CLI Commands ---

@app.cli.command("init-db")
def init_db():
    """Wipes and populates the database."""
    db.drop_all()
    db.create_all()

    # 1. Populate Departments
    dept_names = [
        "Botany", "Chemistry", "Physics", "Mathematics", "English", "Malayalam",
        "Commerce", "Computer Science", "Psychology", "Sociology", "Statistics",
        "Physical Education", "Syriac", "Zoology", "Biotechnology", "Economics", "Social Work"
    ]
    
    depts = {}
    for name in dept_names:
        d = Department(name=name)
        db.session.add(d)
        depts[name] = d # Keep track for user creation if needed
    
    db.session.flush() # To get IDs

    # Reload depts to be sure we have the objects bound
    dept_map = {d.name: d for d in Department.query.all()}

    # 2. Create Users for ALL departments
    users = []
    
    # Admin
    admin = User(username="admin", role="admin", department_id=None)
    admin.set_password("admin123")
    users.append(admin)

    # Create teacher and student for each department
    for dept_name, dept in dept_map.items():
        # Create a clean username (lowercase, replace spaces with underscore)
        clean_name = dept_name.lower().replace(" ", "_")
        
        # Teacher (sub-admin)
        teacher = User(username=f"teacher_{clean_name}", role="sub-admin", department_id=dept.id)
        teacher.set_password("123")
        users.append(teacher)
        
        # Student
        student = User(username=f"student_{clean_name}", role="student", department_id=dept.id)
        student.set_password("123")
        users.append(student)

    for u in users:
        db.session.add(u)
    
    # 3. Populate Event Types
    event_type_names = [
        "Research Methodology", "IPR", "Workshops", "Seminar", "Conference",
        "Internship", "Project", "Industrial Visit", "Field Visit",
        "Expert Talks", "Panel Discussions", "Exhibition",
        "Extension Activities", "Outreach Programs", "Competitions/Fest"
    ]
    
    for et_name in event_type_names:
        et = EventType(name=et_name)
        db.session.add(et)
    
    db.session.commit()
    print("Database initialized with demo data.")


# --- Routes ---

@app.route('/')
def index():
    if current_user.is_authenticated:
        if current_user.role == 'student':
            return redirect(url_for('student_dashboard'))
        elif current_user.role == 'sub-admin':
            return redirect(url_for('sub_admin_dashboard'))
        elif current_user.role == 'admin':
            return redirect(url_for('admin_dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password.', 'danger')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# --- Student Routes ---

@app.route('/student/dashboard', methods=['GET', 'POST'])
@login_required
def student_dashboard():
    if current_user.role != 'student':
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        event_type = request.form.get('event_type')
        description = request.form.get('description')
        
        # Get files (optional now)
        files = request.files.getlist('image')
        has_images = any(f.filename != '' for f in files)
        
        if has_images:
            # Upload images to Cloudinary
            for file in files:
                if file.filename == '':
                    continue
                
                try:
                    upload_result = cloudinary.uploader.upload(file)
                    image_url = upload_result['secure_url']
                    
                    new_sub = Submission(
                        image_filename=image_url,
                        description=description,
                        event_type=event_type,
                        department_id=current_user.department_id,
                        user_id=current_user.id
                    )
                    db.session.add(new_sub)
                except Exception as e:
                    flash(f'Error uploading image: {str(e)}', 'danger')
                    return redirect(request.url)
        else:
            # No images - submit report only
            new_sub = Submission(
                image_filename=None,
                description=description,
                event_type=event_type,
                department_id=current_user.department_id,
                user_id=current_user.id
            )
            db.session.add(new_sub)
        
        db.session.commit()
        flash('Submission uploaded successfully! Status: Pending', 'success')
        return redirect(url_for('student_dashboard'))

    my_submissions = Submission.query.filter_by(user_id=current_user.id).order_by(Submission.created_at.desc()).all()
    event_types = EventType.query.order_by(EventType.name).all()
    return render_template('student.html', submissions=my_submissions, event_types=event_types)

# --- Sub-Admin Routes ---

@app.route('/sub_admin/dashboard')
@login_required
def sub_admin_dashboard():
    if current_user.role != 'sub-admin':
        return redirect(url_for('index'))
    
    # Show only pending submissions for their department
    submissions = Submission.query.filter_by(
        department_id=current_user.department_id, 
        status='pending'
    ).all()
    
    return render_template('sub_admin.html', submissions=submissions)

@app.route('/sub_admin/approve/<int:sub_id>')
@login_required
def approve_submission(sub_id):
    if current_user.role != 'sub-admin':
        return redirect(url_for('index'))
    
    sub = Submission.query.get_or_404(sub_id)
    
    # Verify strict security: Must be same dept
    if sub.department_id != current_user.department_id:
        abort(403)
        
    sub.status = 'approved'
    db.session.commit()
    flash('Submission approved.', 'success')
    return redirect(url_for('sub_admin_dashboard'))

@app.route('/sub_admin/reject/<int:sub_id>')
@login_required
def reject_submission(sub_id):
    if current_user.role != 'sub-admin':
        return redirect(url_for('index'))
    
    sub = Submission.query.get_or_404(sub_id)
    
    if sub.department_id != current_user.department_id:
        abort(403)
    
    # Soft delete - mark as rejected with timestamp
    sub.status = 'rejected'
    sub.rejected_at = datetime.utcnow()
    db.session.commit()
    flash('Submission rejected and moved to bin.', 'warning')
    return redirect(url_for('sub_admin_dashboard'))

@app.route('/sub_admin/bin')
@login_required
def sub_admin_bin():
    if current_user.role != 'sub-admin':
        return redirect(url_for('index'))
    
    # Get rejected submissions within 90 days
    from datetime import timedelta
    cutoff_date = datetime.utcnow() - timedelta(days=90)
    
    rejected = Submission.query.filter(
        Submission.department_id == current_user.department_id,
        Submission.status == 'rejected',
        Submission.rejected_at >= cutoff_date
    ).order_by(Submission.rejected_at.desc()).all()
    
    return render_template('bin.html', submissions=rejected)

@app.route('/sub_admin/restore/<int:sub_id>')
@login_required
def restore_submission(sub_id):
    if current_user.role != 'sub-admin':
        return redirect(url_for('index'))
    
    sub = Submission.query.get_or_404(sub_id)
    
    if sub.department_id != current_user.department_id:
        abort(403)
    
    # Restore to pending
    sub.status = 'pending'
    sub.rejected_at = None
    db.session.commit()
    flash('Submission restored to pending.', 'success')
    return redirect(url_for('sub_admin_bin'))

@app.route('/sub_admin/delete_permanent/<int:sub_id>')
@login_required
def delete_permanent(sub_id):
    if current_user.role != 'sub-admin':
        return redirect(url_for('index'))
    
    sub = Submission.query.get_or_404(sub_id)
    
    if sub.department_id != current_user.department_id:
        abort(403)
    
    db.session.delete(sub)
    db.session.commit()
    flash('Submission permanently deleted.', 'danger')
    return redirect(url_for('sub_admin_bin'))

# --- Admin Routes ---

@app.route('/admin/search')
@login_required
def admin_search():
    if current_user.role != 'admin':
        return redirect(url_for('index'))
    
    query = request.args.get('q', '').strip()
    dept_filter = request.args.get('dept', '')
    event_filter = request.args.get('event', '')
    date_filter = request.args.get('date', '')
    sort_by = request.args.get('sort', 'newest')
    
    # Base query - only approved
    submissions = Submission.query.filter_by(status='approved')
    
    # Apply filters
    if dept_filter:
        submissions = submissions.filter_by(department_id=int(dept_filter))
    
    if event_filter:
        submissions = submissions.filter_by(event_type=event_filter)
    
    # Date filter (convert IST date to UTC range)
    if date_filter:
        try:
            filter_date = datetime.strptime(date_filter, '%Y-%m-%d')
            # IST is UTC+5:30, so IST midnight = UTC previous day 18:30
            # IST date range in UTC: (date - 5:30 hours) to (next date - 5:30 hours)
            utc_start = filter_date - timedelta(hours=5, minutes=30)
            utc_end = utc_start + timedelta(days=1)
            submissions = submissions.filter(
                Submission.created_at >= utc_start,
                Submission.created_at < utc_end
            )
        except ValueError:
            pass
    
    # Smart search across multiple fields
    if query:
        search_pattern = f'%{query}%'
        submissions = submissions.join(User).join(Department).filter(
            db.or_(
                Submission.description.ilike(search_pattern),
                Submission.event_type.ilike(search_pattern),
                User.username.ilike(search_pattern),
                Department.name.ilike(search_pattern)
            )
        )
    
    # Sort
    if sort_by == 'oldest':
        submissions = submissions.order_by(Submission.created_at.asc())
    else:  # newest
        submissions = submissions.order_by(Submission.created_at.desc())
    
    results = submissions.all()
    departments = Department.query.all()
    event_types = db.session.query(Submission.event_type).distinct().all()
    event_types = [e[0] for e in event_types]
    
    return render_template('search.html', 
                           results=results, 
                           query=query,
                           dept_filter=dept_filter,
                           event_filter=event_filter,
                           date_filter=date_filter,
                           sort_by=sort_by,
                           departments=departments,
                           event_types=event_types)

@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    if current_user.role != 'admin':
        return redirect(url_for('index'))
    
    departments = Department.query.all()
    return render_template('admin.html', departments=departments)

@app.route('/admin/gallery/<int:dept_id>')
@login_required
def dept_gallery(dept_id):
    if current_user.role != 'admin':
        return redirect(url_for('index'))
    
    dept = Department.query.get_or_404(dept_id)
    # Get unique event types for this department
    submissions = Submission.query.filter_by(department_id=dept_id, status='approved').all()
    event_types = list(set([s.event_type for s in submissions]))
    
    # Count items per event type
    event_counts = {}
    for et in event_types:
        event_counts[et] = len([s for s in submissions if s.event_type == et])
    
    return render_template('gallery.html', department=dept, event_types=event_types, event_counts=event_counts)

@app.route('/admin/gallery/<int:dept_id>/<event_type>')
@login_required
def event_gallery(dept_id, event_type):
    if current_user.role != 'admin':
        return redirect(url_for('index'))
    
    dept = Department.query.get_or_404(dept_id)
    submissions = Submission.query.filter_by(
        department_id=dept_id, 
        status='approved', 
        event_type=event_type
    ).order_by(Submission.created_at.desc()).all()
    
    return render_template('event_gallery.html', department=dept, event_type=event_type, submissions=submissions)

@app.route('/admin/manage_departments', methods=['GET', 'POST'])
@login_required
def manage_departments():
    if current_user.role != 'admin':
        return redirect(url_for('index'))
    
    new_credentials = None
    
    if request.method == 'POST':
        name = request.form.get('name')
        if name:
            existing = Department.query.filter_by(name=name).first()
            if not existing:
                # Create the department
                new_dept = Department(name=name)
                db.session.add(new_dept)
                db.session.flush()  # Get the ID
                
                # Create clean username
                clean_name = name.lower().replace(" ", "_")
                default_password = "123"
                
                # Create teacher account
                teacher_username = f"teacher_{clean_name}"
                teacher = User(username=teacher_username, role="sub-admin", department_id=new_dept.id)
                teacher.set_password(default_password)
                db.session.add(teacher)
                
                # Create student account
                student_username = f"student_{clean_name}"
                student = User(username=student_username, role="student", department_id=new_dept.id)
                student.set_password(default_password)
                db.session.add(student)
                
                db.session.commit()
                
                # Store credentials to show in popup
                new_credentials = {
                    'department': name,
                    'teacher_username': teacher_username,
                    'student_username': student_username,
                    'password': default_password
                }
                
                flash(f'Department "{name}" added with user accounts!', 'success')
            else:
                flash('Department already exists.', 'warning')
    
    departments = Department.query.all()
    return render_template('manage_departments.html', departments=departments, new_credentials=new_credentials)

@app.route('/admin/delete_department/<int:dept_id>')
@login_required
def delete_department(dept_id):
    if current_user.role != 'admin':
        return redirect(url_for('index'))
    
    dept = Department.query.get_or_404(dept_id)
    db.session.delete(dept)
    db.session.commit()
    flash(f'Department "{dept.name}" deleted.', 'danger')
    return redirect(url_for('manage_departments'))

@app.route('/admin/edit_department/<int:dept_id>', methods=['POST'])
@login_required
def edit_department(dept_id):
    if current_user.role != 'admin':
        return redirect(url_for('index'))
    
    dept = Department.query.get_or_404(dept_id)
    
    # Get form data
    new_dept_name = request.form.get('dept_name', dept.name)
    teacher_username = request.form.get('teacher_username')
    teacher_password = request.form.get('teacher_password')
    student_username = request.form.get('student_username')
    student_password = request.form.get('student_password')
    
    # Update department name
    dept.name = new_dept_name
    
    # Find and update teacher account
    teacher = User.query.filter_by(department_id=dept.id, role='sub-admin').first()
    if teacher:
        if teacher_username:
            teacher.username = teacher_username
        if teacher_password:
            teacher.set_password(teacher_password)
    
    # Find and update student account
    student = User.query.filter_by(department_id=dept.id, role='student').first()
    if student:
        if student_username:
            student.username = student_username
        if student_password:
            student.set_password(student_password)
    
    db.session.commit()
    flash(f'Department "{new_dept_name}" updated successfully.', 'success')
    return redirect(url_for('manage_departments'))

@app.route('/admin/manage_event_types', methods=['GET', 'POST'])
@login_required
def manage_event_types():
    if current_user.role != 'admin':
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        name = request.form.get('name')
        if name:
            existing = EventType.query.filter_by(name=name).first()
            if not existing:
                new_event_type = EventType(name=name)
                db.session.add(new_event_type)
                db.session.commit()
                flash(f'Event Type "{name}" added.', 'success')
            else:
                flash('Event Type already exists.', 'warning')
    
    event_types = EventType.query.order_by(EventType.name).all()
    return render_template('manage_event_types.html', event_types=event_types)

@app.route('/admin/delete_event_type/<int:et_id>')
@login_required
def delete_event_type(et_id):
    if current_user.role != 'admin':
        return redirect(url_for('index'))
    
    et = EventType.query.get_or_404(et_id)
    db.session.delete(et)
    db.session.commit()
    flash(f'Event Type "{et.name}" deleted.', 'danger')
    return redirect(url_for('manage_event_types'))

@app.route('/admin/export/<int:dept_id>')
@login_required
def export_dept_data(dept_id):
    if current_user.role != 'admin':
        return redirect(url_for('index'))
    
    dept = Department.query.get_or_404(dept_id)
    submissions = Submission.query.filter_by(department_id=dept_id, status='approved').all()
    
    data = []
    for s in submissions:
        data.append({
            'ID': s.id,
            'Event Type': s.event_type,
            'Description': s.description,
            'Status': s.status,
            'User': s.user.username if s.user else 'N/A',
            'Image URL': s.image_filename,
            'Date': s.created_at
        })
    
    df = pd.DataFrame(data)
    output = io.BytesIO()
    with pd.ExcelWriter(output, engine='openpyxl') as writer:
        df.to_excel(writer, index=False, sheet_name=dept.name[:31])
    
    output.seek(0)
    
    return send_file(
        output,
        mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        as_attachment=True,
        download_name=f'{dept.name.lower().replace(" ", "_")}_data.xlsx'
    )

@app.route('/admin/export')
@login_required
def export_data():
    if current_user.role != 'admin':
        return redirect(url_for('index'))
    
    # Export all data to Excel
    submissions = Submission.query.all()
    data = []
    for s in submissions:
        data.append({
            'ID': s.id,
            'Event Type': s.event_type,
            'Description': s.description,
            'Status': s.status,
            'Department': s.department.name if s.department else 'N/A',
            'User': s.user.username if s.user else 'N/A',
            'Image URL': s.image_filename,
            'Date': s.created_at
        })
    
    df = pd.DataFrame(data)
    output = io.BytesIO()
    # Use xlsxwriter or openpyxl
    with pd.ExcelWriter(output, engine='openpyxl') as writer:
        df.to_excel(writer, index=False, sheet_name='Submissions')
    
    output.seek(0)
    
    return send_file(
        output,
        mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        as_attachment=True,
        download_name='iqac_event_data.xlsx'
    )

# --- Auto-Initialize DB for Render Free Tier ---
with app.app_context():
    try:
        # Check if tables exist
        inspector = db.inspect(db.engine)
        if not inspector.get_table_names():
            print("No tables found. Initializing database...")
            # Re-use the logic from init_db
            db.create_all()

            # 1. Populate Departments
            dept_names = [
                "Botany", "Chemistry", "Physics", "Mathematics", "English", "Malayalam",
                "Commerce", "Computer Science", "Psychology", "Sociology", "Statistics",
                "Physical Education", "Syriac", "Zoology", "Biotechnology", "Economics", "Social Work"
            ]
            
            depts = {}
            for name in dept_names:
                d = Department(name=name)
                db.session.add(d)
                depts[name] = d 
            
            db.session.flush()

            # Reload depts
            dept_map = {d.name: d for d in Department.query.all()}

            # 2. Create Users
            users = []
            
            # Admin
            admin = User(username="admin", role="admin", department_id=None)
            admin.set_password("admin123")
            users.append(admin)

            # Create teacher and student for each department
            for dept_name, dept in dept_map.items():
                clean_name = dept_name.lower().replace(" ", "_")
                
                # Teacher
                teacher = User(username=f"teacher_{clean_name}", role="sub-admin", department_id=dept.id)
                teacher.set_password("123")
                users.append(teacher)
                
                # Student
                student = User(username=f"student_{clean_name}", role="student", department_id=dept.id)
                student.set_password("123")
                users.append(student)

            for u in users:
                db.session.add(u)
            
            # 3. Populate Event Types
            event_type_names = [
                "Research Methodology", "IPR", "Workshops", "Seminar", "Conference",
                "Internship", "Project", "Industrial Visit", "Field Visit",
                "Expert Talks", "Panel Discussions", "Exhibition",
                "Extension Activities", "Outreach Programs", "Competitions/Fest"
            ]
            
            for et_name in event_type_names:
                et = EventType(name=et_name)
                db.session.add(et)
            
            db.session.commit()
            print("Database initialized automatically.")
    except Exception as e:
        print(f"Error during auto-initialization: {e}")

if __name__ == '__main__':
    app.run(debug=True)
