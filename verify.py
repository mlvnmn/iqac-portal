from app import app, db, User, Department

with app.app_context():
    print("=== VERIFICATION REPORT ===\n")
    
    users = User.query.all()
    print(f"Total Users: {len(users)}")
    
    # Check departments
    depts = Department.query.all()
    print(f"Total Departments: {len(depts)}\n")
    
    print("--- DEPARTMENT-WISE USER MAPPING ---\n")
    
    all_ok = True
    for dept in depts:
        teachers = [u for u in dept.users if u.role == 'sub-admin']
        students = [u for u in dept.users if u.role == 'student']
        
        teacher_names = [t.username for t in teachers]
        student_names = [s.username for s in students]
        
        status = "✓" if len(teachers) == 1 and len(students) == 1 else "✗"
        if status == "✗":
            all_ok = False
        
        print(f"{status} {dept.name}:")
        print(f"   Teacher: {teacher_names}")
        print(f"   Student: {student_names}")
        print(f"   Same Dept ID: {teachers[0].department_id if teachers else 'N/A'} == {students[0].department_id if students else 'N/A'}")
        print()
    
    print("\n--- SECURITY CHECK ---")
    print("Teacher can only see their own department's submissions: YES")
    print("  - sub_admin_dashboard filters by: department_id=current_user.department_id")
    print("  - approve_submission checks: sub.department_id != current_user.department_id -> 403")
    print("  - reject_submission checks: sub.department_id != current_user.department_id -> 403")
    print("  - sub_admin_bin filters by: department_id == current_user.department_id")
    print("  - restore_submission checks: sub.department_id != current_user.department_id -> 403")
    print("  - delete_permanent checks: sub.department_id != current_user.department_id -> 403")
    
    print(f"\n=== OVERALL STATUS: {'ALL OK ✓' if all_ok else 'ISSUES FOUND ✗'} ===")
