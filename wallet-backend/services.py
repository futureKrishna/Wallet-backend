from flask import request, jsonify
from extensions import db, bcrypt
from models import Wallet, Employee, User
from flask_jwt_extended import jwt_required, get_jwt_identity, create_access_token

class WalletService:
    
    @staticmethod
    def register():
        data = request.json
        hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
        new_user = User(username=data['username'], password=hashed_password, is_admin=data.get('is_admin', False))
        db.session.add(new_user)
        db.session.commit()
        
        if new_user.is_admin:
            main_wallet = Wallet(user_id=new_user.id, balance=0.0)
            db.session.add(main_wallet)
            db.session.commit()
        
        return jsonify({'message': 'User registered successfully'})


    @staticmethod
    def login():
        data = request.json
        user = User.query.filter_by(username=data['username']).first()

        if user and bcrypt.check_password_hash(user.password, data['password']):
            access_token = create_access_token(identity={'id': user.id, 'is_admin': user.is_admin})
            
            return jsonify({
                'token': access_token,
                'user': {
                    'id': user.id,
                    'username': user.username,
                    'is_admin': user.is_admin
                }
            })

        return jsonify({'message': 'Invalid credentials'}), 401


    @staticmethod
    @jwt_required()
    def get_wallet_balance():
        current_user = get_jwt_identity()  # Get user from token
        user_wallet = Wallet.query.filter_by(user_id=current_user['id']).first()

        if not user_wallet:
            return jsonify({'message': 'Wallet not found'}), 404

        return jsonify({'balance': user_wallet.balance})


    @staticmethod
    @jwt_required()
    def add_money():
        current_user = get_jwt_identity()
        if not current_user['is_admin']:
            return jsonify({'message': 'Only employers can add money'}), 403
        
        data = request.json
        wallet = Wallet.query.filter_by(user_id=current_user['id']).first()
        wallet.balance += int(data['amount'])
        db.session.commit()
        return jsonify({'message': 'Money added successfully', 'balance': wallet.balance})
    
  
    @staticmethod
    @jwt_required()
    def get_all_users():
        current_user = get_jwt_identity()
        employer = User.query.filter_by(id=current_user['id'], is_admin=True).first()
        if not employer:
            return jsonify({'message': 'Only employers can access this data'}), 403

        employee_ids = db.session.query(Employee.employee_id).filter(Employee.employer_id == employer.id).all()
        employee_ids = [emp.employee_id for emp in employee_ids]

        non_employees = (
            db.session.query(User)
            .filter(User.is_admin == False)
            .filter(~User.id.in_(employee_ids))
            .all()
        )

        return jsonify([
            {"id": user.id, "username": user.username} for user in non_employees
        ])


    @staticmethod
    @jwt_required()
    def add_employees():
        current_user = get_jwt_identity()

        employer = User.query.filter_by(id=current_user['id'], is_admin=True).first()
        if not employer:
            return jsonify({'message': 'Only employers can add employees'}), 403

        data = request.json
        employee_ids = data.get('employeeIds')

        if not employee_ids:
            return jsonify({'message': 'No employees selected'}), 400

        for emp_id in employee_ids:
            existing_relation = Employee.query.filter_by(employer_id=employer.id, employee_id=emp_id).first()
            if not existing_relation:
                new_employee = Employee(employer_id=employer.id, employee_id=emp_id)
                db.session.add(new_employee)

        db.session.commit()

        return jsonify({'message': 'Employees added successfully'})


    @staticmethod
    @jwt_required()
    def get_my_employees():
        current_user = get_jwt_identity()
        employer = User.query.filter_by(id=current_user['id'], is_admin=True).first()
        if not employer:
            return jsonify({'message': 'Only employers can view employees'}), 403

        employees = (
            db.session.query(User.id, User.username)
            .join(Employee, Employee.employee_id == User.id)
            .outerjoin(Wallet, Wallet.user_id == User.id)
            .filter(Employee.employer_id == employer.id, Wallet.user_id == None)
            .all()
        )

        return jsonify([
            {"id": emp_id, "username": username}
            for emp_id, username in employees
        ])


    @staticmethod
    @jwt_required()
    def assign_wallet():
        data = request.get_json()
        employee_ids = data.get("employeeIds", [])

        if not employee_ids:
            return jsonify({"message": "No employees selected"}), 400

        current_user = get_jwt_identity()
        employer_id = current_user["id"]

        employer = User.query.filter_by(id=employer_id, is_admin=True).first()
        if not employer:
            return jsonify({"message": "Only employers can assign wallets"}), 403

        assigned_employees = []
        for emp_id in employee_ids:
            employee = User.query.filter_by(id=emp_id).first()
            if not employee:
                continue  # Skip non-existent users

            existing_assignment = Employee.query.filter_by(employer_id=employer_id, employee_id=emp_id).first()
            if not existing_assignment:
                new_employee = Employee(employer_id=employer_id, employee_id=emp_id)
                db.session.add(new_employee)

            existing_wallet = Wallet.query.filter_by(user_id=emp_id).first()
            if not existing_wallet:
                new_wallet = Wallet(user_id=emp_id, balance=0)
                db.session.add(new_wallet)

            assigned_employees.append(emp_id)

        db.session.commit()

        return jsonify({"message": "Wallet assigned successfully", "assignedEmployees": assigned_employees}), 201
    

    @staticmethod
    @jwt_required()
    def add_wallet():
        current_user = get_jwt_identity()

        employer = User.query.filter_by(id=current_user['id'], is_admin=True).first()
        if not employer:
            return jsonify({'message': 'Only employers can add wallet balance'}), 403

        data = request.json
        employee_id = data.get('employee_id')
        amount = data.get('amount')

        if not employee_id or not amount:
            return jsonify({'message': 'Missing employee_id or amount'}), 400

        wallet = Wallet.query.filter_by(user_id=employee_id).first()
        if not wallet:
            return jsonify({'message': 'Wallet not found for this employee'}), 404

        # Update wallet balance
        wallet.balance += int(amount)
        db.session.commit()

        return jsonify({'message': 'Wallet balance updated successfully', 'new_balance': wallet.balance})


    @staticmethod
    @jwt_required()
    def wallet_transaction():
        data = request.get_json()
        transactions = data.get("transactions", [])

        if not transactions:
            return jsonify({"message": "No transactions provided"}), 400

        current_user = get_jwt_identity()
        employer_id = current_user["id"]

        # Fetch employer wallet
        employer_wallet = Wallet.query.filter_by(user_id=employer_id).first()
        if not employer_wallet:
            return jsonify({"message": "Employer wallet not found"}), 404

        errors = []

        for transaction in transactions:
            emp_id = transaction.get("employee_id")
            amount = transaction.get("amount", 0)
            transaction_type = transaction.get("transaction_type")

            if not emp_id or amount <= 0 or transaction_type not in ["credit", "debit"]:
                errors.append({
                    "employee_id": emp_id,
                    "message": "Invalid transaction data"
                })
                continue

            employee_wallet = Wallet.query.filter_by(user_id=emp_id).first()
            if not employee_wallet:
                errors.append({
                    "employee_id": emp_id,
                    "message": "Employee wallet not found"
                })
                continue

            if transaction_type == "credit":
                if employer_wallet.balance >= amount:
                    employer_wallet.balance -= amount
                    employee_wallet.balance += amount
                else:
                    errors.append({
                        "employee_id": emp_id,
                        "message": "Insufficient employer balance"
                    })
                    continue

            elif transaction_type == "debit":
                if employee_wallet.balance >= amount:
                    employee_wallet.balance -= amount
                    employer_wallet.balance += amount
                else:
                    errors.append({
                        "employee_id": emp_id,
                        "message": "Insufficient employee balance"
                    })
                    continue

        if errors:
            db.session.rollback()
            return jsonify({"errors": errors}), 400

        db.session.commit()
        return jsonify({"message": "Wallet transactions updated successfully"}), 200


    @staticmethod
    @jwt_required()
    def get_my_wallet_employees():
        current_user = get_jwt_identity()
        employer_id = current_user["id"]

        assigned_employees = (
            db.session.query(User.id, User.username, Wallet.balance)
            .join(Employee, Employee.employee_id == User.id)
            .join(Wallet, Wallet.user_id == User.id)
            .filter(Employee.employer_id == employer_id)
            .all()
        )

        if not assigned_employees:
            return jsonify({"message": "No employees with assigned wallets"}), 404

        employee_list = [{"id": emp.id, "username": emp.username, "balance": emp.balance} for emp in assigned_employees]

        return jsonify(employee_list), 200
