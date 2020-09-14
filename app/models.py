import time
import enum
from app import db, app
from sqlalchemy.sql import func
from sqlalchemy import event

import jwt
from werkzeug.security import generate_password_hash, check_password_hash

class SolverResponseEnum(enum.Enum):
    no_result = 0
    sat = 1
    unsat = 2
    timeout = 3
    unknown = 4
    error = 5

class ValidationEnum(enum.Enum):
    no_result = 0
    valid = 1
    invalid = 2
    timeout = 3
    unknown = 4
    error = 5

class PermissionEnum(enum.Enum):
    invalid_perm = 0
    read = 1
    upload_benchmark = 2
    upload_solver = 3
    message_queue = 4
    start_run = 5
    post_results = 6
    change_password = 7
    change_other_password = 8
    admin_user = 9
    
class Benchmark(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64))
    instances = db.relationship('Instance', backref='benchmark', lazy='dynamic', cascade='all, delete-orphan')
    runs = db.relationship('Run', backref='benchmark', lazy='dynamic', cascade='all, delete-orphan')

    def json_obj(self):
        return {'id': self.id, 'name': self.name}

class Instance(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(256))
    benchmark_id = db.Column(db.Integer, db.ForeignKey('benchmark.id'))
    results = db.relationship('Result', backref='instance', lazy='dynamic', cascade='all, delete-orphan')

    def json_obj_summary(self):
        return {'id': self.id, 'name': self.name}
    
    def object_key(self):
        return "instance{}.smt2".format(self.id)

class Solver(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(256))
    validation_solver = db.Column(db.Boolean)
    default_arguments = db.Column(db.String(1024))
    runs = db.relationship('Run', backref='solver', lazy='dynamic', cascade='all, delete-orphan')

    def json_obj_summary(self):
        return {'id': self.id, 'name': self.name, 'validation_solver': self.validation_solver, 'default_arguments': self.default_arguments}

    def object_key(self):
        return "solver{}.bin".format(self.id)

class Run(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    benchmark_id = db.Column(db.Integer, db.ForeignKey('benchmark.id'))
    solver_id = db.Column(db.Integer, db.ForeignKey('solver.id'))
    arguments = db.Column(db.String(1024))
    performance = db.Column(db.Boolean)
    results = db.relationship('Result', backref='run', lazy='dynamic', cascade='all, delete-orphan')
    description = db.Column(db.String(1024), default="")
    start_date = db.Column(db.DateTime(timezone=True))

    def json_obj_summary(self):
        return {'id': self.id, 'benchmark_id': self.benchmark.id, 'solver_id': self.solver.id, 'arguments': self.arguments, 'performance': self.performance, 'description': self.description, 'start_date': self.start_date.isoformat()}

class Result(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    run_id = db.Column(db.Integer, db.ForeignKey('run.id'))
    instance_id = db.Column(db.Integer, db.ForeignKey('instance.id'))
    result = db.Column(db.Enum(SolverResponseEnum), default=SolverResponseEnum.no_result)
    stdout = db.Column(db.UnicodeText())
    runtime = db.Column(db.Integer) # running time in milliseconds
    validation_results = db.relationship('ValidationResult', backref='result', lazy='dynamic', cascade='all, delete-orphan')

    def json_obj_summary(self):
        return {'id': self.id, 'run_id': self.run_id, 'instance_id': self.instance_id, 'result': self.result.name, 'runtime': self.runtime}
    
    def json_obj_details(self):
        return {'id': self.id, 'run_id': self.run_id, 'instance_id': self.instance_id, 'result': self.result.name, 'runtime': self.runtime, 'stdout': self.stdout}

class ValidationResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    result_id = db.Column(db.Integer, db.ForeignKey('result.id'))
    solver_id = db.Column(db.Integer, db.ForeignKey('solver.id'))
    validation = db.Column(db.Enum(ValidationEnum), default=ValidationEnum.no_result)
    stdout = db.Column(db.UnicodeText())

    def json_obj_summary(self):
        return {'id': self.id, 'result_id': self.result_id, 'solver_id': self.solver_id, 'validation': self.validation.name, 'stdout': self.stdout}

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), index=True)
    password_hash = db.Column(db.String(256))
    permissions = db.relationship('Permission', backref='user', cascade='all, delete-orphan')

    def json_obj_summary(self):
        return {'id': self.id, 'username': self.username, 'permissions': self.permissions}

    def hash_password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

    def generate_auth_token(self, expires_in=3600):
        return jwt.encode({'id': self.id, 'exp': time.time() + expires_in}, app.config['SECRET_KEY'], algorithm='HS256')

    def has_permission(self, perm):
        for p in self.permissions:
            if p.permission == perm:
                return True
        return False
    
    @staticmethod
    def verify_auth_token(token):
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        except:
            return None
        return User.query.get(data['id'])

class Permission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    permission = db.Column(db.Enum(PermissionEnum), default=PermissionEnum.invalid_perm)
