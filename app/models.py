import enum
from app import db

class SolverResponseEnum(enum.Enum):\
    no_result = 0
    sat = 1
    unsat = 2
    timeout = 3
    unknown = 4
    error = 5

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

    def json_obj_summary(self):
        return {'id': self.id, 'benchmark_id': self.benchmark.id, 'solver_id': self.solver.id, 'arguments': self.arguments, 'performance': self.performance}

class Result(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    run_id = db.Column(db.Integer, db.ForeignKey('run.id'))
    instance_id = db.Column(db.Integer, db.ForeignKey('instance.id'))
    result = db.Column(db.Enum(SolverResponseEnum), default=SolverResponseEnum.no_result)
    stdout = db.Column(db.UnicodeText())
    runtime = db.Column(db.Integer) # running time in milliseconds
