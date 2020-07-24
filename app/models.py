from app import db

class Benchmark(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64))
    instances = db.relationship('Instance', backref='benchmark', lazy='dynamic', cascade='all, delete-orphan')

    def json_obj(self):
        return {'id': self.id, 'name': self.name}

class Instance(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(256))
    benchmark_id = db.Column(db.Integer, db.ForeignKey('benchmark.id'))

    def json_obj_summary(self):
        return {'id': self.id, 'name': self.name}
    
    def object_key(self):
        return "instance{}.smt2".format(self.id)

class Solver(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(256))
    validation_solver = db.Column(db.Boolean)
    default_arguments = db.Column(db.String(1024))

    def json_obj_summary(self):
        return {'id': self.id, 'name': self.name, 'validation_solver': self.validation_solver, 'default_arguments': self.default_arguments}

    def object_key(self):
        return "solver{}.bin".format(self.id)
