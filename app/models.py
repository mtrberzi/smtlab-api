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
        return self.benchmark.name + "__" + self.name
