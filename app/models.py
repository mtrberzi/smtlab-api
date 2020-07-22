from app import db

class Benchmark(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64))
    instances = db.relationship('Instance', backref='benchmark', lazy='dynamic', cascade='all, delete-orphan')

class Instance(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(256))
    body = db.Column(db.Text())
    benchmark_id = db.Column(db.Integer, db.ForeignKey('benchmark.id'))
