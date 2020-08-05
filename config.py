import os
basedir = os.path.abspath(os.path.dirname(__file__))

class Config(object):
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///' + os.path.join(basedir, 'app.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    OBJECT_STORAGE="filesystem"
    OBJECT_STORAGE_FILESYSTEM_BASE = os.environ.get('OBJECT_STORAGE_FILESYSTEM_BASE') or os.path.join(basedir, 'objs')
    OBJECT_STORAGE_BENCHMARK_BUCKET="benchmarks"
    OBJECT_STORAGE_SOLVER_BUCKET="solvers"
    QUEUE_CONNECTION = [(os.environ.get('QUEUE_HOST') or '127.0.0.1', os.environ.get('QUEUE_PORT') or 62613)]
    QUEUE_USERNAME = os.environ.get('QUEUE_USER') or 'smtlab'
    QUEUE_PASSWORD = os.environ..get('QUEUE_PASS') or 'smtlab'
