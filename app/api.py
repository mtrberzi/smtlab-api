from flask import Flask, request
from flask_restful import Api, Resource, abort
import json
import base64

from app import app, db
from app.models import Benchmark, Instance, Solver
from app.storage import ObjectStorageError, FileSystemObjectStorage

def get_object_storage_client():
    storage_type = app.config['OBJECT_STORAGE']
    if storage_type == "filesystem":
        return FileSystemObjectStorage(app.config['OBJECT_STORAGE_FILESYSTEM_BASE'])
    else:
        raise ValueError("Unknown object storage type {}".format(storage_type))

api = Api(app)

class BenchmarkListAPI(Resource):    
    def get(self):
        all_benchmarks = Benchmark.query.all()
        response = []
        for benchmark in all_benchmarks:
            response.append(benchmark.json_obj())
        return response

    def post(self):
        json_data = request.get_json()
        if not json_data:
            abort(400, description="No input data provided")
        if "name" not in json_data:
            abort(400, description="Benchmark name must be specified")
        new_benchmark = Benchmark(name=json_data["name"])
        db.session.add(new_benchmark)
        db.session.commit()
        return new_benchmark.json_obj()

api.add_resource(BenchmarkListAPI, '/benchmarks', endpoint = 'benchmark_list')

class BenchmarkAPI(Resource):
    def get(self, id):
        benchmark = Benchmark.query.get(id)
        if benchmark is None:
            abort(404)
        else:
            return benchmark.json_obj()

    # Upload instances
    def post(self, id):
        benchmark = Benchmark.query.get(id)
        if benchmark is None:
            abort(404)
        json_data = request.get_json()
        if not json_data:
            abort(400, description="No input data provided")
        objstor = get_object_storage_client()
        objstor.ensure_bucket_exists(app.config['OBJECT_STORAGE_BENCHMARK_BUCKET'])
        instance_data = []
        for inst in json_data:
            if 'name' not in inst or 'body' not in inst:
                abort(400, description="Instance must specify 'name' and 'body'")
            instance = Instance(name=inst['name'], benchmark=benchmark)
            db.session.add(instance)
            instance_data.append( (instance, inst['body'].encode('utf-8')) )
        db.session.commit()
        for instance, body in instance_data:
            objstor.put(app.config['OBJECT_STORAGE_BENCHMARK_BUCKET'], instance.object_key(), body)
        response = []
        for instance, body in instance_data:
            response.append(instance.json_obj_summary())
        return response

    def delete(self, id):
        Benchmark.query.filter(Benchmark.id == id).delete()
        db.session.commit()
        return ('', 204)

api.add_resource(BenchmarkAPI, '/benchmarks/<int:id>', endpoint = 'benchmark')

class InstanceListAPI(Resource):
    def get(self, id):
        benchmark = Benchmark.query.get(id)
        if benchmark is None:
            abort(404)
        instances = []
        for inst in benchmark.instances.all():
            instances.append(inst.json_obj_summary())
        return instances
api.add_resource(InstanceListAPI, '/benchmarks/<int:id>/instances', endpoint = 'instance_list')

class InstanceAPI(Resource):
    def get(self, id):
        instance = Instance.query.get(id)
        if instance is None:
            abort(404)
        inst = instance.json_obj_summary()
        objstor = get_object_storage_client()
        objstor.ensure_bucket_exists(app.config['OBJECT_STORAGE_BENCHMARK_BUCKET'])
        inst['body'] = objstor.get(app.config['OBJECT_STORAGE_BENCHMARK_BUCKET'], instance.object_key()).decode('utf-8')
        return inst

    def put(self, id):
        abort(500) # TODO
        json_data = request.get_json()
        if not json_data:
            abort(400, description="No input data provided")
        
api.add_resource(InstanceAPI, '/instances/<int:id>', endpoint = 'instance')

class SolverListAPI(Resource):
    def get(self):
        all_solvers = Solver.query.all()
        response = []
        for solver in all_solvers:
            response.append(solver.json_obj_summary())
        return response

    def post(self):
        json_data = request.get_json()
        if not json_data:
            abort(400, description="No input data provided")
        if "name" not in json_data or "validation_solver" not in json_data or "base64_binary" not in json_data:
            abort(400, description="Solver must specify 'name', 'validation_solver', and 'base64_binary'")
        if "default_arguments" in json_data:
            args = json_data["default_arguments"]
        else:
            args = ""
        solver_bytes = base64.b64decode(json_data["base64_binary"].encode('ascii'))
        objstor = get_object_storage_client()
        objstor.ensure_bucket_exists(app.config['OBJECT_STORAGE_SOLVER_BUCKET'])
        solver = Solver(name=json_data["name"], validation_solver=json_data["validation_solver"], default_arguments=args)
        db.session.add(solver)
        db.session.commit()
        objstor.put(app.config['OBJECT_STORAGE_SOLVER_BUCKET'], solver.object_key(), solver_bytes)
        return solver.json_obj_summary()

api.add_resource(SolverListAPI, '/solvers', endpoint = 'solver_list')

class SolverAPI(Resource):
    def get(self, id):
        solver = Solver.query.get(id)
        if solver is None:
            abort(404)
        solv = solver.json_obj_summary()
        objstor = get_object_storage_client()
        solver_binary = objstor.get(app.config['OBJECT_STORAGE_SOLVER_BUCKET'], solver.object_key())
        solv['base64_binary'] = base64.b64encode(solver_binary).decode('ascii')
        return solv

api.add_resource(SolverAPI, '/solvers/<int:id>', endpoint = 'solver')
