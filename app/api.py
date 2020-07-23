from flask import Flask, request
from flask_restful import Api, Resource, abort
import json

from app import app, db
from app.models import Benchmark, Instance
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
        for inst in json_data:
            if 'name' not in inst or 'body' not in inst:
                abort(400, description="Instance must specify 'name' and 'body'")
            instance = Instance(name=inst['name'], benchmark=benchmark)
            db.session.add(instance)
            objstor.put(app.config['OBJECT_STORAGE_BENCHMARK_BUCKET'], instance.object_key(), inst['body'].encode('utf-8'))
        db.session.commit()
        return ('', 204)

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
